#!/usr/bin/env python3
"""Native controller dispatch: fixed disabled gates, real Linux flock/Lua/jsonc.
UCI and service commands are explicit private fixtures, never the router.
"""
import argparse,json,os,re,shutil,signal,subprocess,tempfile,time,unittest
from pathlib import Path
from project import ROOT
from lupa.lua51 import LuaRuntime

MODEL=ROOT/'project/luci/lua/luasrc/model/homegate/writer.lua'
CONTROLLER=ROOT/'project/luci/lua/luasrc/controller/homegate.lua'
SHELL=ROOT/'project/core/prototype/homegate-frontend-write.sh'
RUNNER=SHELL.with_suffix('.lua')

def route_map():
    lua=LuaRuntime(); module=lua.execute(MODEL.read_text(encoding='utf-8'))
    return dict(module.routes.items())

class Static(unittest.TestCase):
    def test_all_mutating_post_routes_guarded_before_handler(self):
        source=CONTROLLER.read_text(encoding='utf-8')
        posts=dict(re.findall(r'entry\(\{[^}]*"homegate",\s*"([^"]+)"\},\s*post\("([^"]+)"\)',source))
        readonly={'config_export','config_import','diagnostic_download'}
        self.assertEqual(set(posts)-readonly,set(route_map()))
        self.assertEqual(len(route_map()),17)
        block=source.split('local native_write_routes = {',1)[1].split('}',1)[0]
        self.assertEqual(dict(re.findall(r'(\w+)="([^"]+)"',block)),route_map())
        self.assertEqual(source.count('cur:commit("homegate")'),1)
        lua=LuaRuntime(unpack_returned_tuples=True)
        lua.execute('''captured={}; package.preload['luci.model.homegate.writer']=function() return {
          run=function(route,fn) captured[#captured+1]=route; assert(type(fn)=='function') end} end
          package.preload['luci.model.uci']=function() error('cursor before guard') end''')
        lua.execute(source)
        for route,handler in route_map().items(): lua.globals().luci.controller.homegate[handler]()
        self.assertEqual(set(lua.globals().captured.values()),set(route_map()))

    def test_original_gates_reject_before_io_or_cursor(self):
        lua=LuaRuntime(unpack_returned_tuples=True)
        lua.execute('''captured={}; package.preload['luci.http']=function() return {
          status=function(code) captured.status=code end, prepare_content=function() end,
          write=function(body) captured.body=body end, formvalue=function() error('form IO') end} end''')
        model=lua.execute(MODEL.read_text(encoding='utf-8'))
        for route in route_map(): model.run(route,lua.eval("function() error('handler') end"))
        self.assertEqual(lua.globals().captured.status,503)
        self.assertNotIn('handler',lua.globals().captured.body)
        body=SHELL.read_text(); self.assertEqual(body.count('native_dispatch_enabled=false'),1)
        self.assertNotIn('os.getenv',MODEL.read_text())
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_lua_and_shell_syntax_and_fixed_dispatch(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        self.assertFalse(parser.parse(SHELL.read_bytes()).root_node.has_error)
        for f in [MODEL,CONTROLLER,RUNNER]: LuaRuntime().compile(f.read_text(encoding='utf-8'))
        self.assertIn('flock -n 6',SHELL.read_text())
        self.assertIn('LUA_INIT LUA_PATH LUA_CPATH',SHELL.read_text())
        self.assertEqual(RUNNER.read_text().count('original_exec("exec 6>&-; ("')+RUNNER.read_text().count('original_call("exec 6>&-; ("'),2)
        self.assertNotIn('request.handler',RUNNER.read_text())

class Transport(unittest.TestCase):
    def setUp(self):
        self.lua=LuaRuntime(unpack_returned_tuples=True)
        def encode(value):
            return json.dumps({'route':value.route,'form':dict(value.form.items())})
        def decode(value): return self.lua.table_from(json.loads(value),recursive=True)
        self.lua.globals().encode=encode; self.lua.globals().decode=decode
        self.lua.execute('''
captured={}; form={mode='save',secret='SECRET_SENTINEL'}; result='{"ok":true,"dispatched":true,"redirect":"/cgi-bin/luci/admin/services/homegate/basic?notice=Saved"}'
package.preload['luci.http']=function() return {
 formvalue=function() return form end, status=function(code)captured.status=code end,
 prepare_content=function() end,write=function(body)captured.body=body end,
 redirect=function(url)captured.redirect=url end} end
package.preload['luci.jsonc']=function() return {stringify=encode,parse=decode} end
package.preload['nixio.util']=function() return {} end
package.preload['nixio.fs']=function() return {
 mkdir=function(path,mode) captured.dir=path; assert(mode==448); return not fail_mkdir end,
 unlink=function(path)captured.unlinked=path;return true end,
 rmdir=function(path)captured.removed=path;return true end} end
package.preload['nixio']=function() return {
 open_flags=function(...) assert(table.concat({...},',')=='wronly,creat,excl'); return 1 end,
 open=function(path,flags,mode) assert(mode==384); captured.path=path; return {
 writeall=function(self,body) captured.private_body=body; if fail_write then error('SECRET_SENTINEL') end; return short_write and 0 or #body end,
 close=function()captured.closed=(captured.closed or 0)+1; return true end} end} end
package.preload['luci.sys']=function() return {exec=function(command)
 captured.command=command; if fail_backend then error('SECRET_SENTINEL') end; return result end} end
io.open=function(path,mode) assert(path=='/proc/sys/kernel/random/uuid' and mode=='r'); return {
 read=function() return bad_uuid and "untrusted/../../path" or '12345678-1234-1234-1234-123456789abc\\n' end,close=function()return true end} end
''')
        source=MODEL.read_text().replace('native_dispatch_enabled = false','native_dispatch_enabled = true')
        self.model=self.lua.execute(source)

    def execute(self): self.model.run('basic_apply',self.lua.eval("function() error('original handler bypass') end"))

    def test_credentials_only_in_private_request_and_safe_fixed_command(self):
        self.execute(); c=self.lua.globals().captured
        self.assertIn('SECRET_SENTINEL',c.private_body); self.assertNotIn('SECRET_SENTINEL',c.command)
        self.assertEqual(c.command,"/usr/libexec/homegate/frontend-write '/tmp/homegate-luci-12345678123412341234123456789abc/request' 2>/dev/null")
        self.assertEqual(c.unlinked,c.path); self.assertEqual(c.removed,c.dir); self.assertEqual(c.closed,1)
        self.assertIn('notice=Saved',c.redirect)

    def test_exception_closes_and_cleans_without_echo(self):
        self.lua.globals().fail_write=True; self.execute(); c=self.lua.globals().captured
        self.assertEqual(c.closed,1); self.assertEqual(c.unlinked,c.path); self.assertEqual(c.removed,c.dir)
        self.assertEqual(c.status,503); self.assertNotIn('SECRET_SENTINEL',c.body)

    def test_short_write_and_backend_error_never_report_success(self):
        self.lua.globals().short_write=True; self.execute(); self.assertEqual(self.lua.globals().captured.status,503)
        self.setUp(); self.lua.globals().fail_backend=True; self.execute()
        c=self.lua.globals().captured; self.assertEqual(c.status,503); self.assertIsNone(c.redirect)
        self.assertEqual(c.closed,1); self.assertEqual(c.unlinked,c.path)

    def test_malformed_form_or_uuid_stops_before_private_file(self):
        for value in [True,['array']]:
            self.setUp(); self.lua.globals().form=self.lua.table_from({'mode':value},recursive=True); self.execute()
            self.assertIsNone(self.lua.globals().captured.path)
        self.setUp(); self.lua.globals().bad_uuid=True; self.execute(); self.assertIsNone(self.lua.globals().captured.path)

    def test_foreign_or_injected_redirect_and_oversized_response_refused(self):
        for response in ['{"ok":true,"dispatched":true,"redirect":"https://example.test/"}',
                         '{"ok":true,"dispatched":true,"redirect":"/cgi-bin/luci/admin/services/homegate/../../system"}',
                         '{"ok":true,"dispatched":true,"redirect":"/cgi-bin/luci/admin/services/homegate/basic\\r\\nX: bad"}',
                         'x'*65537]:
            self.setUp(); self.lua.globals().result=response; self.execute(); self.assertEqual(self.lua.globals().captured.status,503)

class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.busybox=shutil.which('busybox'); cls.lua=shutil.which('lua5.1')
        if not cls.busybox or not cls.lua or not (ROOT/'build/service-observer/luci/jsonc.so').is_file():
            raise RuntimeError('Linux BusyBox, Lua51 and official jsonc required')

    def setUp(self):
        self.base=Path(tempfile.mkdtemp(prefix='homegate-native-writer-')); self.base.chmod(0o700)
        self.system=self.base/'system'; self.system.mkdir(mode=0o700)
        self.lockdir=self.system/'lock'; self.lockdir.mkdir(mode=0o700)
        self.lock=self.lockdir/'frontend.lock'; self.lock.touch(mode=0o600)
        unlocked=subprocess.run([self.busybox,'flock','-n',str(self.lock),'/bin/true'],capture_output=True,timeout=2)
        self.assertEqual(unlocked.returncode,0,unlocked.stderr)
        self.trace=self.base/'trace'; self.trace.touch(mode=0o600)
        self.config=self.base/'config.json'; self.config.write_text('{}'); self.config.chmod(0o600)
        self.prefix=str(self.base/'homegate-luci-')
        self.boot=self.base/'boot.lua'; self.engine=self.base/'writer.sh'; self.children=[]
        body=SHELL.read_text().replace('native_dispatch_enabled=false','native_dispatch_enabled=true')
        body=body.replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
        body=body.replace('/tmp/homegate-luci-',self.prefix).replace('/var/run/homegate',str(self.lockdir))
        body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(Path(self.busybox).parent)+':/usr/bin:/bin')
        body=body.replace('exec /usr/bin/lua /usr/libexec/homegate/frontend-write.lua', 'exec '+self.lua+' '+str(self.boot))
        # Prior native-route tests isolate dispatch only. The r24 persistent
        # suite replaces this fixed check with the real copied state engine.
        body=body.replace('/usr/libexec/homegate/config-transaction --persistent writer-check', '/bin/true')
        self.engine.write_text(body); self.engine.chmod(0o700)
        quote=lambda p:json.dumps(str(p))
        self.boot.write_text('''
package.cpath='''+quote(ROOT/'build/service-observer/?.so')+'''..';'..package.cpath
local json=require('luci.jsonc')
local trace,config,lock='''+quote(self.trace)+','+quote(self.config)+','+quote(self.lock)+'''
local function event(name)
 local check=io.popen('exec 6>&-; '..'''+quote(self.busybox+' flock -n ')+'''..lock..' /bin/true >/dev/null 2>&1; printf "%s" "$?"')
 local rc=check:read('*a'); check:close(); assert(rc=='1','lock absent or probe failed')
 local f=assert(io.open(trace,'a')); f:write(name..'\\n'); f:close()
end
local function data() local f=assert(io.open(config,'r')); local s=f:read('*a'); f:close(); return json.parse(s) end
local values=data()
local cur={
 get_all=function(_,pkg,id) event('read'); return {['.type']=id=='host_a' and 'wol_host' or 'homegate',['.name']=id} end,
 get=function(_,pkg,id,key) event('read'); return values[key] end,
 set=function(_,pkg,id,key,value) event('set'); values[key]=value; return true end,
 foreach=function() event('read') end,
 section=function(_,pkg,kind,id,fields) event('set'); for k,v in pairs(fields or {}) do values[k]=v end; return id end,
 delete=function() event('delete'); return true end,
 revert=function() event('revert'); return true end,
 commit=function() event('commit');
   if values.test_pause then os.execute('exec 6>&-; sleep 0.6') end
   if values.test_commit_nil then return nil end
   local f=assert(io.open(config,'w')); f:write(json.stringify(values)); f:close(); return true end}
package.preload['luci.model.uci']=function() return {cursor=function() event('cursor'); return cur end} end
package.preload['luci.http']=function() return {urlencode=function(s) return (tostring(s):gsub('[^%w_%.~-]',function(c)return string.format('%%%02X',c:byte())end)) end} end
package.preload['luci.dispatcher']=function() return {context={authtoken='fixture'},build_url=function(...)return '/cgi-bin/luci/'..table.concat({...},'/')end} end
package.preload['luci.sys']=function() return {
 exec=function(command) assert(command:sub(1,12)=='exec 6>&-; ('); event('exec'); return '' end,
 call=function(command) assert(command:sub(1,12)=='exec 6>&-; ('); event('call'); return 0 end} end
package.preload['luci.model.homegate.writer']=function() return dofile('''+quote(MODEL)+''') end
local original_open=io.open
io.open=function(path,mode)
 if mode and mode:match('[wa]') and path~=trace and path~=config then return nil end
 return original_open(path,mode)
end
package.preload['luci.controller.homegate']=function() event('dispatch'); dofile('''+quote(CONTROLLER)+'''); return luci.controller.homegate end
dofile('''+quote(RUNNER)+''')
''',encoding='utf-8')

    def tearDown(self):
        for p in self.children:
            if p.poll() is None: p.kill(); p.wait(timeout=3)
        shutil.rmtree(self.base)

    def request(self,route='basic_apply',form=None,body=None):
        d=Path(self.prefix+os.urandom(16).hex()); d.mkdir(mode=0o700)
        p=d/'request'; p.write_bytes(body if body is not None else json.dumps({'route':route,'form':form or {
            'ddns_interval':'300','https_port':'443','proxy_https_port':'10443','mode':'save'}},ensure_ascii=False).encode())
        p.chmod(0o600); return p

    def run_request(self,p,code=0,env=None):
        result=subprocess.run([self.busybox,'ash',str(self.engine),str(p)],capture_output=True,timeout=5,env=env)
        self.assertEqual(result.returncode,code,(result.stdout,result.stderr)); self.assertEqual(result.stderr,b'')
        self.assertNotIn(b'SECRET_SENTINEL',result.stdout); return json.loads(result.stdout)

    def test_basic_save_real_controller_under_whole_request_lock(self):
        report=self.run_request(self.request()); self.assertTrue(report['ok'])
        self.assertIn('notice=Saved',report['redirect'])
        self.assertEqual(json.loads(self.config.read_text())['https_port'],'443')
        events=self.trace.read_text().splitlines(); self.assertEqual(events[:2],['dispatch','cursor']); self.assertIn('commit',events)

    def test_busy_lock_prevents_cursor_and_mutation(self):
        import fcntl
        with self.lock.open('rb') as fd:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.run_request(self.request(),4)
        self.assertEqual(self.trace.read_text(),''); self.assertEqual(self.config.read_text(),'{}')

    def test_competing_native_requests_share_flock(self):
        self.config.write_text('{"test_pause":true}')
        p=subprocess.Popen([self.busybox,'ash',str(self.engine),str(self.request())],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.children.append(p); deadline=time.monotonic()+3
        while 'commit' not in self.trace.read_text():
            self.assertLess(time.monotonic(),deadline); time.sleep(0.01)
        self.run_request(self.request(),4)
        out,err=p.communicate(timeout=3); self.assertEqual(p.returncode,0); self.assertEqual(err,b''); self.assertTrue(json.loads(out)['ok'])

    def test_all_write_routes_use_same_guard(self):
        for route in route_map():
            self.trace.write_text(''); self.run_request(self.request(route,{'op':'invalid','id':'invalid','mode':'save'}))
            self.assertTrue(self.trace.read_text(),route)

    def test_unlisted_read_and_handler_override_refused(self):
        for route in ['config_export','config_import','diagnostic_download','api/status','../config_reset','action_basic_apply']:
            self.run_request(self.request(route),2)
        self.run_request(self.request(body=b'{"route":"basic_apply","form":{},"handler":"action_config_reset"}'),2)
        self.assertEqual(self.trace.read_text(),'')

    def test_malformed_trailing_and_typed_inputs_refused(self):
        for body in [b'{}',b'{',b'{"route":"basic_apply","form":[]}{}',b'{"route":"basic_apply","form":{"mode":true}}',
                     b'{"route":"basic_apply","form":{"x":"\\u0000"}}',b'{"route":"basic_apply","form":{"x\\u0000suffix":"text"}}',
                     b'{"route":"basic_apply","form":{"x":"before\\u0000after"}}',b'{"route":"basic_apply","form":{"bad-key":"x"}}']:
            with self.subTest(body=body): self.run_request(self.request(body=body),2)
        self.assertEqual(self.trace.read_text(),'')
        # A literal backslash followed by u0000 is ordinary text, not NUL.
        report=self.run_request(self.request(form={'mode':'save','https_port':'443','ddns_interval':'300',
                                                  'proxy_https_port':'10443','unused':r'\u0000'}))
        self.assertTrue(report['ok'])

    def test_private_path_modes_links_and_limits(self):
        p=self.request(); p.chmod(0o644); self.run_request(p,2); p.chmod(0o600)
        q=p.parent/'link'; os.link(p,q); self.run_request(p,2); q.unlink()
        original=p.read_bytes(); p.unlink(); p.symlink_to(self.config); self.run_request(p,2); p.unlink(); p.write_bytes(original); p.chmod(0o600)
        p.parent.chmod(0o755); self.run_request(p,2); p.parent.chmod(0o700)
        p.write_bytes(b'x'*2097153); self.run_request(p,2)
        self.assertEqual(self.trace.read_text(),'')

    def test_unsafe_lock_never_repaired_replaced_or_followed(self):
        p=self.request(); self.lock.chmod(0o644); self.run_request(p,7); self.assertEqual(self.lock.stat().st_mode&0o777,0o644)
        self.lock.unlink(); self.lock.symlink_to(self.config); self.run_request(p,7)
        self.assertEqual(self.config.read_text(),'{}'); self.assertEqual(self.trace.read_text(),'')

    def test_nil_commit_does_not_reload_or_report_saved(self):
        self.config.write_text('{"test_commit_nil":true}')
        report=self.run_request(self.request(form={'ddns_interval':'300','https_port':'443','proxy_https_port':'10443','mode':'apply'}))
        self.assertFalse(report['ok']); self.assertIn('error=UCI',report['redirect']); self.assertNotIn('call',self.trace.read_text().splitlines())

    def test_wol_commit_failure_prevents_packet(self):
        self.config.write_text('{"test_commit_nil":true}')
        report=self.run_request(self.request('wol_action',{'op':'wake','id':'host_a'}))
        self.assertFalse(report['ok']); self.assertIn('error=UCI',report['redirect']); self.assertNotIn('call',self.trace.read_text().splitlines())

    def test_sigkill_owner_releases_lock_for_next_request(self):
        self.config.write_text('{"test_pause":true}')
        p=subprocess.Popen([self.busybox,'ash',str(self.engine),str(self.request())],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.children.append(p); deadline=time.monotonic()+3
        while 'commit' not in self.trace.read_text():
            self.assertLess(time.monotonic(),deadline); time.sleep(0.01)
        p.kill(); p.wait(timeout=3); self.config.write_text('{}'); request=self.request()
        # A just-forked launcher may not have executed its FD close yet.
        # Bound that scheduling window; a lasting inherited lock still fails.
        deadline=time.monotonic()+2
        while True:
            result=subprocess.run([self.busybox,'ash',str(self.engine),str(request)],capture_output=True,timeout=3)
            if result.returncode!=4: break
            self.assertLess(time.monotonic(),deadline); time.sleep(0.01)
        self.assertEqual(result.returncode,0,(result.stdout,result.stderr)); self.assertEqual(result.stderr,b'')
        self.assertTrue(json.loads(result.stdout)['ok'])

    def test_product_shell_gate_cannot_be_enabled_by_environment(self):
        result=subprocess.run([self.busybox,'ash',str(SHELL),str(self.request())],capture_output=True,timeout=2,
                              env={**os.environ,'native_dispatch_enabled':'true','HOMEGATE_NATIVE_WRITER_ENABLED':'1'})
        self.assertEqual(result.returncode,2); self.assertEqual(self.trace.read_text(),'')

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--runtime',action='store_true'); a=p.parse_args()
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in ([Runtime] if a.runtime else [Static,Transport]))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
