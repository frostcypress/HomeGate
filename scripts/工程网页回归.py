#!/usr/bin/env python3
"""Real pinned LuCI sessions/CSRF -> installed engineering configuration/DDNS.

Reuse the established unprivileged bwrap boundary and external tool fixtures.
No target installation, real credentials or remote DNS operations.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess,sys,time,unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode
from project import ROOT
from engineering_runtime import stage,web_payload

spec=importlib.util.spec_from_file_location('engineering_luci',ROOT/'scripts/luci-ddns-regressions.py')
luci=importlib.util.module_from_spec(spec);spec.loader.exec_module(luci)
rpc=luci.rpc;STATE=rpc.STATE
BASE='/cgi-bin/luci/admin/services/homegate_engineering'
PAGE=BASE+'/configuration'
INSTALLED=None

def install_tree(root):
    base=root/'usr/libexec/homegate-engineering';stage(ROOT,base)
    for name in ['engineering.lua','ddns-control.sh','apply-handle.lua','service-disabled','config-web.sh','config-web.lua','schedule-control.sh']:
        dest=base/name;shutil.copyfile(ROOT/'packaging/engineering/files'/name,dest);dest.chmod(0o755)
    entry=root/'usr/bin/homegate-engineering';entry.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/'packaging/engineering/files/homegate-engineering',entry);entry.chmod(0o755)
    for name,raw in web_payload(ROOT).items():
        dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
    for name,path in [('controller.lua','usr/lib/lua/luci/controller/homegate_engineering.lua'),
                      ('overview.htm','usr/lib/lua/luci/view/homegate_engineering/overview.htm'),
                      ('homegate-engineering.init','etc/init.d/homegate-engineering'),
                      ('95-homegate-engineering','etc/hotplug.d/iface/95-homegate-engineering')]:
        dest=root/path;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/'packaging/engineering/files'/name,dest);dest.chmod(0o755 if name in ['homegate-engineering.init','95-homegate-engineering'] else 0o644)

def setup_state(state):
    luci.setup_state(state)
    installed=state/'installed'
    if INSTALLED:shutil.copytree(INSTALLED,installed,symlinks=True)
    else:installed.mkdir();install_tree(installed)
    # Real LuCI dispatcher/session modules remain untouched. Only the private
    # admin authentication root and native template header are fixture data.
    (state/'controllers/fixture.lua').write_text("""module('luci.controller.fixture',package.seeall)
function index()
 local p=entry({'admin'},firstchild(),'Fixture',1)
 p.sysauth={'fixture_writer'};p.sysauth_authenticator='htmlauth'
end
""")
    (state/'controllers/homegate_ddns.lua').unlink()
    shutil.copytree(installed/'usr/lib/lua/luci/controller',state/'controllers',dirs_exist_ok=True)
    shutil.copytree(installed/'usr/lib/lua/luci/model',state/'models',dirs_exist_ok=True)
    shutil.copytree(installed/'usr/lib/lua/luci/view',state/'view',dirs_exist_ok=True)
    shutil.copytree(installed/'www',state/'www',dirs_exist_ok=True)
    shutil.copytree(installed/'usr/libexec/homegate-engineering',state/'libexec/homegate-engineering')
    (state/'tools').mkdir(exist_ok=True)
    # Backend paths are the actual installed paths; executable lookup and DNS
    # transport are the same explicit fixed external fixtures used previously.
    shutil.copyfile(installed/'usr/bin/homegate-engineering',state/'tools/homegate-engineering')
    (state/'tools/homegate-engineering').chmod(0o755)
    modules=luci.LUA/'prefix/lib/lua'
    (state/'lua-runner.lua').write_text('package.path='+json.dumps(str(modules/'?.lua')+';'+str(modules/'?/init.lua'))+
      '\npackage.cpath='+json.dumps(str(modules/'?.so'))+"\nlocal f=table.remove(arg,1);arg[0]=f;assert(loadfile(f))(unpack(arg))\n")
    shutil.copyfile(ROOT/'build/busybox-runtime/busybox-1.33.2/busybox',state/'tools/busybox')
    (state/'tools/busybox').chmod(0o755)
    for name in ['ash','fsync']:
        dest=state/'tools'/name
        if dest.exists() or dest.is_symlink():dest.unlink()
        dest.symlink_to('busybox')
    (state/'tools/lua').write_text('#!/bin/sh\nexec /usr/bin/lua5.1 /teststate/lua-runner.lua "$@"\n');(state/'tools/lua').chmod(0o755)
    (state/'etc/homegate-engineering').mkdir(mode=0o700)
    (state/'etc/config/homegate_engineering').write_bytes((ROOT/'packaging/engineering/files/homegate_engineering.config').read_bytes())
    (state/'etc/config/homegate_engineering').chmod(0o600)
    (state/'etc/config/homegate').write_bytes(b'PRODUCTION_CONFIGURATION_KEEP\n')
    (state/'etc/rc.common').write_text('#!/bin/sh\nexit 99\n');(state/'etc/rc.common').chmod(0o755)
    (state/'tools/ubus').write_text("#!/bin/sh\nprintf '{}\\n'\n");(state/'tools/ubus').chmod(0o755)
    # This no-op transport confirms the async worker reaches the real provider
    # planner without mutation. Four-provider real TLS is separately exercised.
    (state/'tools/ip').write_text("#!/bin/sh\ncase \"$*\" in *addr*) printf '12: pppoe-wan inet6 2001:db8::2/64 scope global\\n';; *) printf 'default via fe80::1 dev pppoe-wan metric 512\\n';; esac\n");(state/'tools/ip').chmod(0o755)
    curl=state/'tools/curl'
    curl.write_text("""#!/usr/bin/python3
import sys,json,time,re
from pathlib import Path
p=Path(sys.argv[sys.argv.index('--config')+1]);raw=p.read_text()
with open('/teststate/provider-calls','a') as log:log.write('read\\n')
mode=Path('/teststate/provider-mode').read_text() if Path('/teststate/provider-mode').exists() else 'noop'
if mode=='hold':
 Path('/teststate/provider-entered').write_bytes(b'held')
 deadline=time.monotonic()+15
 while not Path('/teststate/provider-release').exists():
  if time.monotonic()>=deadline:sys.exit(99)
  time.sleep(.03)
if mode.startswith('delete-'):
 rec={'id':'2'*32,'name':'www.example.test','type':'AAAA','content':'2001:db8::2','ttl':120,'proxied':False}
 detail=re.search(r'/dns_records/[0-9a-f]{32}',raw)
 if 'request = "DELETE"' in raw:
  Path('/teststate/provider-mode').write_text('delete-absent')
  if mode=='delete-unknown':print('{"success":false,"errors":[{"code":1000}]}');print('HGHTTP:500')
  else:print(json.dumps({'success':True,'result':{'id':'2'*32}}));print('HGHTTP:200')
  sys.exit(0)
 if detail:
  if mode=='delete-absent':print('{"success":false,"errors":[{"code":81044}]}');print('HGHTTP:404')
  else:print(json.dumps({'success':True,'result':rec}));print('HGHTTP:200')
  sys.exit(0)
if 'request = "POST"' in raw or 'request = "PATCH"' in raw or 'request = "DELETE"' in raw:
 if mode!='unknown':sys.exit(99)
 print('{"success":false,"errors":[{"code":1000,"message":"temporary"}]}');print('HGHTTP:500');sys.exit(0)
record='dns_records' in raw
result=[{'id':'2'*32,'name':'www.example.test','type':'AAAA','content':'2001:db8::2','ttl':120,'proxied':False}] if record else [{'id':'1'*32,'name':'example.test','status':'active'}]
if record and mode in ['unknown','delete-absent']:result=[]
page_source=sys.argv[sys.argv.index('--url')+1] if '--url' in sys.argv else raw
page_size=re.search(r'per_page=([0-9]+)',page_source)
print(json.dumps({'success':True,'result':result,'result_info':{'page':1,'total_pages':1,'per_page':int(page_size.group(1)) if page_size else 5,'total_count':len(result)}}))
print('HGHTTP:200')
""");curl.chmod(0o755)
    # Workers deliberately require a regular curl at /usr/bin/curl.
    shutil.copyfile(curl,state/'curl-fixture')
    (state/'curl-fixture').chmod(0o755)
    (state/'business-sha.json').write_text(json.dumps({str(f.relative_to(state/'libexec')):hashlib.sha256(f.read_bytes()).hexdigest() for f in (state/'libexec/homegate-engineering').rglob('*') if f.is_file()}))

class Web(luci.LuaLuCI):
    HTTP_TIMEOUT=30;CGI_TIMEOUT=30
    def setUp(self):pass
    def login(self):
        status,headers,_=self.cgi(PAGE,verb='POST',fields={'luci_username':'fixture_writer','luci_password':rpc.FIXTURE_PASSWORD})
        self.assertEqual(status,302,'Private LuCI login failed')
        cookies=SimpleCookie();cookies.load(headers.get('set-cookie',''));sid=cookies['sysauth'].value
        status,_,body=self.cgi(PAGE,cookie=sid);self.assertEqual(status,200)
        token=re.search(rb'data-token="([0-9a-f]+)"',body);self.assertIsNotNone(token)
        return sid,token.group(1).decode()
    def api(self,area,action,session=None,fields=None,expected=200,verb=None):
        sid,token=session if session else (None,None)
        write=action not in ['read','status','jobs','schedule_status'];payload=dict(fields or {})
        if write and token:payload['token']=token
        status,_,body=self.cgi(BASE+'/'+area+'/'+action,cookie=sid,verb=verb or ('POST' if write else 'GET'),fields=payload)
        self.assertEqual(status,expected,(area,action,status,body[:250] if b'SECRET_SENTINEL' not in body else b'[suppressed]'))
        self.assertNotIn(b'SECRET_SENTINEL',body)
        if expected!=200:return None
        value=json.loads(body);self.assertTrue(value['ok']);return value
    def cfg(self,action,s,**fields):return self.api('configuration_api',action,s,fields)
    def prepare_account(self,s):
        self.cfg('prepare',s)
        preview=self.cfg('preview_account',s,id='dns_a',name='DNS account',provider='cloudflare')
        self.cfg('apply',s,confirmation=preview['report']['confirmation'],consent='1')
    def publish(self,s):
        p=self.cfg('activate_preview',s);self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
    def rule(self,s):
        p=self.cfg('preview_rule',s,id='ddns_a',account='dns_a',zone='example.test',host='www.example.test',source='auto',interface='')
        self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
    def verify_unchanged(self):
        for n,sha in json.loads((STATE/'business-sha.json').read_text()).items():
            self.assertEqual(hashlib.sha256((STATE/'libexec'/n).read_bytes()).hexdigest(),sha,n)
        self.assertEqual(Path('/etc/config/homegate').read_bytes(),b'PRODUCTION_CONFIGURATION_KEEP\n')
        self.assertEqual(list(Path('/tmp').glob('homegate-engineering-web-*')),[])
        self.assertEqual(list(Path('/tmp').glob('homegate-engineering-ddns-ui-*')),[])
    def test_security(self):
        for page in [PAGE,BASE+'/settings/ddns']:
            status,_,_=self.cgi(page);self.assertEqual(status,403)
        s=self.login()
        for action in ['provider_status','zones','delete_rule','prepare','preview_account','apply','secret_put','schedule_start','schedule_stop','schedule_reap']:
            self.api('configuration_api',action,None,{},expected=403)
            self.api('configuration_api',action,s,{},expected=405,verb='GET')
            status,_,_=self.cgi(BASE+'/configuration_api/'+action,cookie=s[0],verb='POST',fields={'token':'bad'})
            self.assertEqual(status,403)
        self.api('configuration_api','prepare',s,{'unexpected':'value'},expected=503)
        self.api('configuration_api','preview_account',s,{'id':'../bad','name':'bad','provider':'cloudflare'},expected=503)
        self.assertFalse(Path('/etc/homegate-engineering/transactions').exists())
        status,_,body=self.cgi(BASE+'/settings/ddns',cookie=s[0]);self.assertEqual(status,200)
        self.assertIn(b'/homegate-engineering/ddns-ui.js',body)
        status,_,body=self.exchange(path='/luci-static/resources/homegate-engineering/configuration.js',verb='GET',raw=b'')
        self.assertEqual(status,200);self.assertIn(b'textContent',body)
        self.verify_unchanged()
    def test_configuration(self):
        s=self.login();self.prepare_account(s)
        data=self.cfg('read',s);self.assertEqual(data['accounts'][0]['id'],'dns_a')
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        data=self.cfg('read',s);self.assertEqual(data['rules'][0]['account'],'dns_a')
        store=Path('/etc/homegate-engineering/transactions')
        self.assertTrue(any(b'SECRET_SENTINEL' in p.read_bytes() for p in store.glob('gen-*/credentials/*')))
        self.assertNotIn(b'SECRET_SENTINEL',Path('/etc/config/homegate_engineering').read_bytes())
        p=self.cfg('preview_account',s,id='dns_a',name='<script>unsafe</script>',provider='cloudflare')
        self.cfg('cancel',s)
        self.api('configuration_api','apply',s,{'confirmation':p['report']['confirmation'],'consent':'1'},expected=503)
        self.assertFalse((store/'ddns-authority').exists());self.assertFalse((STATE/'provider-calls').exists())
        public=Path('/etc/config/homegate_engineering');before=public.read_bytes();revision=(store/'current').read_bytes()
        public.write_bytes(before+b'\n')
        self.api('configuration_api','secret_put',s,{'id':'dns_a','provider':'cloudflare','slot':'secret','value':'OTHER_SECRET_SENTINEL','consent':'1'},expected=503)
        self.assertEqual((store/'current').read_bytes(),revision)
        public.write_bytes(before)
        self.verify_unchanged()
    def test_async(self):
        s=self.login();self.prepare_account(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        def ddns(action,**fields):return self.api('ddns_native',action,s,fields)['report']
        before=ddns('status');self.assertEqual(before['rules'][0]['status'],'unauthorized')
        job='a'*32
        self.api('ddns_native','submit',s,{'job':job,'rule':'ddns_a','consent':'1'},expected=503)
        p=ddns('preview',selection='ddns_a')
        self.api('ddns_native','commit',s,{'confirmation':p['confirmation']},expected=503)
        ddns('commit',confirmation=p['confirmation'],consent='1')
        started=time.monotonic();accepted=ddns('submit',job=job,rule='ddns_a',consent='1')
        self.assertTrue(accepted['pending']);self.assertLess(time.monotonic()-started,5)
        deadline=time.monotonic()+25;finished=None
        while time.monotonic()<deadline:
            jobs=ddns('jobs')['jobs']
            if jobs and not jobs[0]['pending']:finished=jobs[0];break
            time.sleep(.1)
        self.assertIsNotNone(finished)
        self.assertEqual(finished['last_effect'],'none',finished)
        result=json.loads((Path('/var/run/homegate-engineering/ddns-ui-jobs')/job/'raw').read_bytes())
        self.assertEqual(result['result'],'unchanged','Async no-op must be a successful provider result')
        self.assertTrue((STATE/'provider-calls').exists(),'Async worker did not reach provider boundary')
        calls=(STATE/'provider-calls').read_bytes()
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='NEW_SECRET_SENTINEL',consent='1')
        self.api('ddns_native','submit',s,{'job':'b'*32,'rule':'ddns_a','consent':'1'},expected=503)
        self.assertEqual((STATE/'provider-calls').read_bytes(),calls)
        ddns('revoke',consent='1')
        self.verify_unchanged()
    def test_contracts(self):
        s=self.login();self.prepare_account(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        self.assertTrue(self.cfg('provider_status',s,id='dns_a')['report']['credentials_valid'])
        self.assertEqual(self.cfg('zones',s,id='dns_a')['report']['zones'],['example.test'])
        count=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a'},expected=503)
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        self.assertEqual((STATE/'provider-calls').read_bytes(),count)
        p=self.api('ddns_native','preview',s,{'selection':'ddns_a'})['report']
        self.api('ddns_native','commit',s,{'confirmation':p['confirmation'],'consent':'1'})
        (STATE/'provider-mode').write_text('delete-success')
        deleted=self.cfg('delete_rule',s,id='ddns_a',consent='1')
        self.assertEqual((deleted['effect'],deleted['report']['effect'],deleted['report']['result']),('confirmed','confirmed','deleted'))
        journal=Path('/etc/homegate-engineering/transactions/dns-operation')
        slot=journal/('slot-'+(journal/'current').read_text().strip());job=(slot/'manifest').read_text().splitlines()[6]
        count=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        self.assertEqual((STATE/'provider-calls').read_bytes(),count)
        command=['/usr/sbin/ash','/usr/libexec/homegate-engineering/ddns-control.sh','ddns-collect-receipt','cloudflare','dns_a',job,'--confirm']
        collected=subprocess.run(command,capture_output=True,timeout=20);self.assertEqual((collected.returncode,collected.stderr),(0,b''),(collected.stdout,collected.stderr))
        self.assertFalse(journal.exists())
        empty=self.cfg('delete_rule',s,id='ddns_a',consent='1');self.assertEqual(empty['report']['result'],'unchanged')
        (STATE/'provider-mode').write_text('delete-unknown')
        status,_,body=self.cgi(BASE+'/configuration_api/delete_rule',cookie=s[0],verb='POST',fields={'id':'ddns_a','consent':'1','token':s[1]})
        self.assertEqual(status,503);unknown=json.loads(body)
        self.assertEqual((unknown['effect'],unknown['report']['effect']),('unknown','unknown'))
        self.assertFalse(unknown['report']['retryable']);self.assertNotIn(b'SECRET_SENTINEL',body)
        saved={str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()};count=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        self.assertEqual((STATE/'provider-calls').read_bytes(),count)
        self.assertEqual({str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()},saved)
        self.verify_unchanged()
    def test_schedule(self):
        run=Path('/var/run/homegate-engineering');work=run/'ddns-schedule'
        base='/usr/libexec/homegate-engineering'
        def direct(*args,expected=0):
            p=subprocess.run(['/usr/sbin/ash',base+'/schedule-control.sh',*args],capture_output=True,timeout=15)
            self.assertEqual((p.returncode,p.stderr),(expected,b''),(args,p.stdout,p.stderr));return json.loads(p.stdout)
        def wait_state(predicate):
            deadline=time.monotonic()+25;last=None
            while time.monotonic()<deadline:
                status,_,body=self.cgi(BASE+'/configuration_api/schedule_status',cookie=s[0]);last=json.loads(body)
                if predicate(last.get('report',{})):return last['report']
                time.sleep(.1)
            self.fail('Scheduler did not reach expected state: '+str(last))
        self.assertFalse(work.exists())
        self.assertFalse(direct('event','ifup','wan6','pppoe-wan')['active'])
        self.assertFalse(run.exists())
        init=STATE/'installed/etc/init.d/homegate-engineering'
        self.assertEqual(subprocess.run(['/bin/sh',str(init),'boot']).returncode,0)
        self.assertEqual(subprocess.run(['/bin/sh',str(init),'start']).returncode,0)
        self.assertFalse(run.exists())
        s=self.login();self.prepare_account(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        self.api('configuration_api','schedule_start',s,{'consent':'1'},expected=503)
        self.assertFalse(work.exists());self.assertFalse((STATE/'provider-calls').exists())
        preview=self.api('ddns_native','preview',s,{'selection':'ddns_a'})['report']
        self.api('ddns_native','commit',s,{'confirmation':preview['confirmation'],'consent':'1'})
        self.cfg('schedule_start',s,consent='1')
        status=wait_state(lambda d:d.get('status')=='waiting' and d.get('ticks')==1)
        self.assertEqual(json.loads((run/'ddns-state/ddns_a').read_bytes())['outcome'],'unchanged')
        lease=(work/'lease').read_bytes();calls=(STATE/'provider-calls').read_bytes()
        self.assertFalse(direct('event','ifupdate','lan','br-lan')['matched'])
        self.assertTrue(direct('event','ifupdate','wan6','pppoe-wan')['matched'])
        self.assertEqual((work/'lease').read_bytes(),lease)
        self.api('configuration_api','schedule_start',s,{'consent':'1'},expected=503)
        self.api('configuration_api','preview_account',s,{'id':'dns_a','name':'blocked change','provider':'cloudflare'},expected=503)
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        time.sleep(1.1)
        self.assertEqual((STATE/'provider-calls').read_bytes(),calls,'Network wake bypassed pacing')
        self.assertEqual((work/'lease').read_bytes(),lease,'Network wake extended authorization')
        self.assertTrue(direct('event','ifdown','wan6','pppoe-wan')['matched'])
        wait_state(lambda d:d.get('status')=='finished' and d.get('reason')=='stopped')
        self.cfg('schedule_reap',s,consent='1');self.assertFalse(work.exists())
        # ifdown must reach the control lease while the admitted batch owns
        # both business locks. It does not cancel or repeat that provider call.
        p=subprocess.run(['/usr/sbin/ash',base+'/ddns-control.sh','ddns-reset','ddns_a','--confirm'],capture_output=True)
        self.assertEqual(p.returncode,0)
        (STATE/'provider-mode').write_text('hold')
        self.cfg('schedule_start',s,consent='1')
        deadline=time.monotonic()+20
        while not (STATE/'provider-entered').exists() and time.monotonic()<deadline:time.sleep(.05)
        _,_,observed=self.cgi(BASE+'/configuration_api/schedule_status',cookie=s[0])
        self.assertTrue((STATE/'provider-entered').exists(),'Admitted batch did not enter held transport: '+observed.decode(errors='replace'))
        self.assertTrue(direct('event','ifdown','wan6','pppoe-wan')['matched'])
        (STATE/'provider-release').write_bytes(b'release')
        wait_state(lambda d:d.get('status')=='finished' and d.get('reason')=='stopped')
        self.cfg('schedule_reap',s,consent='1');self.assertFalse(work.exists())
        # A new session is another explicit user action. Its unknown provider
        # effect must stop the loop and block both restart and local reaping.
        p=subprocess.run(['/usr/sbin/ash',base+'/ddns-control.sh','ddns-reset','ddns_a','--confirm'],capture_output=True)
        self.assertEqual(p.returncode,0)
        (STATE/'provider-mode').write_text('unknown')
        self.cfg('schedule_start',s,consent='1')
        unknown=wait_state(lambda d:d.get('status')=='finished' and d.get('last_effect')=='unknown')
        self.assertEqual(unknown['reason'],'reconciliation_required')
        journal=Path('/etc/homegate-engineering/transactions/dns-operation');self.assertTrue(journal.exists())
        before={str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()}
        calls=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','schedule_reap',s,{'consent':'1'},expected=503)
        self.api('configuration_api','schedule_start',s,{'consent':'1'},expected=503)
        self.assertFalse(direct('event','ifup','wan6','pppoe-wan')['active'])
        self.assertEqual((STATE/'provider-calls').read_bytes(),calls)
        self.assertEqual({str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()},before)
        self.verify_unchanged()

def main():
    global INSTALLED
    p=argparse.ArgumentParser();p.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd')
    p.add_argument('--http-runtime-dir',type=Path,default=ROOT/'build/uhttpd');p.add_argument('--luci-runtime-dir',type=Path,default=ROOT/'build/luci')
    p.add_argument('--installed-root',type=Path);p.add_argument('--group',choices=['security','configuration','async','schedule','contracts'])
    p.add_argument('--inside-net');p.add_argument('--inside-uid');a=p.parse_args()
    rpc.WORK,luci.HTTP,luci.LUA=a.runtime_dir.resolve(),a.http_runtime_dir.resolve(),a.luci_runtime_dir.resolve()
    luci.BASE=BASE;luci.PAGE=PAGE;INSTALLED=a.installed_root
    if a.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID=a.inside_net,a.inside_uid
        suite=unittest.TestSuite([Web('test_'+a.group)])
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    for group in ([a.group] if a.group else ['security','configuration','async','schedule','contracts']):
        args=['--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--group',group]
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
          extra_mounts=lambda s:((s/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
             (s/'models',luci.LUA/'prefix/lib/lua/luci/model'),(s/'libexec','/usr/libexec'),(s/'tools','/usr/sbin'),
             (s/'curl-fixture','/usr/bin/curl')),
          extra_rw_mounts=lambda s:((s/'etc/homegate-engineering','/etc/homegate-engineering'),(s/'etc/config','/etc/config')),
          state_setup=setup_state,guest_args=args)
        if result:return result
    return 0

if __name__=='__main__':sys.exit(main())
