#!/usr/bin/env python3
"""Private snapshot to real curl 7.83.1 + loopback TLS; no public DNS requests."""
import argparse,hashlib,http.server,json,os,re,shutil,signal,ssl,subprocess,sys,threading,time,unittest
from pathlib import Path
from project import ROOT
from 持久初始化回归 import Runtime as BootstrapRuntime
from 私有配置读取回归 import Codec as PrivateCodec
PROTO=ROOT/'project/core/prototype'

class Static(PrivateCodec):
    def test_shell_grammar_and_closed_fixed_modes(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cloudflare-read.sh','homegate-cloudflare-worker.sh','homegate-service-observer-watchdog.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body)
            self.assertFalse(parser.parse(body).root_node.has_error,name)
            self.assertEqual(body.count(b'dns_read_enabled=false'),1);self.assertNotIn(b'dns_read_enabled=true',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_fixed_tls_curl_and_no_arbitrary_command(self):
        body=(PROTO/'homegate-cloudflare-worker.sh').read_text()
        for flag in ['--disable --config','--proto \'=https\'','--proxy \'\'','--noproxy \'*\'','--connect-timeout 3','--max-time 10','--cacert /etc/ssl/certs/ca-certificates.crt']:
            self.assertIn(flag,body)
        self.assertNotRegex(body,r'--(insecure|location|retry)\b')
        self.assertIn('exec 5<&0',(PROTO/'homegate-service-observer-watchdog.sh').read_text());self.assertIn('0<&5 5<&-',(PROTO/'homegate-service-observer-watchdog.sh').read_text())
        self.assertNotIn('os.getenv',(PROTO/'cloudflare-codec.lua').read_text())
        self.lua.compile((PROTO/'cloudflare-codec.lua').read_bytes())

    def request(self,token=b'PRIVATE_SENTINEL',account=b'dns_a',revision=b'3',frame=None,mode=None):
        slots=[] if token is None else [(b'cloudflare.dns_a.secret',token)]
        self.lua.globals().test_frame=frame if frame is not None else self.frame(slots)
        self.lua.globals().test_codec=self.codec;self.lua.globals().test_reader=self.reader
        self.lua.globals().arg=self.lua.table_from({0:b'/fixture/cloudflare-codec.lua',1:b'request',2:account,3:revision})
        if mode:self.lua.globals().arg[4]=mode
        self.lua.execute(b"loadfile=function(p) if p:match('backup.lua$') then return function() return test_codec end elseif p:match('private%-snapshot.lua$') then return function() return test_reader end else error('unexpected fixture load') end end; require=function(name) assert(name=='luci.jsonc');return {} end; os.exit=function(n) error('__EXIT__'..n) end; output='';request_body='';io.stdin={read=function(self,n) return test_frame:sub(1,n) end};io.stdout={write=function(self,...) for _,v in ipairs({...}) do output=output..v end; return true end};io.write=function(...) for _,v in ipairs({...}) do output=output..v end;return true end;local real_open=io.open;io.open=function(p,m) if p=='/proc/self/fd/4' then return {write=function(self,v) request_body=request_body..v;return true end,close=function() return true end} end;return real_open(p,m) end")
        try:self.lua.execute((PROTO/'cloudflare-codec.lua').read_bytes());return True,self.lua.globals().output,self.lua.globals().request_body
        except Exception as e:self.assertIn('__EXIT__',str(e));return False,self.lua.globals().output,self.lua.globals().request_body

    def test_private_request_quotes_are_escaped_without_public_reflection(self):
        token=b'PRIVATE_SENTINEL"\\# $(echo x)';ok,public,request=self.request(token)
        self.assertTrue(ok);self.assertEqual(public,b'HGDNSREADY1\n');self.assertNotIn(b'PRIVATE_SENTINEL',public)
        self.assertEqual(request,b'url = "https://api.cloudflare.com/client/v4/zones?page=1&per_page=5"\nrequest = "GET"\nheader = "Authorization: Bearer PRIVATE_SENTINEL\\"\\\\# $(echo x)"\n')

    def test_missing_binary_and_multiline_credentials_never_make_requests(self):
        for token in [None,b'   ',b'PRIVATE_SENTINEL\x00',b'PRIVATE_SENTINEL\xff',b'PRIVATE_SENTINEL\nurl = "https://bad.test"']:
            self.setUp();ok,public,request=self.request(token);self.assertFalse(ok);self.assertEqual(request,b'');self.assertNotIn(b'PRIVATE_SENTINEL',public);self.assertIn(b'authentication',public)

    def test_wrong_generation_account_and_truncated_private_frame_refused(self):
        # Also execute the bounded nonce data path; JSON module is unused here.
        for raw,accepted in [(b'12345678-1234-1234-1234-123456789abc\n',True),(b'12345678-1234-1234-1234-123456789abc',False),(b'12345678_1234-1234-1234-123456789abc\n',False)]:
            self.setUp();self.lua.globals().nonce_body=raw;self.lua.globals().arg=self.lua.table_from({0:b'/fixture/cloudflare-codec.lua',1:b'nonce'})
            self.lua.execute(b"require=function()return {}end;os.exit=function()error('__EXIT__')end;output='';io.stdin={read=function(self,n)return nonce_body:sub(1,n)end};io.write=function(v)output=v;return true end")
            if accepted:self.lua.execute((PROTO/'cloudflare-codec.lua').read_bytes());self.assertEqual(self.lua.globals().output,b'12345678123412341234123456789abc')
            else:
                with self.assertRaises(Exception):self.lua.execute((PROTO/'cloudflare-codec.lua').read_bytes())
        for account,rev,frame in [(b'missing',b'3',None),(b'dns_a',b'2',None),(b'dns_a',b'3',self.frame()[:-1])]:
            self.setUp();ok,public,request=self.request(account=account,revision=rev,frame=frame);self.assertFalse(ok);self.assertEqual(request,b'');self.assertNotIn(b'PRIVATE_SENTINEL',public)

class Runtime(BootstrapRuntime):
    @classmethod
    def setUpClass(cls):
        BootstrapRuntime.setUpClass.__func__(cls)
        cls.real_curl=ROOT/'build/curl-runtime/curl-7.83.1/src/curl'
        if not cls.real_curl.is_file():raise RuntimeError('Requires actual pinned official curl 7.83.1')
        cls.openssl=shutil.which('openssl');assert cls.openssl
        cls.ca_dir=ROOT/'build/cloudflare-tls';cls.ca_dir.mkdir(parents=True,exist_ok=True)
        subprocess.run([cls.openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(cls.ca_dir/'key.pem'),'-out',str(cls.ca_dir/'ca.pem')],check=True,capture_output=True,timeout=30)

    def setUp(self):
        super().setUp();self.boot();self.commit_body(self.business);self.secret(b'PRIVATE_SENTINEL')
        self.calls=[];self.response={'success':True,'errors':[],'result':[]};self.http_status=200;self.delay=0;self.chunked=False;self.redirect=None
        outer=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self,method):
                request={'method':method,'path':self.path,'authorization':self.headers.get('Authorization')}
                if method!='GET':
                    size=int(self.headers.get('Content-Length','0'));assert 0<=size<=32768
                    request['body']=self.rfile.read(size)
                outer.calls.append(request)
                if hasattr(outer,'record_http'):status,response=outer.record_http(method,self.path,request.get('body',b''))
                else:status,response=outer.response(self.path) if callable(outer.response) else (outer.http_status,outer.response)
                body=response if isinstance(response,bytes) else json.dumps(response).encode()
                time.sleep(outer.delay)
                try:
                    self.send_response(status)
                    if outer.redirect:self.send_header('Location',outer.redirect)
                    if outer.chunked:self.send_header('Transfer-Encoding','chunked')
                    else:self.send_header('Content-Length',str(len(body)))
                    self.end_headers()
                    if outer.chunked:
                        for pos in range(0,len(body),4096):
                            part=body[pos:pos+4096];self.wfile.write(('%x\r\n'%len(part)).encode()+part+b'\r\n');self.wfile.flush()
                        self.wfile.write(b'0\r\n\r\n')
                    else:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
            def do_GET(self):self.reply('GET')
            def do_POST(self):self.reply('POST')
            def do_PATCH(self):self.reply('PATCH')
            def do_DELETE(self):self.reply('DELETE')
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.daemon_threads=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(self.ca_dir/'ca.pem'),str(self.ca_dir/'key.pem'))
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.endpoint='https://127.0.0.1:'+str(self.server.server_port)+'/client/v4/zones?page=1&per_page=5'
        self.curl=self.base/'curl';shutil.copy2(self.real_curl,self.curl);self.curl.chmod(0o700)
        self.watchdog_pid=self.base/'watchdog.pid';self.diagnostic=self.base/'numeric-diagnostic';self.processes=[];self.known_groups=[]
        mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/usr/bin/curl':str(self.curl),'/etc/ssl/certs/ca-certificates.crt':str(self.ca_dir/'ca.pem')}
        for name in ['homegate-cloudflare-read.sh','homegate-cloudflare-worker.sh','homegate-service-observer-watchdog.sh','cloudflare-codec.lua']:
            file=self.engine.parent/name;body=file.read_text();body=body.replace('dns_read_enabled=false','dns_read_enabled=true')
            body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
            body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+str(os.getuid())+' ]')
            for before,after in [('= 0:700 ]','= '+str(os.getuid())+':700 ]'),('= 0:600:1 ]','= '+str(os.getuid())+':600:1 ]'),('in 0:700:1|0:755:1)','in '+str(os.getuid())+':700:1|'+str(os.getuid())+':755:1)')]:body=body.replace(before,after)
            if name.endswith('.lua'):
                body=body.replace("local json=require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json=require('luci.jsonc')")
                body=body.replace('https://api.cloudflare.com/client/v4/zones?page=1&per_page=5',self.endpoint)
            elif name=='homegate-cloudflare-worker.sh':body=body.replace('--max-time 10','--max-time 0.5')
            elif name=='homegate-service-observer-watchdog.sh':
                body=body.replace('action=cloudflare-check; budget=30','action=cloudflare-check; budget=2')
                needle='sleep 0.001 >/dev/null 2>&1 || exit 1'
                body=body.replace(needle,'printf "%s\\n" "$$" > '+str(self.watchdog_pid)+'\n'+needle)
            # Copied fixture sources only: numeric/module diagnostics, never data.
            if name=='cloudflare-codec.lua':
                body=body.replace("local json=require('luci.jsonc')","local json=require('luci.jsonc')\nlocal real_exit=os.exit; os.exit=function(n) local f=io.open("+json.dumps(str(self.diagnostic))+",'a'); if f then f:write('codec:',debug.getinfo(2,'l').currentline,'\\n');f:close() end;real_exit(n) end")
            elif name=='homegate-cloudflare-worker.sh':
                counter=[0]
                def diagnose(m):
                    counter[0]+=1;return "{ printf 'worker:"+str(counter[0])+"\\n' >> "+str(self.diagnostic)+"; exit 1; }"
                body=re.sub(r'\bexit 1\b',diagnose,body)
            file.write_text(body)
        self.reader=self.engine.parent/'homegate-cloudflare-read.sh'

    def group(self):
        if not self.watchdog_pid.exists():return None
        pid=int(self.watchdog_pid.read_text())
        try:
            fields=Path('/proc/'+str(pid)+'/stat').read_text().split(') ')[1].split();cmd=Path('/proc/'+str(pid)+'/cmdline').read_bytes()
            if int(fields[2])==pid and int(fields[3])==pid and os.fsencode(self.engine.parent/'homegate-service-observer-watchdog.sh') in cmd:
                pair=(pid,fields[19]);self.known_groups.append(pair);return pair
        except FileNotFoundError:pass
        return None

    def tearDown(self):
        self.group()
        for p in self.processes:
            if p.poll() is None:p.kill()
            try:p.communicate(timeout=5)
            except subprocess.TimeoutExpired:pass
        for pid,birth in self.known_groups:
            try:
                rows=Path('/proc/'+str(pid)+'/stat').read_text().split(') ')[1].split()
                if rows[19]==birth and int(rows[2])==pid and int(rows[3])==pid and pid!=os.getpgrp():os.killpg(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            except FileNotFoundError:pass
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
        super().tearDown()

    def check(self,expected=0,account='dns_a',env=None):
        p=subprocess.run([self.busybox,'ash',str(self.reader),account],env=env or self.env,capture_output=True,timeout=12)
        diag=self.diagnostic.read_text()[:128] if self.diagnostic.exists() else ''
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr,diag));self.assertEqual(p.stderr,b'');self.assertNotIn(b'PRIVATE_SENTINEL',p.stdout)
        data=json.loads(p.stdout);self.assertEqual(data['ok'],expected==0);return data

    def unchanged(self):
        self.assertEqual(self.cli('status')['revision'],3);self.assertFalse((self.store/'application').exists());self.assertFalse((self.store/'write-fence').exists())
        self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')));self.writer()

    def test_success_uses_bound_private_token_real_tls_and_no_state_publication(self):
        r=self.check();self.assertEqual(r['configuration_revision'],3);self.assertTrue(r['credentials_valid']);self.assertEqual(r['check_scope'],'zone-read')
        self.assertEqual(self.calls,[{'method':'GET','path':'/client/v4/zones?page=1&per_page=5','authorization':'Bearer PRIVATE_SENTINEL'}]);self.unchanged()

    def test_actual_zone_response_metadata_never_enters_public_report(self):
        self.response={'success':True,'result':[{'id':'a'*32,'name':'PRIVATE_SENTINEL.test','account':{'name':'PRIVATE_SENTINEL'}}]}
        r=self.check();self.assertNotIn('zones',r);self.unchanged()

    def test_missing_invalid_and_unknown_account_stop_before_http(self):
        self.check(1,'missing');self.assertEqual(self.calls,[])
        self.cli('credential-delete','cloudflare','dns_a','secret');self.check(1);self.assertEqual(self.calls,[])
        self.secret(b'PRIVATE_SENTINEL\x00\xff\n');self.check(1);self.assertEqual(self.calls,[])

    def test_quotes_backslashes_and_shell_syntax_stay_header_data(self):
        token=b'PRIVATE_SENTINEL"\\# $(touch /tmp/not-a-command)';self.secret(token);self.check()
        self.assertEqual(self.calls[0]['authorization'],'Bearer '+token.decode());self.assertFalse(Path('/tmp/not-a-command').exists())

    def test_http_error_taxonomy_masks_provider_messages(self):
        for status,kind,retry in [(401,'authentication',False),(403,'authentication',False),(429,'rate_limit',True),(500,'temporary',True),(404,'not_found',False)]:
            self.http_status=status;self.response={'success':False,'errors':[{'code':9109,'message':'PRIVATE_SENTINEL reflected'}]}
            r=self.check(1);self.assertEqual((r['error_kind'],r['retryable'],r['provider_code']),(kind,retry,'9109'))
        self.unchanged()

    def test_http_success_false_or_missing_success_never_authenticates(self):
        for body in [{'success':False,'errors':[{'code':10000,'message':'PRIVATE_SENTINEL'}]}, {'result':[]}, {'success':'true','result':[]}]:
            self.response=body;self.check(1)

    def test_duplicate_keys_escaped_duplicates_nul_and_extra_document_rejected(self):
        for body in [b'{"success":false,"success":true,"result":[]}',b'{"success":false,"su\\u0063cess":true,"result":[]}',b'{"success":true,"result":[],"obj":{"x":1,"x":2}}',b'{"success\\u0000junk":true,"result":[]}',b'{"success":true,"result":[]} {}',b'{"success":true,"result":[]}\x00']:
            self.response=body;self.check(1)

    def test_malformed_zone_results_and_empty_object_not_array_refused(self):
        for result in [{},[{}],[{'id':'a'*32,'name':'example.test'}]*6]:
            self.response={'success':True,'result':result};self.check(1)

    def test_redirect_is_not_followed_and_authorization_not_forwarded(self):
        self.http_status=302;self.redirect=self.endpoint+'&redirected=1';self.check(1);self.assertEqual(len(self.calls),1)

    def test_tls_trust_failure_cannot_be_overridden_with_environment(self):
        worker=self.engine.parent/'homegate-cloudflare-worker.sh';worker.write_text(worker.read_text().replace(str(self.ca_dir/'ca.pem'),'/dev/null'))
        r=self.check(1,env={**self.env,'CURL_CA_BUNDLE':str(self.ca_dir/'ca.pem'),'SSL_CERT_FILE':str(self.ca_dir/'ca.pem')});self.assertEqual(r['error_kind'],'network_unavailable');self.assertEqual(self.calls,[])

    def test_curlrc_proxy_and_decoy_config_environment_are_ignored(self):
        home=self.base/'poison';home.mkdir();(home/'.curlrc').write_text('url = "https://bad.invalid/"\nheader = "PRIVATE_SENTINEL: leak"\ninsecure\n')
        self.check(env={**self.env,'HOME':str(home),'CURL_HOME':str(home),'HTTPS_PROXY':'http://127.0.0.1:1','HOMEGATE_CONFIG_PROTO_STORE':str(home),'LUA_INIT':'error("PRIVATE_SENTINEL")'})
        self.assertEqual(len(self.calls),1);self.unchanged()

    def test_declared_and_chunked_response_limits_fail_without_partial_success(self):
        for chunked in [False,True]:
            self.chunked=chunked;self.response=b'{"success":true,"result":[],"pad":"'+b'x'*70000+b'"}';self.check(1)
        self.unchanged()

    def test_real_curl_timeout_is_bounded_and_classified(self):
        self.delay=2;before=time.monotonic();r=self.check(1);self.assertEqual(r['error_kind'],'timeout');self.assertLess(time.monotonic()-before,3);self.unchanged()

    def test_shared_lock_and_pending_application_prevent_any_http(self):
        import fcntl
        with self.native.lock.open('rb') as held:fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);self.check(4)
        self.assertEqual(self.calls,[]);self.begin();self.check(4);self.assertEqual(self.calls,[])

    def test_missing_or_unsafe_curl_refuses_without_any_http(self):
        self.curl.chmod(0o777);self.check(7);self.assertEqual(self.calls,[])
        self.curl.chmod(0o700);self.curl.unlink();self.check(7);self.assertEqual(self.calls,[])

    def test_private_request_permissions_and_live_curl_argv_exclude_credentials(self):
        self.delay=0.3
        p=subprocess.Popen([self.busybox,'ash',str(self.reader),'dns_a'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        deadline=time.monotonic()+4;seen=False
        while not seen:
            for proc in Path('/proc').glob('[0-9]*/cmdline'):
                try:args=proc.read_bytes()
                except (FileNotFoundError,ProcessLookupError,PermissionError):continue
                if args.split(b'\0')[0]==os.fsencode(self.curl):
                    self.assertNotIn(b'PRIVATE_SENTINEL',args)
                    self.assertNotIn(b'PRIVATE_SENTINEL',(proc.parent/'environ').read_bytes())
                    request=list(self.native.lockdir.glob('.dns-check-*/request'));self.assertEqual(len(request),1)
                    self.assertEqual(request[0].stat().st_mode&0o777,0o600);self.assertEqual(request[0].parent.stat().st_mode&0o777,0o700)
                    self.assertIn(b'PRIVATE_SENTINEL',request[0].read_bytes());seen=True;break
            self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.005)
        out,err=p.communicate(timeout=8);self.assertEqual(p.returncode,0,(out,err));self.assertEqual(err,b'');self.assertNotIn(b'PRIVATE_SENTINEL',out);self.unchanged()

    def test_worker_zero_exit_without_report_cannot_authenticate(self):
        worker=self.engine.parent/'homegate-cloudflare-worker.sh';worker.write_text('exit 0\n')
        self.check(7);self.assertEqual(self.calls,[]);self.unchanged()

    def test_closed_gates_cannot_be_enabled_by_environment(self):
        self.reader.write_text(self.reader.read_text().replace('dns_read_enabled=true','dns_read_enabled=false'))
        self.check(2,env={**self.env,'dns_read_enabled':'true'});self.assertEqual(self.calls,[])

    def test_invalid_arguments_never_allocate_or_request(self):
        for args in [[],['dns_a','https://bad.invalid'],['../dns_a'],['dns_a;echo']]:
            p=subprocess.run([self.busybox,'ash',str(self.reader),*args],env=self.env,capture_output=True,timeout=5);self.assertEqual(p.returncode,2)
        self.assertEqual(self.calls,[]);self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))

    def test_caller_loss_deadline_releases_locks_and_orphan_blocks_new_reads(self):
        self.curl.write_text('#!'+sys.executable+'\nimport time,signal\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True:time.sleep(0.1)\n');self.curl.chmod(0o700)
        p=subprocess.Popen([self.busybox,'ash',str(self.reader),'dns_a'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        deadline=time.monotonic()+5
        while not self.group():self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.02)
        time.sleep(0.1);p.kill();p.communicate(timeout=2);self.writer(4)
        time.sleep(3.4);self.writer();self.check(4)
        self.assertTrue(list(self.native.lockdir.glob('.dns-check-*')));self.assertEqual(self.calls,[])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,v in cls.__dict__.items() if name.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
