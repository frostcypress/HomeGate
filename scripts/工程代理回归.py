#!/usr/bin/env python3
"""Real native nginx behind installed CLI and native LuCI in the existing
single-UID, cap-drop-ALL network namespace. The external component uses an identity-preserving initgroups no-op solely
for its already-zero fixture UID/GID; target privilege drop remains unverified.
"""
import argparse,hashlib,importlib.util,json,os,shutil,subprocess,sys,time,unittest
import http.client,http.server,socket,ssl,threading,base64
from pathlib import Path
from project import ROOT
spec=importlib.util.spec_from_file_location('engineering_web',ROOT/'scripts/工程网页回归.py')
web=importlib.util.module_from_spec(spec);spec.loader.exec_module(web)
rpc,luci,STATE=web.rpc,web.luci,web.STATE
NGINX=ROOT/'build/nginx'
FIXTURE=ROOT/'build/nginx-fixture'

def setup_state(s):
    web.setup_state(s)
    (s/'etc/passwd').write_text((s/'etc/passwd').read_text()+'root:x:0:0:fixture:/tmp:/bin/false\n')
    (s/'etc/group').write_text((s/'etc/group').read_text()+'root:x:0:\n')
    (s/'etc/hosts').write_text('127.0.0.1 localhost upstream.example.test wrong.example.test\n::1 localhost\n')
    (s/'etc/ssl/certs').mkdir(parents=True)
    shutil.copyfile('/etc/ssl/openssl.cnf',s/'etc/ssl/openssl.cnf')
    shutil.copyfile('/etc/ssl/certs/ca-certificates.crt',s/'etc/ssl/certs/ca-certificates.crt')
    shutil.copyfile('/etc/ssl/certs/ca-certificates.crt',s/'original-system-ca.pem')
    # The external component keeps its same fixture credentials and uses real
    # master/workers. The no-op library grants no additional identity/capability. Product config, source/FD guards and locks are untouched.
    (s/'tools/nginx').write_text('#!/bin/sh\nprintf called > /teststate/system-nginx-called\nexit 71\n')
    (s/'tools/nginx').chmod(0o755)
    (s/'libexec/homegate-nginx').mkdir()
    (s/'libexec/homegate-nginx/nginx').write_text('#!/usr/bin/python3\nimport os,sys\na=sys.argv[1:]\nif "-g" in a:a[a.index("-g")+1]="daemon off; master_process on;"\nos.environ["LD_PRELOAD"]='+repr(str(FIXTURE/'same-credentials.so'))+'\nos.execv('+repr(str(NGINX/'nginx'))+',["nginx",*a])\n')
    (s/'libexec/homegate-nginx/nginx').chmod(0o755)
    curl=s/'curl-fixture';raw=curl.read_text();anchor="if Path('/teststate/acme-enabled').exists():"
    injected=r"""if '--url' in sys.argv and sys.argv[sys.argv.index('--url')+1] in ['https://ftp.apnic.net/stats/apnic/delegated-apnic-latest','https://ftp.ripe.net/pub/stats/apnic/delegated-apnic-latest']:
 mode=Path('/teststate/access-mode').read_text() if Path('/teststate/access-mode').exists() else 'valid'
 with open('/teststate/access-calls','a') as f:f.write('fetch\n')
 Path('/teststate/access-entered').touch()
 if mode=='hold':
  import subprocess
  subprocess.Popen(['/usr/sbin/busybox','sleep','45']);time.sleep(45);sys.exit(1)
 if mode=='mirror' and 'ftp.apnic.net' in sys.argv[sys.argv.index('--url')+1]:sys.stdout.write('500');sys.exit(22)
 address='127.0.0.2' if mode=='alternate' else '127.0.0.1'
 body='2|apnic|20261028|2|19830613|20261028|+1000\napnic|*|ipv4|*|1|summary\napnic|*|ipv6|*|1|summary\napnic|CN|ipv4|'+address+'|1|20261028|allocated\napnic|CN|ipv6|::1|128|20261028|assigned\n'
 if mode=='truncated':body=body.rsplit('apnic|CN|ipv6',1)[0]
 if mode=='single':body=body.replace('|CN|ipv6|','|US|ipv6|')
 if mode=='oversized':body='#'+('x'*25165825)
 os.write(3,body.encode());sys.stdout.write('206' if mode=='partial' else '200');sys.exit(0)
"""
    assert anchor in raw;curl.write_text(raw.replace(anchor,injected+anchor,1));curl.chmod(0o755)


class Proxy(web.Web):
    def verify_unchanged(self):
        super().verify_unchanged()
        self.assertFalse((STATE/'system-nginx-called').exists(), 'System nginx must never be invoked')
    def cli(self,*args,raw=None,ok=True):
        r=subprocess.run(['/usr/bin/homegate-engineering',*args],input=raw,capture_output=True,timeout=20)
        if ok:self.assertEqual(r.returncode,0,(args,r.stdout[:400],r.stderr[:100]))
        else:self.assertNotEqual(r.returncode,0,(args,r.stdout[:400]))
        if raw and b'SECRET_SENTINEL' in raw:self.assertNotIn(b'SECRET_SENTINEL',r.stdout+r.stderr)
        return json.loads(r.stdout) if r.stdout.startswith(b'{') else r.stdout
    def cfg(self,action,s,**fields):
        if action not in ['proxy_status','access_status','access_recent']:return super().cfg(action,s,**fields)
        status,_,body=self.cgi(web.BASE+'/configuration_api/'+action,cookie=s[0]);self.assertEqual(status,200,body[:500]);return json.loads(body)
    def ready(self,state='running',seconds=8):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            d=self.cli('proxy-status')
            if d['state']==state and (state=='running' or not d['running']):return d
            time.sleep(.1)
        conf=Path('/var/run/homegate-engineering/proxy/active.conf')
        if conf.exists():
            r=subprocess.run(['/usr/libexec/homegate-nginx/nginx','-t','-p',str(conf.parent)+'/', '-c',str(conf),'-g','daemon off;'],capture_output=True,timeout=5)
            raise AssertionError(('Proxy state timeout',d,r.stderr.decode()[-3000:]))
        self.fail(('Proxy state timeout',d))
    def setup_proxy(self,routes,targets,extra=''):
        s=self.login();self.cfg('prepare',s);self.certificate_config(s)
        for name,domain,https in routes:
            p=self.cfg('preview_web_rule',s,id=name,domain=domain,https='1' if https else '0',certificate='cert_a' if https else '')
            self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
        if extra:
            public=self.cli('config-export');public=public.replace(b"option access_allow ''",b"option access_allow '127.0.0.1/32 ::1/128'") if extra=='allow' else public
            # Canonical renderer may quote both keys and values; use lines.
            lines=public.decode().splitlines()
            for i,line in enumerate(lines):
                if 'access_allow' in line and extra in ['allow','deny']:lines[i]="\toption access_allow '127.0.0.1/32 ::1/128'"
                if 'access_deny' in line and extra=='deny':lines[i]="\toption access_deny '127.0.0.1/32 ::1/128'"
                if 'access_region' in line and extra=='cn':lines[i]="\toption access_region 'CN'"
            p=self.cli('config-preview',raw=('\n'.join(lines)+'\n').encode());self.cli('config-commit',p['confirmation'])
        for name,target in targets.items():self.cfg('web_target_put',s,id=name,value=target,consent='1')
        self.publish(s);self.cfg('lifecycle_enable',s,consent='1')
        self.certificate_import(s,self.certificate_pair('proxy'))
        return s
    def backend(self,tls=False):
        outer=self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*a):pass
            def do_GET(self):
                if self.headers.get('Upgrade','').lower()=='websocket':
                    accept=base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                    self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers();self.wfile.flush()
                    head=self.rfile.read(2);mask=self.rfile.read(4);payload=self.rfile.read(head[1]&127);body=bytes(v^mask[i%4] for i,v in enumerate(payload));self.wfile.write(bytes([0x81,len(body)])+body);self.wfile.flush();self.close_connection=True;return
                body=json.dumps({'path':self.path,'headers':dict(self.headers)}).encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_POST(self):
                # nginx streams using HTTP/1.1 chunked transfer when required.
                body=b''
                if self.headers.get('Transfer-Encoding')=='chunked':
                    while True:
                        n=int(self.rfile.readline().strip(),16)
                        if not n:self.rfile.readline();break
                        body+=self.rfile.read(n);self.rfile.read(2)
                else:body=self.rfile.read(int(self.headers.get('Content-Length','0')))
                out=json.dumps({'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}).encode();self.send_response(200);self.send_header('Content-Length',str(len(out)));self.end_headers();self.wfile.write(out)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
        if tls:
            cert,key=self.certificate_pair('upstream',domains='DNS:upstream.example.test')
            c=STATE/'upstream.pem';k=STATE/'upstream.key';c.write_text(cert);k.write_text(key)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(c,k);server.socket=context.wrap_socket(server.socket,server_side=True)
            with Path('/etc/ssl/certs/ca-certificates.crt').open('a') as f:f.write(cert)
        threading.Thread(target=server.serve_forever,daemon=True).start();self.addCleanup(server.server_close);self.addCleanup(server.shutdown);return server.server_port
    def exchange_proxy(self,host,path='/',tls=True,ipv6=False,headers=None,method='GET',body=None,source=None):
        context=ssl._create_unverified_context()
        conn=http.client.HTTPConnection('::1' if ipv6 else '127.0.0.1',10443 if tls else 10080,timeout=5,source_address=(source,0) if source else None);conn.connect()
        if tls:conn.sock=context.wrap_socket(conn.sock,server_hostname=host)
        hdr={'Host':host,**(headers or {})};conn.request(method,path,body=body,headers=hdr);r=conn.getresponse();out=(r.status,dict(r.getheaders()),r.read());conn.close();return out
    def stop(self,s):
        self.cfg('proxy_stop',s,consent='1');self.ready('stopped');self.cfg('proxy_reap',s,consent='1');self.assertEqual(self.cli('proxy-status')['state'],'idle')
    def test_routing(self):
        port=self.backend();s=self.setup_proxy([('exact','example.test',True),('wild','*.example.test',True),('plain','plain.example.test',False)],{'exact':f'http://127.0.0.1:{port}/base/?fixed=SECRET_SENTINEL$host','wild':f'http://127.0.0.1:{port}/wild/','plain':f'http://127.0.0.1:{port}'})
        started=self.cfg('proxy_start',s,selection='exact,wild,plain',policy='open',consent='1');self.assertTrue(started['report']['running']);self.ready()
        code,_,raw=self.exchange_proxy('example.test','/a%2Fb?q=x',headers={'Forwarded':'for=evil','X-Forwarded-For':'evil','X-Forwarded-Host':'evil','X-Forwarded-Proto':'http'})
        self.assertEqual(code,200,raw);d=json.loads(raw);self.assertEqual(d['path'],'/base/a%2Fb?fixed=SECRET_SENTINEL$host&q=x')
        h={k.lower():v for k,v in d['headers'].items()};self.assertEqual(h['host'],f'127.0.0.1:{port}');self.assertEqual(h['x-forwarded-for'],'127.0.0.1');self.assertEqual(h['x-forwarded-proto'],'https');self.assertEqual(h['x-forwarded-host'],'example.test');self.assertNotIn('forwarded',h)
        probe=ssl._create_unverified_context().wrap_socket(socket.create_connection(('127.0.0.1',10443),timeout=5),server_hostname='example.test')
        expected=ssl.PEM_cert_to_DER_cert((STATE/'cert-fixtures/proxy.pem').read_text());self.assertEqual(probe.getpeercert(binary_form=True),expected);probe.close()
        code,h,_=self.exchange_proxy('example.test','/x?a=b',tls=False);self.assertEqual(code,308);self.assertEqual(h['Location'],'https://example.test/x?a=b')
        code,_,body=self.exchange_proxy('one.example.test','/x',ipv6=True);self.assertEqual(code,200);self.assertEqual(json.loads(body)['path'],'/wild/x');self.assertEqual(json.loads(body)['headers']['X-Forwarded-For'],'::1')
        self.assertEqual(self.exchange_proxy('plain.example.test',tls=False)[0],200)
        self.assertEqual(self.exchange_proxy('two.one.example.test',tls=False)[0],404)
        self.assertEqual(self.exchange_proxy('unknown.test',tls=False)[0],404)
        with self.assertRaises((ssl.SSLError,ConnectionError)):self.exchange_proxy('unknown.test')
        status=self.cfg('proxy_status',s)['report'];self.assertNotIn('SECRET_SENTINEL',json.dumps(status));self.assertFalse(status['health_checked'])
        self.api('configuration_api','web_target_put',s,{'id':'exact','value':'http://other.test','consent':'1'},expected=503)
        self.cli('config-preview',raw=self.cli('config-export'),ok=False)
        self.stop(s);self.verify_unchanged()
    def test_streaming(self):
        port=self.backend();s=self.setup_proxy([('plain','example.test',False)],{'plain':f'http://127.0.0.1:{port}'})
        self.cfg('proxy_start',s,selection='plain',policy='open',consent='1');self.ready()
        body=b'upload'*100000;code,_,raw=self.exchange_proxy('example.test','/upload',tls=False,method='POST',body=body);self.assertEqual(code,200);self.assertEqual(json.loads(raw),{'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
        sock=socket.create_connection(('127.0.0.1',10080),timeout=5);sock.sendall(b'GET /ws HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n');data=b''
        while b'\r\n\r\n' not in data:data+=sock.recv(1024)
        self.assertTrue(data.startswith(b'HTTP/1.1 101'),data);mask=b'abcd';payload=b'hello';sock.sendall(b'\x81\x85'+mask+bytes(v^mask[i%4] for i,v in enumerate(payload)));self.assertEqual(sock.recv(7),b'\x81\x05hello');sock.close()
        self.stop(s);self.verify_unchanged()
    def test_upstream_tls(self):
        port=self.backend(tls=True);s=self.setup_proxy([('good','example.test',False),('bad','bad.example.test',False)],{'good':f'https://upstream.example.test:{port}/base','bad':f'https://wrong.example.test:{port}'})
        self.cfg('proxy_start',s,selection='good,bad',policy='open',consent='1');self.ready()
        code,_,body=self.exchange_proxy('example.test','/x',tls=False);self.assertEqual(code,200,body);self.assertEqual(json.loads(body)['path'],'/base/x')
        self.assertEqual(self.exchange_proxy('bad.example.test',tls=False)[0],502)
        self.stop(s)
        # Removing the private trust root must reject even a correct hostname.
        Path('/etc/ssl/certs/ca-certificates.crt').write_bytes((STATE/'original-system-ca.pem').read_bytes())
        self.cfg('proxy_start',s,selection='good',policy='open',consent='1');self.ready();self.assertEqual(self.exchange_proxy('example.test',tls=False)[0],502);self.stop(s);self.verify_unchanged()
    def test_acl(self):
        port=self.backend();s=self.setup_proxy([('plain','example.test',False)],{'plain':f'http://127.0.0.1:{port}'},extra='deny')
        self.cfg('proxy_start',s,selection='plain',policy='open',consent='1');self.ready();self.assertEqual(self.exchange_proxy('example.test',tls=False)[0],403);self.assertEqual(self.exchange_proxy('example.test',tls=False,ipv6=True)[0],403);self.stop(s)
        # Source/vault changes after stop/reap are permitted; allow policy is an
        # explicit session choice and never revives normalized enabled flags.
        public=self.cli('config-export').decode();lines=[]
        for line in public.splitlines():
            if 'access_deny' in line:line="\toption access_deny ''"
            if 'access_allow' in line:line="\toption access_allow '127.0.0.1/32 ::1/128'"
            lines.append(line)
        p=self.cli('config-preview',raw=('\n'.join(lines)+'\n').encode());self.cli('config-commit',p['confirmation']);self.cfg('lifecycle_enable',s,consent='1')
        self.cfg('proxy_start',s,selection='plain',policy='allow',consent='1');self.ready();self.assertEqual(self.exchange_proxy('example.test',tls=False)[0],200);self.stop(s);self.verify_unchanged()
    def test_lifecycle_proxy(self):
        port=self.backend();s=self.setup_proxy([('plain','example.test',True)],{'plain':f'http://127.0.0.1:{port}'})
        self.cfg('proxy_start',s,selection='plain',policy='open',consent='1');self.ready()
        self.api('configuration_api','proxy_start',s,{'selection':'plain','policy':'open','consent':'1'},expected=503)
        self.api('configuration_api','proxy_reap',s,{'consent':'1'},expected=503)
        # Publication uses the existing certificate transaction and remains
        # possible while nginx holds an immutable private snapshot.
        self.certificate_import(s,self.certificate_pair('rotated'));self.wait_generation(2);self.assertEqual(self.peer(),ssl.PEM_cert_to_DER_cert((STATE/'cert-fixtures/rotated.pem').read_text()))
        self.api('configuration_api','lifecycle_disable',s,{'consent':'1'},expected=503);self.ready('stopped');self.cfg('lifecycle_disable',s,consent='1');self.assertEqual(self.cli('proxy-status')['state'],'idle')
        self.api('configuration_api','proxy_start',s,{'selection':'plain','policy':'open','consent':'1'},expected=503);self.verify_unchanged()
    def peer(self,host='example.test'):
        c=ssl._create_unverified_context().wrap_socket(socket.create_connection(('127.0.0.1',10443),timeout=5),server_hostname=host)
        out=c.getpeercert(binary_form=True);c.close();return out
    def wait_generation(self,generation=None,reload_state=None,seconds=15):
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            d=self.cli('proxy-status')
            if d['state']=='running' and d['running'] and (generation is None or d['generation']==generation) and (reload_state is None or d['reload_state']==reload_state):return d
            time.sleep(.1)
        trace=Path('/var/run/homegate-engineering/proxy/probe/error');print(trace.read_text()[-6000:] if trace.exists() else 'NO VALIDATION TRACE',flush=True)
        self.fail(('Reload did not settle',d))
    def fault_component(self):
        wrapper=STATE/'libexec/homegate-nginx/nginx'
        wrapper.write_text('#!/usr/bin/python3\n'+r"""import os,sys,time,subprocess,re
from pathlib import Path
a=sys.argv[1:]
if '-g' in a:a[a.index('-g')+1]='daemon off; master_process on;'
real=NGINX_BINARY
os.environ['LD_PRELOAD']=FIXTURE_LIBRARY
if '-t' in a and Path('/teststate/reload-fault').exists():
 mode=Path('/teststate/reload-fault').read_text();Path('/teststate/reload-entered').touch()
 with open('/teststate/reload-calls','a') as f:f.write('check\n')
 if mode=='reject':sys.exit(1)
 if mode=='hold':
  subprocess.Popen(['/usr/sbin/busybox','sleep','45'])
  time.sleep(45);sys.exit(1)
 if mode=='missing-key':
  result=subprocess.run([real,*a]);
  if result.returncode:sys.exit(result.returncode)
  conf=Path(a[a.index('-c')+1]).read_text();key=re.search(r'ssl_certificate_key ([^;]+);',conf).group(1)
  Path('/teststate/hidden-key-path').write_text(key);Path(key).rename(key+'.hidden')
  sys.exit(0)
os.execv(real,['nginx',*a])
""".replace('NGINX_BINARY',repr(str(NGINX/'nginx'))).replace('FIXTURE_LIBRARY',repr(str(FIXTURE/'same-credentials.so'))))
        wrapper.chmod(0o755)
    def test_reload(self):
        import ctypes
        lib=ctypes.CDLL(str(FIXTURE/'same-credentials.so'));lib.initgroups.argtypes=[ctypes.c_char_p,ctypes.c_uint];lib.initgroups.restype=ctypes.c_int
        before=(os.getuid(),os.geteuid(),os.getgid(),os.getegid(),os.getgroups())
        self.assertEqual(lib.initgroups(b'root',0),0);self.assertEqual(lib.initgroups(b'root',1),-1);self.assertEqual(lib.initgroups(b'other',0),-1)
        self.assertEqual((os.getuid(),os.geteuid(),os.getgid(),os.getegid(),os.getgroups()),before)
        caps=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        for k in ['CapEff','CapPrm','CapBnd']:self.assertEqual(int(caps[k].strip(),16),0)
        port=self.backend();s=self.setup_proxy([('exact','example.test',True),('wild','*.example.test',True),('collision','a.example.test',True)],{'exact':f'http://127.0.0.1:{port}','wild':f'http://127.0.0.1:{port}','collision':f'http://127.0.0.1:{port}'})
        self.cfg('proxy_start',s,selection='exact,wild,collision',policy='open',consent='1');self.ready();owner=Path('/var/run/homegate-engineering/proxy/owner').read_bytes()
        probes=subprocess.run(['/usr/sbin/lua','/usr/libexec/homegate-engineering/project/core/prototype/homegate-proxy.lua','probes','accepted'],capture_output=True,check=True).stdout.decode().splitlines();self.assertNotEqual(probes[1].split(':')[0],'a.example.test')
        # An established upstream WebSocket must remain usable across reload.
        sock=ssl._create_unverified_context().wrap_socket(socket.create_connection(('127.0.0.1',10443),timeout=5),server_hostname='example.test')
        sock.sendall(b'GET /ws HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n');head=b''
        while b'\r\n\r\n' not in head:head+=sock.recv(1024)
        self.assertTrue(head.startswith(b'HTTP/1.1 101'),head)
        old=self.peer();new=self.certificate_pair('new');self.certificate_import(s,new)
        d=self.wait_generation(2,'verified');self.assertTrue(d['automatic_reload']);self.assertNotEqual(old,self.peer());expected=ssl.PEM_cert_to_DER_cert(new[0]);self.assertEqual(self.peer(),expected);self.assertEqual(self.peer('one.example.test'),expected)
        mask=b'abcd';payload=b'alive';sock.sendall(b'\x81\x85'+mask+bytes(v^mask[i%4] for i,v in enumerate(payload)));self.assertEqual(sock.recv(7),b'\x81\x05alive');sock.close()
        self.assertEqual(Path('/var/run/homegate-engineering/proxy/owner').read_bytes(),owner)
        self.certificate_import(s,self.certificate_pair('third'));self.wait_generation(3,'verified');self.assertEqual(self.peer(),ssl.PEM_cert_to_DER_cert((STATE/'cert-fixtures/third.pem').read_text()))
        self.assertEqual(self.exchange_proxy('example.test')[0],200);self.stop(s);self.verify_unchanged()
    def test_reload_reject(self):
        port=self.backend();s=self.setup_proxy([('exact','example.test',True)],{'exact':f'http://127.0.0.1:{port}'})
        self.cfg('proxy_start',s,selection='exact',policy='open',consent='1');self.ready();old=self.peer();self.fault_component();(STATE/'reload-fault').write_text('reject')
        self.certificate_import(s,self.certificate_pair('rejected'));self.wait_generation(1,'rejected');self.assertEqual(self.peer(),old);self.assertEqual(self.exchange_proxy('example.test')[0],200)
        calls=(STATE/'reload-calls').read_bytes();time.sleep(1.2);self.assertEqual((STATE/'reload-calls').read_bytes(),calls)
        (STATE/'reload-fault').unlink();new=self.certificate_pair('recovered');self.certificate_import(s,new);self.wait_generation(2,'verified');self.assertEqual(self.peer(),ssl.PEM_cert_to_DER_cert(new[0]));self.stop(s);self.verify_unchanged()
    def test_reload_rollback(self):
        port=self.backend();s=self.setup_proxy([('exact','example.test',True)],{'exact':f'http://127.0.0.1:{port}'})
        self.cfg('proxy_start',s,selection='exact',policy='open',consent='1');self.ready();old=self.peer();self.fault_component();(STATE/'reload-fault').write_text('missing-key')
        self.certificate_import(s,self.certificate_pair('not-loaded'));self.wait_generation(1,'rejected');self.assertEqual(self.peer(),old);self.assertEqual(self.exchange_proxy('example.test')[0],200)
        key=(STATE/'hidden-key-path').read_text();Path(key+'.hidden').rename(key);(STATE/'reload-fault').unlink()
        new=self.certificate_pair('after-rollback');self.certificate_import(s,new);self.wait_generation(2,'verified');self.assertEqual(self.peer(),ssl.PEM_cert_to_DER_cert(new[0]));self.stop(s);self.verify_unchanged()
    def test_reload_stop(self):
        port=self.backend();s=self.setup_proxy([('exact','example.test',True)],{'exact':f'http://127.0.0.1:{port}'})
        self.cfg('proxy_start',s,selection='exact',policy='open',consent='1');self.ready();self.fault_component();(STATE/'reload-fault').write_text('hold');self.certificate_import(s,self.certificate_pair('held'))
        until=time.monotonic()+10
        while not (STATE/'reload-entered').exists():
            self.assertLess(time.monotonic(),until);time.sleep(.1)
        self.stop(s);self.assertEqual(self.cfg('read',s)['ok'],True);self.assertEqual(subprocess.run(['/usr/bin/openssl','version'],capture_output=True,timeout=3).returncode,0);self.verify_unchanged()
    def access_wait(self,s,state=None,seconds=12):
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            d=self.cfg('access_status',s)['report']
            if not d['running'] and (state is None or d['state']==state):return d
            time.sleep(.1)
        self.fail(('CN update did not settle',d))
    def audit_wait(self,s,predicate,seconds=5):
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            d=self.cfg('access_recent',s)['report']
            if predicate(d['entries']):return d['entries']
            time.sleep(.1)
        self.fail(('Audit did not settle',d))
    def test_cn_policy(self):
        port=self.backend();s=self.setup_proxy([('plain','example.test',False)],{'plain':f'http://127.0.0.1:{port}'},extra='cn')
        self.api('configuration_api','proxy_start',s,{'selection':'plain','policy':'allow','consent':'1'},expected=503)
        self.cfg('access_update',s,consent='1');d=self.access_wait(s,'published');self.assertTrue(d['cache_valid']);self.assertEqual((d['ipv4'],d['ipv6']),(1,1))
        self.cfg('proxy_start',s,selection='plain',policy='allow',consent='1');self.ready()
        self.assertEqual(self.exchange_proxy('example.test',tls=False)[0],200);self.assertEqual(self.exchange_proxy('example.test',tls=False,ipv6=True)[0],200)
        self.assertEqual(self.exchange_proxy('example.test',tls=False,source='127.0.0.2',headers={'X-Forwarded-For':'127.0.0.1'})[0],403)
        self.audit_wait(s,lambda rows:any(x['reason']=='region' for x in rows) and any(x['reason']=='denied' for x in rows))
        (STATE/'access-mode').write_text('alternate');self.cfg('access_refresh',s,consent='1');self.access_wait(s,'published')
        self.assertEqual(self.exchange_proxy('example.test',tls=False)[0],200);self.stop(s)
        self.cfg('proxy_start',s,selection='plain',policy='allow',consent='1');self.ready();self.assertEqual(self.exchange_proxy('example.test',tls=False)[0],403);self.assertEqual(self.exchange_proxy('example.test',tls=False,source='127.0.0.2')[0],200);self.stop(s)
        p=self.cfg('preview_access',s,allow='127.0.0.1/32,192.0.2.7/32',deny='127.0.0.2/32;127.0.0.3/32',region='CN');self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1');self.cfg('lifecycle_enable',s,consent='1')
        self.cfg('proxy_start',s,selection='plain',policy='allow',consent='1');self.ready();self.assertEqual(self.exchange_proxy('example.test',tls=False)[0],200);self.assertEqual(self.exchange_proxy('example.test',tls=False,source='127.0.0.2')[0],403);self.stop(s);self.verify_unchanged()
    def test_cn_cache(self):
        s=self.login();self.cfg('prepare',s);(STATE/'access-mode').write_text('single');self.cfg('access_update',s,consent='1');d=self.access_wait(s,'failed');self.assertFalse(d['cache_valid']);self.assertFalse(Path('/etc/homegate-engineering/access/CN.cidr').exists())
        (STATE/'access-mode').write_text('mirror');self.cfg('access_refresh',s,consent='1');self.access_wait(s,'published');cache=Path('/etc/homegate-engineering/access/CN.cidr');before=cache.read_bytes()
        calls=(STATE/'access-calls').read_bytes();self.cfg('access_update',s,consent='1');self.access_wait(s,'cached');self.assertEqual((STATE/'access-calls').read_bytes(),calls)
        for mode in ['truncated','partial','oversized']:
            (STATE/'access-mode').write_text(mode);self.cfg('access_refresh',s,consent='1');d=self.access_wait(s,'failed');self.assertTrue(d['cache_valid']);self.assertEqual(cache.read_bytes(),before)
        self.cfg('access_reap',s,consent='1');self.verify_unchanged()
    def test_access_audit(self):
        port=self.backend();s=self.setup_proxy([('plain','example.test',False)],{'plain':f'http://127.0.0.1:{port}/SECRET_SENTINEL'})
        p=self.cfg('preview_access',s,allow='127.0.0.1/32,::1/128',deny='127.0.0.2/32;127.0.0.3/32',region='');self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1');self.cfg('lifecycle_enable',s,consent='1')
        self.cfg('proxy_start',s,selection='plain',policy='open',consent='1');self.ready();self.assertTrue(self.cfg('proxy_status',s)['report']['audit_available'])
        for source in ['127.0.0.1','127.0.0.2']:self.exchange_proxy('example.test','/?SECRET_SENTINEL=hidden',tls=False,source=source,headers={'X-Forwarded-For':'203.0.113.66'})
        self.exchange_proxy('example.test',tls=False,ipv6=True);rows=self.audit_wait(s,lambda rows:len(rows)>=3);self.assertTrue(any(x['ip']=='127.0.0.2' and x['reason']=='manual-deny' for x in rows));self.assertNotIn('SECRET_SENTINEL',json.dumps(rows));self.assertFalse(any(x['ip']=='203.0.113.66' for x in rows))
        # An untrusted local sender knows only the public session token, not the
        # independently generated private audit tag. It cannot forge entries.
        sender=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);token=Path('/var/run/homegate-engineering/proxy/token').read_text().strip();sender.sendto(('<190>Oct 28 00:00:00 '+token+': '+json.dumps({'ip':'192.0.2.9','host':'example.test','allowed':True,'reason':'disabled'})).encode(),'/var/run/homegate-engineering-audit/socket');sender.close()
        for n in range(10,80):self.assertEqual(self.exchange_proxy('example.test',tls=False,source='127.0.0.'+str(n))[0],200)
        rows=self.audit_wait(s,lambda rows:len(rows)==64 and rows[-1]['ip']=='127.0.0.79');self.assertFalse(any(x['ip']=='192.0.2.9' for x in rows))
        self.exchange_proxy('example.test',tls=False,source='127.0.0.79');self.audit_wait(s,lambda rows:rows[-1]['count']>=2)
        self.exchange_proxy('example.test',tls=False,source='127.0.0.2');self.audit_wait(s,lambda rows:any(not x['allowed'] for x in rows));self.cfg('access_clear_denied',s,consent='1');self.audit_wait(s,lambda rows:len(rows)>0 and all(x['allowed'] for x in rows))
        self.cfg('access_clear',s,consent='1');self.audit_wait(s,lambda rows:len(rows)==0)
        # Kill only this freshly observed fixture child through a pidfd; verify
        # cmdline + start time again after opening it, never a stored kill PID.
        import signal
        owner=Path('/var/run/homegate-engineering/proxy/owner').read_text().split(':')[0]
        found=False
        for pid in Path('/proc/'+owner+'/task/'+owner+'/children').read_text().split():
            cmd=Path('/proc/'+pid+'/cmdline').read_bytes()
            if b'/homegate-access-audit.lua\x00serve\x00' not in cmd:continue
            before=Path('/proc/'+pid+'/stat').read_text().split(') ',1)[1].split()[19]
            fd=os.pidfd_open(int(pid));after=Path('/proc/'+pid+'/stat').read_text().split(') ',1)[1].split()[19]
            self.assertEqual(before,after);self.assertEqual(Path('/proc/'+pid+'/cmdline').read_bytes(),cmd);signal.pidfd_send_signal(fd,signal.SIGTERM);os.close(fd);found=True;break
        self.assertTrue(found);until=time.monotonic()+5
        while self.cfg('proxy_status',s)['report']['audit_available']:
            self.assertLess(time.monotonic(),until);time.sleep(.1)
        self.assertEqual(self.exchange_proxy('example.test',tls=False)[0],200)
        self.stop(s);self.assertEqual(self.cfg('access_recent',s)['report']['entries'],[]);self.verify_unchanged()
    def test_access_stop(self):
        s=self.login();self.cfg('prepare',s);(STATE/'access-mode').write_text('hold');self.cfg('access_refresh',s,consent='1');until=time.monotonic()+10
        while not (STATE/'access-entered').exists():self.assertLess(time.monotonic(),until);time.sleep(.1)
        self.api('configuration_api','access_refresh',s,{'consent':'1'},expected=503);self.cfg('access_stop',s,consent='1');self.access_wait(s,'stopped');self.cfg('access_reap',s,consent='1');self.assertTrue(self.cfg('read',s)['ok']);self.verify_unchanged()
    def test_security_proxy(self):
        s=self.login()
        for action in ['preview_access','access_update','access_refresh','access_clear','access_clear_denied','access_stop','access_reap','preview_web_rule','web_target_put','proxy_start','proxy_stop','proxy_reap']:
            self.api('configuration_api',action,None,{},expected=403);self.api('configuration_api',action,s,{},expected=405,verb='GET')
            status,_,_=self.cgi(web.BASE+'/configuration_api/'+action,cookie=s[0],verb='POST',fields={'token':'bad'});self.assertEqual(status,403)
        self.cfg('prepare',s)
        for selection in ['../x','x;touch','x,,y']:
            self.api('configuration_api','proxy_start',s,{'selection':selection,'policy':'open','consent':'1'},expected=503)
        self.assertFalse(Path('/var/run/homegate-engineering/proxy').exists())
        # CN policy must fail closed rather than silently allow all traffic.
        port=self.backend()
        # setup_proxy prepares its own state; retain this test's native session.
        s=self.setup_proxy([('plain','example.test',False)],{'plain':f'http://127.0.0.1:{port}'},extra='cn')
        self.api('configuration_api','proxy_start',s,{'selection':'plain','policy':'allow','consent':'1'},expected=503)
        self.assertFalse(Path('/var/run/homegate-engineering/proxy').exists());self.verify_unchanged()

def main():
    global NGINX,FIXTURE
    p=argparse.ArgumentParser();p.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd');p.add_argument('--http-runtime-dir',type=Path,default=ROOT/'build/uhttpd');p.add_argument('--luci-runtime-dir',type=Path,default=ROOT/'build/luci');p.add_argument('--nginx-runtime-dir',type=Path,default=NGINX);p.add_argument('--nginx-fixture-dir',type=Path,default=FIXTURE);p.add_argument('--inside-net');p.add_argument('--inside-uid');p.add_argument('--group',choices=['routing','streaming','upstream_tls','acl','lifecycle_proxy','security_proxy','reload','reload_reject','reload_rollback','reload_stop','cn_policy','cn_cache','access_audit','access_stop']);a=p.parse_args()
    NGINX=a.nginx_runtime_dir.resolve();FIXTURE=a.nginx_fixture_dir.resolve();rpc.WORK,luci.HTTP,luci.LUA=a.runtime_dir.resolve(),a.http_runtime_dir.resolve(),a.luci_runtime_dir.resolve();luci.BASE,luci.PAGE=web.BASE,web.PAGE
    if a.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID=a.inside_net,a.inside_uid
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([Proxy('test_'+a.group)])).wasSuccessful() else 1
    spec=importlib.util.spec_from_file_location('nginx_runtime',ROOT/'scripts/prepare-nginx.py');runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime);runtime.validate_runtime(NGINX);runtime.validate_fixture(FIXTURE)
    for group in [a.group] if a.group else ['routing','streaming','upstream_tls','acl','lifecycle_proxy','security_proxy','reload','reload_reject','reload_rollback','reload_stop','cn_policy','cn_cache','access_audit','access_stop']:
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA,NGINX,FIXTURE),extra_mounts=lambda s:((Path('/usr/bin'),'/fixture-host-bin'),(s/'usr-bin','/usr/bin'),(s/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),(s/'models',luci.LUA/'prefix/lib/lua/luci/model'),(s/'libexec','/usr/libexec'),(s/'tools','/usr/sbin'),(s/'curl-fixture','/usr/bin/curl')),extra_rw_mounts=lambda s:((s/'etc/homegate-engineering','/etc/homegate-engineering'),(s/'etc/config','/etc/config'),(s/'etc/ssl','/etc/ssl')),state_setup=setup_state,guest_args=['--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--nginx-runtime-dir',str(NGINX),'--nginx-fixture-dir',str(FIXTURE),'--group',group])
        if result:return result
    return 0
if __name__=='__main__':sys.exit(main())
