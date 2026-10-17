#!/usr/bin/env python3
"""AliDNS signature and real curl/loopback TLS tests; no cloud requests."""
import argparse,base64,hashlib,hmac,json,os,re,shutil,subprocess,sys,time,unittest
from pathlib import Path
from urllib.parse import parse_qs,quote,urlsplit
from project import ROOT
from 生命周期业务集成回归 import Runtime as LifecycleRuntime

PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_closed_entry_worker_and_shared_watchdog(self):
        for name,gate in [('homegate-aliyun-read.sh','aliyun_entry_enabled'),('homegate-aliyun-worker.sh','aliyun_read_enabled'),('homegate-cloudflare-read.sh','aliyun_read_enabled'),('homegate-service-observer-watchdog.sh','aliyun_read_enabled')]:
            body=(PROTO/name).read_text(encoding='utf-8');self.assertEqual(body.count(gate+'=false'),1);self.assertNotIn(gate+'=true',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_lua_and_ash_syntax(self):
        from lupa.lua51 import LuaRuntime
        import tree_sitter,tree_sitter_bash
        lua=LuaRuntime();parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        lua.compile((PROTO/'aliyun-reader.lua').read_text());lua.compile((PROTO/'cloudflare-codec.lua').read_text())
        for name in ['homegate-aliyun-read.sh','homegate-aliyun-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error,name)

    def library(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(unpack_returned_tuples=True,encoding=None)
        lua.execute(b"arg={[0]='/fixture/aliyun-reader.lua'};loadfile=function()return function()return {} end end")
        module=lua.execute((PROTO/'aliyun-reader.lua').read_bytes()+b"\n",b'library')
        return lua,module

    def test_percent_encoding_and_sorted_double_encoding(self):
        lua,m=self.library();value=b'a b*~+/%&=\xff'
        self.assertEqual(m[b'escape'](value),quote(value,safe='-._~').encode())
        fields={b'Z':b'x y',b'A':b'\xff*~+'};actual=m[b'canonical'](lua.table_from(fields))
        expected=b'A=%FF%2A~%2B&Z=x%20y';self.assertEqual(actual,expected)
        self.assertEqual(m[b'escape'](actual),quote(expected,safe='-._~').encode())

    def test_hmac_padding_and_base64_against_independent_bytes(self):
        _,m=self.library()
        for key in [b'',b'x',bytes(range(64))]:
            for pad in [54,92]:self.assertEqual(m[b'pad'](key,pad),bytes(x^pad for x in key.ljust(64,b'\0')))
        for n in range(1,22):self.assertEqual(m[b'base64'](bytes(range(n))),base64.b64encode(bytes(range(n))))

    def test_no_credentials_in_crypto_or_curl_argv(self):
        body=(PROTO/'aliyun-reader.lua').read_text()
        self.assertIn('openssl dgst -sha1 -binary < /proc/self/fd/8',body)
        self.assertNotRegex(body,r'-(?:hmac|macopt|passin)\b')
        self.assertNotRegex(body,r'--(?:insecure|location|retry)\b')
        self.assertIn('work.."/request',body);self.assertNotIn('os.getenv',body)

class Runtime(LifecycleRuntime):
    def setUp(self):
        super().setUp()
        self.source.write_bytes(self.source.read_bytes().replace(b"provider 'cloudflare'",b"provider 'aliyun'"))
        self.ali_key=b'OLD_ID';self.ali_secret=b'SECRET_SENTINEL';self.signature_errors=[]
        self.response=None;self.total=2;self.page_size_override=None
        self.openssl_copy=self.base/'openssl';shutil.copy2(self.openssl,self.openssl_copy);self.openssl_copy.chmod(0o700)
        names=['homegate-aliyun-read.sh','homegate-aliyun-worker.sh','aliyun-reader.lua']
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/usr/bin/curl':str(self.curl),'/usr/bin/openssl':str(self.openssl_copy),'/etc/ssl/certs/ca-certificates.crt':str(self.ca_dir/'ca.pem')}
        for name in names:
            p=self.engine.parent/name;body=p.read_text().replace('aliyun_entry_enabled=false','aliyun_entry_enabled=true').replace('aliyun_read_enabled=false','aliyun_read_enabled=true')
            body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
            body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))
            for before,after in [('= 0:700 ]','= '+str(os.getuid())+':700 ]'),('= 0:600:1 ]','= '+str(os.getuid())+':600:1 ]'),('in 0:700:1|0:755:1)','in '+str(os.getuid())+':700:1|'+str(os.getuid())+':755:1)')]:body=body.replace(before,after)
            if name.endswith('.lua'):
                body=body.replace('https://alidns.aliyuncs.com/', 'https://127.0.0.1:'+str(self.server.server_port)+'/')
                body=body.replace('--max-time 10','--max-time 0.5')
            p.write_text(body,encoding='utf-8')
        for p in [self.reader,self.engine.parent/'homegate-service-observer-watchdog.sh']:
            p.write_text(p.read_text().replace('aliyun_read_enabled=false','aliyun_read_enabled=true'))
        self.ali_entry=self.engine.parent/'homegate-aliyun-read.sh'

    def record_http(self,method,path,body):
        q=parse_qs(urlsplit(path).query,keep_blank_values=True)
        valid=all(len(v)==1 for v in q.values())
        signature=q.pop('Signature',[''])[0]
        canonical='&'.join(quote(k,safe='-._~')+'='+quote(v[0],safe='-._~') for k,v in sorted(q.items()))
        expected=base64.b64encode(hmac.new(self.ali_secret+b'&',('GET&%2F&'+quote(canonical,safe='-._~')).encode(),hashlib.sha1).digest()).decode()
        valid=valid and signature==expected and q.get('AccessKeyId')==[self.ali_key.decode()] and q.get('Action')==['DescribeDomains'] and q.get('Version')==['2015-01-09'] and q.get('SignatureMethod')==['HMAC-SHA1'] and q.get('SignatureVersion')==['1.0'] and method=='GET'
        if not valid:self.signature_errors.append('signature mismatch');return 403,{'Code':'SignatureDoesNotMatch','Message':'SECRET_SENTINEL reflected'}
        if callable(self.response):return self.response(q)
        if self.response is not None:return self.http_status,self.response
        page=int(q['PageNumber'][0]);per=int(q['PageSize'][0]);count=max(0,min(per,self.total-(page-1)*per))
        return 200,{'TotalCount':self.total,'PageNumber':page,'PageSize':self.page_size_override or per,'RequestId':'fixture','Domains':{'Domain':[{'DomainName':f'z{n:05d}.example.test'} for n in range((page-1)*per,(page-1)*per+count)]}}

    def aliyun(self,mode=None,expected=0,account='dns_a',env=None):
        args=[account]+([mode] if mode else [])
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),*args],env=env or self.env,capture_output=True,timeout=12)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr,self.signature_errors));self.assertEqual(p.stderr,b'')
        for value in [b'SECRET_SENTINEL',b'OLD_ID',b'PRIVATE_ACCOUNT',b'private-token',self.ali_secret]:self.assertNotIn(value,p.stdout)
        r=json.loads(p.stdout);self.assertEqual(r['ok'],expected==0);return r

    def test_real_signature_tls_and_migration_bound_credentials(self):
        r=self.migrated();before=self.contents();out=self.aliyun()
        self.assertTrue(out['credentials_valid']);self.assertEqual(out['configuration_revision'],r['revision']);self.assertEqual(out['provider'],'aliyun')
        self.assertEqual(self.signature_errors,[]);self.assertEqual(len(self.calls),1);self.assertEqual(self.contents(),before);self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))

    def test_complete_pages_sorted_without_partial_output(self):
        self.total=203;self.migrated();out=self.aliyun('--zones')
        self.assertEqual(len(out['zones']),203);self.assertEqual(out['zones'],sorted(out['zones']));self.assertEqual(len(self.calls),3)
        nonces=[parse_qs(urlsplit(x['path']).query)['SignatureNonce'][0] for x in self.calls];self.assertEqual(len(set(nonces)),3)
        for x in self.calls:self.assertRegex(parse_qs(urlsplit(x['path']).query)['Timestamp'][0],r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')

    def test_empty_array_valid_but_empty_object_rejected(self):
        self.total=0;self.migrated();self.assertEqual(self.aliyun('--zones')['zones'],[])
        self.response={'TotalCount':0,'PageNumber':1,'PageSize':100,'RequestId':'fixture','Domains':{'Domain':{}}};self.aliyun('--zones',expected=1)

    def test_unicode_key_percent_and_long_hmac_secret(self):
        self.ali_key=b'ID +*~/%';self.ali_secret=b'x'*80+b' +*~/'
        self.source.write_bytes(self.source.read_bytes().replace(b'OLD_ID',self.ali_key).replace(b'SECRET_SENTINEL',self.ali_secret));self.migrated();self.aliyun();self.assertEqual(self.signature_errors,[])

    def test_second_page_failure_hides_first_page(self):
        self.total=150;self.migrated()
        def respond(q):
            if q['PageNumber']==['2']:return 403,{'Code':'Forbidden','Message':'SECRET_SENTINEL reflected'}
            return 200,{'TotalCount':150,'PageNumber':1,'PageSize':100,'RequestId':'fixture','Domains':{'Domain':[{'DomainName':'z.example.test'}]*100}}
        self.response=respond;out=self.aliyun('--zones',expected=1);self.assertEqual(out['zones'],[]);self.assertEqual(len(self.calls),2)

    def test_metadata_change_or_premature_empty_page_fails(self):
        self.total=150;self.migrated()
        for bad in [151,150]:
            self.response=lambda q:(200,{'TotalCount':150 if q['PageNumber']==['1'] else bad,'PageNumber':int(q['PageNumber'][0]),'PageSize':100,'RequestId':'fixture','Domains':{'Domain':[{'DomainName':'z.example.test'}]*100 if q['PageNumber']==['1'] else []}})
            self.assertEqual(self.aliyun('--zones',expected=1)['zones'],[])

    def test_wrong_page_size_and_malformed_names_refused(self):
        self.migrated();self.page_size_override=2;self.aliyun(expected=1);self.page_size_override=None
        for value in ['bad..test','-bad.test','bad.test;echo x']:
            self.response={'TotalCount':1,'PageNumber':1,'PageSize':100,'RequestId':'fixture','Domains':{'Domain':[{'DomainName':value}]}}
            self.assertEqual(self.aliyun('--zones',expected=1)['zones'],[])

    def test_idn_uses_validated_punycode_and_deduplicates(self):
        self.migrated();self.response={'TotalCount':3,'PageNumber':1,'PageSize':100,'RequestId':'fixture','Domains':{'Domain':[{'DomainName':' A.Example.Test. '},{'DomainName':'a.example.test'},{'DomainName':'例子.测试','PunyCode':'xn--fsqu00a.xn--0zwm56d'}]}}
        self.assertEqual(self.aliyun('--zones')['zones'],['a.example.test','xn--fsqu00a.xn--0zwm56d'])

    def test_error_codes_redacted_and_retry_classified(self):
        self.migrated()
        for status,code,kind,retry in [(403,'SignatureDoesNotMatch','authentication',False),(429,'Throttling','rate_limit',True),(500,'InternalError','temporary',True),(400,'SECRET_SENTINEL','invalid_request',False)]:
            self.http_status=status;self.response={'Code':code,'Message':'OLD_ID SECRET_SENTINEL SignedURL'};out=self.aliyun(expected=1)
            self.assertEqual((out['error_kind'],out['retryable']),(kind,retry))

    def test_missing_credentials_and_account_never_make_http(self):
        self.source.write_bytes(self.source.read_bytes().replace(b"secret 'SECRET_SENTINEL'",b"secret ''"));self.migrated();self.aliyun(expected=1);self.aliyun(account='missing',expected=1);self.assertEqual(self.calls,[])

    def test_source_change_and_shared_lock_block_before_request(self):
        import fcntl
        self.migrated()
        with self.native.lock.open('rb') as fd:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.aliyun(expected=4)
        self.source.write_bytes(self.source.read_bytes().replace(b'OLD_ID',b'CHANGED'));self.aliyun(expected=7);self.assertEqual(self.calls,[])

    def test_original_gates_and_write_modes_cannot_be_enabled(self):
        self.migrated();original=self.ali_entry.read_text();self.ali_entry.write_text(original.replace('aliyun_entry_enabled=true','aliyun_entry_enabled=false'))
        self.aliyun(expected=2,env={**self.env,'aliyun_entry_enabled':'true'});self.ali_entry.write_text(original)
        for mode in ['--records','--reconcile','--store']:self.aliyun(mode,expected=2)
        self.assertEqual(self.calls,[])

    def test_oversized_or_duplicate_json_never_authenticates(self):
        self.migrated()
        for body in [b'X'*65537,b'{"TotalCount":0,"TotalCount":0}',b'{"Code":"Forbidden","Message":"SECRET_SENTINEL"}\x00']:
            self.response=body;self.aliyun(expected=1)

    def test_real_curl_timeout_is_bounded(self):
        self.migrated();self.delay=1.2;start=time.monotonic();out=self.aliyun(expected=1)
        self.assertEqual(out['error_kind'],'timeout');self.assertLess(time.monotonic()-start,5)

    def test_redirect_never_forwards_signed_material(self):
        self.migrated();self.http_status=302;self.response={};self.redirect=self.endpoint;self.aliyun(expected=1);self.assertEqual(len(self.calls),1)

    def test_live_crypto_and_curl_arguments_exclude_private_material(self):
        self.migrated();self.delay=0.3
        real=self.base/'openssl-real';self.openssl_copy.rename(real)
        capture=self.base/'crypto-arguments.jsonl'
        self.openssl_copy.write_text('#!'+sys.executable+'\nimport json,os,sys\nwith open('+repr(str(capture))+',"a") as f:f.write(json.dumps([sys.argv,dict(os.environ)])+"\\n")\nos.execv('+repr(str(real))+',["openssl",*sys.argv[1:]])\n');self.openssl_copy.chmod(0o700)
        p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        deadline=time.monotonic()+5;seen=False
        while not seen:
            for proc in Path('/proc').glob('[0-9]*/cmdline'):
                try:
                    args=proc.read_bytes()
                    if args.split(b'\0')[0]!=os.fsencode(self.curl):continue
                    environment=(proc.parent/'environ').read_bytes()
                except (FileNotFoundError,ProcessLookupError,PermissionError):continue
                for secret in [self.ali_key,self.ali_secret]:self.assertNotIn(secret,args+environment)
                files=list(self.native.lockdir.glob('.dns-check-*/*'));self.assertEqual(len(files),6)
                for file in files:self.assertEqual(file.stat().st_mode&0o777,0o600);self.assertEqual(file.stat().st_nlink,1)
                seen=True;break
            if not seen:self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.01)
        out,err=p.communicate(timeout=5);self.assertEqual((p.returncode,err),(0,b''));self.assertTrue(json.loads(out)['ok'])
        raw=capture.read_bytes()
        for secret in [self.ali_key,self.ali_secret]:self.assertNotIn(secret,raw)
        rows=[json.loads(line) for line in raw.splitlines()];self.assertEqual(len(rows),2)
        for argv,env in rows:self.assertEqual(argv[1:],['dgst','-sha1','-binary'])
        self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))

    def test_caller_loss_keeps_deadline_and_orphan_barrier(self):
        self.migrated()
        self.curl.write_text('#!'+sys.executable+'\nimport time,signal\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True:time.sleep(0.1)\n');self.curl.chmod(0o700)
        p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        deadline=time.monotonic()+5
        while not self.group():self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.02)
        time.sleep(0.1);p.kill();p.communicate(timeout=2);self.writer(4)
        time.sleep(3.4);self.writer();self.aliyun(expected=4)
        self.assertTrue(list(self.native.lockdir.glob('.dns-check-*')));self.assertEqual(self.calls,[])

    def test_result_cannot_substitute_another_read_scope(self):
        self.migrated();out=self.aliyun();raw=(json.dumps(out,separators=(',',':'))+'\n').encode()
        for mode,expected in [('check',0),('zones',1)]:
            p=subprocess.run(['lua',str(self.engine.parent/'aliyun-reader.lua'),'result','dns_a',str(out['configuration_revision']),'0',mode],input=raw,capture_output=True,env=self.env,timeout=5)
            self.assertEqual(p.returncode,expected);self.assertEqual(p.stderr,b'')
            self.assertEqual(p.stdout,raw if expected==0 else b'')

    def test_missing_openssl_stops_before_request(self):
        self.migrated();self.openssl_copy.unlink();self.aliyun(expected=7);self.assertEqual(self.calls,[])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v))
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if r.wasSuccessful() else 1)
