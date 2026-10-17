#!/usr/bin/env python3
"""TC3 independent signatures and private read-only loopback TLS contracts."""
import argparse,datetime,hashlib,hmac,json,os,re,shutil,subprocess,sys,time,unittest
from pathlib import Path
from Aliyun只读回归 import Runtime as AliRuntime,PROTO

def authorization(key_id,key,payload,timestamp):
    date=datetime.datetime.fromtimestamp(timestamp,datetime.timezone.utc).strftime('%Y-%m-%d');scope=date+'/dnspod/tc3_request'
    canonical=b'POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:dnspod.tencentcloudapi.com\n\ncontent-type;host\n'+hashlib.sha256(payload).hexdigest().encode()
    text=b'TC3-HMAC-SHA256\n'+str(timestamp).encode()+b'\n'+scope.encode()+b'\n'+hashlib.sha256(canonical).hexdigest().encode()
    def mac(k,v):return hmac.new(k,v,hashlib.sha256).digest()
    signed=mac(mac(mac(mac(b'TC3'+key,date.encode()),b'dnspod'),b'tc3_request'),text).hex()
    return 'TC3-HMAC-SHA256 Credential='+key_id.decode()+'/'+scope+', SignedHeaders=content-type;host, Signature='+signed

class Static(unittest.TestCase):
    def test_gates_grammar_and_no_production_install(self):
        from lupa.lua51 import LuaRuntime
        import tree_sitter,tree_sitter_bash
        lua=LuaRuntime();lua.compile((PROTO/'dnspod-reader.lua').read_bytes());parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name,gate in [('homegate-dnspod-read.sh','dnspod_entry_enabled'),('homegate-dnspod-worker.sh','dnspod_read_enabled'),('homegate-cloudflare-read.sh','dnspod_read_enabled'),('homegate-service-observer-watchdog.sh','dnspod_read_enabled')]:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error,name);self.assertEqual(body.count((gate+'=false').encode()),1)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_tc3_digest_injection_matches_independent_hmac(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(encoding=None);lua.globals().ali_body=(PROTO/'aliyun-reader.lua').read_bytes()
        lua.execute(b"arg={[0]='/fixture/dnspod-reader.lua'};require=function()return {}end;loadfile=function(p) if p:match('aliyun%-reader.lua$') then return assert(loadstring(ali_body)) end;return function()return {}end end")
        module=lua.execute((PROTO/'dnspod-reader.lua').read_bytes(),b'library')
        for key in [b'k',b'x'*61,b'x'*80,b'x'*4096]:
            for stamp in [0,1772323199,1772323200]:
                payload=b'{"Limit":100,"Offset":0,"Type":"ALL"}'
                value=module.authorization(b'OLD_ID',key,payload,stamp,lambda s:hashlib.sha256(s).digest())
                self.assertEqual(value,authorization(b'OLD_ID',key,payload,stamp).encode())
    def test_crypto_and_transport_have_no_secret_arguments_or_bypass(self):
        body=(PROTO/'dnspod-reader.lua').read_text();self.assertIn('openssl dgst -sha256 -binary < /proc/self/fd/8',body)
        for forbidden in ['-hmac','-macopt','--insecure','--location','--retry','os.getenv']:self.assertNotIn(forbidden,body)
        self.assertIn("mode~='records' and mode~='reconcile' and action~='DescribeDomainList'",body)
        self.assertIn('DescribeDomainList',body)

class Runtime(AliRuntime):
    def setUp(self):
        super().setUp();self.source.write_bytes(self.source.read_bytes().replace(b"provider 'aliyun'",b"provider 'dnspod'"));self.capture_headers=True
        self.total=2;self.response=None
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/usr/bin/curl':str(self.curl),'/usr/bin/openssl':str(self.openssl_copy),'/etc/ssl/certs/ca-certificates.crt':str(self.ca_dir/'ca.pem')}
        for name in ['homegate-dnspod-read.sh','homegate-dnspod-worker.sh','dnspod-reader.lua']:
            p=self.engine.parent/name;body=p.read_text().replace('dnspod_entry_enabled=false','dnspod_entry_enabled=true').replace('dnspod_read_enabled=false','dnspod_read_enabled=true')
            body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body);body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))
            for before,after in [('= 0:700 ]','= '+str(os.getuid())+':700 ]'),('= 0:600:1 ]','= '+str(os.getuid())+':600:1 ]'),('in 0:700:1|0:755:1)','in '+str(os.getuid())+':700:1|'+str(os.getuid())+':755:1)')]:body=body.replace(before,after)
            if name.endswith('.lua'):body=body.replace('https://dnspod.tencentcloudapi.com/','https://127.0.0.1:'+str(self.server.server_port)+'/').replace('--max-time 10','--max-time 0.5')
            p.write_text(body)
        for p in [self.reader,self.engine.parent/'homegate-service-observer-watchdog.sh']:p.write_text(p.read_text().replace('dnspod_read_enabled=false','dnspod_read_enabled=true'))
        self.ali_entry=self.engine.parent/'homegate-dnspod-read.sh'
    def response_page(self,offset,limit,total=None,items=None):
        total=self.total if total is None else total
        if items is None:items=[{'Name':f'z{n:05d}.example.test'} for n in range(offset,min(offset+limit,total))]
        return {'Response':{'DomainCountInfo':{'DomainTotal':total},'DomainList':items,'RequestId':'fixture'}}
    def record_http(self,method,path,body):
        headers={k.lower():v for k,v in self.calls[-1]['headers'].items()};stamp=headers.get('x-tc-timestamp','')
        try:payload=json.loads(body);expected=authorization(self.ali_key,self.ali_secret,body,int(stamp))
        except Exception:payload={};expected='invalid'
        valid=method=='POST' and path=='/' and headers.get('authorization')==expected and headers.get('x-tc-action')=='DescribeDomainList' and headers.get('x-tc-version')=='2021-03-23' and headers.get('content-type')=='application/json; charset=utf-8' and set(payload)=={'Type','Offset','Limit'} and payload.get('Type')=='ALL'
        if not valid:self.signature_errors.append('signature mismatch');return 403,{'Response':{'Error':{'Code':'AuthFailure.SignatureFailure','Message':'SECRET_SENTINEL'}}}
        if callable(self.response):return self.response(payload)
        if self.response is not None:return self.http_status,self.response
        return 200,self.response_page(payload['Offset'],payload['Limit'])
    def test_real_tc3_tls_and_source_bound_private_credentials(self):
        self.migrated();before=self.contents();out=self.aliyun();self.assertEqual(out['provider'],'dnspod');self.assertTrue(out['credentials_valid']);self.assertEqual(self.signature_errors,[]);self.assertEqual(len(self.calls),1);self.assertEqual(before,self.contents());self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))
    def test_complete_offset_pages_sorted_and_deduplicated(self):
        self.total=203;self.migrated();out=self.aliyun('--zones');self.assertEqual(len(out['zones']),203);self.assertEqual(out['zones'],sorted(out['zones']));self.assertEqual([json.loads(c['body'])['Offset'] for c in self.calls],[0,100,200]);self.assertEqual(self.signature_errors,[])
    def test_empty_array_and_wrong_container_types(self):
        self.total=0;self.migrated();self.assertEqual(self.aliyun('--zones')['zones'],[])
        for value in [{},None,'']:
            self.response=self.response_page(0,100,items=value if value is not None else []);self.response['Response']['DomainList']=value;self.aliyun('--zones',1)
    def test_later_error_hides_partial_zones_and_redacts_message(self):
        self.total=150;self.migrated();self.response=lambda q:(403,{'Response':{'Error':{'Code':'UnauthorizedOperation','Message':'SECRET_SENTINEL'}}}) if q['Offset'] else (200,self.response_page(0,100))
        out=self.aliyun('--zones',1);self.assertEqual(out['zones'],[]);self.assertEqual(out['error_kind'],'authentication');self.assertEqual(len(self.calls),2)
    def test_changed_count_short_page_and_bad_names_refused(self):
        self.total=150;self.migrated()
        for wrong in [151,150]:
            self.response=lambda q:(200,self.response_page(q['Offset'],100,total=150 if not q['Offset'] else wrong,items=None if not q['Offset'] else []));self.assertEqual(self.aliyun('--zones',1)['zones'],[])
        for name in ['bad..test','-bad.test','bad.test;echo x']:
            self.response=self.response_page(0,100,total=1,items=[{'Name':name}]);self.aliyun('--zones',1)
    def test_valid_punycode_normalization(self):
        self.migrated();self.response=self.response_page(0,100,total=3,items=[{'Name':' A.Example.Test. '},{'Name':'a.example.test'},{'Name':'例子.测试','Punycode':'xn--fsqu00a.xn--0zwm56d'}]);self.assertEqual(self.aliyun('--zones')['zones'],['a.example.test','xn--fsqu00a.xn--0zwm56d'])
    def test_error_classification_and_unknown_code_redaction(self):
        self.migrated()
        for status,code,kind,retry in [(200,'AuthFailure.SignatureFailure','authentication',False),(200,'RequestLimitExceeded','rate_limit',True),(500,'InternalError','temporary',True),(400,'SECRET_SENTINEL','invalid_request',False)]:
            self.http_status=status;self.response={'Response':{'Error':{'Code':code,'Message':'OLD_ID SECRET_SENTINEL'}}};out=self.aliyun(expected=1);self.assertEqual((out['error_kind'],out['retryable']),(kind,retry))
    def test_long_hmac_key_and_invalid_id_stops_before_http(self):
        self.ali_secret=b'x'*80+b' +*~';self.source.write_bytes(self.source.read_bytes().replace(b'SECRET_SENTINEL',self.ali_secret));self.migrated();self.aliyun();self.assertEqual(self.signature_errors,[])
        self.source.write_bytes(self.source.read_bytes().replace(b'OLD_ID',b'BAD_ID/HEADER'));self.aliyun(expected=7);self.assertEqual(len(self.calls),1)
    def test_write_modes_and_all_read_gates_refuse_environment_override(self):
        self.migrated()
        for mode in ['--records','--migrated','--reconcile','--store']:self.aliyun(mode,2)
        for p,gate,rc in [(self.ali_entry,'dnspod_entry_enabled',2),(self.reader,'dnspod_read_enabled',2),(self.engine.parent/'homegate-service-observer-watchdog.sh','dnspod_read_enabled',7),(self.engine.parent/'homegate-dnspod-worker.sh','dnspod_read_enabled',7)]:
            raw=p.read_text();p.write_text(raw.replace(gate+'=true',gate+'=false'));self.aliyun(expected=rc,env={**self.env,gate:'true'});p.write_text(raw)
        self.assertEqual(self.calls,[])
    def test_result_scope_account_revision_and_raw_json_are_revalidated(self):
        self.migrated();out=self.aliyun();raw=(json.dumps(out,separators=(',',':'))+'\n').encode()
        for account,revision,mode,body,rc in [('dns_a','3','check',raw,0),('other','3','check',raw,1),('dns_a','2','check',raw,1),('dns_a','3','zones',raw,1),('dns_a','3','check',raw+b' ',1)]:
            p=subprocess.run(['lua',str(self.engine.parent/'dnspod-reader.lua'),'result',account,revision,'0',mode],input=body,capture_output=True,env=self.env,timeout=5);self.assertEqual((p.returncode,p.stderr),(rc,b''));self.assertEqual(p.stdout,raw if rc==0 else b'')
    def test_live_crypto_argv_and_environment_contain_no_private_material(self):
        self.migrated();real=self.base/'openssl-real';self.openssl_copy.rename(real);capture=self.base/'crypto-arguments.jsonl'
        self.openssl_copy.write_text('#!'+sys.executable+'\nimport json,os,sys\nwith open('+repr(str(capture))+',"a") as f:f.write(json.dumps([sys.argv,dict(os.environ)])+"\\n")\nos.execv('+repr(str(real))+',["openssl",*sys.argv[1:]])\n');self.openssl_copy.chmod(0o700)
        self.aliyun();raw=capture.read_bytes()
        for secret in [self.ali_key,self.ali_secret]:self.assertNotIn(secret,raw)
        rows=[json.loads(line) for line in raw.splitlines()];self.assertEqual(len(rows),10)
        for argv,env in rows:self.assertEqual(argv[1:],['dgst','-sha256','-binary'])
    def test_invalid_secret_id_rejected_after_bound_migration(self):
        self.source.write_bytes(self.source.read_bytes().replace(b'OLD_ID',b'BAD_ID/HEADER'));self.migrated();out=self.aliyun(expected=1);self.assertEqual(out['provider_code'],'invalid_credentials');self.assertEqual(self.calls,[])
    def test_live_curl_private_files_arguments_and_descriptors(self):
        self.migrated();self.delay=0.3
        p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        deadline=time.monotonic()+5;seen=False
        while not seen:
            for proc in Path('/proc').glob('[0-9]*/cmdline'):
                try:
                    argv=proc.read_bytes()
                    if argv.split(b'\0')[0]!=os.fsencode(self.curl):continue
                    environment=(proc.parent/'environ').read_bytes()
                    inherited=[]
                    for fd in range(3,10):
                        try:inherited.append(os.readlink(proc.parent/'fd'/str(fd)))
                        except FileNotFoundError:pass
                except (FileNotFoundError,ProcessLookupError,PermissionError):continue
                for secret in [self.ali_key,self.ali_secret]:self.assertNotIn(secret,argv+environment)
                for target in inherited:
                    for forbidden in ['frontend.lock','.supervisor.lock','sign-input','sign-output']:self.assertNotIn(forbidden,target)
                files=list(self.native.lockdir.glob('.dns-check-*/*'));self.assertEqual(len(files),6)
                for file in files:self.assertEqual((file.stat().st_mode&0o777,file.stat().st_nlink),(0o600,1))
                seen=True;break
            if not seen:self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.01)
        out,err=p.communicate(timeout=6);self.assertEqual((p.returncode,err),(0,b''));self.assertTrue(json.loads(out)['ok']);self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))

for name in ['test_missing_credentials_and_account_never_make_http','test_source_change_and_shared_lock_block_before_request','test_oversized_or_duplicate_json_never_authenticates','test_real_curl_timeout_is_bounded','test_redirect_never_forwards_signed_material','test_caller_loss_keeps_deadline_and_orphan_barrier','test_missing_openssl_stops_before_request']:
    setattr(Runtime,name,getattr(AliRuntime,name))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
