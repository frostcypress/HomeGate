#!/usr/bin/env python3
"""Independent SDK-HMAC-SHA256 and real local TLS; no cloud accounts."""
import argparse,hashlib,hmac,json,os,re,subprocess,sys,time,unittest
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from Aliyun只读回归 import Runtime as AliRuntime,PROTO
from DNSPod只读回归 import Runtime as DNSPodRuntime

HOST='dns.cn-north-4.myhuaweicloud.com'
ORIGIN='https://'+HOST
DOMAIN=b'1'*32
def authorization(key_id,key,domain,query,date,method=b'GET',path=b'/v2/zones',payload=b''):
    headers=b'content-type:application/json\nhost:'+HOST.encode()+b'\nx-domain-id:'+domain+b'\nx-sdk-date:'+date+b'\n'
    names=b'content-type;host;x-domain-id;x-sdk-date'
    canonical=method+b'\n'+path.rstrip(b'/')+b'/\n'+query+b'\n'+headers+b'\n'+names+b'\n'+hashlib.sha256(payload).hexdigest().encode()
    text=b'SDK-HMAC-SHA256\n'+date+b'\n'+hashlib.sha256(canonical).hexdigest().encode()
    return b'SDK-HMAC-SHA256 Access='+key_id+b', SignedHeaders='+names+b', Signature='+hmac.new(key,text,hashlib.sha256).hexdigest().encode()

class Static(unittest.TestCase):
    def library(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(encoding=None);lua.globals().ali_body=(PROTO/'aliyun-reader.lua').read_bytes()
        lua.execute(b"arg={[0]='/fixture/huaweicloud-reader.lua'};loadfile=function(p) if p:match('aliyun%-reader.lua$') then return assert(loadstring(ali_body)) end;return function()return {}end end")
        return lua,lua.execute((PROTO/'huaweicloud-reader.lua').read_bytes(),b'library')
    def test_closed_gates_shell_lua_and_no_production_install(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        LuaRuntime().compile((PROTO/'huaweicloud-reader.lua').read_bytes());parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name,gate in [('homegate-huaweicloud-read.sh','huaweicloud_entry_enabled'),('homegate-huaweicloud-worker.sh','huaweicloud_read_enabled'),('homegate-cloudflare-read.sh','huaweicloud_read_enabled'),('homegate-service-observer-watchdog.sh','huaweicloud_read_enabled')]:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error,name);self.assertEqual(body.count((gate+'=false').encode()),1)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_signature_against_independent_hashlib_and_long_keys(self):
        _,m=self.library()
        for key in [b'k',b'x'*64,b'x'*80,b'x'*4096]:
            for date in [b'19700101T000000Z',b'20260331T235959Z',b'20260401T000000Z']:
                query=b'limit=100&offset=0&type=public'
                self.assertEqual(m.authorization(b'OLD_ID',key,DOMAIN,query,date,lambda s:hashlib.sha256(s).digest()),authorization(b'OLD_ID',key,DOMAIN,query,date))
    def test_exact_endpoint_allowlist(self):
        _,m=self.library()
        for value in [ORIGIN,ORIGIN+'/']:self.assertEqual(m.endpoint(value.encode()),HOST.encode())
        for value in ['',ORIGIN+':443',ORIGIN+'/v2',ORIGIN+'?x=1',ORIGIN+'#x','http://'+HOST,'https://127.0.0.1','https://user@'+HOST,ORIGIN+'.evil.test',ORIGIN.upper()]:self.assertIsNone(m.endpoint(value.encode()),value)
    def test_crypto_transport_and_read_only_scope(self):
        body=(PROTO/'huaweicloud-reader.lua').read_text()
        for forbidden in ['-hmac','-macopt','--insecure','--location','--retry','os.getenv','doc.links.next']:self.assertNotIn(forbidden,body)
        self.assertIn('openssl dgst -sha256 -binary < /proc/self/fd/8',body);self.assertIn("method=method or 'GET'",body)
        self.assertIn("if mode=='records' or mode=='reconcile' then\n        valid=",body)
        self.assertIn("if mode=='reconcile' and method~='GET' then valid=false end",body)
        self.assertIn("mode~='check' and mode~='zones'",body)

class Runtime(AliRuntime):
    def setUp(self):
        super().setUp();self.source.write_bytes(self.source.read_bytes().replace(b"provider 'aliyun'",b"provider 'huaweicloud'").replace(b'PRIVATE_ACCOUNT',DOMAIN).replace(b'https://api.test/private-token',ORIGIN.encode()));self.capture_headers=True
        self.total=2;self.response=None
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/usr/bin/curl':str(self.curl),'/usr/bin/openssl':str(self.openssl_copy),'/etc/ssl/certs/ca-certificates.crt':str(self.ca_dir/'ca.pem')}
        for name in ['homegate-huaweicloud-read.sh','homegate-huaweicloud-worker.sh','huaweicloud-reader.lua']:
            p=self.engine.parent/name;body=p.read_text().replace('huaweicloud_entry_enabled=false','huaweicloud_entry_enabled=true').replace('huaweicloud_read_enabled=false','huaweicloud_read_enabled=true')
            body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body);body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))
            for before,after in [('= 0:700 ]','= '+str(os.getuid())+':700 ]'),('= 0:600:1 ]','= '+str(os.getuid())+':600:1 ]'),('in 0:700:1|0:755:1)','in '+str(os.getuid())+':700:1|'+str(os.getuid())+':755:1)')]:body=body.replace(before,after)
            if name.endswith('.lua'):body=body.replace("local origin='"+ORIGIN+"'","local origin='https://127.0.0.1:"+str(self.server.server_port)+"'").replace('--max-time 10','--max-time 0.5')
            p.write_text(body)
        for p in [self.reader,self.engine.parent/'homegate-service-observer-watchdog.sh']:p.write_text(p.read_text().replace('huaweicloud_read_enabled=false','huaweicloud_read_enabled=true'))
        self.ali_entry=self.engine.parent/'homegate-huaweicloud-read.sh'
    def response_page(self,offset,limit,total=None,items=None):
        total=self.total if total is None else total
        if items is None:items=[{'id':str(n+1),'name':f'z{n:05d}.example.test.','zone_type':'public'} for n in range(offset,min(offset+limit,total))]
        return {'zones':items,'metadata':{'total_count':total},'links':{'next':'https://evil.test/never-follow'}}
    def record_http(self,method,path,body):
        h={k.lower():v for k,v in self.calls[-1]['headers'].items()};u=urlsplit(path);q=parse_qs(u.query,keep_blank_values=True);date=h.get('x-sdk-date','')
        expected=authorization(self.ali_key,self.ali_secret,DOMAIN,u.query.encode(),date.encode()).decode()
        valid=method=='GET' and u.path=='/v2/zones' and body==b'' and h.get('host')==HOST and h.get('content-type')=='application/json' and h.get('x-domain-id')==DOMAIN.decode() and re.fullmatch(r'\d{8}T\d{6}Z',date) and h.get('authorization')==expected and set(q)=={'type','offset','limit'} and q['type']==['public'] and all(len(v)==1 for v in q.values())
        if not valid:self.signature_errors.append('signature mismatch');return 403,{'code':'bad-signature','message':'SECRET_SENTINEL'}
        if callable(self.response):return self.response(q)
        if self.response is not None:return self.http_status,self.response
        return 200,self.response_page(int(q['offset'][0]),int(q['limit'][0]))
    def test_real_signature_source_bound_credentials_and_no_store_change(self):
        self.migrated();before=self.contents();out=self.aliyun();self.assertEqual(out['provider'],'huaweicloud');self.assertTrue(out['credentials_valid']);self.assertEqual(self.signature_errors,[]);self.assertEqual(len(self.calls),1);self.assertEqual(self.contents(),before);self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))
    def test_complete_offset_pages_sorted_without_following_links(self):
        self.total=203;self.migrated();out=self.aliyun('--zones');self.assertEqual(len(out['zones']),203);self.assertEqual(out['zones'],sorted(out['zones']));self.assertEqual([parse_qs(urlsplit(c['path']).query)['offset'] for c in self.calls],[['0'],['100'],['200']]);self.assertEqual(self.signature_errors,[])
    def test_empty_array_and_wrong_container_types(self):
        self.total=0;self.migrated();self.assertEqual(self.aliyun('--zones')['zones'],[])
        for value in [{},None,'']:
            self.response=self.response_page(0,100,items=[]);self.response['zones']=value;self.aliyun('--zones',1)
    def test_later_error_hides_partial_list_and_private_message(self):
        self.total=150;self.migrated();self.response=lambda q:(403,{'code':'not-allowed','message':'OLD_ID SECRET_SENTINEL'}) if q['offset']!=['0'] else (200,self.response_page(0,100))
        out=self.aliyun('--zones',1);self.assertEqual((out['zones'],out['error_kind']),([],'authentication'));self.assertEqual(len(self.calls),2)
    def test_changed_count_empty_page_bad_name_and_private_zone_refused(self):
        self.total=150;self.migrated();self.response=lambda q:(200,self.response_page(int(q['offset'][0]),100,total=151 if q['offset']!=['0'] else 150,items=[] if q['offset']!=['0'] else None));self.assertEqual(self.aliyun('--zones',1)['zones'],[])
        for row in [{'id':'1','name':'bad..test','zone_type':'public'},{'id':'1','name':'例子.测试','zone_type':'public'},{'id':'1','name':'a.test','zone_type':'private'},{'id':'bad/id','name':'a.test','zone_type':'public'}]:
            self.response=self.response_page(0,100,total=1,items=[row]);self.aliyun('--zones',1)
    def test_normalized_ascii_punycode_and_duplicates(self):
        self.migrated();self.response=self.response_page(0,100,total=3,items=[{'id':str(i),'name':name,'zone_type':'public'} for i,name in enumerate([' A.Example.Test. ','a.example.test','xn--fsqu00a.xn--0zwm56d.'],1)]);self.assertEqual(self.aliyun('--zones')['zones'],['a.example.test','xn--fsqu00a.xn--0zwm56d'])
    def test_error_status_classification_and_unknown_code_redaction(self):
        self.migrated()
        for status,kind,retry in [(403,'authentication',False),(429,'rate_limit',True),(500,'temporary',True),(400,'invalid_request',False),(200,'invalid_request',False)]:
            self.http_status=status;self.response={'code':'SECRET_SENTINEL','message':'OLD_ID SECRET_SENTINEL'};out=self.aliyun(expected=1);self.assertEqual((out['error_kind'],out['retryable'],out['provider_code']),(kind,retry,'provider_rejected'))
    def test_long_hmac_secret_and_invalid_key_id(self):
        self.ali_secret=b'x'*80+b' +*~';self.source.write_bytes(self.source.read_bytes().replace(b'SECRET_SENTINEL',self.ali_secret));self.migrated();self.aliyun();self.assertEqual(self.signature_errors,[])
    def test_invalid_key_id_refused_before_http(self):
        self.source.write_bytes(self.source.read_bytes().replace(b'OLD_ID',b'BAD_ID/HEADER'));self.migrated();self.assertEqual(self.aliyun(expected=1)['provider_code'],'invalid_credentials');self.assertEqual(self.calls,[])
    def test_invalid_domain_id_refused_before_http(self):
        self.source.write_bytes(self.source.read_bytes().replace(DOMAIN,b'BAD_DOMAIN'));self.migrated();self.assertEqual(self.aliyun(expected=1)['provider_code'],'invalid_credentials');self.assertEqual(self.calls,[])
    def test_arbitrary_endpoint_refused_before_http(self):
        self.source.write_bytes(self.source.read_bytes().replace(ORIGIN.encode(),b'https://user:password@127.0.0.1/private'));self.migrated();self.assertEqual(self.aliyun(expected=1)['provider_code'],'unsupported_endpoint');self.assertEqual(self.calls,[])
    def test_write_modes_and_four_closed_gates_ignore_environment(self):
        self.migrated()
        for mode in ['--records','--migrated','--reconcile','--collect-receipt','--store']:self.aliyun(mode,2)
        for p,gate,rc in [(self.ali_entry,'huaweicloud_entry_enabled',2),(self.reader,'huaweicloud_read_enabled',2),(self.engine.parent/'homegate-service-observer-watchdog.sh','huaweicloud_read_enabled',7),(self.engine.parent/'homegate-huaweicloud-worker.sh','huaweicloud_read_enabled',7)]:
            raw=p.read_text();p.write_text(raw.replace(gate+'=true',gate+'=false'));self.aliyun(expected=rc,env={**self.env,gate:'true'});p.write_text(raw)
        self.assertEqual(self.calls,[])
    def test_result_scope_account_revision_and_raw_frame_revalidated(self):
        self.migrated();out=self.aliyun();raw=(json.dumps(out,separators=(',',':'))+'\n').encode()
        for account,revision,mode,body,rc in [('dns_a','3','check',raw,0),('other','3','check',raw,1),('dns_a','2','check',raw,1),('dns_a','3','zones',raw,1),('dns_a','3','check',raw+b' ',1)]:
            p=subprocess.run(['lua',str(self.engine.parent/'huaweicloud-reader.lua'),'result',account,revision,'0',mode],input=body,capture_output=True,env=self.env,timeout=5);self.assertEqual((p.returncode,p.stderr),(rc,b''));self.assertEqual(p.stdout,raw if rc==0 else b'')
    def test_crypto_argv_environment_and_private_transport_descriptors(self):
        self.migrated();real=self.base/'openssl-real';self.openssl_copy.rename(real);capture=self.base/'crypto-arguments.jsonl'
        self.openssl_copy.write_text('#!'+sys.executable+'\nimport json,os,sys\nwith open('+repr(str(capture))+',"a") as f:f.write(json.dumps([sys.argv,dict(os.environ)])+"\\n")\nos.execv('+repr(str(real))+',["openssl",*sys.argv[1:]])\n');self.openssl_copy.chmod(0o700)
        self.aliyun();raw=capture.read_bytes()
        for value in [self.ali_key,self.ali_secret,DOMAIN]:self.assertNotIn(value,raw)
        rows=[json.loads(v) for v in raw.splitlines()];self.assertEqual(len(rows),4)
        for argv,env in rows:self.assertEqual(argv[1:],['dgst','-sha256','-binary'])
    def test_repeated_page_ids_never_hide_missing_zones(self):
        self.total=101;self.migrated();self.response=lambda q:(200,self.response_page(int(q['offset'][0]),100,items=[{'id':'1','name':'repeated.example.test','zone_type':'public'}] if q['offset']!=['0'] else None))
        out=self.aliyun('--zones',1);self.assertEqual((out['zones'],out['provider_code']),([],'pagination_changed'))
    test_live_curl_private_files_arguments_and_descriptors=DNSPodRuntime.test_live_curl_private_files_arguments_and_descriptors

for name in ['test_missing_credentials_and_account_never_make_http','test_source_change_and_shared_lock_block_before_request','test_oversized_or_duplicate_json_never_authenticates','test_real_curl_timeout_is_bounded','test_redirect_never_forwards_signed_material','test_caller_loss_keeps_deadline_and_orphan_barrier','test_missing_openssl_stops_before_request']:
    setattr(Runtime,name,getattr(AliRuntime,name))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
