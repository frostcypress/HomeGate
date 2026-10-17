#!/usr/bin/env python3
"""Configuration-bound Huawei v2 recordsets against independently signed TLS."""
import argparse,copy,json,os,subprocess,sys,time,unittest
from urllib.parse import parse_qs,urlsplit
from 华为云只读回归 import Runtime as ReadRuntime,Static as ReadStatic,authorization,DOMAIN,HOST,PROTO
from Aliyun记录回归 import Runtime as AliRecordRuntime,VALUE

def record(n,typ='AAAA',name='www.example.test.',values=None,**extra):
    return {'id':str(n),'zone_id':'zone_1','name':name,'type':typ,'ttl':600,'description':'','status':'ACTIVE','default':False,'records':values or ['2001:db8::1'],**extra}

class Static(unittest.TestCase):
    def test_closed_gates_shell_and_lua(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()));lua=LuaRuntime()
        for n in ['homegate-huaweicloud-read.sh','homegate-huaweicloud-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh']:
            b=(PROTO/n).read_bytes();self.assertNotIn(b'\r',b);self.assertFalse(parser.parse(b).root_node.has_error,n);self.assertEqual(b.count(b'huaweicloud_records_enabled=false'),1)
        for n in ['huaweicloud-reader.lua','huaweicloud-records.lua','cloudflare-codec.lua']:lua.compile((PROTO/n).read_bytes())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_txt_quoted_segments_round_trip_and_refuse_ambiguous_escapes(self):
        from lupa.lua51 import LuaRuntime
        m=LuaRuntime().execute((PROTO/'huaweicloud-records.lua').read_text())
        for value in ['',VALUE,'x'*255,'x'*256,'x'*4096]:self.assertEqual(m.txt(m.quote(value)),value)
        self.assertEqual(m.txt('"a" "b"'),'ab');self.assertEqual(m.txt('RAW'),'RAW')
        for value in ['"unfinished','"bad\\q"','"x"  "y"','"x" ','"'+('x'*256)+'"']:self.assertIsNone(m.txt(value),value)
    def test_record_shape_and_invalid_ipv6_are_rejected(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime();m=lua.execute((PROTO/'huaweicloud-records.lua').read_text());plan=lua.execute((PROTO/'cloudflare-record-plan.lua').read_text())
        c=lua.table_from({'zone_id':'zone_1','fqdn':'www.example.test','type':'AAAA','value_key':plan.ipv6('2001:db8::2')})
        shape=lua.table_from({'children':{'records':{'kind':'array','length':1}}},recursive=True)
        self.assertIsNotNone(m.record(c,lua.table_from(record(1),recursive=True),plan,shape))
        for key,value in [('records',['BAD']),('records',{}),('zone_id','other'),('weight',3),('default','false')]:
            r=record(1);r[key]=value;self.assertIsNone(m.record(c,lua.table_from(r,recursive=True),plan,shape),key)
    def test_method_path_and_body_signature_match_independent_python(self):
        _,m=ReadStatic().library()
        for method,path,payload in [(b'GET',b'/v2/zones/zone_1/recordsets',b''),(b'POST',b'/v2/zones/zone_1/recordsets',b'{"records":["x"]}'),(b'PUT',b'/v2/zones/zone_1/recordsets/1',VALUE.encode()),(b'DELETE',b'/v2/zones/zone_1/recordsets/1',b'')]:
            stamp=b'20261016T010203Z'
            self.assertEqual(m.authorization(b'OLD_ID',b'k',DOMAIN,b'',stamp,lambda s:__import__('hashlib').sha256(s).digest(),method,path,payload),authorization(b'OLD_ID',b'k',DOMAIN,b'',stamp,method,path,payload))
    def test_canonical_result_original_attempt_and_marker_order(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime();m=lua.execute((PROTO/'huaweicloud-records.lua').read_text());kinds=lua.table_from({'':True,'temporary':True});codes=lua.table_from({'invalid_receipt':True})
        for result,effect,count,marker,valid in [('created','confirmed',1,'HGHWATTEMPT1\n',True),('deleted','confirmed',2,'HGHWATTEMPT1\n',True),('unchanged','none',0,'',True),('created','confirmed',1,'',False),('updated','confirmed',2,'HGHWATTEMPT1\n',False)]:
            raw=m.report('dns_a','3','',False,'',result,effect,count);self.assertEqual(m.validate(raw,lua.table_from(json.loads(raw)),'dns_a','3','0',marker,kinds,codes) is not None,valid)
        body=(PROTO/'huaweicloud-records.lua').read_text();self.assertLess(body.index("api.write(7,'HGHWATTEMPT1"),body.index('local d,s=api.fetch(method,target'))
        self.assertNotIn('os.execute',body);self.assertIn('api.plan.bind(snapshot,account,revision,q)',body)

class Runtime(ReadRuntime):
    def setUp(self):
        super().setUp();self.db={};self.next_id=1000;self.hook=None
        # The shared loopback handler predates Huawei and has no PUT method.
        self.server.RequestHandlerClass.do_PUT=lambda handler:handler.reply('PUT')
        for n in ['homegate-huaweicloud-read.sh','homegate-huaweicloud-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh']:
            p=self.engine.parent/n;s=p.read_text().replace('huaweicloud_records_enabled=false','huaweicloud_records_enabled=true').replace('dns_records_enabled=false','dns_records_enabled=true')
            if n=='homegate-service-observer-watchdog.sh':s=s.replace('action=cloudflare-check; budget=2','action=cloudflare-check; budget=8')
            p.write_text(s)
        from lupa.lua51 import LuaRuntime
        self.encoder=LuaRuntime();self.codec=self.encoder.execute((PROTO.parent.parent/'luci/lua/luasrc/model/homegate/backup.lua').read_text())
        self.migrated();self.baseline=self.contents()
    encoded=AliRecordRuntime.encoded
    payload=AliRecordRuntime.payload
    txt=AliRecordRuntime.txt
    def add(self,*items):
        for r in items:self.db[r['id']]=copy.deepcopy(r)
    def mutations(self):return [x for x in self.calls if x['method'] in ['POST','PUT','DELETE']]
    def record_http(self,method,path,body):
        u=urlsplit(path);q=parse_qs(u.query,keep_blank_values=True);h={k.lower():v for k,v in self.calls[-1]['headers'].items()}
        expected=authorization(self.ali_key,self.ali_secret,DOMAIN,u.query.encode(),h.get('x-sdk-date','').encode(),method.encode(),u.path.encode(),body).decode()
        if h.get('authorization')!=expected or h.get('host')!=HOST or h.get('x-domain-id')!=DOMAIN.decode() or h.get('content-type')!='application/json':self.signature_errors.append('signature mismatch');return 403,{'code':'bad-signature'}
        data=json.loads(body) if body else None
        if self.hook:
            result=self.hook(method,u.path,q,data)
            if result is not None:return result
        if u.path=='/v2/zones':return 200,{'zones':[{'id':'zone_1','name':'example.test.','zone_type':'public','status':'ACTIVE'}],'metadata':{'total_count':1}}
        prefix='/v2/zones/zone_1/recordsets';self.assertTrue(u.path==prefix or u.path.startswith(prefix+'/'))
        if method=='GET' and u.path==prefix:
            self.assertEqual(set(q),{'limit','offset'});items=list(self.db.values());start=int(q['offset'][0]);return 200,{'recordsets':copy.deepcopy(items[start:start+int(q['limit'][0])]),'metadata':{'total_count':len(items)}}
        if method=='POST':
            self.assertEqual(u.path,prefix);self.next_id+=1;r=record(self.next_id,data['type'],data['name'],data['records'],ttl=data['ttl'],description=data['description']);self.db[r['id']]=r;out=copy.deepcopy(r);out['status']='PENDING_CREATE';return 202,out
        rid=u.path[len(prefix)+1:];r=self.db.get(rid)
        if r is None:return 404,{'code':'not-found'}
        if method=='GET':return 200,copy.deepcopy(r)
        if method=='PUT':r.update(data);out=copy.deepcopy(r);out['status']='PENDING_UPDATE';return 202,out
        if method=='DELETE':out=copy.deepcopy(r);out['status']='PENDING_DELETE';del self.db[rid];return 202,out
        raise AssertionError('Unexpected method')
    def records(self,q=None,expected=0,raw=None,account='dns_a'):
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),account,'--records'],input=raw if raw is not None else self.encoded(q or self.payload()),env=self.env,capture_output=True,timeout=20)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr,self.signature_errors));out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        for value in [b'SECRET_SENTINEL',b'OLD_ID',b'TXT_PRIVATE_VALUE',b'2001:db8::2',DOMAIN]:self.assertNotIn(value,p.stdout)
        if expected in [0,1]:self.assertEqual((out['provider'],out['check_scope']),('huaweicloud','record-operation'))
        self.assertEqual(self.contents(),self.baseline);return out
    def clean(self):self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')));self.writer()
    def uncertain(self,out,count=0):
        self.assertEqual((out['effect'],out['retryable'],out['reconciliation_required'],out['affected']),('unknown',False,True,count));dirs=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(dirs),1);self.assertEqual((dirs[0]/'attempt').read_bytes(),b'HGHWATTEMPT1\n');self.records(expected=4);self.aliyun(expected=4);self.writer()
    def test_create_active_readback_then_unchanged(self):
        self.assertEqual(self.records()['result'],'created');self.assertEqual(self.records()['result'],'unchanged');self.assertEqual(len(self.mutations()),1);self.clean()
    def test_aaaa_update_first_set_and_preserve_other_sets(self):
        self.add(record(1,values=['2001:db8::1','2001:db8::9'],description='keep'),record(2,values=['2001:db8::8']),record(3,name='other.example.test.'))
        self.assertEqual(self.records()['result'],'updated');self.assertEqual(self.db['1']['records'],['2001:db8::2']);self.assertEqual(self.db['1']['description'],'keep');self.assertEqual(self.db['2']['records'],['2001:db8::8']);self.clean()
    def test_txt_append_and_exact_cleanup_preserve_other_bytes_and_ttl(self):
        self.add(record(1,'TXT','_acme-challenge.example.test.',['"OTHER"'],ttl=300,description='keep'))
        self.assertEqual(self.records(self.txt())['result'],'created');self.assertEqual(self.records(self.txt())['result'],'unchanged');self.assertEqual(self.db['1']['records'][0],'"OTHER"');self.assertEqual(self.db['1']['ttl'],300)
        self.records(self.txt(operation='delete'));self.assertEqual((self.db['1']['records'],self.db['1']['ttl'],self.db['1']['description']),(['"OTHER"'],300,'keep'));self.clean()
    def test_segmented_txt_equivalence_never_writes(self):
        self.add(record(1,'TXT','_acme-challenge.example.test.',['"abc" "def"']));self.assertEqual(self.records(self.txt(value='abcdef'))['result'],'unchanged');self.assertEqual(self.mutations(),[]);self.clean()
    def test_exact_aaaa_delete_keeps_other_values_then_explicit_all(self):
        self.add(record(1,values=['2001:db8::1','2001:0db8:0:0:0:0:0:2']),record(2,name='other.example.test.'))
        self.records(self.payload(operation='delete'));self.assertEqual(self.db['1']['records'],['2001:db8::1']);self.records(self.payload(operation='delete',value='',all=True));self.assertEqual(set(self.db),{'2'});self.clean()
    def test_equivalent_value_on_later_page_never_writes(self):
        self.add(*(record(i,name=f'other{i}.example.test.') for i in range(1,101)),record(101,values=['2001:0db8:0:0:0:0:0:2']));self.assertEqual(self.records()['result'],'unchanged');self.assertEqual(self.mutations(),[]);self.clean()
    def test_later_page_error_never_writes(self):
        self.add(*(record(i) for i in range(1,102)));self.hook=lambda m,p,q,d:(500,{'code':'busy'}) if p.endswith('/recordsets') and q.get('offset')==['100'] else None
        self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_prewrite_detail_change_is_refused(self):
        self.add(record(1));self.hook=lambda m,p,q,d:(200,record(1,description='changed')) if p.endswith('/1') else None
        self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_default_pending_and_unsupported_line_refused(self):
        for extra in [{'default':True},{'status':'PENDING_UPDATE'},{'weight':5}]:
            self.db={};self.add(record(1,**extra));self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_missing_and_ambiguous_zone_refused(self):
        for zones in [[],[{'id':str(i),'name':'example.test.','zone_type':'public','status':'ACTIVE'} for i in [1,2]]]:
            self.hook=lambda m,p,q,d:(200,{'zones':zones,'metadata':{'total_count':len(zones)}}) if p=='/v2/zones' else None;self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_null_and_object_record_value_arrays_refused(self):
        for values in [['2001:db8::1',None],[None,'2001:db8::1'],{}]:
            r=record(1);r['records']=values;self.db={};self.add(r);self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_duplicate_id_or_total_drift_never_writes(self):
        self.add(*(record(i) for i in range(1,102)))
        for count,item in [(101,record(1)),(102,record(101))]:
            self.hook=lambda m,p,q,d:(200,{'recordsets':[item],'metadata':{'total_count':count}}) if p.endswith('/recordsets') and q.get('offset')==['100'] else None;self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_accepted_but_still_pending_never_confirms(self):
        self.hook=lambda m,p,q,d:(200,record(1001,values=['2001:db8::2'],status='PENDING_CREATE')) if p.endswith('/1001') else None;self.uncertain(self.records(expected=1));self.assertEqual(len(self.mutations()),1)
    def test_missing_create_receipt_stays_unknown(self):
        self.hook=lambda m,p,q,d:(202,{}) if m=='POST' else None;self.uncertain(self.records(expected=1))
    def test_wrong_postwrite_value_stays_unknown(self):
        self.hook=lambda m,p,q,d:(200,record(1001,values=['2001:db8::9'])) if p.endswith('/1001') else None;self.uncertain(self.records(expected=1))
    def test_delete_without_effect_stays_unknown(self):
        self.add(record(1,values=['2001:db8::2']));self.hook=lambda m,p,q,d:(202,record(1,values=['2001:db8::2'],status='PENDING_DELETE')) if m=='DELETE' else None;self.uncertain(self.records(self.payload(operation='delete'),1))
    def test_partial_delete_keeps_confirmed_prefix_and_never_retries(self):
        self.add(record(1,values=['2001:db8::2']),record(2,values=['2001:db8::2']));self.hook=lambda m,p,q,d:(500,{'code':'busy'}) if m=='DELETE' and p.endswith('/2') else None
        self.uncertain(self.records(self.payload(operation='delete'),1),1);self.assertEqual(set(self.db),{'2'})
    def test_record_gates_ignore_environment_and_cf_receipt_is_refused(self):
        for n,expected in [('homegate-huaweicloud-read.sh',2),('homegate-cloudflare-read.sh',2),('homegate-huaweicloud-worker.sh',7),('homegate-service-observer-watchdog.sh',7)]:
            p=self.engine.parent/n;raw=p.read_text();p.write_text(raw.replace('huaweicloud_records_enabled=true','huaweicloud_records_enabled=false'));self.env['huaweicloud_records_enabled']='true';self.records(expected=expected);p.write_text(raw)
        self.reader.write_text(self.reader.read_text().replace('dns_receipt_enabled=false','dns_receipt_enabled=true'));self.records(expected=2);self.assertEqual(self.calls,[]);self.clean()
    def test_real_signed_txt_payload_keeps_crypto_arguments_private(self):
        real=self.base/'openssl-real';self.openssl_copy.rename(real);capture=self.base/'crypto-args'
        self.openssl_copy.write_text('#!'+sys.executable+'\nimport os,sys\nwith open('+repr(str(capture))+',"ab") as f:f.write(repr([sys.argv,dict(os.environ)]).encode()+b"\\n")\nos.execv('+repr(str(real))+',["openssl",*sys.argv[1:]])\n');self.openssl_copy.chmod(0o700)
        self.records(self.txt());raw=capture.read_bytes()
        for value in [b'OLD_ID',b'SECRET_SENTINEL',b'TXT_PRIVATE_VALUE',DOMAIN]:self.assertNotIn(value,raw)
        self.assertEqual(self.signature_errors,[]);self.clean()
    def test_unfinished_input_is_independently_supervised(self):
        p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a','--records'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env);self.processes.append(p);p.stdin.write(b'{');p.stdin.flush();p.wait(timeout=12);p.stdin.close();p.stdin=None;out,err=p.communicate(timeout=3);self.assertNotEqual(p.returncode,0);self.assertIn(err,[b'',b'Killed\n']);self.assertEqual(self.mutations(),[]);self.clean()
    def test_caller_loss_after_applied_create_keeps_unknown_marker(self):
        import threading
        applied=threading.Event()
        def hook(m,p,q,d):
            if m=='POST':self.db['5000']=record(5000,values=d['records']);self.delay=2;applied.set();return 202,self.db['5000']
        self.hook=hook;p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a','--records'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env);self.processes.append(p);p.stdin.write(self.encoded(self.payload()));p.stdin.close();p.stdin=None;self.assertTrue(applied.wait(7));p.kill();p.communicate(timeout=3);time.sleep(2)
        self.assertIn('5000',self.db);dirs=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(dirs),1);self.assertEqual((dirs[0]/'attempt').read_bytes(),b'HGHWATTEMPT1\n');self.records(expected=4)
    test_invalid_input_resource_account_and_all_are_rejected_before_http=AliRecordRuntime.test_invalid_input_resource_account_and_all_are_rejected_before_http

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
