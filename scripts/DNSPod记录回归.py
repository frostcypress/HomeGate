#!/usr/bin/env python3
"""Configuration-bound DNSPod records against independently signed TLS fixtures."""
import argparse,copy,json,os,subprocess,time,unittest
from pathlib import Path
from DNSPod只读回归 import Runtime as ReadRuntime,authorization,PROTO
from Aliyun记录回归 import Runtime as AliRecordRuntime,VALUE

def record(n,typ='AAAA',rr='www',value='2001:db8::1',**extra):
    return {'RecordId':n,'Name':rr,'Type':typ,'Value':value,'TTL':600,'Line':'默认','LineId':'0','Status':'ENABLE','Weight':None,'Remark':'',**extra}

class Static(unittest.TestCase):
    def test_closed_record_gates_and_grammar(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()));lua=LuaRuntime()
        for n in ['homegate-dnspod-read.sh','homegate-dnspod-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh']:
            body=(PROTO/n).read_bytes();self.assertFalse(parser.parse(body).root_node.has_error,n);self.assertNotIn(b'\r',body);self.assertEqual(body.count(b'dnspod_records_enabled=false'),1)
        for n in ['dnspod-reader.lua','dnspod-records.lua']:lua.compile((PROTO/n).read_bytes())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_numeric_ids_and_distinct_detail_fields(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(unpack_returned_tuples=True);m=lua.execute((PROTO/'dnspod-records.lua').read_text());plan=lua.execute((PROTO/'cloudflare-record-plan.lua').read_text());c=lua.table_from({'rr':'www','type':'AAAA','value':'2001:db8::2','value_key':plan.ipv6('2001:db8::2')})
        self.assertIsNotNone(m.record(c,lua.table_from(record(1,Weight=4)),plan,False))
        for field,value in [('RecordId','1'),('RecordId',9007199254740992),('Value','bad'),('Status','BAD'),('LineId','bad\n'),('Weight',101)]:
            r=record(1,Weight=4);r[field]=value;self.assertIsNone(m.record(c,lua.table_from(r),plan,False),field)
        self.assertIsNone(m.record(c,lua.table_from(record(1,Weight=4)),plan,True))
    def test_canonical_result_bound_to_attempt_and_provider(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime();m=lua.execute((PROTO/'dnspod-records.lua').read_text());kinds=lua.table_from({'':True,'temporary':True});codes=lua.table_from({'invalid_receipt':True})
        for result,effect,count,marker,valid in [('created','confirmed',1,'HGDNPATTEMPT1\n',True),('unchanged','none',0,'',True),('created','confirmed',1,'',False),('updated','confirmed',2,'HGDNPATTEMPT1\n',False)]:
            raw=m.report('dns_a','3','',False,'',result,effect,count);d=json.loads(raw);out=m.validate(raw,lua.table_from(d),'dns_a','3','0',marker,kinds,codes);self.assertEqual(out is not None,valid)
        body=(PROTO/'dnspod-records.lua').read_text();self.assertLess(body.index("api.write(7,'HGDNPATTEMPT1"),body.index('local doc=api.fetch(params,action)'));self.assertNotIn('os.execute',body);self.assertIn('api.plan.bind(snapshot,account,revision,q)',body)

class Runtime(ReadRuntime):
    def setUp(self):
        super().setUp();self.db={};self.next_id=1000;self.hook=None
        for n in ['homegate-dnspod-read.sh','homegate-dnspod-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh']:
            p=self.engine.parent/n;s=p.read_text().replace('dnspod_records_enabled=false','dnspod_records_enabled=true').replace('dns_records_enabled=false','dns_records_enabled=true')
            if n=='homegate-service-observer-watchdog.sh':s=s.replace('action=cloudflare-check; budget=2','action=cloudflare-check; budget=8')
            p.write_text(s)
        from lupa.lua51 import LuaRuntime
        from project import ROOT
        self.encoder=LuaRuntime();self.codec=self.encoder.execute((ROOT/'project/luci/lua/luasrc/model/homegate/backup.lua').read_text());self.migrated();self.baseline=self.contents()
    encoded=AliRecordRuntime.encoded
    payload=AliRecordRuntime.payload
    txt=AliRecordRuntime.txt
    def add(self,*items):
        for r in items:self.db[r['RecordId']]=copy.deepcopy(r)
    def action(self,c):return {k.lower():v for k,v in c['headers'].items()}['x-tc-action']
    def mutations(self):return [c for c in self.calls if self.action(c) in ['CreateRecord','ModifyRecord','DeleteRecord']]
    def record_http(self,method,path,body):
        headers={k.lower():v for k,v in self.calls[-1]['headers'].items()};action=headers.get('x-tc-action')
        try:q=json.loads(body);expected=authorization(self.ali_key,self.ali_secret,body,int(headers['x-tc-timestamp']))
        except Exception:q={};expected='invalid'
        if method!='POST' or path!='/' or headers.get('authorization')!=expected or headers.get('x-tc-version')!='2021-03-23' or headers.get('content-type')!='application/json; charset=utf-8':
            self.signature_errors.append('signature mismatch');return 403,{'Response':{'Error':{'Code':'AuthFailure.SignatureFailure','Message':'SECRET_SENTINEL'}}}
        def ok(**kw):return 200,{'Response':{'RequestId':'fixture',**kw}}
        if self.hook:
            result=self.hook(action,q)
            if result is not None:return result
        if action=='DescribeDomainList':return ok(DomainCountInfo={'DomainTotal':0},DomainList=[])
        self.assertEqual(q['Domain'],'example.test');self.assertNotIn('DomainId',q)
        if action=='DescribeRecordList':
            self.assertEqual(set(q),{'Domain','Offset','Limit','ErrorOnEmpty'});items=list(self.db.values());return ok(RecordCountInfo={'TotalCount':len(items)},RecordList=copy.deepcopy(items[q['Offset']:q['Offset']+q['Limit']]))
        if action=='CreateRecord':
            self.next_id+=1;rid=self.next_id;self.db[rid]=record(rid,q['RecordType'],q['SubDomain'],q['Value'],TTL=q['TTL'],Line=q['RecordLine'],LineId=q['RecordLineId']);return ok(RecordId=rid)
        rid=q['RecordId'];r=self.db.get(rid)
        if r is None:return 400,{'Response':{'Error':{'Code':'InvalidParameter.RecordIdInvalid','Message':'SECRET_SENTINEL'}}}
        if action=='DescribeRecord':return ok(RecordInfo={'Id':rid,'SubDomain':r['Name'],'RecordType':r['Type'],'Value':r['Value'],'TTL':r['TTL'],'RecordLine':r['Line'],'RecordLineId':r['LineId'],'Enabled':1 if r['Status']=='ENABLE' else 0,'Weight':r['Weight'],'Remark':r['Remark']})
        if action=='ModifyRecord':
            r.update(Name=q['SubDomain'],Type=q['RecordType'],Value=q['Value'],TTL=q['TTL'],Line=q['RecordLine'],LineId=q['RecordLineId'],Weight=q.get('Weight'),Remark=q['Remark']);return ok()
        if action=='DeleteRecord':del self.db[rid];return ok()
        raise AssertionError('Unexpected action')
    def records(self,q=None,expected=0,raw=None,account='dns_a'):
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),account,'--records'],input=raw if raw is not None else self.encoded(q or self.payload()),env=self.env,capture_output=True,timeout=16)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr,self.signature_errors));out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        for secret in [b'SECRET_SENTINEL',b'OLD_ID',b'TXT_PRIVATE_VALUE',b'2001:db8::2']:self.assertNotIn(secret,p.stdout)
        if expected in [0,1]:self.assertEqual((out['provider'],out['check_scope']),('dnspod','record-operation'))
        self.assertEqual(self.contents(),self.baseline);return out
    def clean(self):self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')));self.writer()
    def uncertain(self,out,count=0):
        self.assertEqual((out['effect'],out['retryable'],out['reconciliation_required'],out['affected']),('unknown',False,True,count));dirs=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(dirs),1);self.assertEqual((dirs[0]/'attempt').read_bytes(),b'HGDNPATTEMPT1\n');self.records(expected=4);self.aliyun(expected=4);self.writer()
    def test_create_readback_and_unchanged(self):
        self.assertEqual(self.records()['result'],'created');self.assertEqual(self.records()['result'],'unchanged');self.assertEqual(len(self.mutations()),1);self.clean()
    def test_update_preserves_custom_line_weight_remark_and_unrelated(self):
        self.add(record(1,Line='百度',LineId='90=0',Weight=8,Remark='保留备注'),record(2,rr='other'));self.assertEqual(self.records()['result'],'updated');q=json.loads(self.mutations()[0]['body']);self.assertEqual((q['RecordLineId'],q['Weight'],q['Remark']),('90=0',8,'保留备注'));self.assertEqual(self.db[2]['Value'],'2001:db8::1');self.clean()
    def test_second_page_equivalent_value_prevents_write(self):
        self.add(*(record(i) for i in range(1,101)),record(101,value='2001:0DB8:0:0:0:0:0:0002'));self.assertEqual(self.records()['result'],'unchanged');self.assertEqual(self.mutations(),[]);self.assertEqual(len(self.calls),2);self.clean()
    def test_txt_create_and_exact_delete_preserve_other_challenges(self):
        self.add(record(1,'TXT','_acme-challenge','OTHER'),record(2,'TXT','other',VALUE));self.assertEqual(self.records(self.txt())['result'],'created');self.assertEqual(self.records(self.txt())['result'],'unchanged');self.assertEqual(self.records(self.txt(operation='delete'))['affected'],1);self.assertEqual(set(self.db),{1,2});self.clean()
    def test_exact_and_explicit_all_aaaa_delete(self):
        self.add(record(1),record(2,value='2001:db8::2'),record(3,rr='other'));self.records(self.payload(operation='delete'));self.assertEqual(set(self.db),{1,3});self.records(self.payload(operation='delete',value='',all=True));self.assertEqual(set(self.db),{3});self.clean()
    def test_later_page_failure_never_writes(self):
        self.add(*(record(i) for i in range(1,102)))
        self.hook=lambda a,q:(500,{'Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}) if a=='DescribeRecordList' and q['Offset']==100 else None
        self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_cross_page_total_change_never_writes(self):
        self.add(*(record(i) for i in range(1,102)))
        self.hook=lambda a,q:(200,{'Response':{'RequestId':'fixture','RecordCountInfo':{'TotalCount':102},'RecordList':[record(101)]}}) if a=='DescribeRecordList' and q['Offset']==100 else None
        self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_prewrite_detail_change_is_refused(self):
        self.add(record(1))
        def hook(a,q):
            if a=='DescribeRecord':self.db[1]['LineId']='9=0'
        self.hook=hook;self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_disabled_record_is_not_modified(self):
        self.add(record(1,Status='DISABLE'));self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_invalid_or_unsafe_numeric_id_refused(self):
        self.add(record(9007199254740992));self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_delete_without_effect_stays_unknown(self):
        self.add(record(1,value='2001:db8::2'));self.hook=lambda a,q:(200,{'Response':{'RequestId':'fixture'}}) if a=='DeleteRecord' else None;self.uncertain(self.records(self.payload(operation='delete'),1))
    def test_partial_delete_reports_confirmed_prefix_without_retry(self):
        self.add(record(1,value='2001:db8::2'),record(2,value='2001:db8::2'))
        self.hook=lambda a,q:(500,{'Response':{'Error':{'Code':'InternalError'}}}) if a=='DeleteRecord' and q['RecordId']==2 else None
        self.uncertain(self.records(self.payload(operation='delete'),1),1);self.assertEqual(set(self.db),{2})
    def test_missing_create_receipt_stays_unknown(self):
        self.hook=lambda a,q:(200,{'Response':{'RequestId':'fixture'}}) if a=='CreateRecord' else None;self.uncertain(self.records(expected=1))
    def test_delayed_post_create_detail_stays_unknown_without_write_retry(self):
        self.hook=lambda a,q:(400,{'Response':{'Error':{'Code':'InvalidParameter.RecordIdInvalid','Message':'not indexed'}}}) if a=='DescribeRecord' else None
        self.uncertain(self.records(expected=1));self.assertEqual(len(self.mutations()),1);self.assertEqual(len(self.db),1)
    def test_postwrite_wrong_value_never_confirms(self):
        def hook(a,q):
            if a=='DescribeRecord':self.db[q['RecordId']]['Value']='2001:db8::9'
        self.hook=hook;self.uncertain(self.records(expected=1))
    def test_closed_record_gate_ignores_environment(self):
        for n,code in [('homegate-dnspod-read.sh',2),('homegate-cloudflare-read.sh',2),('homegate-dnspod-worker.sh',7),('homegate-service-observer-watchdog.sh',7)]:
            p=self.engine.parent/n;raw=p.read_text();p.write_text(raw.replace('dnspod_records_enabled=true','dnspod_records_enabled=false'));self.env['dnspod_records_enabled']='true';self.records(expected=code);p.write_text(raw)
        self.assertEqual(self.calls,[]);self.clean()
    def test_cf_receipt_gate_cannot_capture_dnspod_operation(self):
        self.reader.write_text(self.reader.read_text().replace('dns_receipt_enabled=false','dns_receipt_enabled=true'));self.records(expected=2);self.assertEqual(self.calls,[]);self.clean()
    def test_real_tc3_txt_payload_and_crypto_argv_remain_private(self):
        real=self.base/'openssl-real';self.openssl_copy.rename(real);capture=self.base/'crypto-args'
        self.openssl_copy.write_text('#!'+__import__('sys').executable+'\nimport os,sys\nwith open('+repr(str(capture))+',"ab") as f:f.write(repr([sys.argv,dict(os.environ)]).encode()+b"\\n")\nos.execv('+repr(str(real))+',["openssl",*sys.argv[1:]])\n');self.openssl_copy.chmod(0o700)
        self.records(self.txt());raw=capture.read_bytes()
        for secret in [b'OLD_ID',b'SECRET_SENTINEL',b'TXT_PRIVATE_VALUE']:self.assertNotIn(secret,raw)
        self.assertEqual(self.signature_errors,[]);self.clean()
    def test_unfinished_operation_input_is_supervised(self):
        p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a','--records'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env);self.processes.append(p);p.stdin.write(b'{');p.stdin.flush()
        p.wait(timeout=12);p.stdin.close();p.stdin=None;out,err=p.communicate(timeout=3);self.assertNotEqual(p.returncode,0);self.assertIn(err,[b'',b'Killed\n']);self.assertEqual(self.mutations(),[]);self.clean()
    def test_caller_loss_after_applied_create_keeps_original_unknown_evidence(self):
        import threading
        applied=threading.Event()
        def hook(a,q):
            if a=='CreateRecord':
                self.db[5000]=record(5000,q['RecordType'],q['SubDomain'],q['Value']);self.delay=2;applied.set();return 200,{'Response':{'RequestId':'fixture','RecordId':5000}}
        self.hook=hook;p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a','--records'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env);self.processes.append(p)
        p.stdin.write(self.encoded(self.payload()));p.stdin.close();p.stdin=None;self.assertTrue(applied.wait(6));p.kill();p.communicate(timeout=3)
        time.sleep(2);self.assertIn(5000,self.db);dirs=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(dirs),1);self.assertEqual((dirs[0]/'attempt').read_bytes(),b'HGDNPATTEMPT1\n');self.records(expected=4);self.writer()
    test_invalid_input_resource_account_and_all_are_rejected_before_http=AliRecordRuntime.test_invalid_input_resource_account_and_all_are_rejected_before_http

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
