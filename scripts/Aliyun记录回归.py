#!/usr/bin/env python3
"""AliDNS record operations against a disposable, independently signed TLS API."""
import argparse,base64,copy,hashlib,hmac,json,os,subprocess,time,unittest
from pathlib import Path
from urllib.parse import parse_qs,quote,urlsplit
from project import ROOT
from Aliyun只读回归 import Runtime as ReadRuntime

PROTO=ROOT/'project/core/prototype'
VALUE='TXT_PRIVATE_VALUE +*~/%\\";$(false)'

def record(n,typ='AAAA',rr='www',value='2001:db8::1',**extra):
    return {'RecordId':str(n),'DomainName':'example.test','RR':rr,'Type':typ,'Value':value,'TTL':600,'Line':'default','Locked':False,'Status':'Enable',**extra}

class Static(unittest.TestCase):
    def test_closed_record_gates_and_shell_grammar(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-aliyun-read.sh','homegate-aliyun-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh']:
            b=(PROTO/n).read_bytes();self.assertNotIn(b'\r',b);self.assertFalse(parser.parse(b).root_node.has_error,n)
            self.assertEqual(b.count(b'aliyun_records_enabled=false'),1);self.assertNotIn(b'aliyun_records_enabled=true',b)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_lua_syntax_pure_operation_and_existing_snapshot_binding(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime()
        for n in ['aliyun-reader.lua','aliyun-records.lua']:lua.compile((PROTO/n).read_text())
        body=(PROTO/'aliyun-records.lua').read_text();self.assertNotIn('os.execute',body);self.assertNotIn('os.getenv',body)
        self.assertIn('api.plan.bind(snapshot,account,revision,q)',body)
        self.assertIn('api.encode(q)',body);self.assertIn('api.read(5,4096)',body)

    def test_private_mutation_marker_precedes_transport_and_no_cf_receipt_alias(self):
        body=(PROTO/'aliyun-records.lua').read_text()
        self.assertLess(body.index("api.write(7,'HGALIATTEMPT1"),body.index('local doc=api.fetch(params,action)'))
        self.assertIn('HGALIRECORD1',body);self.assertNotIn('HGCFATTEMPT',body)
        common=(PROTO/'homegate-cloudflare-read.sh').read_text()
        self.assertIn('[ "$aliyun_records_enabled" = true ] && [ "$dns_receipt_enabled" = false ]',common)

    def test_canonical_results_are_bound_to_attempt_identity_and_count(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(unpack_returned_tuples=True);m=lua.execute((PROTO/'aliyun-records.lua').read_text())
        kinds=lua.table_from({'':True,'temporary':True});codes=lua.table_from({'invalid_receipt':True})
        def check(kind,retry,code,result,effect,count,rc,marker,**alter):
            raw=m.report('dns_a','2',kind,retry,code,result,effect,count);doc=json.loads(raw);doc.update(alter)
            return m.validate(raw,lua.table_from(doc),'dns_a','2',rc,marker,kinds,codes)
        self.assertIsNotNone(check('',False,'','created','confirmed',1,'0','HGALIATTEMPT1\n'))
        self.assertIsNotNone(check('',False,'','unchanged','none',0,'0',''))
        self.assertIsNotNone(check('temporary',False,'invalid_receipt','failed','unknown',1,'1','HGALIATTEMPT1\n'))
        for args in [('',False,'','created','confirmed',1,'0',''),('',False,'','unchanged','none',0,'0','HGALIATTEMPT1\n'),('temporary',True,'invalid_receipt','failed','unknown',0,'1','HGALIATTEMPT1\n'),('',False,'','updated','confirmed',2,'0','HGALIATTEMPT1\n')]:self.assertIsNone(check(*args))
        self.assertIsNone(check('',False,'','created','confirmed',1,'0','HGALIATTEMPT1\n',account='other'))

class Runtime(ReadRuntime):
    def setUp(self):
        super().setUp();self.db={};self.next_id=1000;self.hook=None
        for name in ['homegate-aliyun-read.sh','homegate-aliyun-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh']:
            p=self.engine.parent/name;s=p.read_text().replace('aliyun_records_enabled=false','aliyun_records_enabled=true').replace('dns_records_enabled=false','dns_records_enabled=true')
            if name=='homegate-service-observer-watchdog.sh':s=s.replace('action=cloudflare-check; budget=2','action=cloudflare-check; budget=4')
            p.write_text(s)
        from lupa.lua51 import LuaRuntime
        self.encoder=LuaRuntime();self.codec=self.encoder.execute((ROOT/'project/luci/lua/luasrc/model/homegate/backup.lua').read_text())
        self.migrated();self.baseline=self.contents()

    def encoded(self,q):return (self.codec.json(self.encoder.table_from(q,recursive=True))+'\n').encode()
    def payload(self,**extra):return {'operation':'upsert','kind':'ddns','resource':'ddns_a','value':'2001:db8::2',**extra}
    def txt(self,**extra):return {'operation':'upsert','kind':'dns01','resource':'cert_a','domain':'example.test','value':VALUE,**extra}
    def add(self,*items):
        for r in items:self.db[r['RecordId']]=copy.deepcopy(r)
    def mutations(self):return [x for x in self.calls if parse_qs(urlsplit(x['path']).query).get('Action',[''])[0] in ['AddDomainRecord','UpdateDomainRecord','DeleteDomainRecord']]

    def record_http(self,method,path,body):
        q=parse_qs(urlsplit(path).query,keep_blank_values=True);signature=q.pop('Signature',[''])[0]
        canonical='&'.join(quote(k,safe='-._~')+'='+quote(v[0],safe='-._~') for k,v in sorted(q.items()))
        expected=base64.b64encode(hmac.new(self.ali_secret+b'&',('GET&%2F&'+quote(canonical,safe='-._~')).encode(),hashlib.sha1).digest()).decode()
        if signature!=expected or q.get('AccessKeyId')!=[self.ali_key.decode()] or method!='GET' or not all(len(v)==1 for v in q.values()):
            self.signature_errors.append('signature mismatch');return 403,{'Code':'SignatureDoesNotMatch','Message':'SECRET_SENTINEL'}
        action=q['Action'][0]
        if self.hook:
            result=self.hook(action,q)
            if result is not None:return result
        if action=='DescribeSubDomainRecords':
            items=[copy.deepcopy(r) for r in self.db.values() if r['DomainName']==q['DomainName'][0] and (r['DomainName'] if r['RR']=='@' else r['RR']+'.'+r['DomainName'])==q['SubDomain'][0] and r['Type']==q['Type'][0]]
            page=int(q['PageNumber'][0]);per=int(q['PageSize'][0]);return 200,{'RequestId':'fixture','TotalCount':len(items),'PageNumber':page,'PageSize':per,'DomainRecords':{'Record':items[(page-1)*per:page*per]}}
        if action=='DescribeDomains':return 200,{'RequestId':'fixture','TotalCount':0,'PageNumber':int(q['PageNumber'][0]),'PageSize':int(q['PageSize'][0]),'Domains':{'Domain':[]}}
        if action=='AddDomainRecord':
            self.next_id+=1;rid=str(self.next_id);self.db[rid]=record(rid,q['Type'][0],q['RR'][0],q['Value'][0],DomainName=q['DomainName'][0],TTL=int(q['TTL'][0]),Line=q['Line'][0]);return 200,{'RequestId':'fixture','RecordId':rid}
        rid=q['RecordId'][0];r=self.db.get(rid)
        if r is None:return 400,{'Code':'InvalidRecordId.NotFound','Message':'SECRET_SENTINEL missing'}
        if action=='DescribeDomainRecordInfo':return 200,{'RequestId':'fixture',**copy.deepcopy(r)}
        if action=='UpdateDomainRecord':
            r.update(RR=q['RR'][0],Type=q['Type'][0],Value=q['Value'][0],TTL=int(q['TTL'][0]),Line=q['Line'][0]);return 200,{'RequestId':'fixture','RecordId':rid}
        if action=='DeleteDomainRecord':del self.db[rid];return 200,{'RequestId':'fixture','RecordId':rid}
        raise AssertionError('Unexpected AliDNS action')

    def records(self,q=None,expected=0,raw=None,account='dns_a'):
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),account,'--records'],input=raw if raw is not None else self.encoded(q or self.payload()),env=self.env,capture_output=True,timeout=12)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr,self.signature_errors));self.assertEqual(p.stderr,b'')
        for value in [b'SECRET_SENTINEL',b'OLD_ID',b'TXT_PRIVATE_VALUE',b'2001:db8::2']:self.assertNotIn(value,p.stdout)
        out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        if expected in [0,1]:self.assertEqual(out['check_scope'],'record-operation');self.assertEqual(out['provider'],'aliyun')
        self.assertEqual(self.contents(),self.baseline);return out

    def clean(self):self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')));self.writer()
    def uncertain(self,out,count=0):
        self.assertEqual((out['effect'],out['retryable'],out['reconciliation_required'],out['affected']),('unknown',False,True,count))
        dirs=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(dirs),1);self.assertEqual((dirs[0]/'attempt').read_bytes(),b'HGALIATTEMPT1\n')
        for p in [dirs[0],*dirs[0].iterdir()]:self.assertEqual(p.stat().st_mode&0o777,0o700 if p.is_dir() else 0o600)
        self.records(expected=4);self.aliyun(expected=4);self.writer()

    def test_aaaa_create_readback_then_unchanged(self):
        out=self.records();self.assertEqual((out['result'],out['effect'],out['affected']),('created','confirmed',1))
        self.assertEqual(self.records()['result'],'unchanged');self.assertEqual(len(self.mutations()),1);self.clean()

    def test_update_preserves_custom_line_and_unrelated_records(self):
        self.add(record(1,Line='cn_mobile',Remark='keep',Weight=8),record(2,rr='other'))
        self.assertEqual(self.records()['result'],'updated');q=parse_qs(urlsplit(self.mutations()[0]['path']).query)
        self.assertEqual(q['Line'],['cn_mobile']);self.assertEqual(self.db['1']['Remark'],'keep');self.assertEqual(self.db['1']['Weight'],8);self.assertEqual(self.db['2']['Value'],'2001:db8::1');self.clean()

    def test_equivalent_value_on_second_page_prevents_write(self):
        self.add(*(record(i) for i in range(1,101)),record(101,value='2001:0DB8:0:0:0:0:0:0002'))
        self.assertEqual(self.records()['result'],'unchanged');self.assertEqual(self.mutations(),[]);self.assertEqual(len(self.calls),2);self.clean()

    def test_txt_create_and_exact_cleanup_keep_other_challenges(self):
        self.add(record(1,'TXT','_acme-challenge','OTHER'),record(2,'TXT','other',VALUE))
        self.assertEqual(self.records(self.txt())['result'],'created');self.assertEqual(self.records(self.txt())['result'],'unchanged')
        self.assertEqual(self.records(self.txt(operation='delete'))['affected'],1);self.assertEqual(set(self.db),{'1','2'});self.assertEqual(self.records(self.txt(operation='delete'))['result'],'unchanged');self.clean()

    def test_matching_deletes_on_second_page_are_all_found_before_write(self):
        self.add(*(record(i,'TXT','_acme-challenge','OTHER') for i in range(1,101)),record(101,'TXT','_acme-challenge',VALUE))
        out=self.records(self.txt(operation='delete'));self.assertEqual(out['affected'],1);self.assertEqual(len(self.db),100)
        actions=[parse_qs(urlsplit(x['path']).query)['Action'][0] for x in self.calls]
        self.assertEqual(actions[:2],['DescribeSubDomainRecords']*2);self.clean()

    def test_aaaa_exact_and_explicit_all_have_separate_scopes(self):
        self.add(record(1),record(2,value='2001:db8::2'),record(3,rr='other'))
        self.records(self.payload(operation='delete'));self.assertEqual(set(self.db),{'1','3'})
        self.records(self.payload(operation='delete',value='',all=True));self.assertEqual(set(self.db),{'3'});self.clean()

    def test_invalid_input_resource_account_and_all_are_rejected_before_http(self):
        for q in [self.payload(resource='missing'),self.payload(endpoint='https://bad.invalid'),self.payload(value='bad'),self.payload(operation='delete',value=''),self.txt(operation='delete',value=''),self.txt(operation='delete',all=True),self.txt(domain='other.test')]:self.records(q,1)
        for raw in [b'{}\n',b'{"operation":"upsert","operation":"delete"}\n',b'{}\x00',b'X'*4097]:self.records(expected=1,raw=raw)
        self.records(expected=1,account='other');self.assertEqual(self.calls,[]);self.clean()

    def test_listing_failure_and_drift_never_write(self):
        self.add(*(record(i) for i in range(1,102)))
        def hook(action,q):
            if q.get('PageNumber')==['2']:return 429,{'Code':'Throttling','Message':'OLD_ID SECRET_SENTINEL'}
        self.hook=hook;out=self.records(expected=1);self.assertEqual((out['effect'],out['retryable']),('none',True));self.assertEqual(self.mutations(),[]);self.clean()

    def test_duplicate_identity_or_wrong_scope_and_invalid_aaaa_rejected(self):
        for items in [[record(1),record(1)],[record(1,rr='other')],[record(1,value='not-ipv6')],[record('../bad')]]:
            self.hook=lambda action,q:(200,{'RequestId':'fixture','PageNumber':1,'PageSize':100,'TotalCount':len(items),'DomainRecords':{'Record':items}}) if action=='DescribeSubDomainRecords' else None
            self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()

    def test_update_race_locked_and_disabled_records_never_write(self):
        self.add(record(1))
        for changes in [{'Value':'2001:db8::9'},{'Line':'cn_mobile'},{'Locked':True},{'Status':'Disable'}]:
            self.hook=lambda action,q:(200,{'RequestId':'fixture',**record(1,**changes)}) if action=='DescribeDomainRecordInfo' else None
            self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()

    def test_mutation_http_failure_is_unknown_and_not_retried(self):
        self.hook=lambda action,q:(500,{'Code':'InternalError','Message':'SECRET_SENTINEL'}) if action=='AddDomainRecord' else None
        self.uncertain(self.records(expected=1));self.assertEqual(len(self.mutations()),1)

    def test_readback_mismatch_keeps_barrier_after_real_creation(self):
        self.hook=lambda action,q:(200,{'RequestId':'fixture',**record(q['RecordId'][0],value='2001:db8::9')}) if action=='DescribeDomainRecordInfo' else None
        self.uncertain(self.records(expected=1));self.assertEqual(len(self.db),1)

    def test_delete_race_refuses_changed_value(self):
        self.add(record(1,value='2001:db8::2'))
        self.hook=lambda action,q:(200,{'RequestId':'fixture',**record(1,value='2001:db8::3')}) if action=='DescribeDomainRecordInfo' else None
        self.records(self.payload(operation='delete'),1);self.assertEqual(self.mutations(),[]);self.clean()

    def test_partial_delete_reports_only_confirmed_count(self):
        self.add(record(1,'TXT','_acme-challenge',VALUE),record(2,'TXT','_acme-challenge',VALUE))
        self.hook=lambda action,q:(500,{'Code':'InternalError'}) if action=='DeleteDomainRecord' and q['RecordId']==['2'] else None
        self.uncertain(self.records(self.txt(operation='delete'),1),count=1);self.assertEqual(set(self.db),{'2'})

    def test_invalid_write_receipt_never_claims_success(self):
        self.hook=lambda action,q:(200,{'RequestId':'fixture','RecordId':'not-numeric'}) if action=='AddDomainRecord' else None
        self.uncertain(self.records(expected=1))

    def test_closed_gates_and_cf_receipt_mode_refuse_records(self):
        p=self.ali_entry;original=p.read_text();p.write_text(original.replace('aliyun_records_enabled=true','aliyun_records_enabled=false'));self.records(expected=2);p.write_text(original)
        p=self.reader;p.write_text(p.read_text().replace('dns_receipt_enabled=false','dns_receipt_enabled=true'));self.records(expected=2);self.assertEqual(self.calls,[]);self.clean()

    def test_unfinished_operation_input_is_supervised(self):
        p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a','--records'],env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        start=time.monotonic();p.wait(timeout=8);self.assertNotEqual(p.returncode,0);self.assertLess(time.monotonic()-start,7)
        p.stdin.close();p.stdin=None;p.communicate(timeout=2);self.assertEqual(self.calls,[]);self.clean()

    def test_live_mutation_arguments_and_descriptors_exclude_private_data(self):
        self.delay=0.3
        p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a','--records'],env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        p.stdin.write(self.encoded(self.txt()));p.stdin.close();p.stdin=None
        seen=False;deadline=time.monotonic()+5
        while not seen:
            if self.mutations():
                for proc in Path('/proc').glob('[0-9]*/cmdline'):
                    try:
                        args=proc.read_bytes()
                        if args.split(b'\0')[0]!=os.fsencode(self.curl):continue
                        environment=(proc.parent/'environ').read_bytes()
                        for secret in [self.ali_key,self.ali_secret,VALUE.encode()]:self.assertNotIn(secret,args+environment)
                        work=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(work),1)
                        self.assertEqual(len(list(work[0].iterdir())),9)
                        for file in work[0].iterdir():self.assertEqual(file.stat().st_mode&0o777,0o600);self.assertEqual(file.stat().st_nlink,1)
                        for fd in range(3,10):
                            try:target=os.readlink(proc.parent/'fd'/str(fd))
                            except FileNotFoundError:continue
                            self.assertFalse(target.startswith(str(work[0])),(fd,target))
                        seen=True;break
                    except (FileNotFoundError,ProcessLookupError,PermissionError):continue
            if not seen:self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.01)
        out,err=p.communicate(timeout=6);self.assertEqual((p.returncode,err),(0,b''));self.assertTrue(json.loads(out)['ok']);self.clean()

    def test_caller_killed_after_server_mutation_keeps_unknown_barrier(self):
        reader=self.engine.parent/'aliyun-reader.lua';reader.write_text(reader.read_text().replace('--max-time 0.5','--max-time 10'))
        def hook(action,q):
            if action=='AddDomainRecord':
                self.db['5000']=record(5000,value=q['Value'][0]);self.delay=5
                return 200,{'RequestId':'fixture','RecordId':'5000'}
        self.hook=hook
        p=subprocess.Popen([self.busybox,'ash',str(self.ali_entry),'dns_a','--records'],env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        p.stdin.write(self.encoded(self.payload()));p.stdin.close();p.stdin=None
        deadline=time.monotonic()+5
        while not self.db:self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.02)
        self.assertTrue(self.group());p.kill();p.communicate(timeout=2);self.writer(4)
        time.sleep(5.4);self.writer();self.records(expected=4);self.aliyun(expected=4)
        work=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(work),1);self.assertEqual((work[0]/'attempt').read_bytes(),b'HGALIATTEMPT1\n')
        self.assertEqual(set(self.db),{'5000'});self.assertEqual(len(self.mutations()),1)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if suite.countTestCases()==0:p.error('No matching test case')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if r.wasSuccessful() else 1)
