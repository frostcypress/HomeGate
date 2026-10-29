#!/usr/bin/env python3
"""Configured AAAA/TXT operations against a disposable loopback TLS database."""
import argparse,copy,json,os,re,shutil,subprocess,sys,time,unittest,urllib.parse
from pathlib import Path
from project import ROOT
from Cloudflare区域回归 import Runtime as ZoneRuntime
from Cloudflare只读回归 import PROTO
from 私有配置读取回归 import Codec as PrivateCodec
from 配置预览回归 import CODEC

VALUE='TXT_PRIVATE_VALUE"\\ $(touch /tmp/not-a-dns-command)'
ZID='f'*32
def rec(i,typ='AAAA',name='www.example.test',value='2001:db8::1',**extra):return {'id':format(i,'032x'),'type':typ,'name':name,'content':value,'ttl':600,**extra}
def envelope(result):return {'success':True,'errors':[],'result':result}

class Static(PrivateCodec):
    def setUp(self):
        super().setUp();self.plan=self.lua.execute((PROTO/'cloudflare-record-plan.lua').read_bytes())
        self.snapshot=self.parse(self.frame([(b'cloudflare.dns_a.secret',b'PRIVATE_SENTINEL')]))
    def bind(self,q,account=b'dns_a',revision=b'3'):
        return self.plan.bind(self.snapshot,account,revision,self.lua.table_from(q,recursive=True))
    def ddns(self,**extra):return {b'operation':b'upsert',b'kind':b'ddns',b'resource':b'ddns_a',b'value':b'2001:db8::2',**{k.encode():v for k,v in extra.items()}}
    def test_closed_record_gates_shell_ast_and_no_production_install(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-cloudflare-read.sh','homegate-cloudflare-worker.sh','homegate-service-observer-watchdog.sh']:
            b=(PROTO/n).read_bytes();self.assertNotIn(b'\r',b);self.assertFalse(parser.parse(b).root_node.has_error,n)
            self.assertEqual(len(re.findall(rb'^dns_records_enabled=false$',b,re.M)),1)
            self.assertNotRegex(b,rb'(?m)^dns_records_enabled=true$')
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())
    def test_real_generation_resource_and_domain_binding(self):
        c=self.bind(self.ddns());self.assertEqual((c[b'type'],c[b'fqdn'],c[b'ttl']),(b'AAAA',b'www.example.test',600))
        for q,a,r in [(self.ddns(),b'other',b'3'),(self.ddns(),b'dns_a',b'2'),(self.ddns(resource=b'missing'),b'dns_a',b'3'),(self.ddns(endpoint=b'https://bad.invalid'),b'dns_a',b'3')]:
            self.assertIsNone(self.bind(q,a,r)[0])
        q={b'operation':b'upsert',b'kind':b'dns01',b'resource':b'cert_a',b'value':b'PRIVATE_TXT',b'domain':b'*.example.test'}
        self.assertEqual(self.bind(q)[b'fqdn'],b'_acme-challenge.example.test');q[b'domain']=b'other.example.test';self.assertIsNone(self.bind(q)[0])
    def test_ipv6_forms_share_identity_and_invalid_addresses_are_rejected(self):
        for s in [b'2001:db8::1',b'2001:0DB8:0:0:0:0:0:0001']:
            self.assertEqual(self.plan.ipv6(s),b'2001:0db8:0000:0000:0000:0000:0000:0001')
        self.assertEqual(self.plan.ipv6(b'::ffff:192.0.2.1'),self.plan.ipv6(b'0:0:0:0:0:ffff:c000:201'))
        for s in [b'2001::1:',b':2001::1',b'1:2:3:4:5:6:7::8',b':::',b'1::2::3',b'fe80::1%br-lan',b'::ffff:192.00.2.1',b'2001:db8::\n',b'192.0.2.1']:
            self.assertIsNone(self.plan.ipv6(s),s)
    def test_record_id_name_type_and_value_isolation(self):
        c=self.bind(self.ddns());good=self.lua.table_from({b'id':b'a'*32,b'type':b'AAAA',b'name':b'WWW.EXAMPLE.TEST.',b'content':b'2001:0db8::2'})
        self.assertTrue(self.plan.record(c,good)[b'match'])
        for key,value in [(b'id',b'../other'),(b'name',b'other.example.test'),(b'type',b'A'),(b'content',b'bad')]:
            original=good[key];good[key]=value;self.assertIsNone(self.plan.record(c,good));good[key]=original
        self.assertIsNone(self.bind(self.ddns(operation=b'delete',value=b''))[0])
        self.assertTrue(self.bind(self.ddns(operation=b'delete',value=b'',all=True))[b'delete_all'])
    def test_data_driver_grammar_and_private_argument_contract(self):
        for n in ['cloudflare-record-plan.lua','cloudflare-records.lua']:
            b=(PROTO/n).read_bytes();self.assertNotIn(b'\r',b);self.lua.compile(b)
            self.assertNotIn(b'os.execute',b);self.assertNotIn(b'os.getenv',b)
        worker=(PROTO/'homegate-cloudflare-worker.sh').read_text()
        self.assertIn('0<&4 4>&- 5>"$work/input"',worker)
        self.assertIn('3>&- 4>&- 5>&- 8>&- 9>&-',worker)
        self.assertIn('write(9,\'HGCFATTEMPT1',(PROTO/'cloudflare-records.lua').read_text())

class Runtime(ZoneRuntime):
    def setUp(self):
        super().setUp();self.db={};self.next_id=2000;self.hook=None;self.page_size=100;self.omit_metadata=False
        self.zone_results=[{'id':ZID,'name':'example.test'}]
        self.record_http=self.http
        for n in ['homegate-cloudflare-read.sh','homegate-cloudflare-worker.sh','homegate-service-observer-watchdog.sh']:
            p=self.engine.parent/n;s=p.read_text().replace('dns_records_enabled=false','dns_records_enabled=true')
            if n=='homegate-service-observer-watchdog.sh':s=s.replace('action=cloudflare-check; budget=2','action=cloudflare-check; budget=4')
            p.write_text(s)
        p=self.engine.parent/'cloudflare-records.lua';p.write_text(p.read_text().replace("local json=require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json=require('luci.jsonc')").replace('https://api.cloudflare.com/client/v4',self.endpoint.split('/client/v4/')[0]+'/client/v4'))
        from lupa.lua51 import LuaRuntime
        self.control_lua=LuaRuntime(unpack_returned_tuples=True);self.control_codec=self.control_lua.execute(CODEC.read_text())
        self.baseline={p.relative_to(self.store).as_posix():p.read_bytes() for p in self.store.rglob('*') if p.is_file()}
    def encoded(self,q):return (self.control_codec.json(self.control_lua.table_from(q,recursive=True))+'\n').encode()
    def payload(self,**extra):return {'operation':'upsert','kind':'ddns','resource':'ddns_a','value':'2001:db8::2',**extra}
    def txt(self,**extra):return {'operation':'upsert','kind':'dns01','resource':'cert_a','domain':'example.test','value':VALUE,**extra}
    def add(self,*items):
        for x in items:self.db[x['id']]=copy.deepcopy(x)
    def mutations(self):return [x for x in self.calls if x['method']!='GET']
    def http(self,method,path,body):
        parsed=urllib.parse.urlsplit(path);query=urllib.parse.parse_qs(parsed.query);data=json.loads(body) if body else None
        if self.hook:
            value=self.hook(method,parsed.path,query,data)
            if value is not None:return value
        if parsed.path=='/client/v4/zones':
            return 200,envelope(self.zone_results)
        prefix='/client/v4/zones/'+ZID+'/dns_records'
        assert parsed.path==prefix or parsed.path.startswith(prefix+'/'),parsed.path
        if parsed.path==prefix and method=='GET':
            items=[copy.deepcopy(r) for r in self.db.values() if r['name'].lower().rstrip('.')==query['name'][0] and r['type']==query['type'][0]]
            n=int(query['page'][0]);size=self.page_size;selected=items[(n-1)*size:n*size];doc=envelope(selected)
            if not self.omit_metadata:doc['result_info']={'page':n,'per_page':100,'count':len(selected),'total_count':len(items),'total_pages':(len(items)+size-1)//size}
            return 200,doc
        if parsed.path==prefix and method=='POST':
            self.next_id+=1;r={'id':format(self.next_id,'032x'),**data};self.db[r['id']]=r;return 200,envelope(copy.deepcopy(r))
        rid=parsed.path.rsplit('/',1)[1];r=self.db.get(rid)
        if r is None:return 404,{'success':False,'errors':[{'code':81044,'message':'PRIVATE_SENTINEL missing'}]}
        if method=='GET':return 200,envelope(copy.deepcopy(r))
        if method=='PATCH':r.update(data);return 200,envelope(copy.deepcopy(r))
        if method=='DELETE':del self.db[rid];return 200,envelope({'id':rid})
        raise AssertionError(method)
    def records(self,q=None,expected=0,raw=None,account='dns_a',env=None):
        p=subprocess.run([self.busybox,'ash',str(self.reader),account,'--records'],input=raw if raw is not None else self.encoded(q or self.payload()),env=env or self.env,capture_output=True,timeout=12)
        diag=self.diagnostic.read_text()[:128] if self.diagnostic.exists() else ''
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr,diag));self.assertEqual(p.stderr,b'')
        for marker in [b'PRIVATE_SENTINEL',b'TXT_PRIVATE_VALUE',b'2001:db8::2']:self.assertNotIn(marker,p.stdout)
        r=json.loads(p.stdout);self.assertEqual(r['ok'],expected==0)
        if expected in [0,1]:self.assertEqual(r['check_scope'],'record-operation');self.assertEqual(r['configuration_revision'],int((self.store/'current').read_text()))
        return r
    def clean(self):self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')));self.writer()
    def preserved(self):
        self.assertEqual({p.relative_to(self.store).as_posix():p.read_bytes() for p in self.store.rglob('*') if p.is_file()},self.baseline)
    def uncertain(self,r):
        self.assertEqual((r['effect'],r['retryable'],r['reconciliation_required']),('unknown',False,True))
        work=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(work),1)
        self.assertEqual((work[0]/'attempt').read_bytes(),b'HGCFATTEMPT1\n')
        for p in [work[0],*work[0].iterdir()]:self.assertEqual(p.stat().st_mode&0o777,0o700 if p.is_dir() else 0o600)
        self.records(expected=4);self.check(4);self.writer();self.preserved()

    def test_aaaa_create_is_confirmed_then_second_execution_is_unchanged(self):
        r=self.records();self.assertEqual((r['result'],r['effect'],r['affected']),('created','confirmed',1))
        r=self.records();self.assertEqual((r['result'],r['effect'],r['affected']),('unchanged','none',0))
        self.assertEqual(len(self.mutations()),1);self.clean();self.preserved()
    def test_aaaa_patch_preserves_proxy_comments_and_other_records(self):
        self.add(rec(1,proxied=True,comment='keep',tags=['owner:keep']),rec(2,name='other.example.test'))
        r=self.records();self.assertEqual(r['result'],'updated');body=json.loads(self.mutations()[0]['body'])
        self.assertEqual(set(body),{'content','ttl'});self.assertEqual(self.mutations()[0]['method'],'PATCH')
        self.assertEqual(self.db[format(1,'032x')]['comment'],'keep');self.assertTrue(self.db[format(1,'032x')]['proxied'])
        self.assertEqual(self.db[format(2,'032x')]['content'],'2001:db8::1');self.clean();self.preserved()
    def test_equivalent_ipv6_text_on_later_record_never_causes_update(self):
        self.add(rec(1),rec(2,value='2001:0DB8:0:0:0:0:0:0002'));self.assertEqual(self.records()['result'],'unchanged')
        self.assertEqual(self.mutations(),[]);self.clean()
    def test_txt_create_retains_other_txt_values_and_reexecution_is_idempotent(self):
        self.add(rec(1,'TXT','_acme-challenge.example.test','OTHER_CHALLENGE'))
        self.assertEqual(self.records(self.txt())['result'],'created');self.assertEqual(self.records(self.txt())['result'],'unchanged')
        self.assertEqual(len(self.db),2);self.assertEqual(self.db[format(1,'032x')]['content'],'OTHER_CHALLENGE')
        self.assertEqual([x['method'] for x in self.mutations()],['POST']);self.clean();self.preserved()
    def test_txt_exact_value_cleanup_keeps_other_challenges_names_and_types(self):
        self.add(rec(1,'TXT','_acme-challenge.example.test',VALUE),rec(2,'TXT','_acme-challenge.example.test','OTHER'),rec(3,'TXT','other.example.test',VALUE),rec(4))
        r=self.records(self.txt(operation='delete'));self.assertEqual((r['result'],r['affected']),('deleted',1))
        self.assertEqual(set(self.db),{format(i,'032x') for i in [2,3,4]});self.assertEqual(self.records(self.txt(operation='delete'))['result'],'unchanged');self.clean()
    def test_txt_matching_duplicates_are_deleted_only_after_full_pagination(self):
        self.page_size=1;self.add(rec(1,'TXT','_acme-challenge.example.test',VALUE),rec(2,'TXT','_acme-challenge.example.test',VALUE))
        r=self.records(self.txt(operation='delete'));self.assertEqual(r['affected'],2);self.assertEqual(self.db,{})
        first_mut=next(i for i,x in enumerate(self.calls) if x['method']=='DELETE')
        self.assertTrue(any('page=2' in x['path'] for x in self.calls[:first_mut]));self.clean()
    def test_aaaa_exact_delete_and_explicit_all_have_separate_scopes(self):
        self.add(rec(1),rec(2,value='2001:db8::2'),rec(3,name='other.example.test'))
        self.records(self.payload(operation='delete'));self.assertEqual(set(self.db),{format(1,'032x'),format(3,'032x')})
        self.records(self.payload(operation='delete',value='',all=True));self.assertEqual(set(self.db),{format(3,'032x')});self.clean()
    def test_empty_deletion_requires_explicit_all_and_txt_never_bulk_deletes(self):
        for q in [self.payload(operation='delete',value=''),self.txt(operation='delete',value=''),self.txt(operation='delete',all=True)]:self.records(q,1)
        self.assertEqual(self.calls,[]);self.clean()
    def test_wrong_account_generation_resource_domain_and_type_stop_before_http(self):
        for q,account in [(self.payload(),'other'),(self.payload(resource='missing'),'dns_a'),(self.txt(domain='other.example.test'),'dns_a'),(self.payload(kind='bad'),'dns_a')]:self.records(q,1,account=account)
        self.assertEqual(self.calls,[]);self.clean()
    def test_invalid_payload_duplicate_keys_nul_and_arbitrary_url_are_rejected(self):
        for raw in [b'{}\n',b'{"operation":"upsert","operation":"delete"}\n',b'{}\x00',b'x'*4097]:self.records(expected=1,raw=raw)
        for q in [self.payload(endpoint='https://bad.invalid'),self.payload(value='fe80::1%br-lan'),self.payload(value='192.0.2.1')]:self.records(q,1)
        self.assertEqual(self.calls,[]);self.clean()
    def test_zone_missing_or_ambiguous_never_mutates(self):
        for zones in [[],[{'id':ZID,'name':'other.test'}],[{'id':ZID,'name':'example.test'},{'id':'e'*32,'name':'example.test'}]]:
            self.zone_results=zones;self.records(expected=1)
        self.assertEqual(self.mutations(),[]);self.clean()
    def test_records_full_pages_without_metadata_are_not_truncated(self):
        self.omit_metadata=True;self.add(*(rec(i) for i in range(1,101)),rec(101,value='2001:db8::2'))
        self.assertEqual(self.records()['result'],'unchanged');self.assertTrue(any('page=2' in x['path'] for x in self.calls));self.assertEqual(self.mutations(),[]);self.clean()
    def test_record_scope_mismatch_and_duplicate_id_fail_before_any_write(self):
        def hook(method,path,query,data):
            if path.endswith('/dns_records'):return 200,envelope([rec(1,name='other.example.test')])
        self.hook=hook;self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
        self.hook=lambda method,path,q,data:(200,envelope([rec(1),rec(1)])) if path.endswith('/dns_records') else None
        self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_later_page_failure_and_total_drift_never_issue_mutation(self):
        self.page_size=1;self.add(rec(1),rec(2))
        def hook(method,path,q,data):
            if q.get('page')==['2']:return 429,{'success':False,'errors':[{'message':'PRIVATE_SENTINEL'}]}
        self.hook=hook;r=self.records(expected=1);self.assertEqual((r['effect'],r['error_kind']),('none','rate_limit'));self.assertEqual(self.mutations(),[]);self.clean()
        def drift(method,path,q,data):
            if q.get('page')==['2']:
                doc=envelope([rec(2)]);doc['result_info']={'page':2,'per_page':100,'count':1,'total_count':3,'total_pages':2};return 200,doc
        self.hook=drift;r=self.records(expected=1);self.assertEqual(r['provider_code'],'pagination_changed');self.assertEqual(self.mutations(),[]);self.clean()
    def test_concurrent_value_change_before_aaaa_patch_is_refused(self):
        self.add(rec(1))
        def hook(method,path,q,data):
            if path.endswith('/'+format(1,'032x')):return 200,envelope(rec(1,value='2001:db8::99'))
        self.hook=hook;self.records(expected=1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_concurrent_txt_value_change_before_delete_is_refused(self):
        self.add(rec(1,'TXT','_acme-challenge.example.test',VALUE))
        def hook(method,path,q,data):
            if path.endswith('/'+format(1,'032x')):return 200,envelope(rec(1,'TXT','_acme-challenge.example.test','NEW_OWNER_VALUE'))
        self.hook=hook;self.records(self.txt(operation='delete'),1);self.assertEqual(self.mutations(),[]);self.clean()
    def test_already_absent_record_before_delete_is_idempotent(self):
        self.add(rec(1,'TXT','_acme-challenge.example.test',VALUE))
        self.hook=lambda method,path,q,data:(404,{'success':False}) if path.endswith('/'+format(1,'032x')) else None
        self.assertEqual(self.records(self.txt(operation='delete'))['result'],'unchanged');self.assertEqual(self.mutations(),[]);self.clean()
    def test_applied_create_with_http_failure_is_unknown_and_not_retried(self):
        def hook(method,path,q,data):
            if method=='POST':self.add(rec(500,name=data['name'],value=data['content']));return 500,{'success':False,'errors':[{'message':VALUE}]}
        self.hook=hook;r=self.records(expected=1);self.uncertain(r);self.assertEqual(len(self.mutations()),1);self.assertEqual(len(self.db),1)
    def test_create_transport_timeout_retains_uncertainty_instead_of_retry(self):
        def hook(method,path,q,data):
            if method=='POST':time.sleep(1);return 200,envelope(rec(500,name=data['name'],value=data['content']))
        self.hook=hook;r=self.records(expected=1);self.assertEqual(r['error_kind'],'timeout');self.uncertain(r);self.assertEqual(len(self.mutations()),1)
    def test_forged_mutation_record_id_name_or_content_cannot_acknowledge(self):
        self.hook=lambda method,path,q,data:(200,envelope(rec(500,name='other.example.test',value=data['content']))) if method=='POST' else None
        self.uncertain(self.records(expected=1));self.assertEqual(len(self.mutations()),1)
    def test_readback_mismatch_after_successful_patch_is_unknown(self):
        self.add(rec(1));counter=[0]
        def hook(method,path,q,data):
            if method=='GET' and path.endswith('/'+format(1,'032x')):
                counter[0]+=1
                if counter[0]==2:return 200,envelope(rec(1,value='2001:db8::99'))
        self.hook=hook;self.uncertain(self.records(expected=1));self.assertEqual(len(self.mutations()),1)
    def test_successful_delete_without_absence_confirmation_is_unknown(self):
        self.add(rec(1,'TXT','_acme-challenge.example.test',VALUE))
        self.hook=lambda method,path,q,data:(200,envelope({'id':format(1,'032x')})) if method=='DELETE' else None
        self.uncertain(self.records(self.txt(operation='delete'),1));self.assertEqual(len(self.mutations()),1)
    def test_partial_delete_failure_retains_confirmed_count_and_blocks_new_dns(self):
        self.add(rec(1,'TXT','_acme-challenge.example.test',VALUE),rec(2,'TXT','_acme-challenge.example.test',VALUE))
        self.hook=lambda method,path,q,data:(500,{'success':False}) if method=='DELETE' and path.endswith('/'+format(2,'032x')) else None
        r=self.records(self.txt(operation='delete'),1);self.assertEqual(r['affected'],1);self.uncertain(r)
        self.assertEqual(set(self.db),{format(2,'032x')});self.assertEqual(len(self.mutations()),2)
    def test_tls_failure_before_write_is_known_no_effect(self):
        p=self.engine.parent/'homegate-cloudflare-worker.sh';p.write_text(p.read_text().replace(str(self.ca_dir/'ca.pem'),'/dev/null'))
        r=self.records(expected=1,env={**self.env,'CURL_CA_BUNDLE':str(self.ca_dir/'ca.pem')});self.assertEqual((r['effect'],r['error_kind']),('none','network_unavailable'));self.assertEqual(self.calls,[]);self.clean()
    def test_missing_credentials_and_common_write_barriers_prevent_http(self):
        import fcntl
        with self.native.lock.open('rb') as held:fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);self.records(expected=4)
        self.cli('credential-delete','cloudflare','dns_a','secret');self.records(expected=1)
        self.assertEqual(self.calls,[]);self.begin();self.records(expected=4);self.assertEqual(self.calls,[])
    def test_private_request_body_and_live_curl_argv_do_not_expose_credentials(self):
        self.delay=0.25
        p=subprocess.Popen([self.busybox,'ash',str(self.reader),'dns_a','--records'],env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        p.stdin.write(self.encoded(self.txt()));p.stdin.close();p.stdin=None;deadline=time.monotonic()+6;seen=False
        while not seen:
            for proc in Path('/proc').glob('[0-9]*/cmdline'):
                try:args=proc.read_bytes()
                except (FileNotFoundError,ProcessLookupError,PermissionError):continue
                if args.split(b'\0')[0]==os.fsencode(self.curl):
                    self.assertNotIn(b'PRIVATE_SENTINEL',args);self.assertNotIn(b'TXT_PRIVATE_VALUE',args)
                    self.assertNotIn(b'PRIVATE_SENTINEL',(proc.parent/'environ').read_bytes())
                    for fd in (proc.parent/'fd').iterdir():
                        try:target=os.readlink(fd)
                        except FileNotFoundError:continue
                        self.assertFalse(target.endswith(('/input','/context','/attempt')),target)
                    seen=True;break
            self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.005)
        out,err=p.communicate(timeout=10);self.assertEqual(p.returncode,0,(out,err));self.assertNotIn(b'TXT_PRIVATE_VALUE',out);self.clean()
    def test_blocked_input_is_bounded_by_independent_watchdog(self):
        p=subprocess.Popen([self.busybox,'ash',str(self.reader),'dns_a','--records'],env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        before=time.monotonic();out,err=p.communicate(input=b'{' ,timeout=8)
        # EOF closes incomplete JSON immediately; a separate open writer below
        # proves that waiting for input is supervised rather than unbounded.
        self.assertEqual(p.returncode,1,(out,err));self.clean()
        p=subprocess.Popen([self.busybox,'ash',str(self.reader),'dns_a','--records'],env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        p.wait(timeout=8);p.stdin.close();p.stdin=None;out,err=p.communicate(timeout=2)
        self.assertNotEqual(p.returncode,0);self.assertLess(time.monotonic()-before,8);self.assertEqual(self.calls,[]);self.writer()
    def test_caller_sigkill_after_attempt_keeps_locks_until_session_quiescence(self):
        count=self.base/'curl-count'
        self.curl.write_text('#!'+sys.executable+'\nimport os,signal,sys,time\nfrom pathlib import Path\np=Path('+repr(str(count))+')\nn=int(p.read_text())+1 if p.exists() else 1\np.write_text(str(n))\nif n<3:os.execv('+repr(str(self.real_curl))+',['+repr(str(self.real_curl))+',*sys.argv[1:]])\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True:time.sleep(0.1)\n');self.curl.chmod(0o700)
        p=subprocess.Popen([self.busybox,'ash',str(self.reader),'dns_a','--records'],env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        p.stdin.write(self.encoded(self.payload()));p.stdin.close();p.stdin=None;deadline=time.monotonic()+6
        while not count.exists() or count.read_text()!='3':self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.02)
        self.group();p.kill();p.communicate(timeout=2);self.writer(4);time.sleep(5.4);self.writer();self.records(expected=4);self.check(4)
        work=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(work),1);self.assertEqual((work[0]/'attempt').read_bytes(),b'HGCFATTEMPT1\n')
    def test_closed_record_gate_cannot_be_enabled_by_environment_or_read_gate(self):
        self.reader.write_text(self.reader.read_text().replace('dns_records_enabled=true','dns_records_enabled=false'))
        self.records(expected=2,env={**self.env,'dns_records_enabled':'true'});self.assertEqual(self.calls,[])
        for args in [['dns_a','--records','extra'],['dns_a','--records;echo']]:
            p=subprocess.run([self.busybox,'ash',str(self.reader),*args],input=b'{}\n',env=self.env,capture_output=True,timeout=5);self.assertEqual(p.returncode,2)
    def test_zero_exit_without_report_never_proves_mutation_success(self):
        (self.engine.parent/'homegate-cloudflare-worker.sh').write_text('exit 0\n');self.records(expected=7);self.assertEqual(self.calls,[]);self.clean()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
