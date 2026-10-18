#!/usr/bin/env python3
"""Explicit current-batch closeout, original receipt history and interrupted recovery."""
import argparse,copy,hashlib,json,os,re,subprocess,unittest
from project import ROOT
from DDNS全批协调回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase,Static as BaseStatic
from DDNS计划回归 import fixture_uid
PROTO=ROOT/'project/core/prototype'

class Static(BaseStatic):
    def setUp(self):
        super().setUp();self.results=self.lua.execute((PROTO/'ddns-batch-results.lua').read_bytes())
    def specimen(self):
        receipt=b'{"api_version":1,"prototype":true,"ok":true,"phase":"dns-provider","provider":"cloudflare","account":"a","configuration_revision":3,"check_scope":"record-operation","error_kind":"","retryable":false,"provider_code":"","result":"created","effect":"confirmed","affected":1,"reconciliation_required":false}\n'
        result,_=self.sync.result(receipt,self.table(json.loads(receipt)),b'cloudflare',b'a',b'3',b'ddns_a',b'0')
        return {'schema':'HGDDNSBATCHRESULT1','identity':'a'*64,'generation':'b'*64,'grant':'c'*64,'revision':3,'boot':'11111111-1111-1111-1111-111111111111','batch':'123:456','previous':'none','rows':[{'rule':'ddns_a','provider':'cloudflare','account':'a','job':'123','receipt':receipt.decode(),'result':result.decode(),'hashes':['d'*64,'e'*64,'f'*64,'-','-','1'*64,'2'*64],'state':'recorded','retired':''}]}
    def valid(self,d):return self.results.valid(self.table(d),self.codec.json,lambda raw:self.table(json.loads(raw)),self.sync)
    def close(self,d):
        row=d['rows'][-1];row['state']='closed';row['retired']='\n'.join(['HGCFRetire1','homegate',d['identity'],row['account'],row['job'],'3'*64,*row['hashes'],'4'*64])+'\n';return d
    def test_only_original_confirmed_receipts_and_bounded_unique_rows(self):
        d=self.specimen();self.assertTrue(self.valid(d));self.assertTrue(self.valid(self.close(copy.deepcopy(d))))
        for mutate in [lambda x:x.update(extra='secret'),lambda x:x['rows'].append(copy.deepcopy(x['rows'][0])),lambda x:x['rows'][0].update(result='{}\n'),lambda x:x['rows'][0]['hashes'].__setitem__(0,'-'),lambda x:x['rows'][0].update(state='closed')]:
            bad=copy.deepcopy(d);mutate(bad);self.assertFalse(self.valid(bad))
        many=self.close(copy.deepcopy(d));many['rows']=[dict(copy.deepcopy(many['rows'][0]),rule='r'+str(i)) for i in range(32)]
        for row in many['rows']:
            raw=row['receipt'].encode();row['result']=self.sync.result(raw,self.table(json.loads(raw)),b'cloudflare',b'a',b'3',row['rule'].encode(),b'0')[0].decode()
        self.assertTrue(self.valid(many));many['rows'].append(dict(copy.deepcopy(many['rows'][0]),rule='overflow'));self.assertFalse(self.valid(many))
    def test_transition_requires_exact_predecessor_and_preserves_prior_rows(self):
        old=self.specimen();new=self.close(copy.deepcopy(old));new['previous']='5'*64
        transition=lambda a,b,p:self.results.transition(self.table(a) if a else None,self.table(b),p.encode(),self.codec.json)
        self.assertTrue(transition(None,old,'none'));self.assertTrue(transition(old,new,'5'*64));self.assertFalse(transition(old,new,'6'*64))
        bad=copy.deepcopy(new);bad['rows'][0]['job']='456';self.assertFalse(transition(old,bad,'5'*64))
        append=copy.deepcopy(new);append['previous']='6'*64;append['rows'].append(dict(copy.deepcopy(old['rows'][0]),rule='ddns_b'));self.assertTrue(transition(new,append,'6'*64));self.assertFalse(transition(old,append,'6'*64))
    def test_retirement_proof_is_bound_to_original_job_and_all_hashes(self):
        d=self.close(self.specimen());r=d['rows'][0]
        for index in [2,3,4,6,7,8,9,10,11,12]:
            fields=r['retired'].splitlines();fields[index]='other';self.assertFalse(self.results.proof(self.table(r),d['identity'].encode(),('\n'.join(fields)+'\n').encode()))
        self.assertFalse(self.results.proof(self.table(r),d['identity'].encode(),(r['retired']+'\n').encode()))
    def test_closed_gates_fixed_files_grammar_and_independent_guard(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-ddns-batch.sh','homegate-ddns-batch-results.sh']:
            body=(PROTO/name).read_bytes();self.assertEqual(body.count(b'ddns_batch_closeout_enabled=false'),1);self.assertFalse(parser.parse(body).root_node.has_error);self.assertNotIn(b'\r',body)
        for name in ['ddns-batch-results.lua','homegate-ddns-batch-results.lua']:self.lua.compile((PROTO/name).read_bytes())
        body=(PROTO/'homegate-config-prototype.sh').read_text();self.assertIn('check-recovery',body);self.assertIn('check-writer',body);self.assertIn('dns-batch-results',body)
        helper=(PROTO/'homegate-ddns-batch-results.sh').read_text();self.assertNotIn('curl',helper);self.assertNotIn('rm -r',helper);self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class ResultsMixin:
    def setUp(self):
        super().setUp();self.results_helper=self.engine.parent/'homegate-ddns-batch-results.sh';self.history=self.store/'dns-batch-results';self.history_next=self.store/'.dns-batch-results-next'
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        for helper in [self.batch_helper,self.results_helper]:
            body=helper.read_text().replace('ddns_batch_closeout_enabled=false','ddns_batch_closeout_enabled=true')
            if helper==self.results_helper:body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
            helper.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
        wrapper=self.engine.parent/'homegate-ddns-batch-results.lua';wrapper.write_text(wrapper.read_text().replace("local store='/etc/homegate/transactions'","local store="+repr(str(self.store))))
        revision=self.cli('status')['revision'];body=(self.store/f'gen-{revision}/public.conf').read_text();body=re.sub(r"(config ddns_rule 'ddns_b'\n(?:[^\n]*\n)*?\s+option host )'www.example.test'",r"\1'other.example.test'",body,count=1);self.assertIn("option host 'other.example.test'",body)
        p=self.cli('preview',payload=body.encode());tx=self.cli('commit-apply-projection',p['confirmation']);self.cli('projection-publish',tx['apply_handle'],'apply');self.cli('apply-finish-projection',tx['apply_handle']);p=self.auth('preview-rules','ddns_a,ddns_b');self.auth('commit',p['confirmation']);self.baseline_config=self.config_bytes()
    def batch_call(self,expected=0,args=None,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.batch_helper),*(args if args is not None else ['sync','--confirm-closeouts'])],env=env or self.env,capture_output=True,timeout=120)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0);self.assertFalse(out['write_ready'])
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',b'pppoe-wan',b'identity',b'generation',b'grant']:self.assertNotIn(marker,p.stdout)
        self.assertEqual(self.config_bytes(),self.baseline_config);return out
    def results_call(self,action,expected=0,args=None,env=None):
        n=len(self.calls);p=subprocess.run([self.busybox,'ash',str(self.results_helper),*(args or ([action] if action=='status' else [action,'--confirm']))],env=env or self.env,capture_output=True,timeout=60)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertEqual(len(self.calls),n)
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',b'pppoe-wan']:self.assertNotIn(marker,p.stdout)
        return json.loads(p.stdout)
    def record(self,path=None):
        raw=(path or self.history).read_bytes();body,digest=raw.splitlines();self.assertEqual(hashlib.sha256(body+b'\n').hexdigest().encode(),digest);return json.loads(body)
    def pending(self,tool='mv',code=None):
        self.fault(tool,code or 'sys.exit(1) if any(a.endswith("/.dns-batch-results-next") for a in sys.argv[1:]) else None');self.batch_call(7);self.restore_tool(tool);self.assertEqual(len(self.mutations()),1);self.cli('writer-check',expected=4)
    def test_two_distinct_mutations_keep_original_proofs_and_one_sample(self):
        out=self.batch_call();self.assertEqual([r['status'] for r in out['rules']],['created','created']);self.assertEqual([r['closeout'] for r in out['rules']],['retired','retired']);self.assertEqual(len(self.mutations()),2);self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes'])
        record=self.record();self.assertEqual([r['rule'] for r in record['rows']],['ddns_a','ddns_b']);self.assertEqual([r['state'] for r in record['rows']],['closed','closed']);self.assertNotEqual(record['rows'][0]['job'],record['rows'][1]['job'])
        for r in record['rows']:self.assertEqual(json.loads(r['receipt'])['effect'],'confirmed');self.assertEqual(json.loads(r['result'])['rule'],r['rule']);self.assertIn(r['job'],r['retired'])
        self.assertFalse(self.journal.exists());self.assertFalse(self.archive.exists());self.assertFalse(self.ledger.exists());self.cli('writer-check');self.assertEqual(len(self.results_call('status')['rules']),2)
        before=self.history.read_bytes();n=len(self.calls);self.batch_call(4);self.assertEqual(self.history.read_bytes(),before);self.assertEqual(len(self.calls),n)
    def test_default_confirmation_still_stops_before_second_mutation(self):
        out=self.batch_call(4,['sync','--confirm']);self.assertEqual([r['status'] for r in out['rules']],['created','blocked']);self.assertFalse(self.history.exists());self.assertEqual(len(self.mutations()),1)
        self.maintenance('collect-receipt');archive=self.files(self.archive);n=len(self.calls);self.batch_call(4);self.assertEqual(self.files(self.archive),archive);self.assertEqual(len(self.calls),n)
    def test_unknown_receipt_never_gets_history_or_closeout(self):
        def hook(*args):
            action=args[0];mutation=action!='GET' if self.provider in ['cloudflare','huaweicloud'] else action==('AddDomainRecord' if self.provider=='aliyun' else 'CreateRecord')
            if mutation:self.seed();return 500,{'success':False,'errors':[],'Code':'InternalError','code':'busy','Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
        self.hook=hook;out=self.batch_call(1);self.hook=None;self.assertEqual(out['effect'],'unknown');self.assertFalse(self.history.exists());self.assertFalse(self.archive.exists());before=self.files(self.journal);n=len(self.calls);self.batch_call(4);self.results_call('recover',7);self.assertEqual(len(self.calls),n);self.assertEqual(before,self.files(self.journal))

class CF(ResultsMixin,CFBase):pass
class Ali(ResultsMixin,AliBase):pass
class DNP(ResultsMixin,DNPBase):pass
class HW(ResultsMixin,HWBase):pass

class Boundaries(CF):
    def test_pending_publication_recovers_without_cloud_write(self):
        self.pending();self.assertTrue(self.history_next.exists());self.assertTrue(self.archive.exists());self.assertFalse(self.history.exists());self.results_call('recover');self.assertEqual(self.record()['rows'][0]['state'],'closed');self.assertFalse(self.archive.exists());self.assertEqual(len(self.mutations()),1);self.cli('writer-check');self.results_call('recover')
    def test_partial_retirement_recovers_original_pending_row(self):
        self.pending('rm','sys.exit(1) if any("/dns-retiring/" in a and a.endswith("/context") for a in sys.argv[1:]) else None');self.assertEqual(self.record()['rows'][0]['state'],'recorded');self.assertTrue((self.store/'dns-retiring').exists());self.results_call('recover');self.assertEqual(self.record()['rows'][0]['state'],'closed');self.cli('writer-check')
    def test_closed_stage_after_retirement_recovers_without_second_mutation(self):
        self.pending('mv','from pathlib import Path\nsys.exit(1) if any(a.endswith("/.dns-batch-results-next") and b\'"state":"closed"\' in Path(a).read_bytes() for a in sys.argv[1:]) else None');self.assertEqual(self.record()['rows'][0]['state'],'recorded');self.assertEqual(self.record(self.history_next)['rows'][0]['state'],'closed');self.assertFalse(self.archive.exists());self.results_call('recover');self.cli('writer-check');self.assertEqual(self.record()['rows'][0]['state'],'closed')
    def test_corrupt_stage_keeps_guard_with_feature_gate_disabled(self):
        self.pending();self.history_next.write_bytes(self.history_next.read_bytes()+b' ');before=self.history_next.read_bytes();self.results_call('recover',7);self.results_helper.write_text(self.results_helper.read_text().replace('ddns_batch_closeout_enabled=true','ddns_batch_closeout_enabled=false'));self.cli('writer-check',expected=4);self.results_call('recover',2);self.assertEqual(self.history_next.read_bytes(),before);self.assertTrue(self.archive.exists())
    def test_foreign_stage_identity_is_not_published_or_removed(self):
        self.pending();d=self.record(self.history_next);d['identity']='0'*64;body=json.dumps(d,sort_keys=True,separators=(',',':')).encode()+b'\n';self.history_next.write_bytes(body+hashlib.sha256(body).hexdigest().encode()+b'\n');before=self.history_next.read_bytes();self.results_call('recover',7);self.cli('writer-check',expected=4);self.assertEqual(before,self.history_next.read_bytes());self.assertTrue(self.archive.exists())
    def test_changed_source_preserves_pending_original_archive(self):
        self.pending();before=self.files(self.archive);self.source.write_bytes(self.source.read_bytes()+b'\n');self.results_call('recover',7);self.assertEqual(before,self.files(self.archive));self.assertEqual(self.record()['rows'][0]['state'],'recorded');self.cli('writer-check',expected=4)
    def test_revoked_grant_allows_read_only_closeout(self):
        self.pending();self.revoke_fixture();self.results_call('recover');self.assertEqual(self.record()['rows'][0]['state'],'closed');self.cli('writer-check');self.assertEqual(len(self.mutations()),1)
    def test_forget_requires_closed_history_and_explicit_confirmation(self):
        self.pending();self.results_call('forget',4);self.assertTrue(self.history_next.exists());self.results_call('recover');self.results_call('forget',2,args=['forget']);self.results_call('forget');self.assertFalse(self.history.exists());self.cli('writer-check');self.assertEqual(len(self.mutations()),1)
    def test_new_gates_and_internal_parent_cannot_be_enabled_by_environment(self):
        self.batch_helper.write_text(self.batch_helper.read_text().replace('ddns_batch_closeout_enabled=true','ddns_batch_closeout_enabled=false'));self.batch_call(2,env={**self.env,'ddns_batch_closeout_enabled':'true'});self.results_call('capture-close',7,args=['capture-close','ddns_a',str(os.getpid())]);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();suite=unittest.TestSuite()
    for cls in ([CF,Ali,DNP,HW,Boundaries] if a.runtime else [Static]):
        methods=Boundaries.__dict__ if cls is Boundaries else ResultsMixin.__dict__ if a.runtime else Static.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v))
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
