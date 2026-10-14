#!/usr/bin/env python3
"""Explicit read-only reconciliation; loopback TLS only, evidence never released."""
import argparse,copy,json,subprocess,unittest
from Cloudflare记录回归 import Static as RecordStatic,Runtime as RecordRuntime,PROTO,ZID,rec,envelope

class Static(RecordStatic):
    def setUp(self):
        super().setUp();self.reconcile=self.lua.execute((PROTO/'cloudflare-reconcile-plan.lua').read_bytes())
    def original(self,q=None):
        q=q or self.ddns();c=self.bind(q);c[b'request']=self.lua.table_from(q,recursive=True)
        c[b'zone_id']=b'f'*32;c[b'attempted']=True;c[b'stage']=b'create';return c
    def restore(self,old):return self.reconcile.restore(self.snapshot,b'dns_a',b'3',old,self.plan)
    def test_restores_only_bound_attempted_operations(self):
        c=self.restore(self.original());self.assertTrue(c[b'reconciliation']);self.assertFalse(c[b'attempted'])
        for key,val in [(b'account',b'other'),(b'revision',2),(b'attempted',False),(b'zone_id',b'../bad'),(b'fqdn',b'other.test'),(b'value',b'2001:db8::3'),(b'ttl',60),(b'stage',b'records')]:
            old=self.original();old[key]=val;self.assertIsNone(self.restore(old)[0],key)
    def test_update_requires_frozen_aaaa_target_and_verified_create_requires_id(self):
        old=self.original();old[b'stage']=b'update';self.assertIsNone(self.restore(old)[0]);old[b'first_id']=b'a'*32;self.assertIsNotNone(self.restore(old))
        old[b'stage']=b'verify-upsert';self.assertIsNone(self.restore(old)[0]);old[b'new_id']=b'b'*32;self.assertIsNotNone(self.restore(old))
    def test_desired_presence_is_observation_not_mutation_ownership(self):
        c=self.restore(self.original());self.assertEqual(self.reconcile.result(c),b'desired-absent')
        r=self.plan.record(c,self.lua.table_from({b'id':b'a'*32,b'type':b'AAAA',b'name':b'www.example.test',b'content':b'2001:0db8::2'}))
        self.reconcile.observe(c,r);self.assertEqual(self.reconcile.result(c),b'desired-present');self.assertFalse(c[b'attempted'])
    def test_delete_plan_tracks_all_frozen_ids_and_detects_changed_value(self):
        old=self.original(self.ddns(operation=b'delete'));old[b'stage']=b'delete';old[b'position']=1;old[b'delete_ids']=self.lua.table_from([b'a'*32,b'b'*32])
        c=self.restore(old);self.assertEqual(self.reconcile.result(c),b'planned-targets-absent')
        self.reconcile.observe(c,self.lua.table_from({b'id':b'c'*32,b'match':True}));self.assertEqual(self.reconcile.result(c),b'planned-targets-absent')
        self.reconcile.observe(c,self.lua.table_from({b'id':b'a'*32,b'match':True}));self.assertEqual(self.reconcile.result(c),b'planned-targets-present')
        self.reconcile.observe(c,self.lua.table_from({b'id':b'b'*32,b'match':False}));self.assertEqual(self.reconcile.result(c),b'conflict')
    def test_invalid_delete_array_position_or_confirmed_count_is_rejected(self):
        for ids,pos,count in [([],1,0),([b'a'*32,b'a'*32],1,0),([b'a'*32],0,0),([b'a'*32],2,0),([b'a'*32],1,1),([b'bad'],1,0)]:
            old=self.original(self.ddns(operation=b'delete'));old[b'stage']=b'delete';old[b'delete_ids']=self.lua.table_from(ids);old[b'position']=pos;old[b'affected']=count
            self.assertIsNone(self.restore(old)[0])
    def test_all_new_gates_closed_and_data_module_has_no_execution(self):
        self.test_closed_record_gates_shell_ast_and_no_production_install()
        for n in ['homegate-cloudflare-read.sh','homegate-cloudflare-worker.sh','homegate-service-observer-watchdog.sh']:
            b=(PROTO/n).read_bytes();self.assertEqual(b.count(b'dns_reconcile_enabled=false'),1);self.assertNotIn(b'dns_reconcile_enabled=true',b)
        for n in ['cloudflare-reconcile-plan.lua','cloudflare-records.lua']:
            b=(PROTO/n).read_bytes();self.lua.compile(b);self.assertNotIn(b'os.execute',b);self.assertNotIn(b'os.getenv',b)

class Runtime(RecordRuntime):
    def setUp(self):
        super().setUp()
        for n in ['homegate-cloudflare-read.sh','homegate-cloudflare-worker.sh','homegate-service-observer-watchdog.sh']:
            p=self.engine.parent/n;p.write_text(p.read_text().replace('dns_reconcile_enabled=false','dns_reconcile_enabled=true'))
    def pending(self,q=None,apply=True):
        def hook(method,path,query,data):
            if method=='POST':
                if apply:self.next_id+=1;self.db[format(self.next_id,'032x')]={'id':format(self.next_id,'032x'),**data}
                return 500,{'success':False,'errors':[{'code':10000,'message':'PRIVATE_SENTINEL unknown'}]}
        self.hook=hook;self.records(q,1);self.hook=None
        self.old=list(self.native.lockdir.glob('.dns-check-*'))[0]
        self.saved={p.name:p.read_bytes() for p in self.old.iterdir()};self.oldjob=self.old.name.rsplit('-',1)[1]
        self.before=len(self.mutations());return self.old
    def reconcile(self,expected=0,account='dns_a',args=None):
        p=subprocess.run([self.busybox,'ash',str(self.reader),*(args or [account,'--reconcile',self.oldjob,'--confirm'])],env=self.env,capture_output=True,timeout=12)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr));self.assertEqual(p.stderr,b'')
        r=json.loads(p.stdout);self.assertEqual(r['ok'],expected==0)
        for marker in [b'PRIVATE_SENTINEL',b'TXT_PRIVATE_VALUE',b'2001:db8::2',b'example.test']:self.assertNotIn(marker,p.stdout)
        self.assertEqual(len(self.mutations()),self.before)
        self.assertEqual({p.name:p.read_bytes() for p in self.old.iterdir()},self.saved)
        self.assertEqual(list(self.native.lockdir.glob('.dns-check-*')),[self.old])
        if expected in [0,1]:
            self.assertEqual((r['check_scope'],r['effect'],r['reconciliation_required'],r['retryable']),('record-reconciliation','unknown',True,False))
        return r
    def change_context(self,fn):
        p=self.old/'context';d=json.loads(p.read_bytes());fn(d);p.write_bytes(self.encoded(d));self.saved['context']=p.read_bytes()
    def test_applied_create_observed_but_original_evidence_and_block_remain(self):
        self.pending();self.assertEqual(self.reconcile()['observation'],'desired-present');self.records(expected=4);self.check(4);self.preserved()
    def test_unapplied_create_is_absent_without_automatic_retry(self):
        self.pending(apply=False);self.assertEqual(self.reconcile()['observation'],'desired-absent');self.assertEqual(self.db,{})
    def test_txt_matching_value_preserves_other_challenge_and_can_be_rechecked(self):
        self.add(rec(1,'TXT','_acme-challenge.example.test','OTHER'));self.pending(self.txt())
        self.assertEqual(self.reconcile()['observation'],'desired-present');self.assertEqual(self.reconcile()['observation'],'desired-present');self.assertEqual(len(self.db),2)
    def test_complete_pagination_is_required_before_observation(self):
        self.pending();self.page_size=1;self.add(rec(1),rec(2,value='2001:db8::3'))
        self.assertEqual(self.reconcile()['observation'],'desired-present');self.assertTrue(any('page=3' in x['path'] for x in self.calls))
    def test_wrong_generation_or_scope_stops_before_http(self):
        self.pending();calls=len(self.calls);self.change_context(lambda d:d.update(revision=2))
        self.reconcile(1);self.assertEqual(len(self.calls),calls)
    def test_wrong_account_stops_before_http(self):
        self.pending();calls=len(self.calls);self.reconcile(1,account='other');self.assertEqual(len(self.calls),calls)
    def test_changed_zone_identity_is_refused_and_evidence_kept(self):
        self.pending();self.zone_results=[{'id':'e'*32,'name':'example.test'}];self.reconcile(1)
    def test_invalid_later_page_never_returns_partial_observation(self):
        self.pending();self.page_size=1;self.add(rec(1))
        def hook(method,path,q,data):
            if 'dns_records' in path and q.get('page')==['2']:return 200,envelope([rec(7,name='other.test')])
        self.hook=hook;self.reconcile(1)
    def test_duplicate_record_ids_or_drifting_totals_are_refused(self):
        self.pending()
        def hook(method,path,q,data):
            if 'dns_records' in path:return 200,envelope([rec(1),rec(1)])
        self.hook=hook;self.reconcile(1)
    def test_transport_failure_keeps_uncertainty_and_never_mutates(self):
        self.pending()
        self.hook=lambda *args:(500,{'success':False,'errors':[{'code':10000}]})
        r=self.reconcile(1);self.assertEqual(r['observation'],'incomplete')
    def test_delete_absence_and_reused_id_conflict_are_distinct_observations(self):
        self.add(rec(1,value='2001:db8::2'))
        def hook(method,path,q,data):
            if method=='DELETE':self.db.clear();return 500,{'success':False,'errors':[]}
        self.hook=hook;self.records(self.payload(operation='delete'),1);self.hook=None
        self.old=list(self.native.lockdir.glob('.dns-check-*'))[0];self.oldjob=self.old.name.rsplit('-',1)[1];self.saved={p.name:p.read_bytes() for p in self.old.iterdir()};self.before=len(self.mutations())
        self.assertEqual(self.reconcile()['observation'],'planned-targets-absent')
        self.add(rec(1,value='2001:db8::3'));self.assertEqual(self.reconcile()['observation'],'conflict')
    def test_delete_present_target_never_gets_deleted_during_reconciliation(self):
        self.pending(apply=False);self.change_context(lambda d:d.update(operation='delete',request={**self.payload(),'operation':'delete'},stage='delete',delete_ids=[format(1,'032x')],position=1))
        self.add(rec(1,value='2001:db8::2'));self.assertEqual(self.reconcile()['observation'],'planned-targets-present')
    def test_explicit_confirmation_and_numeric_fixed_job_are_required(self):
        self.pending();calls=len(self.calls)
        for args in [['dns_a','--reconcile',self.oldjob],['dns_a','--reconcile','../bad','--confirm'],['dns_a','--reconcile','0'+self.oldjob,'--confirm'],['dns_a','--reconcile',self.oldjob,'--confirm','extra']]:self.reconcile(2,args=args)
        self.assertEqual(len(self.calls),calls)
    def test_symlink_or_hardlink_original_context_refused_before_http(self):
        self.pending();calls=len(self.calls);p=self.old/'context';backup=self.base/'savedcontext';p.rename(backup);p.symlink_to(backup)
        self.reconcile(7);self.assertEqual(len(self.calls),calls)
    def test_second_orphan_blocks_reconciliation_without_collection(self):
        self.pending();other=self.native.lockdir/'.dns-check-999999999';other.mkdir(mode=0o700)
        p=subprocess.run([self.busybox,'ash',str(self.reader),'dns_a','--reconcile',self.oldjob,'--confirm'],env=self.env,capture_output=True,timeout=5)
        self.assertEqual(p.returncode,4);self.assertTrue(other.is_dir());self.assertEqual(len(self.mutations()),self.before)
    def test_production_gate_cannot_be_enabled_by_environment(self):
        self.pending();self.reader.write_text(self.reader.read_text().replace('dns_reconcile_enabled=true','dns_reconcile_enabled=false'))
        self.env['dns_reconcile_enabled']='true';self.reconcile(2)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
