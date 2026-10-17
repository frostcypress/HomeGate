#!/usr/bin/env python3
"""AliDNS private read-only reconciliation and shared durable checkpoint tests."""
import argparse,hashlib,json,os,re,shutil,subprocess,unittest
from pathlib import Path
from project import ROOT
from Aliyun记录回归 import Runtime as RecordRuntime,record,VALUE,PROTO
from Cloudflare记录回归 import Static as PlanStatic

class Static(PlanStatic):
    def setUp(self):
        super().setUp();self.recovery=self.lua.execute((PROTO/'aliyun-reconcile-plan.lua').read_bytes());self.records_module=self.lua.execute((PROTO/'aliyun-records.lua').read_bytes())
    def context(self):
        q=self.ddns();c=self.bind(q);c[b'schema']=b'HGALIRECORD1';c[b'rr']=b'www';c[b'request']=self.lua.table_from(q,recursive=True);c[b'attempted']=True;c[b'stage']=b'AddDomainRecord';c[b'records']=self.lua.table_from([]);return c
    def restore(self,c):return self.recovery.restore(self.snapshot,b'dns_a',b'3',c,self.plan,self.records_module,self.codec.json)
    def stored(self,n=1,value=b'2001:db8::2'):
        c=self.context();r=self.lua.table_from({b'RecordId':str(n).encode(),b'DomainName':b'example.test',b'RR':b'www',b'Type':b'AAAA',b'Value':value,b'TTL':600,b'Line':b'default',b'Locked':False,b'Status':b'Enable'})
        return self.records_module.record(c,r,self.plan)
    def test_strict_rebinding_rejects_modified_scope_and_unknown_fields(self):
        self.assertIsNotNone(self.restore(self.context()))
        for key,value in [(b'account',b'other'),(b'revision',2),(b'fqdn',b'other.test'),(b'ttl',60),(b'value',b'2001:db8::9'),(b'attempted',False),(b'stage',b'planned'),(b'url',b'https://bad.invalid')]:
            c=self.context();c[key]=value;self.assertIsNone(self.restore(c),key)
    def test_export_excludes_credentials_and_transport(self):
        c=self.context();c[b'token']=b'SECRET_SENTINEL';c[b'headers']=b'SECRET_SENTINEL';c[b'last_id']=b'999';c[b'stage']=b'verify-AddDomainRecord'
        out=self.recovery.export(c);self.assertNotIn(b'SECRET_SENTINEL',self.codec.json(out));self.assertIsNone(out[b'last_id']);self.assertIsNotNone(self.restore(out))
    def test_frozen_delete_plan_requires_exact_position_and_confirmed_prefix(self):
        c=self.context();c[b'operation']=b'delete';c[b'request'][b'operation']=b'delete';c[b'stage']=b'DeleteDomainRecord';c[b'records']=self.lua.table_from([self.stored(1),self.stored(2)]);c[b'position']=1;c[b'target_id']=b'1'
        self.assertIsNotNone(self.restore(c));before=self.lua.table_from(dict(c.items()))
        c[b'position']=2;c[b'target_id']=b'2';c[b'affected']=1;self.assertIsNotNone(self.restore(c))
        self.assertTrue(self.recovery.advance(before,c,self.codec.json))
        c[b'affected']=0;self.assertIsNone(self.restore(c));c[b'affected']=1;c[b'records'][2][b'id']=b'1';self.assertIsNone(self.restore(c))
    def test_observation_does_not_acknowledge_ownership_or_clear_barrier(self):
        c=self.context();restored=self.restore(c);self.assertEqual(self.recovery.observe(restored,self.lua.table_from([self.stored()])),b'desired-present')
        raw=self.recovery.report(b'dns_a',b'3',b'',b'',b'desired-present');doc=json.loads(raw)
        self.assertEqual((doc['effect'],doc['reconciliation_required'],doc['retryable']),('unknown',True,False))
    def test_all_recovery_gates_closed_and_changed_grammar(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-aliyun-read.sh','homegate-aliyun-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh','homegate-dns-receipt.sh','homegate-config-prototype.sh']:
            b=(PROTO/name).read_bytes();self.assertNotIn(b'\r',b);self.assertFalse(parser.parse(b).root_node.has_error,name)
            if name!='homegate-config-prototype.sh':self.assertEqual(b.count(b'aliyun_receipt_enabled=false'),1)
        for name in ['aliyun-reconcile-plan.lua','aliyun-checkpoint.lua']:self.lua.compile((PROTO/name).read_bytes())
        body=(PROTO/'homegate-dns-receipt.sh').read_text();self.assertIn('HGALIJOURNAL1',body)
        self.assertLess(body.index('fsync "$stage/context"'),body.index('mv "$stage" "$inactive"'))
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

class Runtime(RecordRuntime):
    def contents(self):
        return {k:v for k,v in super().contents().items() if not k.startswith('dns-operation/') and k!='dns-operation'}
    def setUp(self):
        super().setUp();self.journal=self.store/'dns-operation';self.helper=self.engine.parent/'homegate-dns-receipt.sh'
        for name in ['homegate-aliyun-read.sh','homegate-aliyun-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh','homegate-dns-receipt.sh']:
            p=self.engine.parent/name;s=p.read_text().replace('aliyun_receipt_enabled=false','aliyun_receipt_enabled=true').replace('aliyun_reconcile_enabled=false','aliyun_reconcile_enabled=true').replace('dns_reconcile_enabled=false','dns_reconcile_enabled=true')
            if name=='homegate-service-observer-watchdog.sh':s=s.replace('action=cloudflare-check; budget=4','action=cloudflare-check; budget=8')
            if name=='homegate-dns-receipt.sh':
                mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
                s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
                s=s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
            p.write_text(s)
        self.engine.write_text(self.engine.read_text().replace('dns_recovery_read_enabled=false','dns_recovery_read_enabled=true'))
        p=self.engine.parent/'aliyun-checkpoint.lua';p.write_text(p.read_text().replace("local json=require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json=require('luci.jsonc')"))
    def active(self):
        current=(self.journal/'current').read_bytes();self.assertIn(current,[b'1\n',b'2\n']);slot=self.journal/('slot-'+current.decode().strip())
        raw=(slot/'context').read_bytes();meta=(slot/'manifest').read_bytes();lines=meta.splitlines();self.assertEqual(len(lines),10)
        self.assertEqual(lines[:2],[b'HGALIJOURNAL1',b'homegate']);self.assertEqual(lines[2],hashlib.sha256(self.identity.read_bytes()).hexdigest().encode())
        self.assertEqual(lines[4],(self.store/'current').read_bytes().strip());self.assertEqual(lines[5],b'dns_a')
        self.assertEqual(lines[7],hashlib.sha256((self.store/('gen-'+lines[4].decode())/'manifest').read_bytes()).hexdigest().encode())
        self.assertEqual(lines[8],hashlib.sha256(raw).hexdigest().encode());self.assertEqual(lines[9],hashlib.sha256(b'\n'.join(lines[:9])+b'\n').hexdigest().encode())
        for p in [self.journal,*self.journal.rglob('*')]:
            self.assertFalse(p.is_symlink());self.assertEqual(p.stat().st_mode&0o777,0o700 if p.is_dir() else 0o600)
            if p.is_file():self.assertEqual(p.stat().st_nlink,1);self.assertNotIn(b'SECRET_SENTINEL',p.read_bytes());self.assertNotIn(b'OLD_ID',p.read_bytes())
        return json.loads(raw),raw
    def journal_bytes(self):return {p.relative_to(self.journal).as_posix():p.read_bytes() for p in self.journal.rglob('*') if p.is_file()}
    def blocked(self):
        self.writer(4);self.cli('writer-check',expected=4);self.cli('credential-delete','aliyun','dns_a','secret',expected=4);self.cli('cancel',expected=4);self.records(expected=4);self.aliyun(expected=4)
    def pending(self,apply=True,q=None):
        def hook(action,params):
            if action=='AddDomainRecord':
                self.active()
                if apply:self.db['5000']=record(5000,params['Type'][0],params['RR'][0],params['Value'][0])
                return 500,{'Code':'InternalError','Message':'SECRET_SENTINEL'}
        self.hook=hook;self.records(q,1);self.hook=None
        self.old=list(self.native.lockdir.glob('.dns-check-*'))[0];self.oldjob=self.old.name.rsplit('-',1)[1]
        self.saved={p.name:p.read_bytes() for p in self.old.iterdir()};self.saved_journal=self.journal_bytes();self.before=len(self.mutations())
    def reconcile(self,expected=0,durable=False,account='dns_a'):
        args=[account,'--reconcile-receipt' if durable else '--reconcile',self.oldjob,'--confirm']
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),*args],env=self.env,capture_output=True,timeout=15)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr));self.assertEqual(p.stderr,b'');out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        self.assertEqual(self.journal_bytes(),self.saved_journal);self.assertEqual(len(self.mutations()),self.before)
        if self.old.exists():self.assertEqual({f.name:f.read_bytes() for f in self.old.iterdir()},self.saved)
        if expected in [0,1]:self.assertEqual([f for f in self.native.lockdir.glob('.dns-check-*') if f!=self.old],[])
        for secret in [b'SECRET_SENTINEL',b'OLD_ID',b'TXT_PRIVATE_VALUE',b'example.test',b'2001:db8::2']:self.assertNotIn(secret,p.stdout)
        if expected in [0,1]:self.assertEqual((out['effect'],out['retryable'],out['reconciliation_required']),('unknown',False,True))
        return out
    def test_checkpoint_precedes_real_mutation_and_success_stays_fenced(self):
        seen=[]
        self.hook=lambda action,q:seen.append(self.active()[0]['stage']) if action=='AddDomainRecord' else None
        self.records();self.assertEqual(seen,['AddDomainRecord']);self.active();self.blocked()
    def test_applied_create_observed_without_acknowledgement(self):
        self.pending();self.assertEqual(self.reconcile()['observation'],'desired-present');self.assertEqual(self.reconcile(durable=True)['observation'],'desired-present');self.blocked()
    def test_unapplied_create_is_absent_without_retry(self):
        self.pending(apply=False);self.assertEqual(self.reconcile(durable=True)['observation'],'desired-absent');self.assertEqual(self.db,{})
    def test_txt_observation_preserves_other_challenges(self):
        self.add(record(1,'TXT','_acme-challenge','OTHER'));self.pending(q=self.txt());self.assertEqual(self.reconcile(durable=True)['observation'],'desired-present');self.assertEqual(len(self.db),2)
    def test_simulated_boot_change_and_volatile_loss_keep_barrier_and_allow_read(self):
        self.pending();self.assertTrue(self.old.resolve().is_relative_to(self.native.base.resolve()));shutil.rmtree(self.old)
        self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.blocked();self.assertEqual(self.reconcile(durable=True)['observation'],'desired-present');self.blocked()
    def test_changed_source_is_refused_before_observation(self):
        self.pending();calls=len(self.calls);self.source.write_bytes(self.source.read_bytes().replace(b'OLD_ID',b'NEW_ID'));self.reconcile(1);self.assertEqual(len(self.calls),calls)
    def test_wrong_scope_context_is_rejected_before_http(self):
        self.pending();calls=len(self.calls);p=self.old/'context';c=json.loads(p.read_bytes());c['fqdn']='other.test';p.write_bytes(self.encoded(c));self.saved['context']=p.read_bytes()
        self.reconcile(1);self.assertEqual(len(self.calls),calls)
    def test_later_page_error_returns_no_partial_observation(self):
        self.pending();self.add(*(record(i) for i in range(1,102)))
        self.hook=lambda action,q:(429,{'Code':'Throttling','Message':'SECRET_SENTINEL'}) if q.get('PageNumber')==['2'] else None
        self.assertEqual(self.reconcile(1,durable=True)['observation'],'incomplete')
    def test_three_deletions_rotate_shared_two_slots(self):
        self.add(*(record(i,value='2001:db8::2') for i in [1,2,3]));self.records(self.payload(operation='delete'))
        c,_=self.active();self.assertEqual((c['position'],c['affected']), (3,2));self.assertEqual(self.db,{})
        self.assertEqual({p.name for p in self.journal.iterdir()},{'current','slot-1','slot-2'});self.blocked()
    def test_context_fsync_failure_prevents_any_mutation(self):
        self.fault('fsync','if any(v.endswith("/.prepare/context") for v in sys.argv[1:]):sys.exit(1)');self.records(expected=1);self.assertEqual(self.mutations(),[]);self.assertTrue(self.journal.exists());self.blocked()
    def test_pointer_rename_failure_keeps_recovery_barrier(self):
        self.fault('mv','if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)');self.records(expected=1);self.assertEqual(self.mutations(),[]);self.assertTrue((self.journal/'.next').exists());self.blocked()
    def test_failed_second_checkpoint_keeps_first_active_context(self):
        self.add(record(1,value='2001:db8::2'),record(2,value='2001:db8::2'));saved=[]
        def hook(action,q):
            if action=='DeleteDomainRecord' and not saved:saved.append(self.active()[1]);self.fault('fsync','if any(v.endswith("/.prepare/context") for v in sys.argv[1:]):sys.exit(1)')
        self.hook=hook;self.records(self.payload(operation='delete'),1);self.assertEqual(self.active()[1],saved[0]);self.assertEqual(len(self.mutations()),1);self.blocked()
    def test_cross_provider_manifest_rejected_without_changing_evidence(self):
        self.pending();p=self.journal/('slot-'+(self.journal/'current').read_text().strip())/'manifest';p.write_bytes(p.read_bytes().replace(b'HGALIJOURNAL1',b'HGCFJOURNAL1'));self.saved_journal=self.journal_bytes()
        self.reconcile(7,durable=True);self.blocked()
    def test_delete_observation_tracks_frozen_ids_and_changed_values(self):
        self.add(record(1,value='2001:db8::2'),record(2,value='2001:db8::2'))
        def hook(action,q):
            if action=='DeleteDomainRecord':self.db.pop(q['RecordId'][0],None);return 500,{'Code':'InternalError'}
        self.hook=hook;self.records(self.payload(operation='delete'),1);self.hook=None
        self.old=list(self.native.lockdir.glob('.dns-check-*'))[0];self.oldjob=self.old.name.rsplit('-',1)[1];self.saved={p.name:p.read_bytes() for p in self.old.iterdir()};self.saved_journal=self.journal_bytes();self.before=len(self.mutations())
        self.assertEqual(self.reconcile(durable=True)['observation'],'planned-targets-present');self.db['2']['Value']='2001:db8::9'
        self.assertEqual(self.reconcile(durable=True)['observation'],'conflict');self.db.clear();self.assertEqual(self.reconcile(durable=True)['observation'],'planned-targets-absent')
    def test_closed_recovery_gate_cannot_be_enabled_by_environment(self):
        self.pending();p=self.ali_entry;p.write_text(p.read_text().replace('aliyun_reconcile_enabled=true','aliyun_reconcile_enabled=false'))
        calls=len(self.calls)
        result=subprocess.run([self.busybox,'ash',str(p),'dns_a','--reconcile',self.oldjob,'--confirm'],env={**self.env,'aliyun_reconcile_enabled':'true'},capture_output=True,timeout=5)
        self.assertEqual(result.returncode,2);self.assertEqual(result.stderr,b'');self.assertEqual(len(self.calls),calls);self.assertEqual(self.journal_bytes(),self.saved_journal)
    def test_context_hash_mismatch_prevents_durable_observation(self):
        self.pending();calls=len(self.calls);slot=self.journal/('slot-'+(self.journal/'current').read_text().strip())
        p=slot/'context';p.write_bytes(p.read_bytes().replace(b'2001:db8::2',b'2001:db8::9'));self.saved_journal=self.journal_bytes()
        self.reconcile(7,durable=True);self.assertEqual(len(self.calls),calls);self.blocked()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if r.wasSuccessful() else 1)
