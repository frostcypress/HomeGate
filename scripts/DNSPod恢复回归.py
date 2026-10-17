#!/usr/bin/env python3
"""DNSPod same-boot/durable observation and shared checkpoint publication."""
import argparse,hashlib,json,os,re,shutil,subprocess,unittest
from DNSPod记录回归 import Runtime as RecordRuntime,record,PROTO
from Cloudflare记录回归 import Static as PlanStatic
from Aliyun恢复回归 import Runtime as AliRecoveryRuntime

class Static(PlanStatic):
    def setUp(self):
        super().setUp();self.recovery=self.lua.execute((PROTO/'dnspod-reconcile-plan.lua').read_bytes());self.records_module=self.lua.execute((PROTO/'dnspod-records.lua').read_bytes())
    def context(self):
        q=self.ddns();c=self.bind(q);c[b'schema']=b'HGDNPRECORD1';c[b'rr']=b'www';c[b'request']=self.lua.table_from(q,recursive=True);c[b'attempted']=True;c[b'stage']=b'CreateRecord';c[b'records']=self.lua.table_from([]);return c
    def restore(self,c):return self.recovery.restore(self.snapshot,b'dns_a',b'3',c,self.plan,self.records_module,self.codec.json)
    def stored(self,n=1):
        return self.records_module.record(self.context(),self.lua.table_from({b'RecordId':n,b'Name':b'www',b'Type':b'AAAA',b'Value':b'2001:db8::2',b'TTL':600,b'Line':b'default',b'LineId':b'0',b'Status':b'ENABLE',b'Remark':b''}),self.plan,False)
    def test_strict_rebinding_and_no_unknown_persistent_fields(self):
        self.assertIsNotNone(self.restore(self.context()))
        for key,value in [(b'schema',b'HGALIRECORD1'),(b'account',b'other'),(b'revision',2),(b'fqdn',b'other.test'),(b'ttl',30),(b'url',b'https://bad.invalid'),(b'attempted',False)]:
            c=self.context();c[key]=value;self.assertIsNone(self.restore(c),key)
    def test_frozen_delete_position_count_and_advance(self):
        c=self.context();c[b'operation']=b'delete';c[b'request'][b'operation']=b'delete';c[b'stage']=b'DeleteRecord';c[b'records']=self.lua.table_from([self.stored(1),self.stored(2)]);c[b'position']=1;c[b'target_id']=b'1';self.assertIsNotNone(self.restore(c));before=self.lua.table_from(dict(c.items()))
        c[b'position']=2;c[b'target_id']=b'2';c[b'affected']=1;self.assertIsNotNone(self.restore(c));self.assertTrue(self.recovery.advance(before,c,self.codec.json));c[b'affected']=0;self.assertIsNone(self.restore(c))
    def test_export_and_observation_never_acknowledge_unknown(self):
        c=self.context();c[b'token']=b'SECRET_SENTINEL';c[b'last_id']=b'999';c[b'stage']=b'verify-CreateRecord';out=self.recovery.export(c);self.assertNotIn(b'SECRET_SENTINEL',self.codec.json(out));self.assertIsNotNone(self.restore(out))
        self.assertEqual(self.recovery.observe(out,self.lua.table_from([self.stored()])),b'desired-present');doc=json.loads(self.recovery.report(b'dns_a',b'3',b'',b'',b'desired-present'));self.assertEqual((doc['effect'],doc['retryable'],doc['reconciliation_required']),('unknown',False,True))
    def test_closed_gates_grammar_and_private_codec(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-dnspod-read.sh','homegate-dnspod-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh','homegate-dns-receipt.sh']:
            b=(PROTO/n).read_bytes();self.assertFalse(parser.parse(b).root_node.has_error,n);self.assertNotIn(b'\r',b);self.assertEqual(b.count(b'dnspod_receipt_enabled=false'),1)
        for n in ['dnspod-reconcile-plan.lua','dnspod-checkpoint.lua','dnspod-reader.lua']:self.lua.compile((PROTO/n).read_bytes())
        b=(PROTO/'homegate-dns-receipt.sh').read_text();self.assertIn('HGDNPJOURNAL1',b);self.assertLess(b.index('fsync "$stage/context"'),b.index('mv "$stage" "$inactive"'));self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class Runtime(RecordRuntime):
    def contents(self):return {k:v for k,v in super().contents().items() if k!='dns-operation' and not k.startswith('dns-operation/')}
    def setUp(self):
        super().setUp();self.journal=self.store/'dns-operation';self.helper=self.engine.parent/'homegate-dns-receipt.sh'
        for n in ['homegate-dnspod-read.sh','homegate-dnspod-worker.sh','homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh','homegate-dns-receipt.sh']:
            p=self.engine.parent/n;s=p.read_text().replace('dnspod_receipt_enabled=false','dnspod_receipt_enabled=true').replace('dnspod_reconcile_enabled=false','dnspod_reconcile_enabled=true').replace('dns_reconcile_enabled=false','dns_reconcile_enabled=true')
            if n=='homegate-dns-receipt.sh':
                mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
                s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s);s=s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
            p.write_text(s)
        self.engine.write_text(self.engine.read_text().replace('dns_recovery_read_enabled=false','dns_recovery_read_enabled=true'))
        from project import ROOT
        p=self.engine.parent/'dnspod-checkpoint.lua';p.write_text(p.read_text().replace("local json=require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json=require('luci.jsonc')"))
    def active(self):
        current=(self.journal/'current').read_bytes();self.assertIn(current,[b'1\n',b'2\n']);slot=self.journal/('slot-'+current.decode().strip());raw=(slot/'context').read_bytes();meta=(slot/'manifest').read_bytes();lines=meta.splitlines();self.assertEqual(len(lines),10)
        self.assertEqual(lines[:2],[b'HGDNPJOURNAL1',b'homegate']);self.assertEqual(lines[2],hashlib.sha256(self.identity.read_bytes()).hexdigest().encode());self.assertEqual(lines[4],(self.store/'current').read_bytes().strip());self.assertEqual(lines[5],b'dns_a');self.assertEqual(lines[7],hashlib.sha256((self.store/('gen-'+lines[4].decode())/'manifest').read_bytes()).hexdigest().encode());self.assertEqual(lines[8],hashlib.sha256(raw).hexdigest().encode());self.assertEqual(lines[9],hashlib.sha256(b'\n'.join(lines[:9])+b'\n').hexdigest().encode())
        for p in [self.journal,*self.journal.rglob('*')]:
            self.assertFalse(p.is_symlink());self.assertEqual(p.stat().st_mode&0o777,0o700 if p.is_dir() else 0o600)
            if p.is_file():self.assertEqual(p.stat().st_nlink,1);self.assertNotIn(b'SECRET_SENTINEL',p.read_bytes());self.assertNotIn(b'OLD_ID',p.read_bytes())
        return json.loads(raw),raw
    journal_bytes=AliRecoveryRuntime.journal_bytes
    reconcile=AliRecoveryRuntime.reconcile
    def blocked(self):
        self.writer(4);self.cli('writer-check',expected=4);self.cli('credential-delete','dnspod','dns_a','secret',expected=4);self.cli('cancel',expected=4);self.records(expected=4);self.aliyun(expected=4)
    def pending(self,apply=True,q=None):
        def hook(a,p):
            if a=='CreateRecord':
                self.active()
                if apply:self.db[5000]=record(5000,p['RecordType'],p['SubDomain'],p['Value'])
                return 500,{'Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
        self.hook=hook;self.records(q,1);self.hook=None;self.capture_pending()
    def capture_pending(self):
        self.old=list(self.native.lockdir.glob('.dns-check-*'))[0];self.oldjob=self.old.name.rsplit('-',1)[1];self.saved={p.name:p.read_bytes() for p in self.old.iterdir()};self.saved_journal=self.journal_bytes();self.before=len(self.mutations())
    def test_checkpoint_precedes_mutation_and_success_keeps_durable_barrier(self):
        seen=[];self.hook=lambda a,p:seen.append(self.active()[0]['stage']) if a=='CreateRecord' else None;self.records();self.assertEqual(seen,['CreateRecord']);self.active();self.blocked()
    def test_applied_and_unapplied_create_only_observed(self):
        self.pending();self.assertEqual(self.reconcile()['observation'],'desired-present');self.assertEqual(self.reconcile(durable=True)['observation'],'desired-present');self.blocked()
    def test_unapplied_create_is_absent_without_retry(self):
        self.pending(False);self.assertEqual(self.reconcile(durable=True)['observation'],'desired-absent');self.assertEqual(self.db,{})
    def test_txt_observation_keeps_other_challenges(self):
        self.add(record(1,'TXT','_acme-challenge','OTHER'));self.pending(q=self.txt());self.assertEqual(self.reconcile(durable=True)['observation'],'desired-present');self.assertEqual(len(self.db),2)
    def test_delete_observation_binds_target_value_and_line(self):
        self.add(record(1,value='2001:db8::2'),record(2,value='2001:db8::2'))
        def hook(a,p):
            if a=='DeleteRecord':self.db.pop(p['RecordId']);return 500,{'Response':{'Error':{'Code':'InternalError'}}}
        self.hook=hook;self.records(self.payload(operation='delete'),1);self.hook=None;self.capture_pending();self.assertEqual(self.reconcile(durable=True)['observation'],'planned-targets-present');self.db[2]['LineId']='9=0';self.assertEqual(self.reconcile(durable=True)['observation'],'conflict');self.db.clear();self.assertEqual(self.reconcile(durable=True)['observation'],'planned-targets-absent')
    def test_three_deletes_rotate_shared_slots(self):
        self.add(*(record(i,value='2001:db8::2') for i in [1,2,3]));self.records(self.payload(operation='delete'));c,_=self.active();self.assertEqual((c['position'],c['affected']),(3,2));self.assertEqual(self.db,{});self.assertEqual({p.name for p in self.journal.iterdir()},{'current','slot-1','slot-2'});self.blocked()
    def test_failed_second_checkpoint_keeps_first(self):
        self.add(record(1,value='2001:db8::2'),record(2,value='2001:db8::2'));saved=[]
        def hook(a,p):
            if a=='DeleteRecord' and not saved:saved.append(self.active()[1]);self.fault('fsync','if any(v.endswith("/.prepare/context") for v in sys.argv[1:]):sys.exit(1)')
        self.hook=hook;self.records(self.payload(operation='delete'),1);self.assertEqual(self.active()[1],saved[0]);self.assertEqual(len(self.mutations()),1);self.blocked()
    def test_cross_provider_manifest_cannot_be_loaded(self):
        self.pending();p=self.journal/('slot-'+(self.journal/'current').read_text().strip())/'manifest';p.write_bytes(p.read_bytes().replace(b'HGDNPJOURNAL1',b'HGALIJOURNAL1'));self.saved_journal=self.journal_bytes();self.reconcile(7,True);self.blocked()
    def test_later_page_failure_returns_incomplete_observation(self):
        self.pending();self.add(*(record(i) for i in range(1,102)));self.hook=lambda a,p:(429,{'Response':{'Error':{'Code':'RequestLimitExceeded'}}}) if a=='DescribeRecordList' and p['Offset']==100 else None
        self.assertEqual(self.reconcile(1,True)['observation'],'incomplete')
    def test_closed_reconcile_and_receipt_gates_ignore_environment(self):
        self.pending()
        for gate,action in [('dnspod_reconcile_enabled','--reconcile'),('dnspod_receipt_enabled','--reconcile-receipt')]:
            raw=self.ali_entry.read_text();self.ali_entry.write_text(raw.replace(gate+'=true',gate+'=false'));calls=len(self.calls)
            p=subprocess.run([self.busybox,'ash',str(self.ali_entry),'dns_a',action,self.oldjob,'--confirm'],env={**self.env,gate:'true'},capture_output=True,timeout=5);self.assertEqual((p.returncode,p.stderr),(2,b''));self.assertEqual(len(self.calls),calls);self.assertEqual(self.saved_journal,self.journal_bytes());self.ali_entry.write_text(raw)

for n in ['test_simulated_boot_change_and_volatile_loss_keep_barrier_and_allow_read','test_changed_source_is_refused_before_observation','test_wrong_scope_context_is_rejected_before_http','test_context_fsync_failure_prevents_any_mutation','test_pointer_rename_failure_keeps_recovery_barrier','test_context_hash_mismatch_prevents_durable_observation']:
    setattr(Runtime,n,getattr(AliRecoveryRuntime,n))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
