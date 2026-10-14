#!/usr/bin/env python3
"""Terminal binding, confirmed archival and cross-boot GET observations; no router."""
import argparse,copy,hashlib,json,os,re,shutil,subprocess,unittest
from Cloudflare记录回归 import Static as RecordStatic,PROTO,rec
from DNS持久回执回归 import Runtime as ReceiptRuntime

class Static(RecordStatic):
    def setUp(self):
        super().setUp();self.receipt=self.lua.execute((PROTO/'cloudflare-receipt.lua').read_bytes())
    def context(self,stage=b'create',operation=b'upsert'):
        q=self.ddns(operation=operation);c=self.bind(q);c[b'request']=self.lua.table_from(q,recursive=True);c[b'attempted']=True;c[b'stage']=stage
        c[b'delete_ids']=self.lua.table_from([b'a'*32,b'b'*32]);c[b'position']=2;c[b'affected']=1 if operation==b'delete' else 0;return c
    def public_receipt(self,**extra):
        return self.lua.table_from({b'account':b'dns_a',b'configuration_revision':3,b'ok':True,b'effect':b'confirmed',b'error_kind':b'',b'provider_code':b'',b'retryable':False,b'reconciliation_required':False,b'result':b'created',b'affected':1,**{k.encode():v for k,v in extra.items()}})
    def test_terminal_requires_confirmed_success_and_exact_original_scope(self):
        c=self.context();self.assertTrue(self.receipt.terminal(c,self.public_receipt()))
        for k,v in [('ok',False),('effect',b'unknown'),('account',b'other'),('configuration_revision',2),('affected',2),('result',b'updated'),('retryable',True),('reconciliation_required',True),('error_kind',b'temporary')]:
            self.assertFalse(self.receipt.terminal(c,self.public_receipt(**{k:v})),k)
    def test_terminal_counts_match_last_delete_checkpoint_not_partial_success(self):
        c=self.context(b'delete',b'delete');self.assertTrue(self.receipt.terminal(c,self.public_receipt(result=b'deleted',affected=2)))
        for n in [0,1,3,2.5]:self.assertFalse(self.receipt.terminal(c,self.public_receipt(result=b'deleted',affected=n)))
        c[b'affected']=0.5;self.assertFalse(self.receipt.terminal(c,self.public_receipt(result=b'deleted',affected=1.5)))
    def test_new_gates_shell_grammar_and_collection_order(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-dns-recovery.sh','homegate-cloudflare-read.sh','homegate-config-prototype.sh']:
            b=(PROTO/n).read_bytes();self.assertNotIn(b'\r',b);self.assertFalse(parser.parse(b).root_node.has_error,n)
        for n in ['homegate-dns-recovery.sh','homegate-cloudflare-read.sh']:self.assertEqual((PROTO/n).read_bytes().count(b'dns_settlement_enabled=false'),1)
        s=(PROTO/'homegate-dns-recovery.sh').read_text();collect=s.split('    collect)\n',1)[1]
        self.assertLess(collect.index('ledger_write collecting'),collect.index('mv "$journal" "$archive"'))
        self.assertLess(collect.index('mv "$journal" "$archive"'),collect.index('ledger_write settled'))
        self.assertNotIn('rm ',s);self.assertNotIn('curl',s);self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
        self.lua.compile((PROTO/'cloudflare-records.lua').read_bytes())

class Runtime(ReceiptRuntime):
    def setUp(self):
        super().setUp();self.recovery=self.engine.parent/'homegate-dns-recovery.sh';self.archive=self.store/'dns-settled';self.ledger=self.store/'dns-collection'
        p=self.reader;p.write_text(p.read_text().replace('dns_settlement_enabled=false','dns_settlement_enabled=true'))
        s=self.recovery.read_text().replace('dns_settlement_enabled=false','dns_settlement_enabled=true')
        mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
        s=s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
        self.recovery.write_text(s)
    def job(self):
        a=(self.journal/'current').read_text().strip();return (self.journal/('slot-'+a)/'manifest').read_text().splitlines()[6]
    def recovery_call(self,mode='--collect-receipt',expected=0,account='dns_a',job=None,args=None):
        p=subprocess.run([self.busybox,'ash',str(self.reader),*(args or [account,mode,job or self.job(),'--confirm'])],env=self.env,capture_output=True,timeout=12)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr));self.assertEqual(p.stderr,b'');r=json.loads(p.stdout);self.assertEqual(r['ok'],expected==0)
        for value in [b'PRIVATE_SENTINEL',b'TXT_PRIVATE_VALUE',b'example.test',b'2001:db8::2']:self.assertNotIn(value,p.stdout)
        return r
    def bytes_tree(self,d):return {p.relative_to(d).as_posix():p.read_bytes() for p in d.rglob('*') if p.is_file()}
    def lose_volatile(self):
        for p in self.native.lockdir.glob('.dns-check-*'):
            assert p.parent.resolve()==self.native.lockdir.resolve() and p.resolve().is_relative_to(self.native.base.resolve());shutil.rmtree(p)
    def test_confirmed_create_persists_bound_terminal_without_releasing_barrier(self):
        self.records();d,_=self.active();r=json.loads((self.journal/'terminal').read_bytes());self.assertEqual((r['result'],r['affected']),('created',1));self.assertEqual(d['stage'],'create');self.blocked()
        lines=(self.journal/'terminal-meta').read_bytes().splitlines();self.assertEqual(len(lines),11);self.assertEqual(lines[0],b'HGCFTerminal1');self.assertEqual(lines[9],hashlib.sha256((self.journal/'terminal').read_bytes()).hexdigest().encode())
    def test_confirmed_collection_preserves_bytes_in_archive_and_opens_writers(self):
        self.records();before=self.bytes_tree(self.journal);n=len(self.mutations());r=self.recovery_call();self.assertTrue(r['archived'])
        self.assertFalse(self.journal.exists());self.assertEqual(self.bytes_tree(self.archive),before);self.assertEqual(len(self.mutations()),n);self.writer();self.cli('writer-check')
    def test_confirmed_collection_after_simulated_boot_change_is_allowed(self):
        self.records();old=self.job();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.recovery_call(job=old);self.writer()
    def test_unknown_cross_boot_uses_durable_evidence_and_never_mutates_or_collects(self):
        self.pending();old=self.job();before=self.bytes_tree(self.journal);self.lose_volatile();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');n=len(self.mutations())
        r=self.recovery_call('--reconcile-receipt',job=old);self.assertEqual((r['observation'],r['effect']),('desired-present','unknown'))
        self.recovery_call(expected=7,job=old);self.assertEqual(self.bytes_tree(self.journal),before);self.assertEqual(len(self.mutations()),n);self.blocked()
    def test_unapplied_unknown_observation_remains_absent_and_blocked(self):
        self.pending(apply=False);self.lose_volatile();r=self.recovery_call('--reconcile-receipt');self.assertEqual(r['observation'],'desired-absent');self.blocked()
    def test_unknown_delete_cross_boot_observes_frozen_plan_without_cleanup(self):
        self.add(rec(1,value='2001:db8::2'))
        def hook(method,*args):
            if method=='DELETE':self.db.clear();return 500,{'success':False,'errors':[]}
        self.hook=hook;self.records(self.payload(operation='delete'),1);self.hook=None;self.lose_volatile()
        r=self.recovery_call('--reconcile-receipt');self.assertEqual(r['observation'],'planned-targets-absent');self.recovery_call(expected=7);self.blocked()
    def test_terminal_partial_delete_report_cannot_authorize_collection(self):
        self.add(rec(1,value='2001:db8::2'),rec(2,value='2001:db8::2'));self.records(self.payload(operation='delete'))
        p=self.journal/'terminal';d=json.loads(p.read_bytes());d['affected']=1;p.write_bytes(self.encoded(d));self.recovery_call(expected=7);self.blocked()
    def test_collection_wrong_account_job_or_confirmation_is_refused(self):
        self.records();before=self.bytes_tree(self.journal);old=self.job()
        self.recovery_call(expected=7,account='other');self.recovery_call(expected=7,job='999999999')
        for args in [['dns_a','--collect-receipt',old],['dns_a','--collect-receipt','../bad','--confirm']]:self.recovery_call(expected=2,args=args)
        self.assertEqual(before,self.bytes_tree(self.journal));self.blocked()
    def test_corrupt_checkpoint_hash_blocks_durable_read_and_collection(self):
        self.records();a=(self.journal/'current').read_text().strip();p=self.journal/('slot-'+a)/'context';p.write_bytes(p.read_bytes()+b' ')
        self.recovery_call('--reconcile-receipt',expected=7);self.recovery_call(expected=4);self.blocked()
    def test_changed_store_identity_refuses_load_and_collection(self):
        self.records();self.write_identity(identity='b'*32);self.recovery_call('--reconcile-receipt',expected=7);self.recovery_call(expected=4);self.blocked()
    def test_terminal_sync_failure_preserves_both_barriers(self):
        self.fault('fsync','if any(v.endswith("/.terminal") for v in sys.argv[1:]):sys.exit(1)');self.records(expected=7);self.assertFalse((self.journal/'terminal').exists());self.blocked()
    def test_terminal_rename_failure_cannot_be_collected(self):
        self.fault('mv','if any(v.endswith("/.terminal-meta") for v in sys.argv[1:]):sys.exit(1)');self.records(expected=7);self.assertTrue((self.journal/'terminal').exists());self.blocked()
    def test_collecting_ledger_fsync_failure_cannot_release_writer(self):
        self.records();self.fault('fsync','if any(v.endswith("/.dns-collection-next") for v in sys.argv[1:]):sys.exit(1)');self.recovery_call(expected=7);self.blocked();self.assertTrue(self.journal.exists())
    def test_archive_rename_failure_can_resume_from_valid_collecting_ledger(self):
        self.records();old=self.job();self.fault('mv','if any(v.endswith("/dns-operation") for v in sys.argv[1:]):sys.exit(1)')
        self.recovery_call(expected=7,job=old);self.blocked();self.restore_tool('mv');self.recovery_call(job=old);self.writer()
    def test_archive_parent_sync_failure_keeps_collecting_fence_and_can_resume(self):
        self.records();old=self.job();self.fault('fsync','from pathlib import Path\nif sys.argv[1:]==['+repr(str(self.store))+'] and Path('+repr(str(self.archive))+').exists():sys.exit(1)')
        self.recovery_call(expected=7,job=old);self.assertFalse(self.journal.exists());self.writer(4);self.restore_tool('fsync');self.recovery_call(job=old);self.writer()
    def test_settled_rename_uncertainty_requires_successful_resync_before_writer(self):
        self.records();old=self.job();self.fault('fsync','from pathlib import Path\nif sys.argv[1:]==['+repr(str(self.store))+'] and Path('+repr(str(self.ledger))+').exists() and "\\nsettled\\n" in Path('+repr(str(self.ledger))+').read_text():sys.exit(1)')
        self.recovery_call(expected=7,job=old);self.writer(4);self.restore_tool('fsync');self.writer();self.recovery_call(job=old)
    def test_tampered_archive_or_ledger_blocks_writers_even_with_new_gate_closed(self):
        self.records();self.recovery_call();self.recovery.write_text(self.recovery.read_text().replace('dns_settlement_enabled=true','dns_settlement_enabled=false'))
        self.writer();self.ledger.write_bytes(b'corrupt\n');self.writer(4);self.cli('writer-check',expected=4)
    def test_archive_capacity_is_one_and_never_overwritten_by_next_operation(self):
        self.records();self.recovery_call();before=self.bytes_tree(self.archive);self.records(self.payload(value='2001:db8::3'));self.recovery_call(expected=7)
        self.assertEqual(before,self.bytes_tree(self.archive));self.blocked()
    def test_same_receipt_collection_is_idempotent_when_archive_is_settled(self):
        self.records();old=self.job();self.recovery_call(job=old);before=self.bytes_tree(self.archive);self.recovery_call(job=old)
        self.assertEqual(before,self.bytes_tree(self.archive));self.writer()
    def test_extra_volatile_orphan_refuses_collection_without_removal(self):
        self.records();p=self.native.lockdir/'.dns-check-999999999';p.mkdir(mode=0o700);self.recovery_call(expected=4);self.assertTrue(p.is_dir());self.writer(4)
    def test_symlink_terminal_or_inactive_slot_is_rejected(self):
        self.records();p=self.journal/'terminal';saved=self.base/'terminal-saved';p.rename(saved);p.symlink_to(saved);self.recovery_call(expected=7);self.blocked()
        p.unlink();saved.rename(p);a=(self.journal/'current').read_text().strip()
        (self.journal/('slot-2' if a=='1' else 'slot-1')).symlink_to(self.base/'missing-slot');self.recovery_call(expected=7);self.blocked()
    def test_closed_settlement_gate_cannot_be_overridden_by_environment(self):
        self.records();self.reader.write_text(self.reader.read_text().replace('dns_settlement_enabled=true','dns_settlement_enabled=false'));self.env['dns_settlement_enabled']='true'
        self.recovery_call(expected=2);self.recovery_call('--reconcile-receipt',expected=2);self.blocked()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
