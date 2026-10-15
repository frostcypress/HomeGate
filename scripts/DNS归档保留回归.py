#!/usr/bin/env python3
"""Confirmed bounded retirement and crash fences; disposable Linux fixtures only."""
import argparse,hashlib,json,os,re,unittest
from DNS回执恢复回归 import Runtime as RecoveryRuntime
from Cloudflare记录回归 import Static as RecordStatic,PROTO

class Static(RecordStatic):
    def test_shell_grammar_closed_gate_and_no_recursive_or_remote_operations(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-dns-retention.sh','homegate-dns-recovery.sh','homegate-cloudflare-read.sh','homegate-config-prototype.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error,name)
        for name in ['homegate-dns-retention.sh','homegate-cloudflare-read.sh']:
            self.assertEqual((PROTO/name).read_bytes().count(b'dns_retention_enabled=false'),1)
        body=(PROTO/'homegate-dns-retention.sh').read_text()
        for forbidden in ['rm -r','rm -f "$store/dns-operation','curl','eval ','source ']:self.assertNotIn(forbidden,body)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_retirement_guard_remains_outside_production_feature_switch(self):
        body=(PROTO/'homegate-config-prototype.sh').read_text();guard=body.split('[ -e "$store/dns-retirement" ]',1)[1].split('    if [ "$persistent_mode"',1)[0]
        self.assertNotIn('enabled',guard);self.assertIn('homegate-dns-retention.sh" check',guard)
        helper=(PROTO/'homegate-dns-retention.sh').read_text().split('if [ "$action" = check ]; then',1)[1].split('\nfi',1)[0]
        self.assertNotIn('enabled',helper);self.assertIn('fsync "$completed" "$store"',helper)

class Runtime(RecoveryRuntime):
    def setUp(self):
        super().setUp();self.retention=self.engine.parent/'homegate-dns-retention.sh'
        self.plan=self.store/'dns-retirement';self.retiring=self.store/'dns-retiring';self.completed=self.store/'dns-retired';self.next=self.store/'.dns-retirement-next'
        self.reader.write_text(self.reader.read_text().replace('dns_retention_enabled=false','dns_retention_enabled=true'))
        s=self.retention.read_text().replace('dns_retention_enabled=false','dns_retention_enabled=true')
        mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir)}
        s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
        self.retention.write_text(s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]'))
    def archived(self):
        self.records();old=self.job();self.recovery_call(job=old);return old
    def retire(self,old,expected=0,account='dns_a',args=None):
        r=self.recovery_call('--retire-archive',job=old,expected=expected,account=account,args=args)
        if expected==0:self.assertTrue(r['retired']);self.assertFalse(r['write_ready'])
        return r
    def cleared(self):
        for p in [self.archive,self.ledger,self.plan,self.retiring,self.next]:self.assertFalse(p.exists(),str(p))
        self.assertTrue(self.completed.is_file());self.assertEqual(self.completed.stat().st_mode&0o777,0o600)
        lines=self.completed.read_bytes().splitlines();self.assertEqual(len(lines),14);self.assertEqual(lines[0],b'HGCFRetire1')
        self.assertEqual(lines[-1],hashlib.sha256(b'\n'.join(lines[:-1])+b'\n').hexdigest().encode())
        self.writer();self.cli('writer-check')
    def stop_after_rename(self,old):
        self.fault('fsync','from pathlib import Path\nif '+repr(str(self.store))+' in sys.argv[1:] and Path('+repr(str(self.retiring))+').exists():sys.exit(1)')
        self.retire(old,7);self.assertTrue(self.retiring.is_dir());self.assertTrue(self.plan.is_file());self.restore_tool('fsync');self.writer(4)
    def test_retirement_reclaims_capacity_and_preserves_configuration_and_identity(self):
        old=self.archived();preserved={p:p.read_bytes() for p in self.store.rglob('*') if p.is_file() and self.archive not in p.parents and p!=self.ledger};n=len(self.mutations())
        self.retire(old);self.cleared();self.assertEqual(n,len(self.mutations()))
        for p,b in preserved.items():self.assertEqual(p.read_bytes(),b,str(p))
        self.records(self.payload(value='2001:db8::3'));new=self.job();self.recovery_call(job=new);self.retire(new);self.cleared();self.assertNotEqual(old,new)
        self.assertEqual(self.completed.read_text().splitlines()[4],new)
    def test_active_next_receipt_is_preserved_and_still_blocks_writers(self):
        old=self.archived();self.records(self.payload(value='2001:db8::3'));new=self.job();before=self.bytes_tree(self.journal)
        self.retire(old);self.assertEqual(self.bytes_tree(self.journal),before);self.writer(4)
        self.recovery_call(job=new);self.writer()
    def test_unknown_receipt_cannot_be_retired_or_reclassified_as_settled(self):
        self.pending();old=self.job();before=self.bytes_tree(self.journal);self.retire(old,4);self.lose_volatile();self.retire(old,7)
        self.assertEqual(before,self.bytes_tree(self.journal));self.assertFalse(self.plan.exists());self.blocked()
    def test_wrong_account_job_or_confirmation_preserves_archive(self):
        old=self.archived();before=self.bytes_tree(self.archive)
        self.retire(old,7,account='other');self.retire('999999999',7)
        for args in [['dns_a','--retire-archive',old],['dns_a','--retire-archive','../bad','--confirm']]:self.retire(old,2,args=args)
        self.assertEqual(before,self.bytes_tree(self.archive));self.assertFalse(self.plan.exists());self.writer()
    def test_terminal_corruption_refuses_plan_and_preserves_all_evidence(self):
        old=self.archived();p=self.archive/'terminal';p.write_bytes(p.read_bytes()+b' ');before=self.bytes_tree(self.archive)
        self.retire(old,7);self.assertEqual(before,self.bytes_tree(self.archive));self.assertFalse(self.plan.exists());self.writer(4)
    def test_symlink_and_hardlinked_archive_members_are_never_removed(self):
        old=self.archived();p=self.archive/'terminal';outside=self.base/'outside-terminal';p.rename(outside);p.symlink_to(outside);before=outside.read_bytes()
        self.retire(old,7);self.assertTrue(p.is_symlink());self.assertEqual(outside.read_bytes(),before);p.unlink();os.link(outside,p);self.retire(old,7);self.assertEqual(outside.read_bytes(),before);self.writer(4)
    def test_plan_file_sync_failure_leaves_archive_intact_and_gate_independent_fence(self):
        old=self.archived();before=self.bytes_tree(self.archive)
        self.fault('fsync','if any(v.endswith("/.dns-retirement-next") for v in sys.argv[1:]):sys.exit(1)');self.retire(old,7);self.assertTrue(self.next.is_file())
        self.assertEqual(before,self.bytes_tree(self.archive));self.retention.write_text(self.retention.read_text().replace('dns_retention_enabled=true','dns_retention_enabled=false'));self.writer(4)
    def test_plan_rename_failure_does_not_delete_archive_or_automatically_remove_scratch(self):
        old=self.archived();before=self.bytes_tree(self.archive);self.fault('mv','if any(v.endswith("/.dns-retirement-next") for v in sys.argv[1:]):sys.exit(1)')
        self.retire(old,7);self.restore_tool('mv');self.retire(old,7);self.assertEqual(before,self.bytes_tree(self.archive));self.assertTrue(self.next.exists());self.writer(4)
    def test_plan_parent_sync_failure_can_resume_only_after_durable_recheck(self):
        old=self.archived();self.fault('fsync','from pathlib import Path\nif '+repr(str(self.store))+' in sys.argv[1:] and Path('+repr(str(self.plan))+').exists():sys.exit(1)')
        self.retire(old,7);self.assertTrue(self.archive.is_dir());self.writer(4);self.restore_tool('fsync');self.retire(old);self.cleared()
    def test_archive_rename_failure_can_resume_from_same_bound_plan(self):
        old=self.archived();self.fault('mv','if any(v.endswith("/dns-settled") for v in sys.argv[1:]):sys.exit(1)')
        self.retire(old,7);self.assertTrue(self.archive.is_dir());self.assertTrue(self.plan.is_file());self.writer(4);self.restore_tool('mv');self.retire(old);self.cleared()
    def test_archive_rename_sync_failure_can_resume_without_opening_writers(self):
        old=self.archived();self.stop_after_rename(old);self.retire(old);self.cleared()
    def test_partial_member_deletion_resumes_from_plan_without_original_slot_context(self):
        old=self.archived();self.stop_after_rename(old)
        current=(self.retiring/'current').read_text().strip();p=self.retiring/('slot-'+current)/'context';assert p.resolve().is_relative_to(self.base.resolve());p.unlink()
        self.retire(old);self.cleared()
    def test_slot_directory_sync_failure_remains_fenced_and_resumes(self):
        old=self.archived();self.fault('fsync','if any("/dns-retiring/slot-" in v for v in sys.argv[1:]):sys.exit(1)')
        self.retire(old,7);self.writer(4);self.restore_tool('fsync');self.retire(old);self.cleared()
    def test_slot_rmdir_failure_remains_fenced_and_resumes(self):
        old=self.archived();self.fault('rmdir','if any("/dns-retiring/slot-" in v for v in sys.argv[1:]):sys.exit(1)')
        self.retire(old,7);self.writer(4);self.restore_tool('rmdir');self.retire(old);self.cleared()
    def test_terminal_removal_failure_resumes_after_slots_have_gone(self):
        old=self.archived();self.fault('rm','if any(v.endswith("/dns-retiring/current") for v in sys.argv[1:]):sys.exit(1)')
        self.retire(old,7);self.assertTrue(self.retiring.is_dir());self.writer(4);self.restore_tool('rm');self.retire(old);self.cleared()
    def test_ledger_removal_failure_resumes_after_archive_directory_has_gone(self):
        old=self.archived();self.fault('rm','if any(v.endswith("/dns-collection") for v in sys.argv[1:]):sys.exit(1)')
        self.retire(old,7);self.assertFalse(self.retiring.exists());self.assertTrue(self.ledger.exists());self.writer(4);self.restore_tool('rm');self.retire(old);self.cleared()
    def test_completion_rename_failure_retains_plan_until_explicit_resume(self):
        old=self.archived();self.fault('mv','if sys.argv[-1].endswith("/dns-retired"):sys.exit(1)')
        self.retire(old,7);self.assertFalse(self.archive.exists());self.assertFalse(self.ledger.exists());self.writer(4);self.restore_tool('mv');self.retire(old);self.cleared()
    def test_completion_sync_uncertainty_requires_successful_resync_before_writer(self):
        old=self.archived();self.fault('fsync','if any(v.endswith("/dns-retired") for v in sys.argv[1:]):sys.exit(1)')
        self.retire(old,7);self.assertTrue(self.completed.is_file());self.writer(4);self.restore_tool('fsync');self.writer();self.retire(old);self.cleared()
    def test_resume_rejects_unlisted_files_without_further_deletion(self):
        old=self.archived();self.stop_after_rename(old);extra=self.retiring/'.unlisted';extra.write_bytes(b'keep-me');extra.chmod(0o600);before=self.bytes_tree(self.retiring)
        self.retire(old,7);self.assertEqual(before,self.bytes_tree(self.retiring));self.writer(4)
    def test_plan_corruption_wrong_identity_and_wrong_job_cannot_authorize_removal(self):
        old=self.archived();self.stop_after_rename(old);before=self.bytes_tree(self.retiring);saved=self.plan.read_bytes();self.plan.write_bytes(saved+b' ')
        self.retire(old,7);self.assertEqual(before,self.bytes_tree(self.retiring));self.plan.write_bytes(saved);self.retire('999999999',7);self.assertEqual(before,self.bytes_tree(self.retiring))
        self.write_identity(identity='b'*32);self.retire(old,4);self.assertEqual(before,self.bytes_tree(self.retiring));self.writer(4)
    def test_completed_receipt_corruption_blocks_writer_with_feature_gate_closed(self):
        old=self.archived();self.retire(old);self.retention.write_text(self.retention.read_text().replace('dns_retention_enabled=true','dns_retention_enabled=false'))
        self.completed.write_bytes(self.completed.read_bytes()+b' ');self.writer(4);self.cli('writer-check',expected=4)
    def test_idempotent_old_confirmation_preserves_new_archive_and_never_contacts_provider(self):
        old=self.archived();self.retire(old);self.records(self.payload(value='2001:db8::3'));new=self.job();self.recovery_call(job=new);before=self.bytes_tree(self.archive);count=len(self.mutations())
        self.retire(old);self.assertEqual(before,self.bytes_tree(self.archive));self.assertEqual(count,len(self.mutations()));self.retire(new);self.cleared()
    def test_orphan_and_closed_gate_refuse_retirement_without_environment_override(self):
        old=self.archived();self.reader.write_text(self.reader.read_text().replace('dns_retention_enabled=true','dns_retention_enabled=false'));self.env['dns_retention_enabled']='true';self.retire(old,2)
        self.reader.write_text(self.reader.read_text().replace('dns_retention_enabled=false','dns_retention_enabled=true'));orphan=self.native.lockdir/'.dns-check-999999999';orphan.mkdir(mode=0o700);self.retire(old,4);self.assertTrue(orphan.exists());self.assertFalse(self.plan.exists())

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',action='store_true');args=parser.parse_args();cls=Runtime if args.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,value in cls.__dict__.items() if name.startswith('test_') and callable(value))
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
