#!/usr/bin/env python3
"""Resume a fully bound terminal pair; never infer success from observation."""
import argparse,hashlib,json,os,unittest
from DNS回执恢复回归 import Runtime as RecoveryRuntime
from Cloudflare记录回归 import Static as RecordStatic,PROTO

class Static(RecordStatic):
    def test_closed_gates_shell_grammar_and_no_installed_prototype(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-dns-recovery.sh','homegate-cloudflare-read.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error)
            self.assertEqual(body.count(b'dns_terminal_repair_enabled=false'),1)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_repair_is_fixed_pair_publication_without_remote_calls_or_deletion(self):
        body=(PROTO/'homegate-dns-recovery.sh').read_text().split('    repair-terminal)\n',1)[1].split('    retire-check)\n',1)[0]
        for forbidden in ['rm ','curl','work/zones','mkdir ','eval ']:self.assertNotIn(forbidden,body)
        self.assertIn('terminal_check "$terminal_candidate" "$meta_candidate"',body)
        self.assertIn('"write_ready":false',(PROTO/'homegate-cloudflare-read.sh').read_text())

class Runtime(RecoveryRuntime):
    def setUp(self):
        super().setUp()
        for file in [self.reader,self.recovery]:file.write_text(file.read_text().replace('dns_terminal_repair_enabled=false','dns_terminal_repair_enabled=true'))
    def prepared(self):
        self.fault('fsync','if any(v.endswith("/.terminal") for v in sys.argv[1:]):sys.exit(1)')
        self.records(expected=7);self.restore_tool('fsync');old=self.job()
        self.assertTrue((self.journal/'.terminal').is_file());self.assertTrue((self.journal/'.terminal-meta').is_file());return old
    def hybrid(self):
        self.fault('mv','if any(v.endswith("/.terminal-meta") for v in sys.argv[1:]):sys.exit(1)')
        self.records(expected=7);self.restore_tool('mv');return self.job()
    def repair(self,old,expected=0,account='dns_a',args=None):
        result=self.recovery_call('--repair-terminal',job=old,expected=expected,account=account,args=args)
        if expected==0:self.assertTrue(result['terminal_repaired']);self.assertFalse(result['write_ready'])
        return result
    def published(self,report,binding):
        self.assertEqual((self.journal/'terminal').read_bytes(),report);self.assertEqual((self.journal/'terminal-meta').read_bytes(),binding)
        self.assertFalse((self.journal/'.terminal').exists());self.assertFalse((self.journal/'.terminal-meta').exists());self.writer(4)
    def prepared_bytes(self):return (self.journal/'.terminal').read_bytes(),(self.journal/'.terminal-meta').read_bytes()
    def resign_binding(self,report,meta):
        lines=meta.read_bytes().splitlines();self.assertEqual(len(lines),11)
        lines[9]=hashlib.sha256(report.read_bytes()).hexdigest().encode();lines[10]=hashlib.sha256(b'\n'.join(lines[:10])+b'\n').hexdigest().encode();meta.write_bytes(b'\n'.join(lines)+b'\n')
    def test_complete_prepared_pair_publishes_exact_bytes_but_preserves_volatile_evidence(self):
        old=self.prepared();report,meta=self.prepared_bytes();work=self.native.lockdir/('.dns-check-'+old);before=self.bytes_tree(work);n=len(self.mutations())
        self.repair(old);self.published(report,meta);self.assertEqual(before,self.bytes_tree(work));self.assertEqual(n,len(self.mutations()));self.recovery_call(expected=4,job=old)
    def test_published_report_and_prepared_binding_resume_then_collect_after_volatile_loss(self):
        old=self.hybrid();report=(self.journal/'terminal').read_bytes();meta=(self.journal/'.terminal-meta').read_bytes();self.lose_volatile()
        self.repair(old);self.published(report,meta);self.recovery_call(job=old);self.writer()
    def test_prepared_report_and_published_binding_can_be_validated_without_inference(self):
        old=self.prepared();report,meta=self.prepared_bytes();(self.journal/'.terminal-meta').rename(self.journal/'terminal-meta')
        self.repair(old);self.published(report,meta)
    def test_already_published_pair_is_idempotent_and_does_not_release_active_barrier(self):
        self.records();old=self.job();before=self.bytes_tree(self.journal);count=len(self.mutations());self.repair(old);self.repair(old)
        self.assertEqual(before,self.bytes_tree(self.journal));self.assertEqual(count,len(self.mutations()));self.writer(4)
    def test_simulated_new_boot_uses_original_bound_persistent_pair(self):
        old=self.prepared();report,meta=self.prepared_bytes();self.lose_volatile();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n')
        self.repair(old);self.published(report,meta);self.recovery_call(job=old);self.writer()
    def test_wrong_account_job_or_missing_confirmation_cannot_change_files(self):
        old=self.prepared();self.lose_volatile();before=self.bytes_tree(self.journal)
        self.repair(old,7,account='other');self.repair('999999999',7)
        for args in [['dns_a','--repair-terminal',old],['dns_a','--repair-terminal','../bad','--confirm']]:self.repair(old,2,args=args)
        self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_other_orphan_request_blocks_repair_and_is_not_removed(self):
        old=self.prepared();other=self.native.lockdir/'.dns-check-999999999';other.mkdir(mode=0o700);before=self.bytes_tree(self.journal)
        self.repair(old,4);self.assertEqual(before,self.bytes_tree(self.journal));self.assertTrue(other.exists());self.writer(4)
    def test_original_orphan_symlink_is_not_followed_or_removed(self):
        old=self.prepared();self.lose_volatile();outside=self.base/'outside-work';outside.mkdir(mode=0o700);orphan=self.native.lockdir/('.dns-check-'+old);orphan.symlink_to(outside)
        self.repair(old,4);self.assertTrue(orphan.is_symlink());self.assertTrue(outside.is_dir());self.writer(4)
    def test_both_closed_repair_gates_cannot_be_overridden_by_environment(self):
        old=self.prepared();before=self.bytes_tree(self.journal);self.env['dns_terminal_repair_enabled']='true'
        self.reader.write_text(self.reader.read_text().replace('dns_terminal_repair_enabled=true','dns_terminal_repair_enabled=false'));self.repair(old,2)
        self.reader.write_text(self.reader.read_text().replace('dns_terminal_repair_enabled=false','dns_terminal_repair_enabled=true'));self.recovery.write_text(self.recovery.read_text().replace('dns_terminal_repair_enabled=true','dns_terminal_repair_enabled=false'));self.repair(old,7)
        self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_missing_report_cannot_be_reconstructed_from_volatile_success(self):
        old=self.prepared();(self.journal/'.terminal').unlink();before=self.bytes_tree(self.journal);self.repair(old,7)
        self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_missing_binding_cannot_be_synthesized_from_valid_report(self):
        old=self.prepared();(self.journal/'.terminal-meta').unlink();before=self.bytes_tree(self.journal);self.repair(old,7)
        self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_unknown_http_result_has_no_confirmed_pair_and_remains_unknown(self):
        self.pending();old=self.job();before=self.bytes_tree(self.journal);count=len(self.mutations());self.repair(old,7)
        self.assertEqual(before,self.bytes_tree(self.journal));self.assertEqual(count,len(self.mutations()));self.assertFalse((self.journal/'terminal').exists());self.blocked()
    def test_corrupt_binding_or_report_never_causes_partial_publication(self):
        old=self.prepared();report,meta=self.prepared_bytes();m=self.journal/'.terminal-meta';m.write_bytes(meta+b' ');before=self.bytes_tree(self.journal);self.repair(old,7);self.assertEqual(before,self.bytes_tree(self.journal))
        m.write_bytes(meta);p=self.journal/'.terminal';p.write_bytes(report+b' ');before=self.bytes_tree(self.journal);self.repair(old,7);self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_unknown_or_partial_count_even_with_matching_hash_binding_is_rejected(self):
        old=self.prepared();p=self.journal/'.terminal';m=self.journal/'.terminal-meta';saved=p.read_bytes()
        for key,value in [('effect','unknown'),('affected',2),('result','updated')]:
            doc=json.loads(saved);doc[key]=value;p.write_bytes(self.encoded(doc));self.resign_binding(p,m);before=self.bytes_tree(self.journal)
            self.repair(old,7);self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_duplicate_json_fields_cannot_be_accepted_by_rebinding_metadata(self):
        old=self.prepared();p=self.journal/'.terminal';m=self.journal/'.terminal-meta';raw=p.read_bytes();p.write_bytes(raw.replace(b'"ok":true',b'"ok":true,"ok":true'));self.resign_binding(p,m)
        self.repair(old,7);self.assertTrue(p.exists());self.assertFalse((self.journal/'terminal').exists());self.writer(4)
    def test_corrupt_active_checkpoint_is_not_replaced_by_other_slots(self):
        old=self.prepared();current=(self.journal/'current').read_text().strip();p=self.journal/('slot-'+current)/'context';p.write_bytes(p.read_bytes()+b' ');before=self.bytes_tree(self.journal)
        self.repair(old,7);self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_invalid_current_pointer_is_not_inferred_from_prepared_terminal(self):
        old=self.prepared();(self.journal/'current').write_bytes(b'9\n');before=self.bytes_tree(self.journal);self.repair(old,7)
        self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_checkpoint_prepare_or_pointer_residue_is_not_silently_discarded(self):
        old=self.prepared();stage=self.journal/'.prepare';stage.mkdir(mode=0o700);extra=stage/'context';extra.write_bytes(b'keep');extra.chmod(0o600);before=self.bytes_tree(self.journal)
        self.repair(old,7);self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_duplicate_candidates_even_with_identical_bytes_require_explicit_resolution(self):
        self.records();old=self.job();extra=self.journal/'.terminal';extra.write_bytes((self.journal/'terminal').read_bytes());extra.chmod(0o600);before=self.bytes_tree(self.journal)
        self.repair(old,7);self.assertEqual(before,self.bytes_tree(self.journal));self.writer(4)
    def test_symlink_report_and_hardlink_binding_never_modify_outside_files(self):
        old=self.prepared();p=self.journal/'.terminal';outside=self.base/'outside-report';p.rename(outside);p.symlink_to(outside);saved=outside.read_bytes();self.repair(old,7);self.assertTrue(p.is_symlink());self.assertEqual(saved,outside.read_bytes())
        p.unlink();outside.rename(p);m=self.journal/'.terminal-meta';other=self.base/'outside-binding';os.link(m,other);saved=other.read_bytes();self.repair(old,7);self.assertEqual(saved,other.read_bytes());self.writer(4)
    def test_private_mode_failure_does_not_fix_permissions_or_publish(self):
        old=self.prepared();p=self.journal/'.terminal';p.chmod(0o640);before=self.bytes_tree(self.journal);self.repair(old,7)
        self.assertEqual(before,self.bytes_tree(self.journal));self.assertEqual(p.stat().st_mode&0o777,0o640);self.writer(4)
    def test_candidate_sync_failure_leaves_pair_unpublished_until_explicit_retry(self):
        old=self.prepared();report,meta=self.prepared_bytes();self.fault('fsync','if any(v.endswith("/.terminal") for v in sys.argv[1:]):sys.exit(1)');self.repair(old,7)
        self.assertFalse((self.journal/'terminal').exists());self.writer(4);self.restore_tool('fsync');self.repair(old);self.published(report,meta)
    def test_report_rename_failure_is_recoverable_without_deleting_evidence(self):
        old=self.prepared();report,meta=self.prepared_bytes();self.fault('mv','if any(v.endswith("/.terminal") for v in sys.argv[1:]):sys.exit(1)');self.repair(old,7)
        self.assertTrue((self.journal/'.terminal').exists());self.writer(4);self.restore_tool('mv');self.repair(old);self.published(report,meta)
    def test_binding_rename_failure_resumes_from_hybrid_pair(self):
        old=self.prepared();report,meta=self.prepared_bytes();self.fault('mv','if any(v.endswith("/.terminal-meta") for v in sys.argv[1:]):sys.exit(1)');self.repair(old,7)
        self.assertTrue((self.journal/'terminal').exists());self.assertTrue((self.journal/'.terminal-meta').exists());self.writer(4);self.restore_tool('mv');self.repair(old);self.published(report,meta)
    def test_final_sync_uncertainty_never_releases_active_barrier(self):
        old=self.prepared();report,meta=self.prepared_bytes();self.fault('fsync','if any(v.endswith("/terminal") for v in sys.argv[1:]):sys.exit(1)');self.repair(old,7)
        self.assertTrue((self.journal/'terminal').exists());self.assertTrue((self.journal/'terminal-meta').exists());self.writer(4)
        self.restore_tool('fsync');self.repair(old);self.published(report,meta);self.lose_volatile();self.recovery_call(job=old);self.writer()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',action='store_true');args=parser.parse_args();cls=Runtime if args.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,value in cls.__dict__.items() if name.startswith('test_') and callable(value))
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
