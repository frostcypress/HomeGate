#!/usr/bin/env python3
"""Bounded collection of an original, confirmed DNS job's volatile evidence."""
import argparse,hashlib,json,os,re,subprocess,unittest
from DNS终态修复回归 import Runtime as TerminalRuntime
from DNS回执恢复回归 import Static as RecoveryStatic
from Cloudflare记录回归 import PROTO,rec

class Static(RecoveryStatic):
    def test_three_closed_gates_shell_grammar_and_no_production_install(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cloudflare-read.sh','homegate-dns-recovery.sh','homegate-dns-orphan.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error)
            self.assertEqual(body.count(b'dns_orphan_collection_enabled=false'),1)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text());self.lua.compile((PROTO/'cloudflare-records.lua').read_bytes())
    def test_no_recursive_delete_remote_request_or_old_pid_signal(self):
        body=(PROTO/'homegate-dns-orphan.sh').read_text()
        for forbidden in ['rm -r','curl','kill ','eval ','rm -f "$journal','rm -f "$store']:self.assertNotIn(forbidden,body)
        self.assertLess(body.index('preflight remaining && quiet'),body.index('rm -f "$work/$name"'))
        self.assertIn('HGCFOrphan1',body);self.assertIn('receipt-orphan',body)
    def test_binding_requires_exact_request_and_verified_stage(self):
        c=self.context();w=self.context();w[b'stage']=b'verify-upsert';w[b'result']=b'created';w[b'new_id']=b'a'*32
        self.assertTrue(self.receipt.orphan(c,w,c[b'request'],self.codec))
        w[b'stage']=b'create';self.assertFalse(self.receipt.orphan(c,w,c[b'request'],self.codec));w[b'stage']=b'verify-upsert'
        w[b'account']=b'other';self.assertFalse(self.receipt.orphan(c,w,c[b'request'],self.codec))

class Runtime(TerminalRuntime):
    def setUp(self):
        super().setUp();self.collector=self.engine.parent/'homegate-dns-orphan.sh'
        for file in [self.reader,self.recovery]:file.write_text(file.read_text().replace('dns_orphan_collection_enabled=false','dns_orphan_collection_enabled=true'))
        text=self.collector.read_text().replace('dns_orphan_collection_enabled=false','dns_orphan_collection_enabled=true')
        mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        text=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],text)
        self.collector.write_text(text.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]'))
        self.plan=self.journal/'orphan-plan';self.next=self.journal/'.orphan-plan'
    def complete(self,payload=None):
        if payload is None:old=self.prepared()
        else:
            self.fault('fsync','if any(v.endswith("/.terminal") for v in sys.argv[1:]):sys.exit(1)');self.records(payload,expected=7);self.restore_tool('fsync');old=self.job()
        self.repair(old);self.work=self.native.lockdir/('.dns-check-'+old)
        self.assertEqual({p.name for p in self.work.iterdir()},{'request','result','zones','state','input','context','attempt'})
        return old
    def collect(self,old,expected=0,account='dns_a',args=None):
        n=len(self.calls);r=self.recovery_call('--collect-orphan',expected,account,old,args);self.assertEqual(n,len(self.calls));self.writer(4)
        if expected==0:self.assertTrue(r['orphan_collected']);self.assertFalse(r['write_ready']);self.assertFalse(self.plan.exists());self.assertFalse(self.next.exists())
        return r
    def reject(self,old,expected=7):
        before=self.bytes_tree(self.journal);work=self.bytes_tree(self.work);self.collect(old,expected)
        self.assertEqual(before,self.bytes_tree(self.journal));self.assertEqual(work,self.bytes_tree(self.work))
    def pause_before_delete(self,old):
        self.fault('rm','if any("/.dns-check-" in v for v in sys.argv[1:]):sys.exit(1)');self.collect(old,7);self.restore_tool('rm');self.assertTrue(self.plan.exists())
    def resign_plan(self,p):
        lines=p.read_bytes().splitlines();lines[-1]=hashlib.sha256(b'\n'.join(lines[:-1])+b'\n').hexdigest().encode();p.write_bytes(b'\n'.join(lines)+b'\n')
    def test_success_removes_only_original_work_and_keeps_durable_receipt_until_separate_collect(self):
        old=self.complete();durable=self.bytes_tree(self.journal);self.collect(old);self.assertFalse(self.work.exists());self.assertEqual(durable,self.bytes_tree(self.journal))
        self.recovery_call(job=old);self.writer();self.assertTrue(self.archive.is_dir())
    def test_complete_collection_can_be_repeated_without_reclassifying_terminal(self):
        old=self.complete();self.collect(old);before=self.bytes_tree(self.journal);self.collect(old);self.assertEqual(before,self.bytes_tree(self.journal))
    def test_unknown_result_never_authorizes_deletion(self):
        self.pending();old=self.job();self.work=self.native.lockdir/('.dns-check-'+old);self.reject(old)
    def test_prepared_terminal_requires_separate_terminal_repair(self):
        old=self.prepared();self.work=self.native.lockdir/('.dns-check-'+old);self.reject(old);self.repair(old);self.collect(old)
    def test_partial_delete_terminal_cannot_release_original_work(self):
        self.add(rec(1,value='2001:db8::2'),rec(2,value='2001:db8::2'));old=self.complete(self.payload(operation='delete'));p=self.journal/'terminal';d=json.loads(p.read_bytes());d['affected']=1;p.write_bytes(self.encoded(d));self.reject(old)
    def test_confirmed_delete_preserves_frozen_durable_plan_and_collects_original_work(self):
        self.add(rec(1,value='2001:db8::2'),rec(2,value='2001:db8::2'));old=self.complete(self.payload(operation='delete'));before=self.bytes_tree(self.journal);self.collect(old);self.assertEqual(before,self.bytes_tree(self.journal))
    def test_confirmed_txt_challenge_can_be_collected_without_public_value_reflection(self):
        old=self.complete(self.txt());self.collect(old);self.assertFalse(self.work.exists())
    def test_work_input_and_context_must_bind_same_frozen_operation(self):
        old=self.complete();p=self.work/'input';saved=p.read_bytes();d=json.loads(saved);d['value']='2001:db8::3';p.write_bytes(self.encoded(d));self.reject(old);p.write_bytes(saved)
        p=self.work/'context';d=json.loads(p.read_bytes());d['request']['value']='2001:db8::3';p.write_bytes(self.encoded(d));self.reject(old)
    def test_unknown_stage_or_noncanonical_context_is_not_collected(self):
        old=self.complete();p=self.work/'context';saved=p.read_bytes();d=json.loads(saved);d['stage']='create';p.write_bytes(self.encoded(d));self.reject(old)
        p.write_bytes(saved+b' ');self.reject(old)
    def test_volatile_success_must_equal_already_bound_terminal(self):
        old=self.complete();p=self.work/'zones';p.write_bytes(p.read_bytes().replace(b'"created"',b'"updated"'));self.reject(old)
    def test_missing_member_without_plan_is_not_treated_as_partial_cleanup(self):
        old=self.complete();(self.work/'request').unlink();self.reject(old);self.assertFalse(self.plan.exists())
    def test_extra_file_subdirectory_and_dangling_link_are_preserved(self):
        old=self.complete();p=self.work/'extra';p.write_bytes(b'keep');p.chmod(0o600);self.reject(old);p.unlink();p.mkdir(mode=0o700);self.reject(old);p.rmdir();p.symlink_to(self.base/'missing');self.reject(old)
    def test_symlink_or_hardlink_member_is_not_removed(self):
        old=self.complete();p=self.work/'request';outside=self.base/'outside-request';p.rename(outside);p.symlink_to(outside);saved=outside.read_bytes();self.reject(old);self.assertEqual(saved,outside.read_bytes());p.unlink();os.link(outside,p);self.reject(old);self.assertEqual(saved,outside.read_bytes())
    def test_wrong_permission_is_not_repaired_or_deleted(self):
        old=self.complete();p=self.work/'request';p.chmod(0o640);self.reject(old);self.assertEqual(p.stat().st_mode&0o777,0o640)
    def test_second_orphan_and_original_directory_symlink_remain_blocking(self):
        old=self.complete();other=self.native.lockdir/'.dns-check-999999999';other.mkdir(mode=0o700);self.reject(old,4);other.rmdir()
        outside=self.base/'outside-work';self.work.rename(outside);self.work.symlink_to(outside);self.reject(old,4);self.assertTrue(outside.is_dir())
    def test_wrong_account_job_and_missing_confirmation_cannot_collect(self):
        old=self.complete();self.collect(old,7,account='other');self.collect('999999999',4)
        self.collect(old,2,args=['dns_a','--collect-orphan',old]);self.collect(old,2,args=['dns_a','--collect-orphan','../bad','--confirm']);self.assertTrue(self.work.exists())
    def test_simulated_new_boot_with_work_still_present_is_refused(self):
        old=self.complete();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.reject(old)
    def test_volatile_loss_after_new_boot_requires_no_pid_signal_or_evidence_rebuild(self):
        old=self.complete();self.lose_volatile();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.collect(old)
    def test_common_lock_busy_prevents_any_plan_or_deletion(self):
        import fcntl
        old=self.complete()
        with (self.store/'.supervisor.lock').open('r') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);self.reject(old,4)
        self.assertFalse(self.plan.exists());self.collect(old)
    def test_live_or_reused_original_coordinator_pid_is_not_signalled_or_collected(self):
        old=self.complete();p=self.engine.parent/'worker-process.lua';text=p.read_text()
        for action in ['io.write("S:1:2:3:4:0\\n");return','os.exit(1)']:
            p.write_text('if arg[1]=="info" and arg[2]=="'+old+'" then '+action+' end\n'+text);self.reject(old)
    def test_all_three_closed_gates_ignore_environment_override(self):
        old=self.complete();self.env['dns_orphan_collection_enabled']='true'
        for p,code in [(self.reader,2),(self.recovery,7),(self.collector,7)]:
            saved=p.read_text();p.write_text(saved.replace('dns_orphan_collection_enabled=true','dns_orphan_collection_enabled=false'));self.reject(old,code);p.write_text(saved)
    def test_internal_collector_requires_borrowed_locks(self):
        old=self.complete();before=self.bytes_tree(self.work);p=subprocess.run([self.busybox,'ash',str(self.collector),'collect-orphan','dns_a','3',old],env=self.env,capture_output=True,timeout=5)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(1,b'',b''));self.assertEqual(before,self.bytes_tree(self.work));self.assertFalse(self.plan.exists())
    def test_plan_contains_hashes_only_and_no_token_request_or_challenge_content(self):
        old=self.complete();self.pause_before_delete(old);raw=self.plan.read_bytes();self.assertEqual(len(raw.splitlines()),17);self.assertTrue(raw.startswith(b'HGCFOrphan1\n'))
        for value in [b'PRIVATE_SENTINEL',b'Authorization',b'example.test',b'2001:db8::2']:self.assertNotIn(value,raw)
        self.collect(old)
    def test_plan_file_sync_failure_preserves_work_and_complete_scratch_can_resume(self):
        old=self.complete();before=self.bytes_tree(self.work);self.fault('fsync','if any(v.endswith("/.orphan-plan") for v in sys.argv[1:]):sys.exit(1)');self.collect(old,7)
        self.assertEqual(before,self.bytes_tree(self.work));self.assertTrue(self.next.exists());self.recovery_call(job=old,expected=4);self.restore_tool('fsync');self.collect(old)
    def test_plan_rename_failure_resumes_only_after_full_revalidation(self):
        old=self.complete();self.fault('mv','if any(v.endswith("/.orphan-plan") for v in sys.argv[1:]):sys.exit(1)');self.collect(old,7);self.restore_tool('mv');self.collect(old)
    def test_unpublished_scratch_cannot_authorize_missing_work_member(self):
        old=self.complete();self.fault('mv','if any(v.endswith("/.orphan-plan") for v in sys.argv[1:]):sys.exit(1)');self.collect(old,7);self.restore_tool('mv')
        (self.work/'request').unlink();self.reject(old);self.assertFalse(self.plan.exists());self.assertTrue(self.next.exists())
    def test_partial_or_duplicate_plan_is_not_discarded(self):
        old=self.complete();p=self.next;p.write_bytes(b'keep');p.chmod(0o600);self.reject(old);p.unlink();self.pause_before_delete(old)
        p.write_bytes(self.plan.read_bytes());p.chmod(0o600);self.reject(old)
    def test_plan_bound_to_terminal_and_directory_inode_before_resume(self):
        old=self.complete();self.pause_before_delete(old);saved=self.plan.read_bytes();lines=saved.splitlines();lines[7]=b'a'*64;self.plan.write_bytes(b'\n'.join(lines)+b'\n');self.resign_plan(self.plan);self.reject(old)
        self.plan.write_bytes(saved);lines=saved.splitlines();lines[8]=b'0:1';self.plan.write_bytes(b'\n'.join(lines)+b'\n');self.resign_plan(self.plan);self.reject(old)
    def test_remaining_member_tamper_blocks_before_any_further_delete(self):
        old=self.complete();self.pause_before_delete(old);p=self.work/'attempt';p.write_bytes(b'bad');self.reject(old);self.assertTrue((self.work/'request').exists())
    def test_plan_parent_sync_failure_never_starts_deletion(self):
        old=self.complete();before=self.bytes_tree(self.work);self.fault('fsync','from pathlib import Path\nif any(v.endswith("/orphan-plan") for v in sys.argv[1:]):sys.exit(1)');self.collect(old,7);self.assertEqual(before,self.bytes_tree(self.work));self.restore_tool('fsync');self.collect(old)
    def test_partial_fixed_file_deletion_resumes_from_hash_plan(self):
        old=self.complete();self.fault('fsync','if sys.argv[1:]==['+repr(str(self.native.lockdir))+"+'/.dns-check-' + "+repr(old)+']:sys.exit(1)');self.collect(old,7);self.restore_tool('fsync')
        self.assertTrue(self.plan.exists());self.assertFalse((self.work/'request').exists());self.assertTrue((self.work/'context').exists());self.collect(old)
    def test_directory_remove_failure_resumes_from_empty_original_directory(self):
        old=self.complete();self.fault('rmdir','if any("/.dns-check-" in v for v in sys.argv[1:]):sys.exit(1)');self.collect(old,7);self.assertEqual(list(self.work.iterdir()),[]);self.restore_tool('rmdir');self.collect(old)
    def test_plan_remove_failure_can_finish_after_work_has_gone(self):
        old=self.complete();self.fault('rm','if any(v.endswith("/orphan-plan") for v in sys.argv[1:]):sys.exit(1)');self.collect(old,7);self.assertFalse(self.work.exists());self.assertTrue(self.plan.exists());self.restore_tool('rm');self.collect(old)
    def test_last_plan_removal_sync_uncertainty_rechecks_terminal_on_repeat(self):
        old=self.complete();self.fault('fsync','from pathlib import Path\nif sys.argv[1:]==['+repr(str(self.journal))+','+repr(str(self.store))+'] and not Path('+repr(str(self.work))+').exists() and not Path('+repr(str(self.plan))+').exists():sys.exit(1)')
        self.collect(old,7);self.assertFalse(self.work.exists());self.assertFalse(self.plan.exists());self.restore_tool('fsync');self.collect(old)
    def test_simulated_boot_change_after_partial_deletion_with_volatile_loss_keeps_terminal(self):
        old=self.complete();self.pause_before_delete(old);before=(self.journal/'terminal-meta').read_bytes();self.lose_volatile();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.collect(old);self.assertEqual(before,(self.journal/'terminal-meta').read_bytes())

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
