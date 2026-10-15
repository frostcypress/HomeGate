#!/usr/bin/env python3
"""Checkpoint publication only, isolated Linux faults, no provider or router."""
import argparse,hashlib,json,os,re,subprocess,unittest
from DNS回执恢复回归 import Runtime as RecoveryRuntime, Static as RecoveryStatic
from Cloudflare记录回归 import PROTO,rec

class Static(RecoveryStatic):
    def test_closed_gates_grammar_and_no_production_install(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-dns-checkpoint-repair.sh','homegate-cloudflare-read.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error)
            self.assertEqual(body.count(b'dns_checkpoint_repair_enabled=false'),1)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
        self.lua.compile((PROTO/'cloudflare-records.lua').read_bytes())
    def test_no_network_deletion_or_volatile_inference(self):
        body=(PROTO/'homegate-dns-checkpoint-repair.sh').read_text()
        for forbidden in ['curl','rm ','rmdir','work/context','work/zones','eval ','os.execute']:self.assertNotIn(forbidden,body)
        self.assertIn('receipt-checkpoint',body);self.assertIn('dns-recovery-snapshot-read',body)
    def test_advance_keeps_exact_frozen_request_and_moves_forward_only(self):
        before=self.context(b'delete',b'delete');after=self.context(b'delete',b'delete')
        for c in [before,after]:c[b'delete_ids'][3]=b'c'*32
        after[b'position']=3;after[b'affected']=2
        self.assertTrue(self.receipt.advance(before,after,self.codec))
        after[b'position']=1;self.assertFalse(self.receipt.advance(before,after,self.codec));after[b'position']=3
        after[b'affected']=0;self.assertFalse(self.receipt.advance(before,after,self.codec));after[b'affected']=2
        after[b'request'][b'value']=b'2001:db8::3';self.assertFalse(self.receipt.advance(before,after,self.codec))

class Runtime(RecoveryRuntime):
    def setUp(self):
        super().setUp();self.checkpoint=self.engine.parent/'homegate-dns-checkpoint-repair.sh'
        self.reader.write_text(self.reader.read_text().replace('dns_checkpoint_repair_enabled=false','dns_checkpoint_repair_enabled=true'))
        body=self.checkpoint.read_text().replace('dns_checkpoint_repair_enabled=false','dns_checkpoint_repair_enabled=true')
        mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir)}
        body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
        body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
        self.checkpoint.write_text(body)
    def interrupted(self,where='prepared',second=False,third=False):
        failures={
            'prepared':('fsync','if any(v.endswith("/.prepare/context") for v in sys.argv[1:]):sys.exit(1)'),
            'slot':('fsync','if sys.argv[1:]==['+repr(str(self.journal))+']:sys.exit(1)'),
            'pointer':('fsync','if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)'),
            'rename':('mv','if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)'),
            'final':('fsync','if sys.argv[1:]==['+repr(str(self.journal))+','+repr(str(self.store))+']:sys.exit(1)')}
        tool,code=failures[where]
        if second or third:
            self.add(*(rec(i,value='2001:db8::2') for i in [1,2,3]))
            seen=[0]
            def hook(method,*args):
                if method=='DELETE':
                    seen[0]+=1
                    if seen[0]==(2 if third else 1):self.fault(tool,code)
            self.hook=hook;self.records(self.payload(operation='delete'),expected=7);self.hook=None
        else:self.fault(tool,code);self.records(expected=7)
        self.restore_tool(tool)
        work=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(work),1)
        return work[0].name.removeprefix('.dns-check-')
    def repair(self,job,expected=0,account='dns_a',args=None):
        n=len(self.calls);result=self.recovery_call('--repair-checkpoint',expected,account,job,args)
        self.assertEqual(n,len(self.calls))
        if expected==0:self.assertTrue(result['checkpoint_repaired']);self.assertFalse(result['write_ready'])
        self.writer(4);return result
    def resign(self,slot):
        p=slot/'manifest';lines=p.read_bytes().splitlines();self.assertEqual(len(lines),10)
        lines[8]=hashlib.sha256((slot/'context').read_bytes()).hexdigest().encode()
        lines[9]=hashlib.sha256(b'\n'.join(lines[:9])+b'\n').hexdigest().encode();p.write_bytes(b'\n'.join(lines)+b'\n')
    def reject(self,job,expected=7):
        before=self.bytes_tree(self.journal);self.repair(job,expected);self.assertEqual(before,self.bytes_tree(self.journal))
    def test_complete_initial_prepare_publishes_without_http_or_orphan_deletion(self):
        job=self.interrupted();work=self.native.lockdir/('.dns-check-'+job);original=self.bytes_tree(work);saved=self.bytes_tree(self.journal/'.prepare')
        self.repair(job);self.assertEqual((self.journal/'current').read_bytes(),b'1\n');self.assertEqual(self.bytes_tree(self.journal/'slot-1'),saved)
        self.assertEqual(self.bytes_tree(work),original);self.assertFalse((self.journal/'.prepare').exists());self.assertFalse((self.journal/'.next').exists());self.assertEqual(self.mutations(),[])
    def test_published_initial_slot_and_empty_pointer_resume(self):
        job=self.interrupted('slot');self.assertEqual((self.journal/'.next').read_bytes(),b'');self.repair(job);self.assertEqual((self.journal/'current').read_bytes(),b'1\n')
    def test_complete_pointer_after_sync_failure_resumes(self):
        job=self.interrupted('pointer');self.assertEqual((self.journal/'.next').read_bytes(),b'1\n');self.repair(job)
    def test_pointer_rename_failure_resumes(self):
        job=self.interrupted('rename');self.repair(job)
    def test_final_sync_uncertainty_resyncs_current_idempotently(self):
        job=self.interrupted('final');before=self.bytes_tree(self.journal);self.repair(job);self.repair(job);self.assertEqual(before,self.bytes_tree(self.journal))
    def test_second_delete_prepare_preserves_previous_checkpoint(self):
        job=self.interrupted(second=True);old=self.bytes_tree(self.journal/'slot-1');self.repair(job)
        self.assertEqual((self.journal/'current').read_bytes(),b'2\n');self.assertEqual(old,self.bytes_tree(self.journal/'slot-1'));self.assertEqual(len(self.mutations()),1)
    def test_second_published_candidate_advances_only_to_bound_pointer(self):
        job=self.interrupted('rename',second=True);self.assertEqual((self.journal/'current').read_bytes(),b'1\n');self.repair(job);self.assertEqual((self.journal/'current').read_bytes(),b'2\n')
    def test_third_checkpoint_rotates_back_without_discarding_current(self):
        job=self.interrupted(third=True);old=self.bytes_tree(self.journal/'slot-2');self.repair(job)
        self.assertEqual((self.journal/'current').read_bytes(),b'1\n');self.assertEqual(old,self.bytes_tree(self.journal/'slot-2'));self.assertEqual(len(self.mutations()),2)
    def test_original_boot_binding_survives_simulated_boot_change_and_volatile_loss(self):
        job=self.interrupted();self.lose_volatile();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.repair(job)
        self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))
    def test_repaired_plan_only_allows_explicit_read_observation_and_never_collection(self):
        job=self.interrupted();self.repair(job);self.lose_volatile();r=self.recovery_call('--reconcile-receipt',job=job)
        self.assertEqual(r['effect'],'unknown');self.assertEqual(r['observation'],'desired-absent');self.recovery_call(job=job,expected=7);self.writer(4)
    def test_missing_manifest_is_not_recreated(self):
        job=self.interrupted();(self.journal/'.prepare/manifest').unlink();self.reject(job)
    def test_corrupt_context_is_not_discarded(self):
        job=self.interrupted();p=self.journal/'.prepare/context';p.write_bytes(p.read_bytes()+b' ');self.reject(job)
    def test_resigned_unknown_context_field_is_rejected(self):
        job=self.interrupted();slot=self.journal/'.prepare';p=slot/'context';d=json.loads(p.read_bytes());d['token']='PRIVATE_SENTINEL';p.write_bytes(self.encoded(d));self.resign(slot);self.reject(job)
    def test_changed_request_cannot_advance_current_delete(self):
        job=self.interrupted(second=True);slot=self.journal/'.prepare';p=slot/'context';d=json.loads(p.read_bytes());d['request']['value']='2001:db8::3';p.write_bytes(self.encoded(d));self.resign(slot);self.reject(job)
    def test_changed_frozen_delete_ids_cannot_advance(self):
        job=self.interrupted(second=True);slot=self.journal/'.prepare';p=slot/'context';d=json.loads(p.read_bytes());d['delete_ids'][0]='a'*32;p.write_bytes(self.encoded(d));self.resign(slot);self.reject(job)
    def test_nonforward_candidate_cannot_replace_current(self):
        job=self.interrupted(second=True);slot=self.journal/'.prepare';p=slot/'context';d=json.loads(p.read_bytes());d['position']=1;d['affected']=0;p.write_bytes(self.encoded(d));self.resign(slot);self.reject(job)
    def test_invalid_current_is_never_inferred_from_other_candidates(self):
        job=self.interrupted(second=True);(self.journal/'current').write_bytes(b'9\n');self.reject(job)
    def test_corrupt_active_slot_cannot_be_replaced_by_valid_prepare(self):
        job=self.interrupted(second=True);p=self.journal/'slot-1/context';p.write_bytes(p.read_bytes()+b' ');self.reject(job)
    def test_missing_current_with_two_slot_history_is_not_initialization(self):
        job=self.interrupted('rename',second=True);(self.journal/'current').unlink();self.reject(job)
    def test_partial_or_wrong_pointer_is_preserved(self):
        job=self.interrupted()
        for value in [b'1',b'3\n',b'2\n',b'1\n\n']:(self.journal/'.next').write_bytes(value);self.reject(job)
    def test_missing_pointer_with_prepare_is_not_recreated(self):
        job=self.interrupted();(self.journal/'.next').unlink();self.reject(job)
    def test_duplicate_prepared_and_published_candidate_is_rejected(self):
        import shutil
        job=self.interrupted();shutil.copytree(self.journal/'.prepare',self.journal/'slot-1');self.reject(job)
    def test_terminal_evidence_prevents_checkpoint_republication(self):
        job=self.interrupted();p=self.journal/'terminal';p.write_bytes(b'keep');p.chmod(0o600);self.reject(job)
    def test_symlink_candidate_and_hardlink_pointer_are_not_followed(self):
        job=self.interrupted();p=self.journal/'.prepare/context';outside=self.base/'outside-context';p.rename(outside);p.symlink_to(outside);saved=outside.read_bytes();self.reject(job);self.assertEqual(saved,outside.read_bytes());p.unlink();outside.rename(p)
        os.link(self.journal/'.next',self.base/'outside-pointer');self.reject(job)
    def test_private_mode_and_unknown_entries_remain_unchanged(self):
        job=self.interrupted();p=self.journal/'.prepare/context';p.chmod(0o640);self.reject(job);self.assertEqual(p.stat().st_mode&0o777,0o640);p.chmod(0o600)
        extra=self.journal/'.prepare/extra';extra.write_bytes(b'keep');extra.chmod(0o600);self.reject(job)
    def test_wrong_original_identity_account_job_or_confirmation_is_refused(self):
        job=self.interrupted();self.repair(job,7,account='other');self.repair('999999999',4);self.lose_volatile();self.repair('999999999',7)
        self.repair(job,2,args=['dns_a','--repair-checkpoint',job]);self.repair(job,2,args=['dns_a','--repair-checkpoint','../bad','--confirm'])
        p=self.journal/'.prepare/manifest';lines=p.read_bytes().splitlines();lines[2]=b'a'*64;lines[9]=hashlib.sha256(b'\n'.join(lines[:9])+b'\n').hexdigest().encode();p.write_bytes(b'\n'.join(lines)+b'\n');self.reject(job)
    def test_other_orphan_and_original_symlink_remain_blocking(self):
        job=self.interrupted();other=self.native.lockdir/'.dns-check-999999999';other.mkdir(mode=0o700);self.reject(job,4);other.rmdir();self.lose_volatile()
        outside=self.base/'outside-orphan';outside.mkdir(mode=0o700);(self.native.lockdir/('.dns-check-'+job)).symlink_to(outside);self.reject(job,4);self.assertTrue(outside.is_dir())
    def test_both_gates_cannot_be_overridden_by_environment(self):
        job=self.interrupted();self.env['dns_checkpoint_repair_enabled']='true';self.reader.write_text(self.reader.read_text().replace('dns_checkpoint_repair_enabled=true','dns_checkpoint_repair_enabled=false'));self.reject(job,2)
        self.reader.write_text(self.reader.read_text().replace('dns_checkpoint_repair_enabled=false','dns_checkpoint_repair_enabled=true'));self.checkpoint.write_text(self.checkpoint.read_text().replace('dns_checkpoint_repair_enabled=true','dns_checkpoint_repair_enabled=false'));self.reject(job)
    def test_no_borrowed_locks_cannot_modify_the_journal(self):
        job=self.interrupted();before=self.bytes_tree(self.journal);p=subprocess.run([self.busybox,'ash',str(self.checkpoint),'repair-checkpoint','dns_a','3',job],env=self.env,capture_output=True,timeout=5)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(1,b'',b''));self.assertEqual(before,self.bytes_tree(self.journal))
    def test_candidate_fsync_failure_preserves_all_bytes_and_can_retry(self):
        job=self.interrupted();self.fault('fsync','if any(v.endswith("/.prepare/context") for v in sys.argv[1:]):sys.exit(1)');self.reject(job);self.restore_tool('fsync');self.repair(job)
    def test_candidate_rename_failure_can_retry_without_erasing_evidence(self):
        job=self.interrupted();self.fault('mv','if any(v.endswith("/.prepare") for v in sys.argv[1:]):sys.exit(1)');self.reject(job);self.restore_tool('mv');self.repair(job)
    def test_post_candidate_rename_fsync_failure_can_resume(self):
        job=self.interrupted();self.fault('fsync','from pathlib import Path\nif sys.argv[1:]==['+repr(str(self.journal))+'] and Path('+repr(str(self.journal/'slot-1'))+').exists():sys.exit(1)');self.repair(job,7);self.assertTrue((self.journal/'slot-1').is_dir());self.restore_tool('fsync');self.repair(job)
    def test_pointer_sync_and_rename_failures_resume_without_dns(self):
        job=self.interrupted();self.fault('fsync','if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)');self.repair(job,7);self.restore_tool('fsync')
        self.fault('mv','if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)');self.reject(job);self.restore_tool('mv');self.repair(job)
    def test_final_sync_failure_keeps_active_barrier_until_explicit_resync(self):
        job=self.interrupted();self.fault('fsync','if any(v.endswith("/current") for v in sys.argv[1:]):sys.exit(1)');self.repair(job,7);self.assertEqual((self.journal/'current').read_bytes(),b'1\n');self.restore_tool('fsync');self.repair(job)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
