#!/usr/bin/env python3
"""Durable bound intent preparation, explicit resume, no source/service apply."""
import argparse
import hashlib
import json
import os
import subprocess
import unittest
from project import ROOT,identity
from 启动配置接合回归 import Published as PublishedBase
from 启用意图应用核对回归 import Request as ApplicationRequest

PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_grammar_closed_record_gate_and_no_production_install(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh','homegate-lifecycle-prepare.sh','homegate-config-prototype.sh']:
            self.assertFalse(parser.parse((PROTO/name).read_bytes()).root_node.has_error,name)
        LuaRuntime().compile((PROTO/'homegate-startup.lua').read_bytes())
        self.assertEqual((PROTO/'homegate-lifecycle-prepare.sh').read_text().count('lifecycle_intent_record_enabled=false'),1)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_candidate_private_pipe_requires_producer_success_and_record_has_no_raw_candidate(self):
        body=(PROTO/'homegate-lifecycle-prepare.sh').read_text();binding=(PROTO/'startup-record.sh').read_text()
        self.assertIn('HGSTARTUPCANDIDATESTATUS:%s',binding)
        self.assertIn('candidate_status=$?',binding);self.assertIn('HGSTARTUPCANDIDATESTATUS:0',binding)
        payload=binding.split('record_payload=$(',1)[1].split('\n',1)[0]
        self.assertIn('"$candidate_sum"',payload)
        for forbidden in ['credentials','active_configuration','legacy.conf']:self.assertNotIn(forbidden,payload)
        self.assertIn('(set -C; printf',body);self.assertIn('mv "$record_stage" "$record"',body)
        self.assertIn('rm -f "$record_path/context"',body);self.assertIn('rmdir "$record_path"',body)
        old_paths=body.replace('rm -f "$record_path/context"','').replace('rmdir "$record_path"','')
        self.assertNotRegex(old_paths,r'(?m)^\s*(?:rm|rmdir|chmod|chown|kill|curl|uci|service)\b')
        self.assertNotIn('rm -r',body)
    def test_persistent_presence_fence_has_no_feature_gate_exception(self):
        body=(PROTO/'homegate-config-prototype.sh').read_text()
        barrier=body.split('# A private main-switch preparation record',1)[1].split('max_revision=0',1)[0]
        self.assertIn('startup-intent',barrier);self.assertIn('.startup-intent-next',barrier)
        self.assertIn('status|export|editor-state-read|runtime-startup-snapshot-read',barrier)
        self.assertNotIn('enabled',barrier);self.assertNotIn('writer-check',barrier)

class Published(ApplicationRequest,PublishedBase):
    def setUp(self):
        super().setUp()
        self.prepare_script.write_text(self.prepare_script.read_text().replace('lifecycle_intent_record_enabled=false','lifecycle_intent_record_enabled=true'))
        self.record=self.store/'startup-intent';self.record_stage=self.store/'.startup-intent-next'
    def call_record(self,action='save',desired='enabled',expected=0,args=None,env=None):
        command=args if args is not None else ['lifecycle-intent-record',action,desired,'--confirm']
        p=subprocess.run([self.busybox,'ash',str(self.startup_cli),*command],env=env or self.env,capture_output=True,timeout=30)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),p.stdout)
        self.assertLess(len(p.stdout),2048)
        for secret in [b'PRIVATE_SENTINEL',b'SECRET_SENTINEL',b'example.test',b'127.0.0.1',os.fsencode(self.store)]:self.assertNotIn(secret,p.stdout)
        out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        if expected==0:
            self.assertEqual(out['version'],identity()['normalized']);self.assertEqual(out['phase'],'lifecycle-intent-record')
            self.assertEqual(out['configuration_revision'],self.revision);self.assertEqual(out['requested_state'],desired)
            self.assertTrue(out['intent_persisted']);self.assertTrue(out['source_bound']);self.assertTrue(out['requires_apply_revalidation'])
            self.assertEqual(out['durability_reconfirmed'],action!='check')
            for field in ['candidate_persisted','apply_authorized','start_authorized','configuration_changed','daemon_started','readers_switched','production_ready','write_ready']:self.assertFalse(out[field])
        self.assertEqual(self.calls,[])
        return out
    def unchanged_data(self):
        return {k:v for k,v in self.contents().items() if not any(k==name or k.startswith(name+'/') for name in ['startup-intent','.startup-intent-next'])}
    def stage_by_rename_failure(self):
        self.fault('mv','sys.exit(1) if sys.argv[1:]==['+repr(str(self.record_stage))+','+repr(str(self.record))+'] else None')
        try:self.call_record(expected=7)
        finally:self.restore_tool('mv')
        self.assertTrue((self.record_stage/'context').is_file());self.assertFalse(self.record.exists())
    def test_save_check_and_idempotent_resume_preserve_all_old_configuration(self):
        before=self.unchanged_data();source=self.source.read_bytes()
        out=self.call_record();self.assertEqual(out['record_state'],'prepared')
        saved=self.contents();self.call_record('check');self.assertEqual(self.contents(),saved)
        self.call_record('resume');self.assertEqual(self.contents(),saved)
        self.call_record(expected=4);self.call_record('resume','disabled',expected=7)
        self.assertEqual(self.unchanged_data(),before);self.assertEqual(self.source.read_bytes(),source)
    def test_disabled_record_has_fixed_checksum_and_no_secret_plaintext(self):
        before=self.unchanged_data();self.call_record(desired='disabled')
        raw=(self.record/'context').read_bytes();lines=raw.splitlines()
        self.assertEqual(lines[:2],[b'HGSTARTUPINTENT1',b'homegate']);self.assertEqual(len(lines),10)
        self.assertEqual(lines[3:5],[b'disabled',b'projection-disabled'])
        self.assertEqual(lines[-1],hashlib.sha256(b'\n'.join(lines[:-1])+b'\n').hexdigest().encode())
        for secret in [b'PRIVATE_SENTINEL',b'SECRET_SENTINEL',b'example.test',b'127.0.0.1']:self.assertNotIn(secret,raw)
        self.assertEqual((self.record/'context').stat().st_mode&0o777,0o600);self.assertEqual(self.record.stat().st_mode&0o777,0o700)
        self.assertEqual(self.unchanged_data(),before)
    def test_stage_fsync_failure_retains_context_until_explicit_resume(self):
        before=self.unchanged_data()
        self.fault('fsync','sys.exit(1) if '+repr(str(self.record_stage/'context'))+' in sys.argv[1:] else None')
        try:self.call_record(expected=6)
        finally:self.restore_tool('fsync')
        self.assertFalse(self.record.exists());self.assertTrue((self.record_stage/'context').exists())
        staged=self.contents();self.call_record(expected=4);self.assertEqual(self.contents(),staged)
        self.call_record('resume');self.assertFalse(self.record_stage.exists());self.assertEqual(self.unchanged_data(),before)
    def test_rename_failure_check_does_not_auto_resume(self):
        before=self.unchanged_data();self.stage_by_rename_failure();staged=self.contents()
        out=self.call_record('check');self.assertEqual(out['record_state'],'staged');self.assertEqual(self.contents(),staged)
        self.call_record('resume');self.assertFalse(self.record_stage.exists());self.assertEqual(self.unchanged_data(),before)
    def test_post_rename_fsync_failure_requires_durability_reconfirmation(self):
        before=self.unchanged_data()
        self.fault('fsync','sys.exit(1) if '+repr(str(self.record/'context'))+' in sys.argv[1:] else None')
        try:self.call_record(expected=6)
        finally:self.restore_tool('fsync')
        self.assertTrue(self.record.exists());self.assertFalse(self.record_stage.exists())
        self.assertFalse(self.call_record('check')['durability_reconfirmed'])
        self.assertTrue(self.call_record('resume')['durability_reconfirmed']);self.assertEqual(self.unchanged_data(),before)
    def test_partial_stage_and_conflicting_records_are_preserved(self):
        self.record_stage.mkdir(mode=0o700);before=self.contents();self.call_record('resume',expected=7);self.assertEqual(self.contents(),before)
        self.record_stage.rmdir();self.call_record();self.record_stage.mkdir(mode=0o700)
        before=self.contents();self.call_record('resume',expected=7);self.assertEqual(self.contents(),before)
    def test_invalid_context_permissions_links_and_extra_entries_are_not_repaired(self):
        self.call_record();context=self.record/'context';original=context.read_bytes()
        for raw in [original[:-1],original[:-1]+b'\0',original.replace(b'enabled',b'disabld',1)]:
            context.write_bytes(raw);before=self.contents();self.call_record('check',expected=7);self.assertEqual(self.contents(),before)
        context.write_bytes(original);context.chmod(0o644);before=self.contents();self.call_record('resume',expected=7);self.assertEqual(self.contents(),before)
        context.chmod(0o600);extra=self.record/'unknown';extra.write_bytes(b'KEEP');extra.chmod(0o600)
        before=self.contents();self.call_record('resume',expected=7);self.assertEqual(self.contents(),before);extra.unlink()
        outside=self.base/'retained-context';context.rename(outside);context.symlink_to(outside)
        self.call_record('resume',expected=7);self.assertTrue(context.is_symlink());self.assertEqual(outside.read_bytes(),original)
        context.unlink();os.link(outside,context);self.call_record('resume',expected=7);self.assertEqual(context.stat().st_nlink,2)
    def test_linked_record_directory_is_not_followed_or_replaced(self):
        outside=self.base/'outside-intent';outside.mkdir(mode=0o700);(outside/'keep').write_text('PRIVATE_SENTINEL')
        self.record_stage.symlink_to(outside,target_is_directory=True)
        self.call_record('resume',expected=7);self.assertTrue(self.record_stage.is_symlink());self.assertEqual((outside/'keep').read_text(),'PRIVATE_SENTINEL')
    def test_same_bytes_source_replacement_invalidates_retained_binding(self):
        self.call_record();before=self.contents();old=self.source.read_bytes()
        replacement=self.source.with_name('replacement');replacement.write_bytes(old);replacement.chmod(0o600);os.replace(replacement,self.source)
        self.call_record('resume',expected=7);self.assertEqual(self.contents(),before);self.assertEqual(self.source.read_bytes(),old)
    def test_valid_changed_source_cannot_reuse_the_record(self):
        self.call_record();before=self.contents()
        self.source.write_bytes(self.source.read_bytes().replace(b"ddns_interval '300'",b"ddns_interval '600'"))
        self.call_record('resume',expected=7);self.assertEqual(self.contents(),before)
    def test_unknown_DNS_journal_blocks_resume_without_losing_evidence(self):
        self.stage_by_rename_failure();journal=self.store/'dns-operation';journal.mkdir(mode=0o700)
        file=journal/'context';file.write_bytes(b'UNKNOWN PRIVATE_SENTINEL');file.chmod(0o600)
        before=self.contents();self.call_record('resume',expected=7);self.assertEqual(self.contents(),before)
        self.assertFalse(self.record.exists())
    def test_all_three_live_locks_refuse_before_record_creation(self):
        import fcntl
        before=self.contents()
        for lock in [self.native.lock,self.store/'.supervisor.lock',self.native.lockdir/'ddns-schedule.lock']:
            with lock.open('rb') as handle:
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB);self.call_record(expected=4)
        self.assertEqual(self.contents(),before);self.assertFalse(self.record_stage.exists())
    def test_pending_record_fences_startup_and_config_engine_even_with_gate_off(self):
        self.call_record();before=self.contents()
        self.startup(expected=4);self.request(expected=4)
        self.engine.write_text(self.engine.read_text().replace('startup_admission_enabled=true','startup_admission_enabled=false'))
        self.cli('writer-check',expected=4);self.cli('status');self.assertEqual(self.contents(),before)
    def test_source_change_during_stage_sync_retains_stale_stage(self):
        before=self.unchanged_data()
        self.fault('fsync','\nif '+repr(str(self.record_stage/'context'))+' in sys.argv[1:]:\n from pathlib import Path\n p=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes()+b"\\n")')
        try:self.call_record(expected=7)
        finally:self.restore_tool('fsync')
        self.assertTrue(self.record_stage.exists());self.assertFalse(self.record.exists());self.assertEqual(self.unchanged_data(),before)
        self.call_record('resume',expected=1)
    def test_arguments_and_environment_cannot_open_record_gate(self):
        before=self.contents()
        for args in [['lifecycle-intent-record'],['lifecycle-intent-record','save','enabled'],['lifecycle-intent-record','save','enabled','wrong'],['lifecycle-intent-record','apply','enabled','--confirm']]:
            self.call_record(expected=2,args=args)
        self.prepare_script.write_text(self.prepare_script.read_text().replace('lifecycle_intent_record_enabled=true','lifecycle_intent_record_enabled=false'))
        self.call_record(expected=2,env={**self.env,'lifecycle_intent_record_enabled':'true'});self.assertEqual(self.contents(),before)
    def test_failed_candidate_producer_cannot_persist_an_empty_digest(self):
        (self.engine.parent/'startup-candidate.lua').unlink();before=self.contents()
        self.call_record(expected=7);self.assertEqual(self.contents(),before);self.assertFalse(self.record_stage.exists())

def suite(runtime):
    cls=Published if runtime else Static
    return unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    result=unittest.TextTestRunner(verbosity=2,failfast=True).run(suite(a.runtime));raise SystemExit(not result.wasSuccessful())
