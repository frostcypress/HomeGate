#!/usr/bin/env python3
"""Explicit intent requests are bound preflight facts, never activation permits."""
import argparse
import json
import os
import subprocess
import unittest
from project import ROOT,identity
from 核心配置校验回归 import models,RAW
from 启动配置接合回归 import Cold as ColdBase,Published as PublishedBase

PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_explicit_state_is_required_for_all_source_provenances(self):
        lua,codec,validator,ip=models();model=lua.execute((PROTO/'startup-intent.lua').read_text())
        for marker in ['ordinary-enabled','ordinary-disabled','projection-disabled']:
            for desired in ['enabled','disabled']:
                out=model.request(marker,desired)
                self.assertEqual(out['requested_state'],desired);self.assertTrue(out['explicit_request'])
                self.assertEqual(out['source_intent']['known'],marker!='projection-disabled')
                self.assertEqual(out['changes_observed_flag'],(marker=='ordinary-enabled')!=(desired=='enabled'))
            for bad in [None,'','1','--confirm','SECRET_SENTINEL']:
                self.assertIsNone(model.request(marker,bad))
        self.assertIsNone(model.request('projection-enabled','enabled'))
    def test_requests_are_fresh_values_and_do_not_rewrite_source_intent(self):
        lua,codec,validator,ip=models();model=lua.execute((PROTO/'startup-intent.lua').read_text())
        first=model.request('projection-disabled','enabled');first['source_intent']['known']=True
        second=model.request('projection-disabled','disabled')
        self.assertFalse(second['source_intent']['known']);self.assertEqual(second['source_intent']['desired_state'],'unconfirmed')
        self.assertEqual(model.describe('ordinary-enabled')['desired_state'],'enabled')
    def test_grammar_closed_gate_and_no_apply_or_service_implementation(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh','homegate-lifecycle-prepare.sh']:
            self.assertFalse(parser.parse((PROTO/name).read_bytes()).root_node.has_error)
        LuaRuntime().compile((PROTO/'homegate-startup.lua').read_bytes())
        body=(PROTO/'homegate-lifecycle-prepare.sh').read_text()
        self.assertIn('lifecycle_intent_check_enabled=false',body)
        for forbidden in ['projection-publish','migration-source-commit','service restart','kill ']:self.assertNotIn(forbidden,body)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class Request:
    def setUp(self):
        super().setUp()
        self.lua_restore=None
        self.prepare_script.write_text(self.prepare_script.read_text().replace('lifecycle_intent_check_enabled=false','lifecycle_intent_check_enabled=true'))
    def tearDown(self):
        if self.lua_restore:
            tool,target=self.lua_restore
            tool.unlink();tool.symlink_to(target)
        super().tearDown()
    def request(self,*args,expected=0,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.startup_cli),*(args or ('lifecycle-intent-check','enabled','--confirm'))],
                         env=env or self.env,capture_output=True,timeout=20)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),p.stdout)
        self.assertLess(len(p.stdout),2048)
        for secret in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'127.0.0.1',os.fsencode(self.store)]:self.assertNotIn(secret,p.stdout)
        out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        if expected==0:
            self.assertEqual(out['phase'],'lifecycle-intent-check');self.assertEqual(out['version'],identity()['normalized'])
            self.assertEqual(out['scope'],'enable-intent-application-preflight');self.assertTrue(out['source_bound'])
            self.assertTrue(out['configuration_ready']);self.assertTrue(out['point_in_time']);self.assertTrue(out['requires_apply_revalidation'])
            for flag in ['apply_authorized','start_authorized','intent_persisted','configuration_changed','daemon_started','readers_switched','production_ready','write_ready']:
                self.assertFalse(out[flag],flag)
            self.assertNotIn('token',out);self.assertEqual(out['effect'],'runtime-metadata-preparation')
        if hasattr(self,'calls'):self.assertEqual(self.calls,[])
        return out
    def inject_report(self,code):
        tool=self.bin/'lua';target=tool.resolve();tool.unlink()
        tool.write_text('#!'+os.sys.executable+'\nimport os,sys\nif len(sys.argv)>2 and sys.argv[1].endswith("/homegate-startup.lua") and sys.argv[2]=="request-report":\n'+code+'\nos.execv('+repr(str(target))+',['+repr(str(target))+',*sys.argv[1:]])\n')
        tool.chmod(0o700)
        self.lua_restore=(tool,target)

class Cold(Request,ColdBase):
    def test_invalid_or_missing_confirmation_fails_before_metadata_creation(self):
        for args in [(),('enabled',),('disabled','--wrong'),('SECRET_SENTINEL','--confirm'),('enabled','--confirm','extra')]:
            self.request('lifecycle-intent-check',*args,expected=2)
        self.assertFalse(self.native.lockdir.exists());self.assertFalse(self.store.exists())
    def test_closed_gate_cannot_be_opened_by_environment(self):
        self.prepare_script.write_text(self.prepare_script.read_text().replace('lifecycle_intent_check_enabled=true','lifecycle_intent_check_enabled=false'))
        self.request(expected=2,env={**self.env,'lifecycle_intent_check_enabled':'true','HOMEGATE_CONFIG_PROTO_STORE':str(self.base)})
        self.assertFalse(self.store.exists());self.assertFalse(self.native.lockdir.exists())
    def test_valid_cold_source_is_not_auto_adopted_or_enabled(self):
        self.request(expected=7);self.assertEqual(self.source.read_text(),RAW)
        self.assertEqual(self.cli('status')['revision'],1)
        self.assertFalse(any(self.store.glob('gen-*/legacy.conf')))
    def test_invalid_source_does_not_create_runtime_or_store(self):
        self.source.write_text(RAW.replace('https://127.0.0.1:8443/a?q=1','ftp://PRIVATE_SENTINEL'))
        self.request(expected=1);self.assertFalse(self.native.lockdir.exists());self.assertFalse(self.store.exists())

class Published(Request,PublishedBase):
    def test_both_explicit_choices_preserve_unknown_projection_and_store(self):
        before=self.contents();raw=self.source.read_bytes()
        for desired in ['enabled','disabled']:
            out=self.request('lifecycle-intent-check',desired,'--confirm')
            self.assertEqual(out['configuration_revision'],self.revision)
            self.assertEqual(out['request']['requested_state'],desired);self.assertTrue(out['request']['explicit_request'])
            self.assertEqual(out['request']['confirmation_source'],'command-argument')
            self.assertEqual(out['request']['source_intent'],dict(known=False,provenance='public-disabled-projection',desired_state='unconfirmed'))
        self.assertEqual(self.contents(),before);self.assertEqual(self.source.read_bytes(),raw)
    def test_all_three_locks_are_owned_by_this_invocation(self):
        import fcntl
        before=self.contents()
        for lock in [self.native.lock,self.store/'.supervisor.lock',self.native.lockdir/'ddns-schedule.lock']:
            inode=lock.stat().st_ino
            with lock.open('rb') as handle:
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB);self.request(expected=4)
            self.assertEqual(lock.stat().st_ino,inode)
        self.assertEqual(self.contents(),before)
    def test_runtime_and_persistent_recovery_fences_remain(self):
        for name in ['.health-read-99999','.recovery-read-99999','.ddns-recovery-next','.ddns-recovery-pending','.dns-check-99999','.ddns-plan-99999']:
            file=self.native.lockdir/name;file.write_bytes(b'KEEP PRIVATE_SENTINEL');file.chmod(0o600)
            before=self.contents();self.request(expected=4);self.assertEqual(self.contents(),before);file.unlink()
        journal=self.store/'dns-operation';journal.mkdir(mode=0o700);file=journal/'context';file.write_text('UNKNOWN PRIVATE_SENTINEL');file.chmod(0o600)
        before=self.contents();self.request(expected=4);self.assertEqual(self.contents(),before)
    def test_valid_stale_source_cannot_be_reconfirmed_without_adoption(self):
        self.source.write_bytes(self.source.read_bytes().replace(b"ddns_interval '300'",b"ddns_interval '600'"))
        before=self.contents();self.request(expected=7);self.assertEqual(self.contents(),before)
    def test_source_change_during_report_refuses_buffered_success(self):
        self.inject_report(' from pathlib import Path\n p=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes()+b"\\n")')
        before=self.contents();self.request(expected=7);self.assertEqual(self.contents(),before)
    def test_same_bytes_manifest_replacement_during_report_refuses(self):
        manifest=self.store/f'gen-{self.revision}/manifest';old=manifest.stat().st_ino
        self.inject_report(' from pathlib import Path\n p=Path('+repr(str(manifest))+');q=p.with_name("replacement");q.write_bytes(p.read_bytes());q.chmod(0o600);os.replace(q,p)')
        before=self.contents();self.request(expected=7);self.assertNotEqual(manifest.stat().st_ino,old)
        after=self.contents();key=str(manifest.relative_to(self.store))
        self.assertEqual(after[key][::2],before[key][::2])
        before[key]=(before[key][0],after[key][1],before[key][2]);self.assertEqual(after,before)
    def test_persistent_unknown_created_during_report_is_not_ignored(self):
        journal=self.store/'dns-operation'
        self.inject_report(' from pathlib import Path\n p=Path('+repr(str(journal))+');p.mkdir(mode=0o700);q=p/"context";q.write_text("UNKNOWN PRIVATE_SENTINEL");q.chmod(0o600)')
        self.request(expected=7);self.assertEqual((journal/'context').read_text(),'UNKNOWN PRIVATE_SENTINEL')
    def test_late_runtime_fence_refuses_without_removing_evidence(self):
        pending=self.native.lockdir/'.ddns-recovery-next'
        self.inject_report(' from pathlib import Path\n p=Path('+repr(str(pending))+');p.write_text("KEEP PRIVATE_SENTINEL");p.chmod(0o600)')
        self.request(expected=4);self.assertEqual(pending.read_text(),'KEEP PRIVATE_SENTINEL')
    def test_prior_report_is_not_cached_or_a_reusable_authorization(self):
        first=self.request();self.assertFalse(first['apply_authorized'])
        self.source.write_bytes(self.source.read_bytes()+b'\n');self.request(expected=1)
    def test_DDNS_write_authority_is_not_required_or_enabled(self):
        self.engine.write_text(self.engine.read_text().replace('production_writes_enabled=true','production_writes_enabled=false').replace('ddns_authority_enabled=true','ddns_authority_enabled=false'))
        before=self.contents();self.request();self.assertEqual(self.contents(),before)

def suite(runtime):
    classes=[Cold,Published] if runtime else [Static]
    return unittest.TestSuite(cls(n) for cls in classes for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    result=unittest.TextTestRunner(verbosity=2,failfast=True).run(suite(a.runtime));raise SystemExit(not result.wasSuccessful())
