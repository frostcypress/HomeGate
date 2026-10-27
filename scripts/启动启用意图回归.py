#!/usr/bin/env python3
"""Real source switches and lossy disabled projections are different facts."""
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
    def test_real_source_flags_survive_private_parse_before_backup_normalization(self):
        lua,codec,validator,ip=models();model=lua.execute((PROTO/'startup-intent.lua').read_text())
        for value,label in [('1','enabled'),('0','disabled')]:
            raw=RAW.replace("option enabled '1'","option enabled '"+value+"'",1)
            candidate=codec.private_configuration(raw)
            self.assertIsNotNone(validator.validate(candidate,candidate,codec.json,ip))
            marker=model.marker(candidate);self.assertEqual(marker,'ordinary-'+label)
            report=model.public(marker);self.assertTrue(report['known']);self.assertEqual(report['desired_state'],label)
            self.assertEqual(candidate['configuration'][1]['values']['enabled'],'0')
    def test_safety_projection_is_unknown_intent_and_never_guessed_from_disabled_flag(self):
        lua,codec,validator,ip=models();model=lua.execute((PROTO/'startup-intent.lua').read_text());public=[]
        for value in ['1','0']:
            raw=RAW.replace("option enabled '1'","option enabled '"+value+"'",1)
            projected,slots=codec.migration(raw);public.append(projected)
            candidate=codec.private_configuration(projected);self.assertEqual(model.marker(candidate),'projection-disabled')
            self.assertFalse(model.public('projection-disabled')['known'])
            self.assertEqual(model.public('projection-disabled')['desired_state'],'unconfirmed')
        self.assertEqual(public[0],public[1])
        for marker in ['','enabled','ordinary-SECRET_SENTINEL','projection-enabled']:
            self.assertIsNone(model.describe(marker))
        self.assertIsNone(model.marker(lua.table_from(dict(switches=dict(main=dict(kind='homegate',enabled='1')),public_projection=True),recursive=True)))
    def test_closed_gates_pure_model_and_source_only_return_precedes_runtime_creation(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        LuaRuntime().compile((PROTO/'homegate-startup.lua').read_bytes())
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh','homegate-lifecycle-prepare.sh']:
            self.assertFalse(parser.parse((PROTO/name).read_bytes()).root_node.has_error)
        body=(PROTO/'homegate-lifecycle-prepare.sh').read_text()
        self.assertLess(body.index('if [ "$source_only" = true ]'),body.index('mkdir "$runtime"'))
        self.assertIn('lifecycle_startup_enabled=false',body)
        pure=(PROTO/'startup-intent.lua').read_text()
        for forbidden in ['io.','os.','loadfile','require(']:self.assertNotIn(forbidden,pure)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class Request:
    def intent(self,*args,expected=0,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.startup_cli),*(args or ('lifecycle-source-intent',))],
                         env=env or self.env,capture_output=True,timeout=15)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),p.stdout)
        self.assertLess(len(p.stdout),2048)
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'127.0.0.1',os.fsencode(self.store)]:self.assertNotIn(marker,p.stdout)
        out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        if expected==0:
            self.assertEqual(out['version'],identity()['normalized']);self.assertEqual(out['phase'],'lifecycle-source-intent')
            self.assertFalse(out['adoption_checked']);self.assertFalse(out['source_bound']);self.assertFalse(out['start_authorized'])
            self.assertFalse(out['metadata_changed']);self.assertFalse(out['daemon_started']);self.assertFalse(out['production_ready'])
            self.assertFalse(out['write_ready']);self.assertEqual(out['effect'],'none');self.assertNotIn('configuration_ready',out)
        if hasattr(self,'calls'):self.assertEqual(self.calls,[])
        return out
    def absent_metadata(self):
        self.assertFalse(self.native.lockdir.exists());self.assertFalse(self.store.exists())

class Cold(Request,ColdBase):
    def test_actual_enabled_source_is_read_only_and_does_not_adopt_or_start(self):
        before=self.source.read_bytes();out=self.intent()
        self.assertEqual(out['enable_intent'],dict(known=True,provenance='ordinary-source',desired_state='enabled'))
        self.assertTrue(out['observed_enabled']);self.assertFalse(out['enable_intent_confirmation_required'])
        self.assertEqual(self.source.read_bytes(),before);self.absent_metadata()
    def test_actual_disabled_source_is_known_without_clearing_other_rule_flags(self):
        self.source.write_text(RAW.replace("option enabled '1'","option enabled '0'",1));before=self.source.read_bytes()
        out=self.intent();self.assertEqual(out['enable_intent']['desired_state'],'disabled');self.assertTrue(out['enable_intent']['known'])
        self.assertFalse(out['observed_enabled']);self.assertEqual(self.source.read_bytes(),before);self.absent_metadata()
    def test_both_original_intents_collapse_to_same_unknown_public_projection(self):
        lua,codec,validator,ip=models();outputs=[]
        for value in ['1','0']:
            public,slots=codec.migration(RAW.replace("option enabled '1'","option enabled '"+value+"'",1))
            self.source.write_text(public);out=self.intent();outputs.append(out['enable_intent'])
            self.assertFalse(out['enable_intent']['known']);self.assertEqual(out['enable_intent']['desired_state'],'unconfirmed')
            self.assertTrue(out['enable_intent_confirmation_required']);self.absent_metadata()
        self.assertEqual(outputs[0],outputs[1])
    def test_missing_invalid_and_semantically_bad_sources_fail_without_metadata(self):
        for raw,code in [('',7),('PRIVATE_SENTINEL',1),(RAW.replace('https://127.0.0.1:8443/a?q=1','ftp://PRIVATE_SENTINEL'),1),
                         (RAW.replace("option enabled '1'","option enabled '2'",1),1)]:
            self.source.write_text(raw);self.intent(expected=code);self.absent_metadata()
        self.source.unlink();self.intent(expected=7);self.absent_metadata()
    def test_unsafe_permissions_and_linked_sources_are_not_repaired(self):
        self.source.chmod(0o644);self.intent(expected=7);self.assertEqual(self.source.stat().st_mode&0o777,0o644)
        self.source.chmod(0o600);original=self.source.with_name('original');self.source.rename(original);self.source.symlink_to(original)
        self.intent(expected=7);self.assertTrue(self.source.is_symlink());self.source.unlink();os.link(original,self.source)
        self.intent(expected=7);self.assertEqual(original.read_text(),RAW);self.assertEqual(self.source.stat().st_nlink,2);self.absent_metadata()
    def test_source_change_while_building_intent_report_refuses_stale_result(self):
        tool=self.bin/'lua';target=tool.resolve();tool.unlink()
        injection='\nif len(sys.argv)>2 and sys.argv[1].endswith("/homegate-startup.lua") and sys.argv[2]=="intent-report":\n from pathlib import Path\n p=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes().replace(b"enabled \'1\'",b"enabled \'0\'",1))'
        tool.write_text('#!'+os.sys.executable+'\nimport os,sys\n'+injection+'\nos.execv('+repr(str(target))+',['+repr(str(target))+',*sys.argv[1:]])\n');tool.chmod(0o700)
        try:self.intent(expected=7)
        finally:tool.unlink();tool.symlink_to(target)
        self.absent_metadata()
    def test_gates_arguments_and_environment_cannot_redirect_source_or_enable_entry(self):
        self.intent('lifecycle-source-intent','../PRIVATE_SENTINEL',expected=2)
        self.prepare_script.write_text(self.prepare_script.read_text().replace('lifecycle_startup_enabled=true','lifecycle_startup_enabled=false'))
        self.intent(expected=2,env={**self.env,'lifecycle_startup_enabled':'true','HOMEGATE_CONFIG_PROTO_STORE':str(self.base)})
        self.absent_metadata()
    def test_source_intent_does_not_need_runtime_layout_store_or_DDNS_authority(self):
        self.engine.write_text(self.engine.read_text().replace('startup_admission_enabled=true','startup_admission_enabled=false'))
        self.alias.unlink();self.alias.symlink_to(self.base,target_is_directory=True)
        self.fault('mkdir','sys.exit(99)');self.intent();self.restore_tool('mkdir');self.absent_metadata()

class Published(Request,PublishedBase):
    def test_startup_report_preserves_projection_provenance_instead_of_inventing_disable_intent(self):
        before=self.contents();source=self.source.read_bytes();preview=self.intent();startup=self.startup()
        self.assertEqual(preview['enable_intent'],startup['enable_intent'])
        self.assertFalse(startup['enable_intent']['known']);self.assertEqual(startup['enable_intent']['desired_state'],'unconfirmed')
        self.assertTrue(startup['enable_intent_confirmation_required']);self.assertFalse(startup['start_authorized'])
        self.assertEqual(self.contents(),before);self.assertEqual(self.source.read_bytes(),source)
    def test_source_preview_does_not_bypass_persistent_DNS_startup_barrier(self):
        journal=self.store/'dns-operation';journal.mkdir(mode=0o700);(journal/'context').write_text('UNKNOWN PRIVATE_SENTINEL');(journal/'context').chmod(0o600)
        before=self.contents();out=self.intent();self.assertFalse(out['start_authorized']);self.startup(expected=4)
        self.assertEqual(self.contents(),before)
    def test_legacy_backup_is_not_a_fallback_enable_intent_authority(self):
        old=self.store/f'gen-{self.revision}/legacy.conf';old.write_text(RAW);old.chmod(0o600)
        before=self.contents();out=self.intent();self.assertFalse(out['enable_intent']['known'])
        self.assertEqual(out['enable_intent']['desired_state'],'unconfirmed');self.assertEqual(self.contents(),before)

def suite(runtime):
    classes=[Cold,Published] if runtime else [Static]
    return unittest.TestSuite(cls(n) for cls in classes for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    result=unittest.TextTestRunner(verbosity=2,failfast=True).run(suite(a.runtime));raise SystemExit(not result.wasSuccessful())
