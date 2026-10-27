#!/usr/bin/env python3
"""Cold source validation and locked ordinary-generation startup preflight."""
import argparse
import json
import os
import subprocess
import unittest
from project import ROOT,identity
from DDNS计划回归 import fixture_uid
from 生命周期准备回归 import Runtime as ColdBase
from 核心配置校验回归 import Runtime as PublishedBase,RAW

PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_grammar_closed_gates_and_no_production_install(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh','homegate-lifecycle-prepare.sh','homegate-config-prototype.sh']:
            raw=(PROTO/name).read_bytes();self.assertNotIn(b'\r',raw)
            self.assertFalse(parser.parse(raw).root_node.has_error,name)
        LuaRuntime().compile((PROTO/'homegate-startup.lua').read_bytes())
        self.assertIn('lifecycle_startup_enabled=false',(PROTO/'homegate-lifecycle-prepare.sh').read_text())
        self.assertIn('startup_admission_enabled=false',(PROTO/'homegate-config-prototype.sh').read_text())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_source_validation_precedes_metadata_creation_and_original_commands_remain(self):
        body=(PROTO/'homegate-lifecycle-prepare.sh').read_text()
        self.assertLess(body.index('configuration=$(lua'),body.index('mkdir "$runtime"'))
        self.assertIn('prepare) bootstrap_action=bootstrap',body);self.assertIn('resume) bootstrap_action=resume',body)
        self.assertIn('exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-',body)
        self.assertIn('supervisor_binding && startup_fences',body)
        self.assertIn('"$(startup_source_stamp)" = "$source_stamp"',body)
    def test_full_schema_and_existing_source_binding_without_business_actions(self):
        body=(PROTO/'homegate-startup.lua').read_text()
        self.assertIn('codec.private_configuration(raw)',body)
        self.assertIn('validator.validate(candidate,candidate,codec.json,ip)',body)
        self.assertIn('runtime-health.lua',body);self.assertIn('262145',body)
        self.assertIn('daemon_started=false',body);self.assertIn('point_in_time=true',body)
        for forbidden in ['os.execute','io.popen','running=true','healthy=true']:
            self.assertNotIn(forbidden,body)
        entry=(PROTO/'homegate-lifecycle-prepare.sh').read_text()
        for forbidden in ['migration-source-commit','projection-publish','ddns-state.sh','service restart','kill ']:self.assertNotIn(forbidden,entry)

def startup_fixture(self):
    body=self.prepare_script.read_text().replace('lifecycle_startup_enabled=false','lifecycle_startup_enabled=true')
    for old,new in [('startup_source=/etc/config/homegate',self.source),('startup_parent=/etc/config',self.source.parent),
                    ('startup_etc=/etc',self.etc),('store=/etc/homegate/transactions',self.store)]:
        body=body.replace(old,old.split('=',1)[0]+'='+str(new))
    self.prepare_script.write_text(body)
    self.engine.write_text(self.engine.read_text().replace('startup_admission_enabled=false','startup_admission_enabled=true'))
    adapter=self.engine.parent/'homegate-startup.lua';body=(PROTO/adapter.name).read_text()
    body=body.replace('/etc/config/homegate',str(self.source))
    body=body.replace("dir..'/../../../VERSION'",json.dumps(str(ROOT/'VERSION'))).replace("dir..'/../../../RELEASE'",json.dumps(str(ROOT/'RELEASE')))
    adapter.write_text(body)
    self.startup_cli=self.engine.parent/'homegate-cli.sh'
    body=self.startup_cli.read_text().replace('native_cli_enabled=false','native_cli_enabled=true')
    self.startup_cli.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))

class Request:
    def startup(self,*args,expected=0,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.startup_cli),*(args or ('lifecycle-startup',))],
                         env=env or self.env,capture_output=True,timeout=20)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),p.stdout)
        self.assertLess(len(p.stdout),2048)
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'127.0.0.1',os.fsencode(self.store)]:self.assertNotIn(marker,p.stdout)
        out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        if expected==0:
            self.assertEqual(out['phase'],'lifecycle-startup');self.assertEqual(out['version'],identity()['normalized'])
            self.assertTrue(out['configuration_ready']);self.assertFalse(out['daemon_started'])
            self.assertFalse(out['production_ready']);self.assertFalse(out['readers_switched']);self.assertFalse(out['write_ready'])
        if hasattr(self,'calls'):self.assertEqual(self.calls,[])
        return out

class Cold(Request,ColdBase):
    def setUp(self):
        super().setUp();directory=self.etc/'config';directory.mkdir(mode=0o700)
        self.source=directory/'homegate';self.source.write_text(RAW);self.source.chmod(0o600)
        startup_fixture(self)
    def test_invalid_full_source_refuses_before_runtime_or_baseline_creation(self):
        for raw in ['PRIVATE_SENTINEL',RAW.replace('https://127.0.0.1:8443/a?q=1','ftp://PRIVATE_SENTINEL'),
                    RAW.replace("option enabled '1'","option enabled 'INVALID'",1)]:
            self.source.write_text(raw);self.startup(expected=1)
            self.assertFalse(self.native.lockdir.exists());self.assertFalse(self.store.exists())
    def test_unsafe_or_linked_source_is_preserved_without_metadata_creation(self):
        self.source.chmod(0o644);self.startup(expected=7);self.assertEqual(self.source.stat().st_mode&0o777,0o644)
        self.source.chmod(0o600);outside=self.source.with_name('original');self.source.rename(outside);self.source.symlink_to(outside)
        self.startup(expected=7);self.assertTrue(self.source.is_symlink());self.assertEqual(outside.read_text(),RAW)
        self.assertFalse(self.native.lockdir.exists());self.assertFalse(self.store.exists())
    def test_valid_cold_source_is_not_silently_adopted_into_disabled_baseline(self):
        self.startup(expected=7);self.assertEqual(self.source.read_text(),RAW)
        self.assertEqual(self.cli('status')['revision'],1);self.assertEqual(list((self.store/'gen-1/credentials').iterdir()),[])
        before=self.contents();inode=self.native.lock.stat().st_ino
        self.startup(expected=7);self.assertEqual(self.contents(),before);self.assertEqual(self.native.lock.stat().st_ino,inode)
        self.assertFalse(any(self.store.glob('gen-*/legacy.conf')))
    def test_incomplete_bootstrap_requires_original_explicit_resume(self):
        self.fault('mv','sys.exit(1) if sys.argv[1:]==['+repr(str(self.stage))+','+repr(str(self.store))+'] else None')
        self.startup(expected=7);self.restore_tool('mv');self.assertTrue(self.stage.exists())
        before=self.contents(self.stage);self.startup(expected=7);self.assertEqual(self.contents(self.stage),before)
        self.run_prepare('resume');self.startup(expected=7);self.assertEqual(self.source.read_text(),RAW)

class Published(Request,PublishedBase):
    def setUp(self):
        super().setUp();startup_fixture(self)
    def test_prepared_ordinary_source_is_validated_without_DNS_or_runtime_health_claim(self):
        before=self.contents();source=self.source.read_bytes();inode=self.native.lock.stat().st_ino
        out=self.startup();self.assertEqual(out['configuration_revision'],self.revision)
        self.assertFalse(out['enabled']);self.assertTrue(out['point_in_time'])
        self.assertEqual(self.contents(),before);self.assertEqual(self.source.read_bytes(),source)
        self.assertEqual(self.native.lock.stat().st_ino,inode)
    def test_startup_reader_does_not_require_DDNS_write_authority(self):
        body=self.engine.read_text().replace('production_writes_enabled=true','production_writes_enabled=false').replace('ddns_authority_enabled=true','ddns_authority_enabled=false')
        self.engine.write_text(body);self.startup()
        self.assertNotIn('runtime-ddns-snapshot-read',(PROTO/'homegate-lifecycle-prepare.sh').read_text())
    def test_valid_external_source_change_refuses_without_adoption(self):
        old=self.source.read_bytes();self.assertIn(b"ddns_interval '300'",old)
        self.source.write_bytes(old.replace(b"ddns_interval '300'",b"ddns_interval '600'"));before=self.contents()
        self.startup(expected=7);self.assertEqual(self.contents(),before)
    def test_all_three_shared_locks_refuse_and_keep_original_inodes(self):
        import fcntl
        before=self.contents()
        for lock in [self.native.lock,self.store/'.supervisor.lock',self.native.lockdir/'ddns-schedule.lock']:
            inode=lock.stat().st_ino
            with lock.open('rb') as f:
                fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.startup(expected=4)
            self.assertEqual(lock.stat().st_ino,inode)
        self.assertEqual(self.contents(),before)
    def test_all_known_runtime_observation_and_summary_fences_are_retained(self):
        for name in ['.health-read-99999','.recovery-read-99999','.ddns-recovery-next','.ddns-recovery-pending','.dns-check-99999','.ddns-plan-99999']:
            file=self.native.lockdir/name;file.write_bytes(b'KEEP PRIVATE_SENTINEL');file.chmod(0o600)
            before=self.contents();self.startup(expected=4)
            self.assertEqual(file.read_bytes(),b'KEEP PRIVATE_SENTINEL');self.assertEqual(self.contents(),before);file.unlink()
    def test_unknown_DNS_receipt_stays_a_persistent_startup_barrier(self):
        journal=self.store/'dns-operation';journal.mkdir(mode=0o700);file=journal/'context';file.write_bytes(b'UNKNOWN PRIVATE_SENTINEL');file.chmod(0o600)
        before=self.contents();self.startup(expected=4);self.assertEqual(self.contents(),before)
    def test_same_bytes_source_replacement_after_preflight_refuses(self):
        original=self.source.read_bytes()
        self.fault('flock','\nif sys.argv[1:]==["-n","6"]:\n from pathlib import Path\n import os\n p=Path('+repr(str(self.source))+');q=p.with_name("replacement");q.write_bytes(p.read_bytes());q.chmod(0o600);os.replace(q,p)')
        self.startup(expected=7);self.restore_tool('flock');self.assertEqual(self.source.read_bytes(),original)
    def test_source_change_during_bootstrap_cannot_publish_ready_report(self):
        original=self.source.read_bytes()
        self.fault('fsync','\nif any(a.endswith("/bootstrap-receipt") for a in sys.argv[1:]):\n from pathlib import Path\n p=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes().replace(b"ddns_interval \'300\'",b"ddns_interval \'600\'"))')
        self.startup(expected=7);self.restore_tool('fsync')
        self.assertFalse((self.native.lockdir/'runtime.json').exists())
        self.source.write_bytes(original)
        manifest=self.store/f'gen-{self.revision}/manifest'
        tool=self.bin/'lua';target=tool.resolve();tool.unlink()
        triggered=self.base/'manifest-replaced-once'
        injection='\nif len(sys.argv)>2 and sys.argv[1].endswith("/homegate-startup.lua") and sys.argv[2]=="bound":\n from pathlib import Path\n marker=Path('+repr(str(triggered))+')\n if not marker.exists():\n  p=Path('+repr(str(manifest))+');q=p.with_name("replacement-manifest");q.write_bytes(p.read_bytes());q.chmod(0o600);os.replace(q,p);marker.write_text("triggered")'
        tool.write_text('#!'+os.sys.executable+'\nimport os,sys\n'+injection+'\nos.execv('+repr(str(target))+',['+repr(str(target))+',*sys.argv[1:]])\n');tool.chmod(0o700)
        try:self.startup(expected=7)
        finally:tool.unlink();tool.symlink_to(target)
        self.assertTrue(triggered.exists())
    def test_argument_and_source_gates_cannot_be_enabled_by_environment(self):
        self.startup('lifecycle-startup','extra',expected=2);self.startup('daemon',expected=2)
        before=self.contents();body=self.prepare_script.read_text()
        self.prepare_script.write_text(body.replace('lifecycle_startup_enabled=true','lifecycle_startup_enabled=false'))
        self.startup(expected=2,env={**self.env,'lifecycle_startup_enabled':'true'});self.prepare_script.write_text(body)
        self.engine.write_text(self.engine.read_text().replace('startup_admission_enabled=true','startup_admission_enabled=false'))
        self.startup(expected=7);self.assertEqual(self.contents(),before)

def suite(runtime):
    classes=[Cold,Published] if runtime else [Static]
    return unittest.TestSuite(cls(n) for cls in classes for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    result=unittest.TextTestRunner(verbosity=2,failfast=True).run(suite(a.runtime));raise SystemExit(not result.wasSuccessful())
