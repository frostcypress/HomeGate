#!/usr/bin/env python3
"""Bound UCI file projection in explicit private Linux fixtures; production gate off.
Real files, fsync/rename, flocks, Linux processes and fixed observer are exercised.
No router, procd or service start/stop command is executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from project import ROOT
from 配置事务原型回归 import SCRIPT
from 完整配置事务回归 import Runtime as FullRuntime
from 服务采样回归 import Runtime as ObserverRuntime


class Static(unittest.TestCase):
    def test_fixed_gate_paths_and_shell_grammar(self):
        import tree_sitter
        import tree_sitter_bash
        body=SCRIPT.read_bytes()
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        self.assertFalse(parser.parse(body).root_node.has_error)
        self.assertNotIn(b'\r',body)
        self.assertEqual(body.count(b'production_writes_enabled=false'),1)
        self.assertNotIn(b'production_writes_enabled=true',body)
        self.assertIn(b'/etc/config/homegate',body)
        self.assertIn(b'/var/run/homegate/frontend.lock',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_lua51_compiles_without_credential_output(self):
        from lupa.lua51 import LuaRuntime
        source=(SCRIPT.parent/'config-codec.lua').read_text()
        LuaRuntime().compile(source)
        branch=source.split('elseif arg[1]=="source-baseline"',1)[1].split('elseif arg[1]=="migrate"',1)[0]
        self.assertNotIn('io.write',branch)
        self.assertNotIn('os.getenv',branch)


class Runtime(unittest.TestCase):
    setUpClass=classmethod(ObserverRuntime.setUpClass.__func__)
    tearDown=ObserverRuntime.tearDown
    raw=ObserverRuntime.raw
    cli=FullRuntime.cli
    export=FullRuntime.export
    commit_body=FullRuntime.commit_body
    preview=FullRuntime.preview
    secret=FullRuntime.secret
    secret_path=FullRuntime.secret_path
    fault=FullRuntime.fault
    restore_tool=FullRuntime.restore_tool
    enable=ObserverRuntime.enable
    query=ObserverRuntime.query
    daemon_start=ObserverRuntime.daemon_start
    doc=ObserverRuntime.doc

    def setUp(self):
        ObserverRuntime.setUp(self)
        self.system=self.base/'fixture-system'
        self.config_dir=self.system/'etc/config'
        self.lock_dir=self.system/'var/run/homegate'
        self.config_dir.mkdir(parents=True,mode=0o700)
        self.lock_dir.mkdir(parents=True,mode=0o700)
        self.lock=self.lock_dir/'frontend.lock'; self.lock.touch(mode=0o600)
        self.source=self.config_dir/'homegate'
        self.original=b'\n'.join(line for line in self.business.split(b'\n') if not line.startswith(b'#'))
        self.source.write_bytes(self.original); self.source.chmod(0o600)
        self.certificate=self.system/'certificate.pem'; self.certificate.write_bytes(b'CERTIFICATE_SENTINEL')
        body=self.engine.read_text()
        body=body.replace('/var/run/homegate',str(self.lock_dir))
        body=body.replace('/etc/config',str(self.config_dir))
        body=body.replace('[ -d /etc ] && [ ! -L /etc ]','[ -d '+str(self.system/'etc')+' ] && [ ! -L '+str(self.system/'etc')+' ]')
        self.assertEqual(body.count('production_writes_enabled=false'),1)
        body=body.replace('production_writes_enabled=false','production_writes_enabled=true')
        body=body.replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
        self.engine.write_text(body)

    def begin(self,expected=0):
        report=self.cli('commit-apply-projection',self.plan['confirmation'],expected=expected)
        if expected: return report
        self.handle=report['apply_handle']; self.target=report['revision']
        self.assertFalse(report['business_applied'])
        journal=(self.store/'application').read_bytes().splitlines()
        self.assertEqual(len(journal),11); self.assertEqual(journal[0],b'HGAPPLICATION3')
        captured=self.store/f'gen-{self.target}/source.conf'
        self.assertEqual(captured.read_bytes(),self.original)
        self.assertEqual(captured.stat().st_mode&0o777,0o600)
        self.assertIn(b'  source.conf\n',(captured.parent/'manifest').read_bytes())
        self.assertEqual(self.source.read_bytes(),self.original)
        return report

    def publish(self,role='apply',expected=0):
        result=self.cli('projection-publish',self.handle,role,expected=expected)
        if not expected:
            self.assertTrue(result['configuration_published']); self.assertFalse(result['business_applied'])
        return result

    def finish(self,role='apply',expected=0):
        return self.cli(role+'-finish-projection',self.handle,expected=expected)

    def recover(self): return self.cli('recover-application')

    def seed_secret(self):
        self.secret(b'PRIVATE_SENTINEL')
        self.original=self.original.replace(b"config dns_account 'dns_a'\n",b"config dns_account 'dns_a'\n\toption secret 'PRIVATE_SENTINEL'\n")
        self.source.write_bytes(self.original)
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))

    def unchanged(self):
        self.assertEqual(self.source.read_bytes(),self.original)
        self.assertFalse((self.store/'application').exists())
        self.assertFalse(list(self.config_dir.glob('.homegate-projection.*')))

    def test_public_publication_uci_readback_and_exact_private_restore(self):
        self.seed_secret(); self.begin(); self.publish()
        projected=(self.store/f'gen-{self.target}/public.conf').read_bytes()
        self.assertEqual(self.source.read_bytes(),projected)
        self.assertNotIn(b'PRIVATE_SENTINEL',projected)
        save=self.base/'uci-save'; save.mkdir()
        parsed=subprocess.run([str(ROOT/'build/uci-parser/uci'),'-c',str(self.config_dir),'-P',str(save),'-q','show','homegate'],capture_output=True,timeout=10)
        self.assertEqual(parsed.returncode,0,parsed.stderr)
        self.assertIn(b"homegate.main.enabled='0'",parsed.stdout)
        self.assertNotIn(b'PRIVATE_SENTINEL',parsed.stdout)
        self.recover(); self.publish('restore'); self.finish('restore')
        self.assertEqual(self.source.read_bytes(),self.original)
        self.assertEqual(self.source.stat().st_mode&0o777,0o600)
        self.assertEqual(self.certificate.read_bytes(),b'CERTIFICATE_SENTINEL')
        self.assertEqual(self.secret_path(3).read_bytes(),b'PRIVATE_SENTINEL')

    def test_actual_readback_ack_refuses_flags_and_legacy_success(self):
        self.begin(); self.finish(expected=7)
        self.cli('apply-finish',self.handle,'success',expected=5)
        self.cli('apply-finish-intent',self.handle,'success','1','0',expected=5)
        self.cli('apply-finish-projection',self.handle,'1','0',expected=2)
        self.publish(); self.finish()
        self.assertFalse(self.cli('status')['application_pending'])
        self.finish(expected=5)

    def test_four_independent_boot_running_states_and_restore_observation(self):
        # Each transaction starts at the original immutable baseline after recovery.
        for boot,running in [(0,0),(0,1),(1,0),(1,1)]:
            with self.subTest(boot=boot,running=running):
                self.enable(boot)
                daemon=self.daemon_start() if running else None
                self.query(self.doc(daemon.pid) if daemon else {})
                self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))
                self.begin()
                intent=self.cli('service-intent-read',self.handle)
                self.assertEqual(intent['boot_enabled'],bool(boot))
                self.assertEqual(intent['baseline_running'],bool(running))
                if daemon:
                    self.publish(expected=7)
                    daemon.terminate(); daemon.wait(timeout=5); self.query({})
                self.publish()
                self.recover(); self.finish('restore',expected=7)
                self.publish('restore')
                if running:
                    self.finish('restore',expected=7)
                    daemon=self.daemon_start(); self.query(self.doc(daemon.pid))
                self.finish('restore')
                if daemon:
                    daemon.terminate(); daemon.wait(timeout=5); self.query({})
                self.assertEqual(self.source.read_bytes(),self.original)
        self.assertTrue(all(line=='enabled' for line in (self.base/'init-calls').read_text().splitlines()))

    def test_source_and_vault_must_match_baseline_before_candidate(self):
        self.source.write_bytes(self.original.replace(b"option https_port '443'",b"option https_port '9443'"))
        self.begin(expected=7)
        self.source.write_bytes(self.original)
        self.secret(b'PRIVATE_SENTINEL')
        self.plan=self.preview(self.business)
        self.begin(expected=7); self.unchanged()

    def test_unsafe_source_permissions_links_size_and_directory(self):
        self.source.chmod(0o644); self.begin(expected=7); self.source.chmod(0o600)
        link=self.config_dir/'link'; os.link(self.source,link); self.begin(expected=7); link.unlink()
        self.source.unlink(); self.source.symlink_to(self.certificate); self.begin(expected=7)
        self.source.unlink(); self.source.write_bytes(b'x'*262145); self.source.chmod(0o600); self.begin(expected=7)
        self.source.write_bytes(b''); self.begin(expected=7)
        self.source.write_bytes(self.original); self.config_dir.chmod(0o777); self.begin(expected=7)
        self.config_dir.chmod(0o700); self.unchanged()

    def test_legacy_writer_flock_excludes_capture_publication_and_ack(self):
        import fcntl
        with self.lock.open('rb') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB); self.begin(expected=4)
        self.begin()
        with self.lock.open('rb') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB); self.publish(expected=4)
        self.publish()
        with self.lock.open('rb') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB); self.finish(expected=4)
        self.finish()

    def test_foreign_change_never_gets_overwritten_on_apply_or_restore(self):
        self.begin(); foreign=b'EXTERNAL_WRITER_SENTINEL\n'; self.source.write_bytes(foreign)
        self.publish(expected=7); self.assertEqual(self.source.read_bytes(),foreign)
        self.source.write_bytes(self.original); self.publish(); self.recover()
        self.source.write_bytes(foreign); self.publish('restore',expected=7)
        self.assertEqual(self.source.read_bytes(),foreign); self.finish('restore',expected=7)

    def test_sealed_source_backup_tamper_is_rejected(self):
        self.begin(); backup=self.store/f'gen-{self.target}/source.conf'
        backup.write_bytes(backup.read_bytes()+b'\n')
        self.cli('status',expected=1); self.publish(expected=1)
        self.assertEqual(self.source.read_bytes(),self.original)

    def test_wrong_handle_role_and_phase_cannot_publish(self):
        self.begin()
        self.cli('projection-publish','0'*32,'apply',expected=5)
        self.cli('projection-publish',self.handle,'start',expected=2)
        self.publish('restore',expected=5)
        self.publish(); self.recover(); self.publish(expected=5)
        self.publish('restore'); self.finish('restore')

    def test_staging_fsync_and_rename_fail_keep_original_and_barrier(self):
        self.begin()
        self.fault('fsync','if any(".homegate-projection." in a for a in sys.argv[1:]): sys.exit(70)')
        self.publish(expected=7); self.restore_tool('fsync')
        self.assertEqual(self.source.read_bytes(),self.original)
        self.fault('mv','if sys.argv[-1]=='+repr(str(self.source))+': sys.exit(71)')
        self.publish(expected=7); self.restore_tool('mv')
        self.assertEqual(self.source.read_bytes(),self.original)
        self.assertTrue(self.cli('status')['application_pending'])
        self.assertFalse(list(self.config_dir.glob('.homegate-projection.*')))
        self.recover(); self.publish('restore'); self.finish('restore')

    def test_directory_fsync_uncertain_after_rename_requires_explicit_restore(self):
        self.begin()
        self.fault('fsync','if '+repr(str(self.config_dir))+' in sys.argv[1:]: sys.exit(72)')
        self.publish(expected=7); self.restore_tool('fsync')
        self.assertEqual(self.source.read_bytes(),(self.store/f'gen-{self.target}/public.conf').read_bytes())
        self.assertTrue(self.cli('status')['application_pending'])
        self.recover(); self.publish('restore'); self.finish('restore')
        self.assertEqual(self.source.read_bytes(),self.original)

    def test_sigkill_after_config_rename_keeps_bound_recovery(self):
        self.begin()
        self.fault('mv','if sys.argv[-1]=='+repr(str(self.source))+':\n subprocess=None\n import subprocess\n subprocess.run(['+repr(self.busybox)+',"mv",*sys.argv[1:]],check=True)\n os.kill(os.getppid(),signal.SIGKILL)\n sys.exit(0)')
        result=subprocess.run([self.busybox,'ash',str(self.engine),'--public-uci','projection-publish',self.handle,'apply'],env=self.env,capture_output=True,timeout=12)
        self.assertEqual(result.returncode,-9,(result.stdout,result.stderr)); self.assertEqual(result.stdout,b''); self.assertEqual(result.stderr,b'')
        self.restore_tool('mv')
        self.assertEqual(self.source.read_bytes(),(self.store/f'gen-{self.target}/public.conf').read_bytes())
        self.assertEqual(self.cli('status')['application_phase'],'applying')
        self.recover(); self.publish('restore'); self.finish('restore')
        self.assertEqual(self.source.read_bytes(),self.original)

    def test_idempotent_publication_and_following_bound_public_baseline(self):
        self.seed_secret(); self.begin(); self.publish()
        inode=self.source.stat().st_ino; self.publish(); self.assertEqual(self.source.stat().st_ino,inode)
        self.finish()
        self.original=self.source.read_bytes(); self.business=self.export()
        self.plan=self.preview(self.business.replace(b"option https_port '8443'",b"option https_port '9443'"))
        self.begin(); self.publish(); self.recover(); self.publish('restore'); self.finish('restore')
        self.assertEqual(self.source.read_bytes(),self.original)
        self.assertNotIn(b'PRIVATE_SENTINEL',self.source.read_bytes())

    def test_state_change_after_projection_blocks_ack_without_trusted_flags(self):
        self.begin(); self.publish(); self.enable(0); self.finish(expected=7)
        self.enable(1); daemon=self.daemon_start(); self.query(self.doc(daemon.pid)); self.finish(expected=7)
        daemon.terminate(); daemon.wait(timeout=5); self.query({}); self.finish()

    def test_unmodified_product_gate_refuses_cli_and_environment_enable(self):
        for command,args in [('projection-publish',('0'*32,'apply')),('apply-finish-projection',('0'*32,)),('restore-finish-projection',('0'*32,))]:
            result=subprocess.run([self.busybox,'ash',str(SCRIPT),'--public-uci',command,*args],env={**self.env,'production_writes_enabled':'true','HOMEGATE_PRODUCTION_WRITES':'1'},capture_output=True,timeout=10)
            self.assertEqual(result.returncode,2,(result.stdout,result.stderr))
            self.assertEqual(result.stderr,b'')
            self.assertIn(b'Production writer migration is incomplete',result.stdout)
        self.unchanged()


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--runtime',action='store_true'); p.add_argument('--static',action='store_true')
    a=p.parse_args(); result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if a.runtime else Static))
    raise SystemExit(not result.wasSuccessful())
