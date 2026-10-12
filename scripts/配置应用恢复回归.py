#!/usr/bin/env python3
"""Real Linux transactions, journal and process faults; explicit worker ACKs.
No DNS, ACME, firewall or proxy business is executed by these tests.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
import shutil
import subprocess
import unittest
from project import ROOT
from 私有配置读取回归 import Runtime as PrivateRuntime
from 完整配置事务回归 import Runtime as FullRuntime
from 配置事务原型回归 import SCRIPT

class Runtime(unittest.TestCase):
    setUpClass=classmethod(FullRuntime.setUpClass.__func__)
    setUp=FullRuntime.setUp
    tearDown=FullRuntime.tearDown
    raw=FullRuntime.raw
    cli=FullRuntime.cli
    export=FullRuntime.export
    commit_body=FullRuntime.commit_body
    secret=FullRuntime.secret
    secret_path=FullRuntime.secret_path
    fault=FullRuntime.fault
    restore_tool=FullRuntime.restore_tool
    preview=FullRuntime.preview
    snapshot=PrivateRuntime.snapshot
    decode=PrivateRuntime.decode

    def start(self):
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))
        return self.cli('commit-apply',self.plan['confirmation'])

    def finish(self,handle,result='success'):
        return self.cli('apply-finish',handle,result)

    def recover(self): return self.cli('recover-application')
    def restored(self,handle): return self.cli('restore-finish',handle,'success')
    def phase(self): return self.cli('status')['application_phase']

    def killed_commit(self,code):
        plan=self.preview(); self.fault('mv',code)
        result=subprocess.run([self.busybox,'ash',str(SCRIPT),'--public-uci','commit-apply',plan['confirmation']],
            env=self.env,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,-9,(result.stdout,result.stderr))
        self.assertEqual(result.stdout,b''); self.assertEqual(result.stderr,b'')
        self.restore_tool('mv')
        self.assertTrue((self.store/'gen-3/manifest').is_file())

    def test_success_waits_for_worker_ack_and_private_snapshot_is_bound(self):
        self.secret(b'PRIVATE_SENTINEL')
        started=self.start(); handle=started['apply_handle']
        self.assertFalse(started['business_applied']); self.assertEqual(started['revision'],4)
        self.assertEqual(self.phase(),'applying')
        self.snapshot(expected=4)
        report,frame=self.snapshot('apply-snapshot-read',handle)
        self.assertEqual(report['revision'],4)
        self.assertEqual(self.decode(frame)[b'credentials'][b'cloudflare.dns_a.secret'],b'PRIVATE_SENTINEL')
        status=json.dumps(self.cli('status'))
        self.assertNotIn(handle,status); self.assertNotIn('PRIVATE_SENTINEL',status)
        self.finish(handle)
        self.assertEqual(self.phase(),'none')
        self.assertIn(b"option https_port '8443'",self.export())
        self.cli('apply-finish',handle,'success',expected=5)

    def test_failure_restores_pointer_and_requires_business_restoration_ack(self):
        self.secret(b'OLD_PRIVATE')
        started=self.start(); handle=started['apply_handle']
        restored=self.finish(handle,'failure')
        self.assertEqual(restored['revision'],3); self.assertFalse(restored['business_restored'])
        self.assertEqual(self.phase(),'restoring'); self.assertEqual(self.export(),self.business)
        self.cli('preview',payload=self.business,expected=4)
        self.secret(b'NEW_PRIVATE',expected=4)
        self.snapshot(expected=4)
        report,frame=self.snapshot('restore-snapshot-read',handle)
        self.assertEqual(report['revision'],3)
        self.assertEqual(self.decode(frame)[b'credentials'][b'cloudflare.dns_a.secret'],b'OLD_PRIVATE')
        self.cli('restore-finish',handle,'failure',expected=7)
        self.assertEqual(self.phase(),'restoring')
        self.restored(handle)
        self.assertEqual(self.phase(),'none')

    def test_writer_commands_are_barred_and_wrong_worker_handles_do_not_mutate(self):
        started=self.start(); journal=(self.store/'application').read_bytes(); current=(self.store/'current').read_bytes()
        for args in [('init',),('cancel',),('rollback-preview','1'),('commit',self.plan['confirmation']),
                     ('commit-apply',self.plan['confirmation']),('migration-preview',),('credential-delete','cloudflare','dns_a','secret')]:
            self.cli(*args,expected=4)
        for args in [('apply-finish','0'*32,'success'),('restore-finish','0'*32,'failure')]: self.cli(*args,expected=5)
        self.snapshot('apply-snapshot-read','0'*32,expected=5)
        self.snapshot('restore-snapshot-read',started['apply_handle'],expected=5)
        self.assertEqual((self.store/'application').read_bytes(),journal)
        self.assertEqual((self.store/'current').read_bytes(),current)

    def test_candidate_sync_failure_creates_no_application_intent(self):
        plan=self.preview()
        self.fault('fsync','if any(value.endswith("/parent") for value in sys.argv[1:]): sys.exit(1)')
        self.cli('commit-apply',plan['confirmation'],expected=1)
        self.assertFalse((self.store/'application').exists())
        self.assertFalse((self.store/'gen-3').exists())
        self.restore_tool('fsync')
        self.assertEqual(self.phase(),'none')
        self.cli('commit-apply',plan['confirmation'])

    def test_intent_file_sync_failure_keeps_preview_and_deletes_unreferenced_candidate(self):
        plan=self.preview()
        self.fault('fsync','from pathlib import Path\nif sys.argv[-1].split("/")[-1].startswith(".work.") and Path(sys.argv[-1]).read_bytes().startswith(b"HGAPPLICATION1"):\n    sys.exit(1)')
        self.cli('commit-apply',plan['confirmation'],expected=7)
        self.assertFalse((self.store/'application').exists()); self.assertFalse((self.store/'gen-3').exists())
        self.restore_tool('fsync')
        self.cli('commit-apply',plan['confirmation'])

    def test_intent_directory_sync_failure_preserves_prepared_target_for_recovery(self):
        plan=self.preview()
        self.fault('fsync','if sys.argv[-1]=='+repr(str(self.store))+': sys.exit(1)')
        self.cli('commit-apply',plan['confirmation'],expected=7)
        self.assertTrue((self.store/'gen-3/manifest').is_file())
        self.assertEqual(self.phase(),'prepared'); self.assertEqual(self.cli('status')['revision'],2)
        self.cli('commit',plan['confirmation'],expected=4)
        self.restore_tool('fsync'); recovery=self.recover(); self.restored(recovery['restore_handle'])
        self.cli('commit',plan['confirmation'],expected=5)

    def test_publish_directory_sync_failure_has_recoverable_prepared_intent(self):
        plan=self.preview()
        self.fault('fsync','from pathlib import Path\nif sys.argv[-1]=='+repr(str(self.store))+' and Path('+repr(str(self.store/'current'))+').read_text()=="3\\n": sys.exit(1)')
        self.cli('commit-apply',plan['confirmation'],expected=6)
        self.assertEqual(self.phase(),'prepared'); self.assertEqual(self.cli('status')['revision'],3)
        self.restore_tool('fsync'); recovery=self.recover(); self.restored(recovery['restore_handle'])
        self.assertEqual(self.cli('status')['revision'],2)

    def test_kill_before_pointer_publish_recovers_without_losing_target(self):
        self.killed_commit('if sys.argv[-1].endswith("/current"):\n    os.kill(os.getppid(),signal.SIGKILL); sys.exit(1)')
        self.assertEqual(self.phase(),'prepared'); self.assertEqual(self.cli('status')['revision'],2)
        recovery=self.recover(); self.restored(recovery['restore_handle'])
        self.assertEqual(self.export(),self.business)

    def test_kill_after_pointer_publish_recovers_original_generation(self):
        self.killed_commit('import subprocess\nif sys.argv[-1].endswith("/current"):\n    subprocess.run(['+repr(self.busybox)+',"mv",*sys.argv[1:]],check=True); os.kill(os.getppid(),signal.SIGKILL); sys.exit(0)')
        self.assertEqual(self.phase(),'prepared'); self.assertEqual(self.cli('status')['revision'],3)
        recovery=self.recover(); self.restored(recovery['restore_handle'])
        self.assertEqual(self.cli('status')['revision'],2)

    def test_kill_after_applying_journal_rename_recovers_conservatively(self):
        self.killed_commit('import subprocess\nfrom pathlib import Path\nif sys.argv[-1].endswith("/application") and Path(sys.argv[-2]).read_text().splitlines()[4]=="applying":\n    subprocess.run(['+repr(self.busybox)+',"mv",*sys.argv[1:]],check=True); os.kill(os.getppid(),signal.SIGKILL); sys.exit(0)')
        self.assertEqual(self.phase(),'applying')
        recovery=self.recover(); self.restored(recovery['restore_handle'])
        self.assertEqual(self.export(),self.business)

    def test_acknowledged_completion_survives_journal_cleanup_failure(self):
        started=self.start()
        self.fault('rm','if sys.argv[-1].endswith("/application"): sys.exit(1)')
        self.cli('apply-finish',started['apply_handle'],'success',expected=7)
        self.assertEqual(self.phase(),'applied')
        self.restore_tool('rm')
        recovery=self.recover()
        self.assertFalse(recovery['application_pending']); self.assertEqual(recovery['revision'],3)
        self.assertIn(b"option https_port '8443'",self.export())

    def test_restoration_sync_failure_retains_barrier_and_recovery_can_retry(self):
        started=self.start()
        self.fault('fsync','from pathlib import Path\nif sys.argv[-1].split("/")[-1].startswith(".work.") and Path(sys.argv[-1]).read_text().strip().isdigit(): sys.exit(1)')
        self.cli('apply-finish',started['apply_handle'],'failure',expected=7)
        self.assertEqual(self.phase(),'restoring')
        self.restore_tool('fsync')
        recovery=self.recover()
        self.fault('rm','if sys.argv[-1].endswith("/application"): sys.exit(1)')
        self.cli('restore-finish',recovery['restore_handle'],'success',expected=7)
        self.assertEqual(self.phase(),'restored')
        self.restore_tool('rm'); self.recover()
        self.assertEqual(self.phase(),'none'); self.assertEqual(self.export(),self.business)

    def test_replay_wrong_phase_and_concurrent_recovery_are_rejected(self):
        started=self.start(); old=started['apply_handle']
        self.cli('restore-finish',old,'success',expected=5)
        self.finish(old,'failure')
        self.cli('apply-finish',old,'success',expected=5)
        def complete():
            return subprocess.run([self.busybox,'ash',str(SCRIPT),'--public-uci','restore-finish',old,'success'],env=self.env,capture_output=True,timeout=30)
        with ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(lambda _:complete(),range(4)))
        self.assertEqual(sum(r.returncode==0 for r in results),1)
        self.assertTrue(all(r.returncode in (0,4,5) for r in results))
        self.cli('commit-apply',self.plan['confirmation'],expected=5)
        new=self.start()['apply_handle']; self.assertNotEqual(new,old)
        self.cli('apply-finish',old,'success',expected=5)

    def test_recovery_directory_sync_failure_and_full_history_keep_recovery_available(self):
        started=self.start()
        (self.store/'gen-32').mkdir(mode=0o700)  # Unreachable interrupted candidate consumes capacity.
        self.fault('fsync','from pathlib import Path\nif sys.argv[-1]=='+repr(str(self.store))+' and Path('+repr(str(self.store/'current'))+').read_text()=="2\\n": sys.exit(1)')
        self.cli('apply-finish',started['apply_handle'],'failure',expected=7)
        self.assertEqual(self.phase(),'restoring'); self.assertEqual(self.cli('status')['revision'],2)
        self.cli('preview',payload=self.business,expected=4)
        self.restore_tool('fsync')
        recovery=self.recover(); self.restored(recovery['restore_handle'])
        self.assertEqual(self.phase(),'none')
        plan=self.preview(); self.cli('commit-apply',plan['confirmation'],expected=4)

    def test_malformed_linked_changed_and_copied_journal_fail_closed(self):
        self.start(); journal=self.store/'application'; original=journal.read_bytes()
        other=self.base/'other'; other.mkdir(mode=0o700)
        shutil.copytree(self.store,other,dirs_exist_ok=True)
        self.cli('recover-application',env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(other)},expected=1)
        for body in [original[:-1],original+b'\n',original.replace(b'applying',b'unknown'),original.replace(b'HGAPPLICATION1',b'PRIVATE_SENTINEL')]:
            journal.write_bytes(body)
            result=self.cli('recover-application',expected=1)
            self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
        journal.write_bytes(original)
        target=self.base/'target'; target.write_bytes(original); target.chmod(0o600)
        journal.unlink(); journal.symlink_to(target); self.cli('status',expected=1)
        journal.unlink(); os.link(target,journal); self.cli('status',expected=1)
        journal.unlink(); journal.write_bytes(original); journal.chmod(0o600)
        (self.store/'gen-3/public.conf').write_bytes(b'PRIVATE_SENTINEL')
        self.cli('recover-application',expected=1)
        self.assertEqual((self.store/'current').read_text(),'3\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--runtime',action='store_true',required=True); parser.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Runtime))
    raise SystemExit(not result.wasSuccessful())
