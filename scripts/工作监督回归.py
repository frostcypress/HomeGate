#!/usr/bin/env python3
"""Real BusyBox sessions/FIFOs/deadlines; derived-state receipt only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from project import ROOT
from 完整配置事务回归 import Runtime as FullRuntime

DIRECTORY=ROOT/'project/core/prototype'
SUPERVISOR=DIRECTORY/'homegate-worker-supervisor.sh'

class Static(unittest.TestCase):
    def test_fixed_shell_entrypoints_and_self_session_signals(self):
        import tree_sitter
        import tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for file in [SUPERVISOR,DIRECTORY/'homegate-worker-watchdog.sh']:
            body=file.read_bytes(); self.assertNotIn(b'\r',body)
            # tree-sitter-bash 0.25.1 omits POSIX <> redirection. Mask only
            # these two fixed descriptor operators, preserving byte offsets;
            # native sh -n and real BusyBox ash validate the actual operators.
            self.assertEqual(body.count(b'<>'),1)
            parsed=body.replace(b'exec 5<> ',b'exec 5>> ').replace(b'exec 6<> ',b'exec 6>> ')
            self.assertNotIn(b'<>',parsed)
            tree=parser.parse(parsed)
            check=[tree.root_node]; errors=[]
            while check:
                item=check.pop()
                if item.type=='ERROR' or item.is_missing: errors.append((str(item.start_point),body[item.start_byte:item.end_byte][:120]))
                check.extend(item.named_children)
            self.assertFalse(tree.root_node.has_error,(file.name,errors))
            nodes=[tree.root_node]
            while nodes:
                node=nodes.pop()
                self.assertNotIn(node.type,{'process_substitution','herestring_redirect','array','c_style_for_statement'})
                if node.type=='command':
                    name=node.child_by_field_name('name')
                    if name:
                        command=body[name.start_byte:name.end_byte].decode()
                        self.assertNotIn('$',command)
                        self.assertNotIn(command,{'eval','.','source','uci','curl','wget','service','nft','ip6tables','reboot'})
                        if command=='kill': self.assertIn(b'"-$$"',body[node.start_byte:node.end_byte])
                nodes.extend(node.named_children)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

class Runtime(unittest.TestCase):
    setUpClass=classmethod(FullRuntime.setUpClass.__func__)
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

    def setUp(self):
        FullRuntime.setUp(self)
        self.env['HOMEGATE_WORKER_PROTO_TIMEOUT']='2'
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))
        self.handle=self.cli('commit-apply',self.plan['confirmation'])['apply_handle']
        self.processes=[]
        self.group_ids=[]

    def tearDown(self):
        # Only process groups created by this fixture are touched, never an
        # untrusted PID read from a product response.
        for process in self.processes:
            if process.poll() is None: process.kill()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: pass
        for group in self.group_ids:
            try: os.killpg(group,signal.SIGKILL)
            except ProcessLookupError: pass
        FullRuntime.tearDown(self)

    def supervise(self,*args,expected=0,env=None):
        result=subprocess.run([self.busybox,'ash',str(SUPERVISOR),*args],env=env or self.env,capture_output=True,timeout=20)
        self.assertEqual(result.returncode,expected,(args,result.stdout,result.stderr))
        self.assertEqual(result.stderr,b''); self.assertLess(len(result.stdout),2048)
        report=json.loads(result.stdout); self.assertEqual(report['ok'],expected==0)
        self.assertNotIn('PRIVATE_SENTINEL',result.stdout.decode())
        return report

    def start_supervisor(self):
        process=subprocess.Popen([self.busybox,'ash',str(SUPERVISOR),'run-apply',self.handle],env=self.env,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.processes.append(process)
        deadline=time.monotonic()+5
        while not (self.store/'worker').exists():
            if process.poll() is not None: self.fail(process.communicate())
            if time.monotonic()>deadline: self.fail('Worker lease was not published')
            time.sleep(0.02)
        lease=(self.store/'worker').read_text().splitlines()
        self.assertEqual(lease[0],'HGWORKER1')
        self.group_ids.append(int(lease[5]))
        return process,lease

    def fake_lua(self,code):
        path=self.bin/'lua'; path.unlink()
        path.write_text('#!'+sys.executable+'\nimport os,sys,time,signal\n'+code+'\n'
                        'os.execv('+repr(self.lua)+',["lua",*sys.argv[1:]])\n')
        path.chmod(0o700)

    def real_lua(self):
        (self.bin/'lua').unlink(); (self.bin/'lua').symlink_to(self.lua)

    def hang_apply(self):
        self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua") and sys.argv[2]=="apply":\n    signal.signal(signal.SIGTERM,signal.SIG_IGN)\n    while True: time.sleep(0.1)')

    def recover_after_loss(self):
        deadline=time.monotonic()+6
        while True:
            result=subprocess.run([self.busybox,'ash',str(SUPERVISOR),'recover'],env=self.env,capture_output=True,timeout=10)
            if result.returncode==4 and time.monotonic()<deadline: time.sleep(0.05); continue
            self.assertEqual(result.returncode,0,(result.stdout,result.stderr))
            self.assertEqual(result.stderr,b'')
            return json.loads(result.stdout)

    def receipt(self): return dict(line.split('=',1) for line in (self.store/'runtime').read_text().splitlines()[1:])
    def readable_status(self):
        # The snapshot producer may briefly own the configuration flock.
        # Retry only the documented busy response, never a validation error.
        deadline=time.monotonic()+2
        while True:
            result=subprocess.run([self.busybox,'ash',str(DIRECTORY/'homegate-config-prototype.sh'),'--public-uci','status'],
                                  env=self.env,capture_output=True,timeout=5)
            if result.returncode==4 and time.monotonic()<deadline: time.sleep(0.02); continue
            self.assertEqual(result.returncode,0,(result.stdout,result.stderr))
            self.assertEqual(result.stderr,b''); return json.loads(result.stdout)
    def assert_closed(self,revision):
        status=self.cli('status')
        self.assertEqual(status['revision'],revision)
        self.assertFalse(status['application_pending']); self.assertFalse(status['workers_pending'])
        self.assertFalse((self.store/'worker').exists())

    def test_fixed_worker_applies_receipt_and_acknowledges_only_after_quiescence(self):
        report=self.supervise('run-apply',self.handle)
        self.assertTrue(report['applied']); self.assertEqual(report['scope'],'isolated-worker-receipt')
        self.assertEqual(self.receipt(),{'revision':'3','role':'apply','https_port':'8443'})
        self.assert_closed(3)
        self.cli('apply-finish',self.handle,'success',expected=5)

    def test_binary_credentials_stay_in_private_pipe_and_not_receipt_or_output(self):
        self.cli('apply-finish',self.handle,'failure'); self.cli('restore-finish',self.handle,'success')
        self.secret(b'PRIVATE_SENTINEL\x00\xff\n')
        plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))
        self.handle=self.cli('commit-apply',plan['confirmation'])['apply_handle']
        self.supervise('run-apply',self.handle)
        self.assert_closed(5)
        self.assertNotIn(b'PRIVATE_SENTINEL',(self.store/'runtime').read_bytes())
        self.assertEqual(self.secret_path(5).read_bytes(),b'PRIVATE_SENTINEL\x00\xff\n')
        for file in self.store.glob('worker*'): self.assertNotIn(b'PRIVATE_SENTINEL',file.read_bytes())

    def test_failed_apply_worker_restores_old_receipt_and_reports_request_failure(self):
        self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua") and sys.argv[2]=="apply": sys.exit(9)')
        report=self.supervise('run-apply',self.handle,expected=8)
        self.assertTrue(report['baseline_restored']); self.assertFalse(report['timed_out'])
        self.assert_closed(2); self.assertEqual(self.receipt()['https_port'],'443')

    def test_unread_private_pipe_timeout_kills_family_before_restoration(self):
        self.hang_apply(); began=time.monotonic()
        report=self.supervise('run-apply',self.handle,expected=8)
        self.assertTrue(report['timed_out']); self.assertLess(time.monotonic()-began,7)
        self.assert_closed(2); self.assertEqual(self.receipt()['role'],'restore')

    def test_failed_restoration_keeps_application_barrier_and_can_retry(self):
        self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua"): sys.exit(9)')
        self.supervise('run-apply',self.handle,expected=7)
        status=self.cli('status'); self.assertEqual(status['application_phase'],'restoring'); self.assertFalse(status['workers_pending'])
        self.cli('preview',payload=self.business,expected=4)
        self.real_lua(); self.supervise('recover'); self.assert_closed(2)

    def test_partial_snapshot_producer_failure_cannot_acknowledge_application(self):
        self.fake_lua('if sys.argv[1].endswith("config-codec.lua") and "snapshot" in sys.argv and sys.argv[-2].endswith("/gen-3"): sys.exit(9)')
        self.supervise('run-apply',self.handle,expected=8)
        self.assert_closed(2); self.assertEqual(self.receipt()['role'],'restore')

    def test_active_worker_blocks_manual_ack_recovery_and_second_supervisor(self):
        self.env['HOMEGATE_WORKER_PROTO_TIMEOUT']='5'
        release=self.base/'release'
        self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua") and sys.argv[2]=="apply":\n    while not os.path.exists('+repr(str(release))+'): time.sleep(0.05)')
        process,lease=self.start_supervisor()
        self.assertTrue(self.readable_status()['workers_pending'])
        self.cli('apply-finish',self.handle,'success',expected=4)
        self.cli('recover-application',expected=4)
        self.supervise('recover',expected=4)
        release.write_text('ready')
        stdout,stderr=process.communicate(timeout=10)
        self.assertEqual(process.returncode,0,(stdout,stderr)); self.assertEqual(stderr,b'')
        self.assert_closed(3)

    def test_outer_sigterm_waits_for_family_and_leaves_explicit_recovery(self):
        self.hang_apply(); process,lease=self.start_supervisor()
        process.terminate(); stdout,stderr=process.communicate(timeout=8)
        self.assertEqual(process.returncode,143,(stdout,stderr)); self.assertEqual(stderr,b'')
        self.assertTrue(self.cli('status')['application_pending']); self.assertFalse(self.cli('status')['workers_pending'])
        self.recover_after_loss(); self.assert_closed(2)

    def test_outer_sigkill_original_watchdog_can_be_asked_to_stop_safely(self):
        self.hang_apply(); process,lease=self.start_supervisor()
        process.kill(); process.communicate(timeout=5)
        self.recover_after_loss(); self.assert_closed(2)
        self.assertEqual(self.receipt()['role'],'restore')

    def test_sigkill_of_owner_and_watchdog_with_live_children_fails_closed(self):
        self.hang_apply(); process,lease=self.start_supervisor()
        # Ensure the gate was released and the child is actually running.
        time.sleep(0.2)
        process.kill(); process.communicate(timeout=5)
        try: os.kill(int(lease[5]),signal.SIGKILL)
        except ProcessLookupError: self.fail('Watchdog ended before fault injection')
        self.supervise('recover',expected=7)
        self.assertTrue(self.cli('status')['workers_pending'])
        self.cli('apply-finish',self.handle,'success',expected=4)

    def stale_lease(self):
        self.hang_apply(); process,lease=self.start_supervisor()
        process.kill(); process.communicate(timeout=5)
        time.sleep(3.4)  # The independent watchdog deadline expires.
        self.real_lua()
        return lease

    def protected_process(self):
        process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True)
        self.processes.append(process); self.group_ids.append(process.pid)
        body=Path('/proc/'+str(process.pid)+'/stat').read_text().rsplit(') ',1)[1].split()
        return process,body[19]

    def write_lease(self,lease): (self.store/'worker').write_text('\n'.join(lease)+'\n')

    def test_stale_pid_birth_or_nonce_mismatch_never_signals_unrelated_session(self):
        lease=self.stale_lease(); protected,birth=self.protected_process()
        lease[5]=str(protected.pid); lease[6]=birth; self.write_lease(lease)
        self.supervise('recover',expected=7)
        self.assertIsNone(protected.poll()); self.assertFalse((self.store/'worker-stop').exists())

    def test_old_boot_lease_does_not_target_current_boot_pid(self):
        lease=self.stale_lease(); protected,birth=self.protected_process()
        lease[1]='0'*36; lease[5]=str(protected.pid); lease[6]=birth; self.write_lease(lease)
        self.supervise('recover'); self.assertIsNone(protected.poll()); self.assert_closed(2)

    def test_bad_or_linked_lease_and_runtime_paths_are_not_followed(self):
        target=self.base/'target'; target.write_bytes(b'PRIVATE_SENTINEL'); target.chmod(0o600)
        file=self.store/'runtime'; file.symlink_to(target)
        self.supervise('run-apply',self.handle,expected=7)
        self.assertEqual(target.read_bytes(),b'PRIVATE_SENTINEL')
        file.unlink()
        lease=self.store/'worker'; lease.symlink_to(target)
        self.supervise('recover',expected=2)
        lease.unlink(); os.link(target,lease); self.supervise('recover',expected=2)
        lease.unlink(); lease.write_bytes(b'PRIVATE_SENTINEL\n'); lease.chmod(0o600)
        self.supervise('recover',expected=7)
        self.assertEqual(target.read_bytes(),b'PRIVATE_SENTINEL')

    def test_zero_exit_without_generation_receipt_does_not_mean_applied(self):
        self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua") and sys.argv[2]=="apply": sys.exit(0)')
        self.supervise('run-apply',self.handle,expected=8)
        self.assert_closed(2); self.assertEqual(self.receipt()['revision'],'2')

    def test_leftover_child_in_same_session_is_stopped_before_restore(self):
        self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua") and sys.argv[2]=="apply":\n    pid=os.fork()\n    if pid==0:\n        signal.signal(signal.SIGTERM,signal.SIG_IGN)\n        os.write(1,b"PRIVATE_SENTINEL")\n        while True: time.sleep(0.1)\n    sys.exit(0)')
        self.supervise('run-apply',self.handle,expected=8)
        self.assert_closed(2)

    def test_lease_file_sync_failure_keeps_startup_gate_closed(self):
        self.fault('fsync','from pathlib import Path\nif sys.argv[-1].split("/")[-1].startswith(".worker.") and Path(sys.argv[-1]).read_bytes().startswith(b"HGWORKER1"): sys.exit(1)')
        self.supervise('run-apply',self.handle,expected=7)
        self.assertFalse((self.store/'runtime').exists()); self.assertFalse((self.store/'worker').exists())
        self.restore_tool('fsync'); self.recover_after_loss(); self.assert_closed(2)

    def test_lease_directory_sync_failure_preserves_unstarted_worker_record(self):
        self.fault('fsync','from pathlib import Path\nif sys.argv[-1]=='+repr(str(self.store))+' and Path('+repr(str(self.store/'worker'))+').exists(): sys.exit(1)')
        self.supervise('run-apply',self.handle,expected=7)
        self.assertFalse((self.store/'runtime').exists()); self.assertTrue((self.store/'worker').exists())
        self.cli('apply-finish',self.handle,'success',expected=4)
        self.restore_tool('fsync'); self.recover_after_loss(); self.assert_closed(2)

    def test_bounds_wrong_handle_and_arbitrary_command_are_rejected(self):
        self.supervise('run-apply','0'*32,expected=5)
        self.supervise('run-apply',self.handle,'/bin/sh',expected=2)
        self.supervise('run','/bin/sh',expected=2)
        for value in ['0','31','2;false','01']:
            self.supervise('run-apply',self.handle,env={**self.env,'HOMEGATE_WORKER_PROTO_TIMEOUT':value},expected=2)
        self.assertTrue(self.cli('status')['application_pending']); self.assertFalse((self.store/'worker').exists())

if __name__=='__main__':
    parser=argparse.ArgumentParser(); group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--static',action='store_true'); group.add_argument('--runtime',action='store_true'); args=parser.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if args.runtime else Static))
    raise SystemExit(not result.wasSuccessful())
