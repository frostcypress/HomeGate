#!/usr/bin/env python3
"""Fixed persistent supervision/anchors in Linux copies; receipt business only."""
import argparse, hashlib, json, os, re, shlex, signal, subprocess, time, unittest
from pathlib import Path
from project import ROOT
from 持久初始化回归 import Runtime as BootstrapRuntime
from 工作监督回归 import Runtime as WorkerRuntime, Static as WorkerStatic

PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_existing_supervisor_grammar_and_no_foreign_signals(self):
        result=unittest.TestResult(); WorkerStatic('test_fixed_shell_entrypoints_and_self_session_signals').run(result)
        self.assertFalse(result.errors+result.failures,result.errors+result.failures)

    def test_closed_fixed_modes_and_lua_syntax(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(); compile_lua=lua.eval('function(s) return assert(loadstring(s)) end')
        for name,gate in [('homegate-worker-supervisor.sh','persistent_supervision_enabled=false'),
                          ('homegate-worker-watchdog.sh','persistent_worker_enabled=false'),
                          ('homegate-worker-prototype.lua','persistent_worker_enabled=false')]:
            body=(PROTO/name).read_text(); self.assertEqual(body.count(gate),1)
            self.assertIn('/etc/homegate/transactions',body)
            if name.endswith('.lua'): compile_lua(body)
        compile_lua((PROTO/'worker-process.lua').read_text())
        engine=(PROTO/'homegate-config-prototype.sh').read_text()
        self.assertEqual(engine.count('orphan_recovery_enabled=false'),1)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_anchor_precedes_active_fence_and_binding_preserves_boot(self):
        body=(PROTO/'homegate-config-prototype.sh').read_text()
        begin=body.split('journal_begin() {',1)[1].split('journal_need() {',1)[0]
        self.assertLess(begin.index('persistent_anchor_write'),begin.index('persistent_fence_write active'))
        self.assertIn('journal_read anchor',body)
        self.assertIn('persistent_anchor_bind',body.split('journal_need() {',1)[1].split('intent_ack_need() {',1)[0])

    def test_shared_fd_is_separate_from_fifo_and_worker_cannot_hold_it(self):
        body=(PROTO/'homegate-worker-watchdog.sh').read_text()
        self.assertIn('exec 4<> "$store/worker-data"',body)
        self.assertIn('produce_snapshot 3>&4 4>&-',body)
        self.assertIn('4>&- 6>&- 7>&-',body)
        supervisor=(PROTO/'homegate-worker-supervisor.sh').read_text()
        self.assertLess(supervisor.index('orphan_quiescence; stale=true'),supervisor.index('exec 6>>/var/run/homegate/frontend.lock'))
        self.assertIn('HGWORKER2',supervisor)

class Runtime(BootstrapRuntime):
    def setUp(self):
        super().setUp()
        self.engine.write_text(self.engine.read_text().replace('orphan_recovery_enabled=false','orphan_recovery_enabled=true'))
        self.boot(); self.commit_body(self.business)
        self.supervisor=self.engine.parent/'homegate-worker-supervisor.sh'
        mapping={'/etc/homegate/transactions':str(self.store),'/etc/homegate':str(self.home),'/etc':str(self.etc),
                 '/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        for name in ['homegate-worker-supervisor.sh','homegate-worker-watchdog.sh','homegate-worker-prototype.lua','worker-process.lua']:
            p=self.engine.parent/name; body=p.read_text()
            body=body.replace('persistent_supervision_enabled=false','persistent_supervision_enabled=true').replace('persistent_worker_enabled=false','persistent_worker_enabled=true')
            body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
            body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))
            body=body.replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
            body=body.replace('[ "$persistent_mode" = false ] || budget=30','[ "$persistent_mode" = false ] || budget=2')
            p.write_text(body,encoding='utf-8')
        self.processes=[]; self.group_ids=[]

    def tearDown(self):
        for p in self.processes:
            if p.poll() is None: p.kill()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:pass
        # Only groups created and observed by this fixture, never mutated IDs.
        for group in self.group_ids:
            try:os.killpg(group,signal.SIGKILL)
            except ProcessLookupError:pass
        super().tearDown()

    fake_lua=WorkerRuntime.fake_lua
    real_lua=WorkerRuntime.real_lua
    protected_process=WorkerRuntime.protected_process
    receipt=WorkerRuntime.receipt
    killed_begin=__import__('持久事务屏障回归').Runtime.killed_begin

    def supervise(self,*args,expected=0,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.supervisor),'--persistent',*args],env=env or self.env,capture_output=True,timeout=20)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr)); self.assertEqual(p.stderr,b'')
        self.assertLess(len(p.stdout),2048); self.assertNotIn(b'PRIVATE_SENTINEL',p.stdout)
        result=json.loads(p.stdout); self.assertEqual(result['ok'],expected==0); return result

    def hang_apply(self):
        self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua") and "apply" in sys.argv[2:]:\n    signal.signal(signal.SIGTERM,signal.SIG_IGN)\n    while True: time.sleep(0.1)')

    def start(self):
        p=subprocess.Popen([self.busybox,'ash',str(self.supervisor),'--persistent','run-apply',self.handle],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.processes.append(p); deadline=time.monotonic()+5
        while not (self.store/'worker').exists():
            if p.poll() is not None:self.fail(p.communicate())
            if time.monotonic()>deadline:self.fail('Worker lease was not published')
            time.sleep(0.02)
        lease=(self.store/'worker').read_text().splitlines(); self.assertEqual(lease[0],'HGWORKER2')
        self.group_ids.append(int(lease[5])); return p,lease

    def recover_after_loss(self):
        deadline=time.monotonic()+8
        while True:
            p=subprocess.run([self.busybox,'ash',str(self.supervisor),'--persistent','recover'],env=self.env,capture_output=True,timeout=15)
            self.assertEqual(p.stderr,b'')
            if p.returncode==4 and time.monotonic()<deadline:time.sleep(0.05);continue
            self.assertEqual(p.returncode,0,(p.stdout,p.stderr)); return json.loads(p.stdout)

    def assert_closed(self,revision):
        report=self.cli('status'); self.assertEqual(report['revision'],revision)
        self.assertFalse(report['application_pending']); self.assertFalse(report['workers_pending']); self.assertFalse(report['persistent_fence_pending'])
        self.assertFalse((self.store/'worker').exists()); self.writer()

    def test_persistent_success_receipt_and_settled_fence(self):
        self.begin()
        wrapper=self.base/'inherited-supervisor.sh'
        wrapper.write_text('exec 6>>'+shlex.quote(str(self.native.lock))+'\nflock -n 6 || exit 4\nexec '+shlex.quote(self.busybox)+' ash '+shlex.quote(str(self.supervisor))+' --persistent run-apply '+self.handle+'\n')
        p=subprocess.run([self.busybox,'ash',str(wrapper)],env=self.env,capture_output=True,timeout=15)
        self.assertEqual(p.returncode,0,(p.stdout,p.stderr));self.assertEqual(p.stderr,b'');self.assertTrue(json.loads(p.stdout)['ok'])
        self.assert_closed(3)
        self.assertEqual(self.receipt()['https_port'],'8443'); self.assertIn(b'settled-applied\n',self.fence())

    def test_binary_private_frame_never_enters_receipt_or_public_response(self):
        self.secret(b'PRIVATE_SENTINEL\x00\xff\n'); self.begin()
        self.supervise('run-apply',self.handle); self.assert_closed(4)
        self.assertNotIn(b'PRIVATE_SENTINEL',(self.store/'runtime').read_bytes())

    def test_failed_apply_restores_only_after_worker_quiescence(self):
        self.begin(); self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua") and "apply" in sys.argv[2:]: sys.exit(9)')
        report=self.supervise('run-apply',self.handle,expected=8); self.assertTrue(report['baseline_restored']); self.assert_closed(2)

    def test_unread_pipe_independent_deadline_restores_baseline(self):
        self.begin(); self.hang_apply(); started=time.monotonic()
        report=self.supervise('run-apply',self.handle,expected=8); self.assertTrue(report['timed_out']); self.assertLess(time.monotonic()-started,9); self.assert_closed(2)

    def test_sigkill_caller_keeps_shared_native_barrier_until_safe_recovery(self):
        self.begin(); self.hang_apply(); p,lease=self.start(); self.writer(4)
        p.kill(); p.communicate(timeout=5); self.writer(4)
        self.recover_after_loss(); self.assert_closed(2)

    def test_sigterm_caller_leaves_explicit_recovery_after_quiescence(self):
        self.begin(); self.hang_apply(); p,lease=self.start(); p.terminate(); stdout,stderr=p.communicate(timeout=7)
        self.assertEqual(p.returncode,143,(stdout,stderr)); self.assertEqual(stderr,b'')
        self.supervise('recover'); self.assert_closed(2)

    def test_double_sigkill_with_live_family_never_reconstructs_or_acks(self):
        self.begin(); self.hang_apply(); p,lease=self.start(); time.sleep(0.2)
        p.kill(); p.communicate(timeout=5); os.kill(int(lease[5]),signal.SIGKILL)
        time.sleep(0.1); self.supervise('recover',expected=7)
        self.assertEqual((self.store/'current').read_bytes(),b'3\n'); self.assertTrue((self.store/'worker').exists())

    def test_matching_orphan_anchor_restores_missing_journal_without_guessing(self):
        self.begin(); (self.store/'application').unlink(); self.writer(7)
        self.supervise('recover'); self.assert_closed(2); self.assertEqual(self.receipt()['role'],'restore')

    def test_sigkill_between_active_fence_and_journal_has_recoverable_anchor(self):
        self.killed_begin('write-fence'); self.assertFalse((self.store/'application').exists()); self.writer(7)
        self.supervise('recover'); self.assert_closed(2)

    def test_service_intent_anchor_preserves_format_and_refuses_receipt_ack(self):
        self.begin(intent=True); (self.store/'application').unlink()
        self.cli('recover-fence'); body=(self.store/'application').read_bytes(); self.assertTrue(body.startswith(b'HGAPPLICATION2\n'))
        self.supervise('recover',expected=5); self.assertTrue((self.store/'application').exists()); self.writer(4)

    def test_corrupt_existing_journal_is_not_replaced_by_anchor(self):
        self.begin(); p=self.store/'application'; p.write_bytes(b'PRIVATE_SENTINEL\n')
        self.supervise('recover',expected=7); self.assertEqual(p.read_bytes(),b'PRIVATE_SENTINEL\n'); self.assertEqual((self.store/'current').read_bytes(),b'3\n')

    def test_anchor_corruption_missing_links_and_old_transaction_fail_closed(self):
        self.begin(); (self.store/'application').unlink()
        for name in ['application-anchor','application-anchor-meta']:
            p=self.store/name; original=p.read_bytes(); p.write_bytes(original[:-1]+b'\x00')
            self.cli('recover-fence',expected=7); self.assertFalse((self.store/'application').exists()); p.write_bytes(original)
            alias=self.base/(name+'-alias'); os.link(p,alias); self.cli('recover-fence',expected=7); alias.unlink()
            p.unlink(); self.cli('recover-fence',expected=7); p.write_bytes(original); p.chmod(0o600)
        p=self.store/'application-anchor'; p.write_bytes(p.read_bytes().replace(self.handle.encode(),b'0'*32))
        self.supervise('recover',expected=7); self.assertEqual((self.store/'current').read_bytes(),b'3\n')

    def test_old_boot_anchor_cannot_authorize_ack_or_automatic_recovery(self):
        self.begin(); self.boot_id.write_text('0'*36+'\n'); before=(self.store/'current').read_bytes()
        self.cli('apply-finish',self.handle,'success',expected=7); self.supervise('recover',expected=7)
        self.assertEqual((self.store/'current').read_bytes(),before); self.assertFalse((self.store/'worker').exists())

    def test_foreign_store_identity_cannot_consume_anchor(self):
        self.begin(); (self.store/'application').unlink(); self.write_identity(identity='b'*32)
        self.supervise('recover',expected=7); self.assertEqual((self.store/'current').read_bytes(),b'3\n')

    def test_missing_control_lock_never_created_by_supervisor(self):
        for name in ['.recovery.lock','.supervisor.lock']:
            p=self.store/name; p.unlink(); self.supervise('recover',expected=7); self.assertFalse(p.exists()); p.touch(mode=0o600)

    def test_environment_cannot_redirect_store_inject_lua_or_choose_budget(self):
        self.begin(); decoy=self.base/'decoy'; decoy.mkdir(mode=0o700)
        self.supervise('run-apply',self.handle,env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(decoy),'LUA_INIT':"error('PRIVATE_SENTINEL')",'HOMEGATE_WORKER_PROTO_TIMEOUT':'31'})
        self.assertEqual(list(decoy.iterdir()),[]); self.assert_closed(3)

    def test_closed_supervision_and_recovery_gates_ignore_environment(self):
        p=subprocess.run([self.busybox,'ash',str(PROTO/'homegate-worker-supervisor.sh'),'--persistent','recover'],env={**self.env,'persistent_supervision_enabled':'true'},capture_output=True,timeout=3)
        self.assertEqual(p.returncode,2); self.assertEqual(p.stderr,b'')
        body=self.engine.read_text(); self.engine.write_text(body.replace('orphan_recovery_enabled=true','orphan_recovery_enabled=false'))
        self.cli('recover-fence',expected=2)

    def test_zero_worker_exit_without_receipt_is_not_success(self):
        self.begin(); self.fake_lua('if sys.argv[1].endswith("homegate-worker-prototype.lua") and "apply" in sys.argv[2:]: sys.exit(0)')
        self.supervise('run-apply',self.handle,expected=8); self.assert_closed(2)

    def test_anchor_sync_failure_never_publishes_active_fence(self):
        plan=self.preview(); self.fault('fsync','from pathlib import Path\nif Path(sys.argv[-1]).is_file() and Path(sys.argv[-1]).read_bytes().startswith(b"HGRECOVERY1"): sys.exit(1)')
        self.cli('commit-apply',plan['confirmation'],expected=7); self.assertFalse((self.store/'write-fence').exists()); self.assertFalse((self.store/'application').exists())
        self.restore_tool('fsync'); self.cli('writer-check')

    def test_lease_sync_failure_keeps_gate_closed_and_barrier_recoverable(self):
        self.begin(); self.fault('fsync','from pathlib import Path\nif Path(sys.argv[-1]).is_file() and Path(sys.argv[-1]).read_bytes().startswith(b"HGWORKER2"): sys.exit(1)')
        self.supervise('run-apply',self.handle,expected=7); self.assertFalse((self.store/'runtime').exists())
        self.restore_tool('fsync'); self.recover_after_loss(); self.assert_closed(2)

    def test_arbitrary_command_path_and_wrong_handle_rejected(self):
        self.begin(); self.supervise('run-apply','0'*32,expected=5)
        for args in [('recover','/bin/sh'),('run-apply',self.handle,'/bin/sh'),('run','/bin/sh')]:self.supervise(*args,expected=2)
        self.writer(4)

    def test_foreign_worker_binding_does_not_touch_unrelated_process(self):
        self.begin(); self.hang_apply(); p,lease=self.start(); p.kill(); p.communicate(timeout=5)
        time.sleep(3.4); self.real_lua(); protected,birth=self.protected_process()
        lease[2]='0'*64; lease[5]=str(protected.pid); lease[6]=birth
        (self.store/'worker').write_text('\n'.join(lease)+'\n')
        self.supervise('recover',expected=7); self.assertIsNone(protected.poll()); self.assertFalse((self.store/'worker-stop').exists())

    def test_old_boot_worker_record_requires_reconciliation_and_never_signals_pid(self):
        self.begin(); self.hang_apply(); p,lease=self.start(); p.kill(); p.communicate(timeout=5)
        time.sleep(3.4); self.real_lua(); protected,birth=self.protected_process()
        lease[1]='0'*36; lease[5]=str(protected.pid); lease[6]=birth
        (self.store/'worker').write_text('\n'.join(lease)+'\n')
        self.supervise('recover',expected=7); self.assertIsNone(protected.poll()); self.assertFalse((self.store/'worker-stop').exists())

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,value in cls.__dict__.items() if name.startswith('test_') and callable(value))
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
