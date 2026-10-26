#!/usr/bin/env python3
"""Status/check health semantics over real fixed runtime and process metadata."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from project import ROOT, identity
from DDNS计划回归 import fixture_uid
from 核心账户CLI回归 import CF as AccountFixture

PROTO = ROOT / 'project/core/prototype'
STATE = {'pid': 0, 'started_at': '2026-10-26T03:04:05.123456789Z', 'version': '1.3.0-118'}


def models():
    from lupa.lua51 import LuaRuntime
    lua = LuaRuntime(unpack_returned_tuples=True)
    codec = lua.execute((ROOT / 'project/luci/lua/luasrc/model/homegate/backup.lua').read_text())
    return lua, codec, lua.execute((PROTO / 'runtime-health.lua').read_text())


class Static(unittest.TestCase):
    def test_grammar_closed_gates_and_reference_status_check_semantics(self):
        import tree_sitter, tree_sitter_bash
        lua, codec, model = models()
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh', 'homegate-health-read.sh', 'homegate-health-worker.sh', 'homegate-service-observer-watchdog.sh']:
            body = (PROTO / name).read_bytes()
            self.assertNotIn(b'\r', body)
            self.assertFalse(parser.parse(body).root_node.has_error, name)
        lua.compile((PROTO / 'homegate-health.lua').read_bytes())
        for name in ['homegate-health-read.sh', 'homegate-health-worker.sh', 'homegate-service-observer-watchdog.sh']:
            self.assertEqual((PROTO / name).read_text().count('health_status_enabled=false'), 1)
        body = (PROTO / 'homegate-health.lua').read_text()
        for word in ['io.popen', 'os.execute', 'kill ', '/sbin/ubus', 'curl ']:
            self.assertNotIn(word, body)
        main = (ROOT / 'project/core/src/cmd/homegate/main.go').read_text()
        check = main.split('case "check":', 1)[1].split('\n\tcase ', 1)[0]
        self.assertIn('if checkErr != nil', check)
        status = main.split('case "status":', 1)[1].split('\n\tcase ', 1)[0]
        self.assertNotIn('if !', status)
        report = (ROOT / 'project/core/src/internal/status/status.go').read_text()
        self.assertIn('report.Service.Enabled == report.Service.Running', report)
        self.assertNotIn('prototype/', (PROTO.parent / 'Makefile').read_text())

    def test_health_truth_table_and_configuration_error_precedence(self):
        lua, codec, model = models()
        for configured in [False, True]:
            for enabled in [False, True]:
                for running in [False, True]:
                    config = lua.table_from({'configured': configured, 'enabled': enabled, 'error_kind': '' if configured else 'invalid_configuration'})
                    probe = lua.table_from({'running': running})
                    report = json.loads(model.report('1.3.0-r126', '1', config, probe, codec.json))
                    self.assertEqual(report['ok'], configured and enabled == running)
                    self.assertEqual(report['service']['healthy'], report['ok'])
        config = lua.table_from({'configured': False, 'enabled': False, 'error_kind': 'invalid_configuration'})
        probe = lua.table_from({'running': False, 'error_kind': 'runtime_state_unavailable'})
        self.assertEqual(json.loads(model.report('1.3.0-r126', '1', config, probe, codec.json))['error_kind'], 'invalid_configuration')

    def test_runtime_metadata_calendar_and_process_identity_rules(self):
        lua, codec, model = models()
        self.assertIsNotNone(model.state(lua.table_from(STATE), json.dumps(STATE)))
        self.assertIsNone(model.state(lua.table_from(STATE), json.dumps(STATE).replace('"pid": 0', '"pid": 0e0')))
        self.assertIsNone(model.state(lua.table_from({**STATE, 'process_start_ticks': 0}), json.dumps({**STATE, 'process_start_ticks': 0}).replace('"process_start_ticks": 0', '"process_start_ticks": 0.0')))
        for key, value in [('pid', 1.5), ('pid', 1000000000), ('started_at', '2026-02-29T00:00:00Z'),
                           ('started_at', '2026-10-26T24:00:00Z'), ('started_at', 'SECRET_SENTINEL'),
                           ('version', 'SECRET_SENTINEL'), ('process_start_ticks', 9007199254740992)]:
            self.assertIsNone(model.state(lua.table_from({**STATE, key: value})))
        for stamp in ['2024-02-29T00:00:00Z', '2026-10-26T01:02:03+08:00', '0001-01-01T00:00:00Z']:
            self.assertTrue(model.timestamp(stamp))
        self.assertIsNone(model.state(lua.table_from({**STATE, 'extra': 'SECRET_SENTINEL'})))
        state = lua.table_from({**STATE, 'pid': 123, 'process_start_ticks': 77})
        stat = '123 (name with ) brackets) S ' + ' '.join(['1'] * 18 + ['77']) + '\n'
        def read(kind, pid, limit):
            return (stat, 'ok') if kind == 'stat' else ('/usr/bin/homegate\0daemon\0', 'ok')
        self.assertTrue(model.probe(state, read)['running'])
        self.assertFalse(model.probe(lua.table_from({**dict(state.items()), 'process_start_ticks': 78}), read)['running'])
        self.assertFalse(model.probe(state, lambda k, p, n: (stat.replace(') S ', ') Z '), 'ok'))['running'])
        self.assertEqual(model.probe(state, lambda k, p, n: (None, 'error'))['error_kind'], 'runtime_identity_unavailable')
        self.assertFalse(model.probe(state, lambda k, p, n: (None, 'absent'))['running'])

    def test_strict_report_validation_refuses_tampering_and_partial_documents(self):
        lua, codec, model = models()
        context = lua.table_from({'configured': True, 'enabled': False, 'error_kind': ''})
        raw = model.report('1.3.0-r126', '1', context, lua.table_from({'running': False}), codec.json)
        doc = lua.table_from(json.loads(raw), recursive=True)
        self.assertEqual(model.validate(raw, doc, '1.3.0-r126', '1', context, codec.json), (raw, True))
        for corrupt in [raw.replace('"none"', '"confirmed"'), raw + '{}', raw.replace('"ok":true', '"ok":false'),
                        raw.replace('"service":{', '"service":{"private":"SECRET_SENTINEL",')]:
            try:
                parsed = json.loads(corrupt)
            except json.JSONDecodeError:
                parsed = json.loads(raw)
            self.assertIsNone(model.validate(corrupt, lua.table_from(parsed, recursive=True), '1.3.0-r126', '1', context, codec.json))


class Runtime(AccountFixture):
    def setUp(self):
        super().setUp()
        self.health_entry = self.engine.parent / 'homegate-health-read.sh'
        self.health_worker = self.engine.parent / 'homegate-health-worker.sh'
        self.health_adapter = self.engine.parent / 'homegate-health.lua'
        self.runtime_file = self.native.lockdir / 'runtime.json'
        for file in [self.health_entry, self.health_worker, self.engine.parent / 'homegate-service-observer-watchdog.sh']:
            body = file.read_text().replace('health_status_enabled=false', 'health_status_enabled=true')
            if file.name != 'homegate-service-observer-watchdog.sh':
                body = body.replace('/var/run/homegate', str(self.native.lockdir)).replace('/etc/homegate/transactions', str(self.store))
            body = body.replace('0:600:1|0:644:1', str(os.getuid()) + ':600:1|' + str(os.getuid()) + ':644:1')
            file.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'PATH=' + str(self.bin))))
        body = self.health_adapter.read_text().replace("dir..'/../../../VERSION'", json.dumps(str(ROOT / 'VERSION')))
        body = body.replace("dir..'/../../../RELEASE'", json.dumps(str(ROOT / 'RELEASE')))
        body = body.replace('/etc/config/homegate', str(self.source))
        self.health_adapter.write_text('package.cpath=' + json.dumps(str(ROOT / 'build/service-observer/?.so') + ';;') + '\n' + body)

    def health(self, action='status', expected=0, ok=None, args=None, env=None):
        p = subprocess.run([self.busybox, 'ash', str(self.candidate), *(args or [action])], env=env or self.env,
                           capture_output=True, timeout=12)
        self.assertEqual((p.returncode, p.stderr), (expected, b''), p.stdout)
        self.assertLess(len(p.stdout), 8192)
        for marker in [b'SECRET_SENTINEL', b'OLD_ID', b'example.test', os.fsencode(self.store)]:
            self.assertNotIn(marker, p.stdout)
        out = json.loads(p.stdout)
        if ok is not None:
            self.assertEqual(out['ok'], ok)
        self.assertFalse(out['write_ready'])
        self.assertEqual(out['effect'], 'none')
        self.assertEqual(self.calls, [])
        return out

    def state(self, **extra):
        doc = {**STATE, **extra}
        self.runtime_file.write_text(json.dumps(doc) + '\n')
        self.runtime_file.chmod(0o644)
        return doc

    def daemon(self):
        fifo = self.base / 'daemon'
        os.mkfifo(fifo, 0o600)
        p = subprocess.Popen(['/usr/bin/homegate', 'daemon'], executable='/bin/cat', cwd=self.base,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(p)
        deadline = time.monotonic() + 2
        while Path('/proc/' + str(p.pid) + '/cmdline').read_bytes() != b'/usr/bin/homegate\0daemon\0':
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        ticks = int(Path('/proc/' + str(p.pid) + '/stat').read_text().rsplit(') ', 1)[1].split()[19])
        return p, ticks

    def unchanged_health(self):
        self.unchanged_status()
        self.assertFalse(list(self.native.lockdir.glob('.health-read-*')))

    def test_disabled_absent_runtime_is_healthy_and_both_commands_exit_zero(self):
        for action in ['status', 'check']:
            out = self.health(action, ok=True)
            self.assertEqual(out['service'], {'configured': True, 'enabled': False, 'running': False, 'healthy': True})
            self.assertNotIn('runtime', out)
        self.unchanged_health()

    def test_live_exact_daemon_is_unhealthy_when_disabled_and_check_exits_one(self):
        p, ticks = self.daemon()
        state = self.state(pid=p.pid, process_start_ticks=ticks)
        before = self.runtime_file.read_bytes()
        out = self.health(ok=False)
        self.assertTrue(out['service']['running'])
        self.assertEqual(out['runtime'], state)
        self.health('check', 1, False)
        self.assertIsNone(p.poll())
        self.assertEqual(self.runtime_file.read_bytes(), before)
        self.unchanged_health()

    def test_unrelated_live_pid_is_never_healthy_even_without_ticks(self):
        p = subprocess.Popen(['/bin/sleep', '60'])
        self.processes.append(p)
        self.state(pid=p.pid)
        out = self.health(ok=False)
        self.assertFalse(out['service']['running'])
        self.assertEqual(out['error_kind'], 'runtime_identity_unavailable')
        self.assertNotIn('runtime', out)
        self.assertIsNone(p.poll())
        self.unchanged_health()

    def test_reused_pid_ticks_are_stale_metadata_not_a_running_process(self):
        p, ticks = self.daemon()
        doc = self.state(pid=p.pid, process_start_ticks=ticks + 1)
        out = self.health('check', ok=True)
        self.assertEqual(out['runtime'], doc)
        self.assertFalse(out['service']['running'])
        self.assertIsNone(p.poll())
        self.unchanged_health()

    def test_legacy_no_ticks_requires_exact_stable_daemon_identity(self):
        p, ticks = self.daemon()
        doc = self.state(pid=p.pid)
        out = self.health('check', 1, False)
        self.assertTrue(out['service']['running'])
        self.assertEqual(out['runtime'], doc)
        self.unchanged_health()

    def test_zombie_and_nonpositive_pid_are_not_running(self):
        p = subprocess.Popen(['/bin/true'])
        self.processes.append(p)
        deadline = time.monotonic() + 2
        while Path('/proc/' + str(p.pid) + '/stat').read_text().rsplit(') ', 1)[1].split()[0] != 'Z':
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        self.state(pid=p.pid)
        self.assertFalse(self.health('check', ok=True)['service']['running'])
        p.wait(timeout=2)
        self.assertFalse(self.health('check', ok=True)['service']['running'])
        for pid in [0, -1]:
            self.state(pid=pid, process_start_ticks=0)
            out = self.health('check', ok=True)
            self.assertEqual(out['runtime']['pid'], pid)
            self.assertNotIn('process_start_ticks', out['runtime'])
        self.unchanged_health()

    def test_malformed_duplicate_trailing_and_oversize_runtime_are_unknown(self):
        for raw in ['SECRET_SENTINEL', '{}', json.dumps(STATE) + '{}',
                    json.dumps(STATE).replace('"pid": 0', '"pid": 0,"pid": 0'),
                    json.dumps(STATE).replace('"pid": 0', '"pid": 0e0'),
                    json.dumps({**STATE, 'process_start_ticks': 0}).replace('"process_start_ticks": 0', '"process_start_ticks": 0.0'), 'X' * 4097]:
            self.runtime_file.write_text(raw)
            self.runtime_file.chmod(0o644)
            out = self.health('check', 1, False)
            self.assertEqual(out['error_kind'], 'runtime_state_unavailable')
            self.assertNotIn('runtime', out)
        self.unchanged_health()

    def test_unsafe_runtime_symlink_hardlink_and_permissions_are_never_readiness(self):
        foreign = self.base / 'foreign-runtime'
        foreign.write_text('SECRET_SENTINEL')
        foreign.chmod(0o600)
        self.runtime_file.symlink_to(foreign)
        self.assertEqual(self.health('check', 1, False)['error_kind'], 'runtime_state_unavailable')
        self.runtime_file.unlink()
        os.link(foreign, self.runtime_file)
        self.health('check', 1, False)
        self.runtime_file.unlink()
        self.state()
        self.runtime_file.chmod(0o666)
        self.health('check', 1, False)
        self.assertEqual(foreign.read_text(), 'SECRET_SENTINEL')
        self.unchanged_health()

    def test_invalid_or_missing_ordinary_uci_is_configuration_error_not_health(self):
        for raw in [b'bad SECRET_SENTINEL\n', None]:
            if raw is None:
                self.source.unlink()
            else:
                self.source.write_bytes(raw)
            out = self.health(ok=False)
            self.assertEqual(out['error_kind'], 'invalid_configuration')
            self.assertFalse(out['service']['configured'])
            self.health('check', 1, False)
            self.source.write_bytes(self.source_before)
        self.unchanged_health()

    def test_common_locks_and_replaced_inode_and_orphan_refuse(self):
        import fcntl
        for file in [self.native.lock, self.store / '.supervisor.lock']:
            with file.open('rb') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.health(expected=4)
        work = self.native.lockdir / '.health-read-123'
        work.mkdir(mode=0o700)
        self.health(expected=4)
        work.rmdir()
        self.health_entry.write_text(self.health_entry.read_text().replace('locks_match || fail 4',
            'rm -f "$run/frontend.lock"; : > "$run/frontend.lock"\nlocks_match || fail 4', 1))
        self.health(expected=4)
        self.unchanged_health()

    def test_source_changed_during_worker_never_publishes_stale_healthy_report(self):
        self.health_adapter.write_text(self.health_adapter.read_text().replace('local output=model.report',
            'local f=assert(io.open(' + json.dumps(str(self.source)) + ",'ab'));f:write('\\n');f:close()\nlocal output=model.report"))
        self.health(expected=7)
        self.assertNotEqual(self.source.read_bytes(), self.source_before)
        self.assertTrue(list(self.native.lockdir.glob('.health-read-*')))
        self.source.write_bytes(self.source_before)
        self.health(expected=4)

    def test_worker_result_tampering_is_rejected_before_output(self):
        self.health_adapter.write_text(self.health_adapter.read_text().replace('if #output>8192 then',
            "output=output:gsub('none','confirmed')\nif #output>8192 then"))
        self.health(expected=7)
        self.assertTrue(list(self.native.lockdir.glob('.health-read-*')))

    def test_arguments_closed_gates_environment_and_forged_watchdog_action(self):
        for action in ['status', 'check']:
            self.health(expected=2, args=[action, 'SECRET_SENTINEL'])
        watch = self.engine.parent / 'homegate-service-observer-watchdog.sh'
        p = subprocess.run([self.busybox, 'ash', str(watch), '--action', '0' * 32, 'health-status'], env=self.env,
                           capture_output=True, timeout=3)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (2, b'', b''))
        self.health_entry.write_text(self.health_entry.read_text().replace('health_status_enabled=true', 'health_status_enabled=false'))
        self.health(expected=2, env={**self.env, 'health_status_enabled': 'true', 'HOMEGATE_RUNTIME_STATE': 'SECRET_SENTINEL'})
        self.unchanged_health()

    def test_partial_final_public_file_is_refused_before_publication(self):
        body = self.health_entry.read_text()
        body = body.replace('private_file "$work/public" && [ -s "$work/public" ]',
                            'printf "%s" "{" > "$work/public"\nprivate_file "$work/public" && [ -s "$work/public" ]')
        self.health_entry.write_text(body)
        self.health(expected=7)
        self.assertTrue(list(self.native.lockdir.glob('.health-read-*')))

    def stall(self):
        self.marker = self.base / 'health-worker-entered'
        self.health_adapter.write_text(self.health_adapter.read_text().replace('local output=model.report',
            'local f=assert(io.open(' + json.dumps(str(self.marker)) + ",'wb'));f:write('ready');f:close();os.execute('sleep 30')\nlocal output=model.report"))

    def test_stalled_probe_keeps_existing_independent_deadline(self):
        self.stall()
        p, ticks = self.daemon()
        start = time.monotonic()
        self.health(expected=7)
        self.assertLess(time.monotonic() - start, 10)
        self.assertTrue(self.marker.exists())
        self.assertIsNone(p.poll(), 'Probe killed an unrelated service process')
        self.assertTrue(list(self.native.lockdir.glob('.health-read-*')))

    def test_caller_loss_keeps_locks_until_watchdog_own_family_is_quiet(self):
        import fcntl
        self.stall()
        p = subprocess.Popen([self.busybox, 'ash', str(self.candidate), 'status'], env=self.env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(p)
        deadline = time.monotonic() + 5
        while not self.marker.exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        self.group()
        p.kill()
        with self.native.lock.open('rb') as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            deadline = time.monotonic() + 9
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.05)
        p.communicate(timeout=2)
        self.health(expected=4)


def suite(runtime):
    cls = Runtime if runtime else Static
    return unittest.TestSuite(cls(n) for n, v in cls.__dict__.items() if n.startswith('test_') and callable(v))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(suite(args.runtime))
    raise SystemExit(not result.wasSuccessful())
