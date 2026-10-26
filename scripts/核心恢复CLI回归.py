#!/usr/bin/env python3
"""Source-bound recovery observation; no retry or reconciliation side effects."""
import argparse
import hashlib
import json
import os
import subprocess
import time
import unittest
from project import ROOT, identity
from DDNS计划回归 import fixture_uid
from 核心健康CLI回归 import Runtime as HealthFixture

PROTO = ROOT / 'project/core/prototype'
STAMP = '2026-10-26T03:04:05Z'


def row(module='ddns', state='retrying', **extra):
    out = dict(module=module, state=state, retryable=state != 'requires_user_action', updated_at=STAMP)
    if state == 'retrying':
        out.update(attempt=1, max_attempts=5, next_retry_at='2026-10-26T03:04:10Z')
    out.update(extra)
    return out


def models():
    from lupa.lua51 import LuaRuntime
    lua = LuaRuntime(unpack_returned_tuples=True)
    codec = lua.execute((ROOT / 'project/luci/lua/luasrc/model/homegate/backup.lua').read_text())
    health = lua.execute((PROTO / 'runtime-health.lua').read_text())
    return lua, codec, health, lua.execute((PROTO / 'recovery-report.lua').read_text())


class Static(unittest.TestCase):
    def setUp(self):
        self.lua, self.codec, self.health, self.model = models()
        self.binding = self.model.binding('a' * 64 + ':' + 'b' * 64 + ':clear:0')
        self.context = self.lua.table_from({'config': {'configured': True, 'enabled': False, 'error_kind': ''},
                                          'binding': dict(self.binding.items())}, recursive=True)

    def record(self, modules=(), bound=True, **extra):
        out = dict(api_version=1, ok=True, version='1.3.0-r127', phase='recovery', degraded=False, modules=list(modules))
        if bound:
            out['source'] = dict(schema='HGRECOVERYSOURCE1', configuration_revision=1, identity='a' * 64, generation='b' * 64)
        out.update(extra)
        return out

    def parse(self, doc):
        return self.model.record(json.dumps(doc), self.lua.table_from(doc, recursive=True),
                                 self.lua.table_from({'modules': 'array'}), '1.3.0-r127', '1', self.binding, self.health.timestamp)

    def test_grammar_closed_gates_actual_legacy_missing_semantics_and_exit_zero(self):
        import tree_sitter, tree_sitter_bash
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh', 'homegate-recovery-read.sh', 'homegate-recovery-worker.sh', 'homegate-service-observer-watchdog.sh']:
            body = (PROTO / name).read_bytes()
            self.assertNotIn(b'\r', body)
            self.assertFalse(parser.parse(body).root_node.has_error, name)
        self.lua.compile((PROTO / 'homegate-recovery.lua').read_bytes())
        for name in ['homegate-recovery-read.sh', 'homegate-recovery-worker.sh', 'homegate-service-observer-watchdog.sh']:
            self.assertEqual((PROTO / name).read_text().count('recovery_status_enabled=false'), 1)
        main = (ROOT / 'project/core/src/cmd/homegate/main.go').read_text()
        branch = main.split('case "recovery-status":', 1)[1].split('\n\tcase ', 1)[0]
        self.assertNotIn('if !', branch)
        old = (ROOT / 'project/core/src/internal/recovery/status.go').read_text()
        self.assertIn('return Empty(version)', old.split('func (s Store) Read', 1)[1])
        wrapper = (PROTO / 'homegate-recovery-read.sh').read_text()
        for forbidden in ['recover-application', 'recover-fence', 'archive-recover', '--confirm', 'curl ', 'eval ']:
            self.assertNotIn(forbidden, wrapper)
        self.assertNotIn('prototype/', (PROTO.parent / 'Makefile').read_text())

    def test_binding_unknown_and_safe_modules_do_not_claim_recovered(self):
        good = self.parse(self.record())
        self.assertTrue(good['bound'])
        report = json.loads(self.model.report('1.3.0-r127', '1', self.context, good, STAMP, self.codec.json))
        self.assertTrue(report['ok'])
        self.assertEqual(report['modules'], [])
        self.assertFalse(report['complete_recovery_verified'])
        for record in [None, self.parse(self.record(bound=False))]:
            report = json.loads(self.model.report('1.3.0-r127', '1', self.context, record, STAMP, self.codec.json))
            self.assertFalse(report['ok'])
            self.assertEqual(report['modules'][0]['state'], 'requires_user_action')
        doc = self.record([row('proxy', 'degraded', error='SECRET_SENTINEL'), row('ddns')])
        result = self.parse(doc)
        raw = self.model.report('1.3.0-r127', '1', self.context, result, STAMP, self.codec.json)
        self.assertNotIn('SECRET_SENTINEL', raw)
        self.assertEqual([r['module'] for r in json.loads(raw)['modules']], ['ddns', 'proxy'])
        doc['source']['configuration_revision'] = 2
        self.assertFalse(self.parse(doc)['bound'])

    def test_schema_and_integer_tokens_reject_malformed_record_without_partial_rows(self):
        for change in [{'modules': [row('unknown')]}, {'modules': [row(), row()]},
                       {'modules': [row(updated_at='SECRET_SENTINEL')]}, {'modules': [row(attempt=6)]},
                       {'modules': [row(retryable=False)]}, {'version': '1.3.0-r126'}, {'extra': 'SECRET_SENTINEL'}]:
            self.assertIsNone(self.parse(self.record(**change)))
        self.assertTrue(self.model.integer_tokens('{"error":"secret 0e0 and 1.0","attempt":1}'))
        for raw in ['{"attempt":1e0}', '{"api_version":1.0}', '{"attempt":-1}']:
            self.assertFalse(self.model.integer_tokens(raw))

    def test_result_rebuild_refuses_private_rows_extra_fields_and_partial_json(self):
        rec = self.parse(self.record([row(error='SECRET_SENTINEL', error_kind='SECRET_SENTINEL')]))
        raw = self.model.report('1.3.0-r127', '1', self.context, rec, STAMP, self.codec.json)
        doc = self.lua.table_from(json.loads(raw), recursive=True)
        self.assertEqual(self.model.validate(raw, doc, '1.3.0-r127', '1', self.context, self.codec.json, self.health.timestamp), raw)
        for bad in [raw.replace('"none"', '"confirmed"'), raw + '{}', raw.replace('"complete_recovery_verified":false', '"complete_recovery_verified":true')]:
            self.assertIsNone(self.model.validate(bad, doc, '1.3.0-r127', '1', self.context, self.codec.json, self.health.timestamp))
        obj = json.loads(raw)
        obj['modules'][0]['private'] = 'SECRET_SENTINEL'
        self.assertIsNone(self.model.validate(json.dumps(obj), self.lua.table_from(obj, recursive=True), '1.3.0-r127', '1', self.context, self.codec.json, self.health.timestamp))


class Runtime(HealthFixture):
    def setUp(self):
        super().setUp()
        self.recovery_entry = self.engine.parent / 'homegate-recovery-read.sh'
        self.recovery_worker = self.engine.parent / 'homegate-recovery-worker.sh'
        self.recovery_adapter = self.engine.parent / 'homegate-recovery.lua'
        self.recovery_file = self.native.lockdir / 'recovery.json'
        for file in [self.recovery_entry, self.recovery_worker, self.engine.parent / 'homegate-service-observer-watchdog.sh']:
            body = file.read_text().replace('recovery_status_enabled=false', 'recovery_status_enabled=true')
            if file.name != 'homegate-service-observer-watchdog.sh':
                body = body.replace('/var/run/homegate', str(self.native.lockdir)).replace('/etc/homegate/transactions', str(self.store))
            body = body.replace('0:600:1|0:644:1', str(os.getuid()) + ':600:1|' + str(os.getuid()) + ':644:1')
            file.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'PATH=' + str(self.bin))))
        body = self.recovery_adapter.read_text().replace("dir..'/../../../VERSION'", json.dumps(str(ROOT / 'VERSION')))
        body = body.replace("dir..'/../../../RELEASE'", json.dumps(str(ROOT / 'RELEASE'))).replace('/etc/config/homegate', str(self.source))
        self.recovery_adapter.write_text('package.cpath=' + json.dumps(str(ROOT / 'build/service-observer/?.so') + ';;') + '\n' + body)
        self.engine.write_text(self.engine.read_text().replace('dns_recovery_read_enabled=false', 'dns_recovery_read_enabled=true'))

    def recovery(self, expected=0, ok=None, args=None, env=None):
        p = subprocess.run([self.busybox, 'ash', str(self.candidate), *(args or ['recovery-status'])], env=env or self.env,
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

    def record(self, modules=(), bound=True, **extra):
        out = dict(api_version=1, ok=True, version=identity()['normalized'], phase='recovery', degraded=False, modules=list(modules))
        if bound:
            out['source'] = dict(schema='HGRECOVERYSOURCE1', configuration_revision=self.revision,
                                 identity=hashlib.sha256((self.store / 'identity').read_bytes()).hexdigest(),
                                 generation=hashlib.sha256((self.store / f'gen-{self.revision}/manifest').read_bytes()).hexdigest())
        out.update(extra)
        self.recovery_file.write_text(json.dumps(out) + '\n')
        self.recovery_file.chmod(0o644)
        return out

    def unchanged_recovery(self):
        self.unchanged_status()
        self.assertFalse(list(self.native.lockdir.glob('.recovery-read-*')))

    def test_missing_and_broken_record_are_unknown_and_zero_exit_without_creation(self):
        for raw in [None, 'SECRET_SENTINEL']:
            if raw is not None:
                self.recovery_file.write_text(raw)
                self.recovery_file.chmod(0o644)
            out = self.recovery(ok=False)
            self.assertEqual(out['modules'][0]['error_kind'], 'state_unavailable')
            self.assertFalse(out['record_valid'])
            if raw is None:
                self.assertFalse(self.recovery_file.exists())
        self.unchanged_recovery()

    def test_bound_empty_array_is_clear_only_for_this_observation_scope(self):
        self.record(ok=False, degraded=True)
        before = self.recovery_file.read_bytes()
        out = self.recovery(ok=True)
        self.assertEqual(out['modules'], [])
        self.assertTrue(out['record_source_bound'])
        self.assertTrue(out['config_source_bound'])
        self.assertTrue(out['observation_only'])
        self.assertFalse(out['complete_recovery_verified'])
        self.assertEqual(self.recovery_file.read_bytes(), before)
        self.unchanged_recovery()

    def test_legacy_record_is_readable_sanitized_but_not_bound_or_recovered(self):
        self.record([row(error='SECRET_SENTINEL https://private.example.test/path', error_kind='rate_limit')], bound=False,
                    version=identity()['legacy'])
        out = self.recovery(ok=False)
        self.assertTrue(out['record_valid'])
        self.assertFalse(out['record_source_bound'])
        self.assertEqual([r['module'] for r in out['modules']], ['ddns', 'recovery'])
        self.assertEqual(out['modules'][0]['error_kind'], 'rate_limit')
        self.assertEqual(out['modules'][1]['error_kind'], 'unbound_state')
        self.unchanged_recovery()

    def test_wrong_revision_store_generation_and_stale_version_never_clear(self):
        for key, value in [('configuration_revision', self.revision + 1), ('identity', 'a' * 64), ('generation', 'b' * 64)]:
            doc = self.record()
            doc['source'][key] = value
            self.recovery_file.write_text(json.dumps(doc))
            self.assertEqual(self.recovery(ok=False)['modules'][0]['error_kind'], 'source_mismatch')
        self.record(version='1.3.0-r126')
        self.assertFalse(self.recovery(ok=False)['record_valid'])
        self.unchanged_recovery()

    def test_three_legacy_states_sort_keep_retry_metadata_and_sanitize_unknown_kind(self):
        self.record([row('proxy', 'degraded', attempt=5, max_attempts=5, error='SECRET_SENTINEL'),
                     row('firewall', 'requires_user_action', max_attempts=5, error_kind='SECRET_SENTINEL'), row('ddns')])
        out = self.recovery(ok=False)
        self.assertEqual([r['module'] for r in out['modules']], ['ddns', 'firewall', 'proxy'])
        self.assertEqual(out['modules'][0]['attempt'], 1)
        self.assertEqual(out['modules'][0]['next_retry_at'], '2026-10-26T03:04:10Z')
        self.assertEqual(out['modules'][1]['error_kind'], 'unclassified')
        self.unchanged_recovery()

    def test_duplicate_trailing_arrays_and_noninteger_metadata_reject_whole_record(self):
        doc = self.record([row()])
        good = json.dumps(doc)
        for raw in [good + '{}', good.replace('"api_version": 1', '"api_version": 1,"api_version": 1'),
                    good.replace('"api_version": 1', '"api_version": 1e0'),
                    good.replace('"attempt": 1', '"attempt": 1.0'), good.replace('"ddns"', '"SECRET_SENTINEL"'), '[]']:
            self.recovery_file.write_text(raw)
            out = self.recovery(ok=False)
            self.assertFalse(out['record_valid'])
            self.assertEqual([r['module'] for r in out['modules']], ['recovery'])
        self.unchanged_recovery()

    def test_symlink_hardlink_bad_permissions_and_oversize_record_are_unknown(self):
        foreign = self.base / 'foreign-recovery'
        foreign.write_text('SECRET_SENTINEL')
        foreign.chmod(0o600)
        self.recovery_file.symlink_to(foreign)
        self.assertFalse(self.recovery(ok=False)['record_valid'])
        self.recovery_file.unlink()
        os.link(foreign, self.recovery_file)
        self.recovery(ok=False)
        self.recovery_file.unlink()
        self.record()
        self.recovery_file.chmod(0o666)
        self.recovery(ok=False)
        self.recovery_file.chmod(0o600)
        self.recovery_file.write_text('X' * 65537)
        self.recovery(ok=False)
        self.assertEqual(foreign.read_text(), 'SECRET_SENTINEL')
        self.unchanged_recovery()

    def test_durable_dns_evidence_blocks_clear_without_being_parsed_cleared_or_retried(self):
        self.record()
        marker = self.store / 'dns-operation'
        marker.write_text('SECRET_SENTINEL')
        marker.chmod(0o600)
        self.before = self.contents()
        out = self.recovery(ok=False)
        self.assertEqual(out['writer_state'], 'pending')
        self.assertIn('candidate', [r['module'] for r in out['modules']])
        self.assertEqual(marker.read_text(), 'SECRET_SENTINEL')
        self.assertEqual(self.contents(), self.before)
        self.assertEqual(self.source.read_bytes(), self.source_before)
        self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))
        self.assertFalse(list(self.native.lockdir.glob('.recovery-read-*')))
        self.assertTrue(marker.exists())

    def test_orphan_and_schedule_evidence_remain_visible_and_are_never_removed(self):
        self.record()
        orphan = self.native.lockdir / '.health-read-123'
        orphan.mkdir(mode=0o700)
        keep = orphan / 'result'
        keep.write_text('SECRET_SENTINEL')
        keep.chmod(0o600)
        schedule = self.native.lockdir / 'ddns-schedule'
        schedule.mkdir(mode=0o700)
        for _ in range(2):
            out = self.recovery(ok=False)
            self.assertTrue(out['orphan_evidence'])
            self.assertEqual(out['modules'][0]['module'], 'candidate')
            self.assertEqual(keep.read_text(), 'SECRET_SENTINEL')
            self.assertTrue(schedule.exists())
        self.unchanged_recovery()

    def test_locks_arguments_closed_gate_environment_and_forged_action_refuse(self):
        import fcntl
        for file in [self.native.lock, self.store / '.supervisor.lock']:
            with file.open('rb') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.recovery(expected=4)
        self.recovery(expected=2, args=['recovery-status', 'SECRET_SENTINEL'])
        watch = self.engine.parent / 'homegate-service-observer-watchdog.sh'
        p = subprocess.run([self.busybox, 'ash', str(watch), '--action', '0' * 32, 'recovery-status'], env=self.env,
                           capture_output=True, timeout=3)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (2, b'', b''))
        self.recovery_entry.write_text(self.recovery_entry.read_text().replace('recovery_status_enabled=true', 'recovery_status_enabled=false'))
        self.recovery(expected=2, env={**self.env, 'recovery_status_enabled': 'true', 'HOMEGATE_RECOVERY_STATUS': 'SECRET_SENTINEL'})
        self.unchanged_recovery()

    def test_source_change_during_worker_refuses_stale_clear_and_retains_evidence(self):
        self.record()
        self.recovery_adapter.write_text(self.recovery_adapter.read_text().replace('local output=model.report',
            'local f=assert(io.open(' + json.dumps(str(self.source)) + ",'ab'));f:write('\\n');f:close()\nlocal output=model.report"))
        self.recovery(expected=7)
        self.assertNotEqual(self.source.read_bytes(), self.source_before)
        self.assertTrue(list(self.native.lockdir.glob('.recovery-read-*')))
        self.source.write_bytes(self.source_before)

    def test_worker_result_tampering_cannot_enter_public_response(self):
        self.record()
        self.recovery_adapter.write_text(self.recovery_adapter.read_text().replace('if #output>8192 then',
            "output=output:gsub('none','confirmed')\nif #output>8192 then"))
        self.recovery(expected=7)
        works = list(self.native.lockdir.glob('.recovery-read-*'))
        self.assertTrue(works)
        self.assertIn(b'confirmed', (works[0] / 'result').read_bytes())

    def test_partial_final_file_is_refused_without_partial_json(self):
        self.record()
        self.recovery_entry.write_text(self.recovery_entry.read_text().replace('private_file "$work/public" && [ -s "$work/public" ]',
            'printf "%s" "{" > "$work/public"\nprivate_file "$work/public" && [ -s "$work/public" ]'))
        self.recovery(expected=7)
        self.assertTrue(list(self.native.lockdir.glob('.recovery-read-*')))

    def stall_recovery(self):
        self.marker = self.base / 'recovery-worker-entered'
        self.recovery_adapter.write_text(self.recovery_adapter.read_text().replace('local output=model.report',
            'local f=assert(io.open(' + json.dumps(str(self.marker)) + ",'wb'));f:write('ready');f:close();os.execute('sleep 30')\nlocal output=model.report"))

    def test_stalled_observation_has_original_independent_deadline(self):
        self.stall_recovery()
        start = time.monotonic()
        self.recovery(expected=7)
        self.assertLess(time.monotonic() - start, 10)
        self.assertTrue(self.marker.exists())
        self.assertTrue(list(self.native.lockdir.glob('.recovery-read-*')))

    def test_caller_loss_keeps_shared_locks_until_own_family_quiet_then_exposes_orphan(self):
        import fcntl
        self.stall_recovery()
        before = self.recovery_adapter.read_text()
        p = subprocess.Popen([self.busybox, 'ash', str(self.candidate), 'recovery-status'], env=self.env,
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
        self.assertTrue(list(self.native.lockdir.glob('.recovery-read-*')))
        # Remove only the fault injection in this copied adapter, not evidence.
        needle = 'local f=assert(io.open(' + json.dumps(str(self.marker)) + ",'wb'));f:write('ready');f:close();os.execute('sleep 30')\n"
        self.recovery_adapter.write_text(before.replace(needle, ''))
        self.assertTrue(self.recovery(ok=False)['orphan_evidence'])


def suite(runtime):
    cls = Runtime if runtime else Static
    return unittest.TestSuite(cls(n) for n, v in cls.__dict__.items() if n.startswith('test_') and callable(v))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(suite(args.runtime))
    raise SystemExit(not result.wasSuccessful())
