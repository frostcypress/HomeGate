#!/usr/bin/env python3
"""Full private configuration validation; public health check remains pending."""
import argparse
import json
import os
import subprocess
import unittest
from project import ROOT, identity
from 配置预览回归 import BUSINESS, CODEC
from DDNS计划回归 import fixture_uid
from 核心账户CLI回归 import CF as AccountFixture

PROTO = ROOT / 'project/core/prototype'
RAW = BUSINESS.replace("config web_rule 'web_a'", "config web_rule 'web_a'\n option target 'https://127.0.0.1:8443/a?q=1'")


def models():
    from lupa.lua51 import LuaRuntime
    lua = LuaRuntime(unpack_returned_tuples=True)
    return (lua, lua.execute(CODEC.read_text()),
            lua.execute((PROTO / 'configuration-validation.lua').read_text()),
            lua.execute((PROTO / 'cloudflare-record-plan.lua').read_text()))


def candidate(codec, raw=RAW):
    result = codec.private_configuration(raw)
    assert result is not None, 'invalid fixture'
    return result


def frame(codec, raw):
    public, slots = codec.migration(raw)
    body = public.encode()
    records = []
    for name, value in sorted(slots.items()):
        n, v = name.encode(), value.encode()
        records.append(str(len(n)).encode() + b'\n' + str(len(v)).encode() + b'\n' + n + v)
    return b'HGPRIVATE1\n1\n' + str(len(body)).encode() + b'\n' + str(len(records)).encode() + b'\n' + body + b''.join(records) + b'END\n'


class Static(unittest.TestCase):
    def test_grammar_closed_internal_gate_and_actual_check_contract(self):
        import tree_sitter, tree_sitter_bash
        lua, codec, model, ip = models()
        lua.compile((PROTO / 'homegate-configuration.lua').read_bytes())
        body = (PROTO / 'homegate-configuration-read.sh').read_bytes()
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        self.assertFalse(parser.parse(body).root_node.has_error)
        self.assertNotIn(b'\r', body)
        self.assertEqual(body.count(b'configuration_validation_enabled=false'), 1)
        for forbidden in [b'curl ', b'setsid ', b'kill ', b'mktemp', b'--confirm']:
            self.assertNotIn(forbidden, body)
        main = (ROOT / 'project/core/src/cmd/homegate/main.go').read_text()
        branch = main.split('case "check":', 1)[1].split('\n\tcase ', 1)[0]
        self.assertIn('a.Check(ctx)', branch)
        self.assertIn('if checkErr != nil', branch)
        app = (ROOT / 'project/core/src/internal/app/app.go').read_text()
        self.assertIn('r := a.Status(ctx)', app.split('func (a App) Check', 1)[1])
        self.assertNotIn('homegate-configuration-read', (PROTO / 'homegate-cli.sh').read_text())
        self.assertNotIn('prototype/', (PROTO.parent / 'Makefile').read_text())

    def test_private_switches_survive_without_changing_exports_or_ddns_contract(self):
        lua, codec, model, ip = models()
        private = candidate(codec)
        for name in ['main', 'ddns_a', 'cert_a', 'web_a']:
            self.assertEqual(private['switches'][name]['enabled'], '1')
        self.assertEqual(private['switches']['main']['access_enabled'], '1')
        self.assertTrue(all(s['values']['enabled'] in [None, '0'] for s in private['configuration'].values()))
        migrated, slots = codec.migration(RAW)
        self.assertEqual(codec.canonical(migrated), migrated)
        self.assertNotIn('8443', migrated)
        projected = codec.private_configuration(migrated)
        self.assertTrue(projected['public_projection'])
        self.assertEqual(projected['switches']['web_a']['enabled'], '0')
        self.assertIsNotNone(model.validate(private, projected, codec.json, ip))
        self.assertIsNone(codec.private_configuration(migrated + '\n'))
        self.assertEqual(codec.private_ddns_switches(RAW)['ddns_a'], '1')
        self.assertEqual(codec.private_ddns_switches(RAW.replace("option enabled '1'", "option enabled '0'"))['ddns_a'], '0')
        self.assertIsNone(codec.private_configuration(RAW.replace("option enabled '1'", "option enabled 'SECRET_SENTINEL'", 1)))

    def test_all_six_types_and_cross_references_use_existing_schema(self):
        lua, codec, model, ip = models()
        c = candidate(codec)
        self.assertEqual(dict(model.validate(c, c, codec.json, ip).items()),
                         dict.fromkeys(['homegate', 'dns_account', 'ddns_rule', 'certificate', 'web_rule', 'wol_host'], 1))
        for a, b in [("option provider 'cloudflare'", "option provider 'unknown'"),
                     ("option account 'dns_a'", "option account 'missing'"),
                     ("option mac 'AA-BB-CC-DD-EE-FF'", "option mac '01:00:00:00:00:01'"),
                     ("option certificate 'cert_a'", "option certificate 'missing'"),
                     ("list domains '*.example.test'", "list domains '*.outside.test'"),
                     ("option access_allow '192.0.2.1,2001:db8::/32'", "option access_allow 'SECRET_SENTINEL'"),
                     ("option last_wol_host 'host_a'", "option last_wol_host 'missing'")]:
            with self.subTest(field=a):
                self.assertIsNone(codec.private_configuration(RAW.replace(a, b)))

    def test_web_targets_ports_disabled_rules_and_stricter_authorities(self):
        lua, codec, model, ip = models()
        for url in ['http://localhost/', 'https://example.test:65535/a?q=1', 'http://[2001:db8::1]:8080/', 'http://192.0.2.1']:
            self.assertTrue(model.target(url, ip), url)
        for url in ['', 'ftp://example.test', 'http://', 'http://user:SECRET_SENTINEL@example.test',
                    'http://example.test/#fragment', 'http://[bad]/', 'http://a:0', 'http://a:65536',
                    'http://-bad.test', 'http://a..test', 'http://127.00.0.1', 'http://a\\b', 'http://a\n']:
            self.assertFalse(model.target(url, ip), url)
        missing = RAW.replace(" option target 'https://127.0.0.1:8443/a?q=1'\n", '')
        c = candidate(codec, missing)
        self.assertEqual(model.validate(c, c, codec.json, ip), (None, 'invalid_web_target'))
        disabled = candidate(codec, missing.replace("config web_rule 'web_a'\n option enabled '1'", "config web_rule 'web_a'\n option enabled '0'"))
        self.assertIsNotNone(model.validate(disabled, disabled, codec.json, ip))
        for key in ['proxy_https_port', 'proxy_http_port']:
            raw = RAW.replace("config homegate 'main'", "config homegate 'main'\n option " + key + " '0'")
            c = candidate(codec, raw)
            self.assertEqual(model.validate(c, c, codec.json, ip), (None, 'web_port_unavailable'))

    def test_private_binding_and_reports_never_serialize_private_values(self):
        lua, codec, model, ip = models()
        c, other = candidate(codec), candidate(codec, RAW.replace('8443', '9443'))
        self.assertEqual(model.validate(c, other, codec.json, ip), (None, 'source_mismatch'))
        for counts, kind in [(None, 'invalid_web_target'), (model.validate(c, c, codec.json, ip), None)]:
            raw = model.report('1.3.0-r125', '1', counts, kind, codec.json)
            report = json.loads(raw)
            self.assertFalse(report['health_checked'])
            self.assertFalse(report['external_resources_checked'])
            for marker in ['example.test', '8443', '"dns_a"', '"host_a"', 'access_allow']:
                self.assertNotIn(marker, raw)
        body = (PROTO / 'configuration-validation.lua').read_text()
        for forbidden in ['io.', 'os.', 'loadfile', 'require(']:
            self.assertNotIn(forbidden, body)


class Runtime(AccountFixture):
    def setUp(self):
        super().setUp()
        self.config_entry = self.engine.parent / 'homegate-configuration-read.sh'
        self.config_adapter = self.engine.parent / 'homegate-configuration.lua'
        body = self.config_entry.read_text().replace('configuration_validation_enabled=false', 'configuration_validation_enabled=true')
        body = body.replace('/var/run/homegate', str(self.native.lockdir)).replace('/etc/homegate/transactions', str(self.store))
        self.config_entry.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'PATH=' + str(self.bin))))
        body = self.config_adapter.read_text().replace("dir..'/../../../VERSION'", json.dumps(str(ROOT / 'VERSION')))
        body = body.replace("dir..'/../../../RELEASE'", json.dumps(str(ROOT / 'RELEASE')))
        self.config_adapter.write_text(body.replace('/etc/config/homegate', str(self.source)))

    def validate(self, expected=0, args=(), env=None):
        result = subprocess.run([self.busybox, 'ash', str(self.config_entry), *args], env=env or self.env,
                                capture_output=True, timeout=15)
        self.assertEqual((result.returncode, result.stderr), (expected, b''), result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['ok'], expected == 0)
        self.assertEqual(report['effect'], 'none')
        self.assertFalse(report['write_ready'])
        for marker in [b'SECRET_SENTINEL', b'OLD_ID', b'example.test', os.fsencode(self.store)]:
            self.assertNotIn(marker, result.stdout)
        self.assertEqual(self.calls, [])
        return report

    def direct(self, raw, expected=0, supplied=None):
        lua, codec, model, ip = models()
        self.source.write_text(raw)
        try:
            result = subprocess.run([str(self.bin / 'lua'), str(self.config_adapter), 'validate', '1'],
                                    input=frame(codec, raw) if supplied is None else supplied,
                                    env=self.env, capture_output=True, timeout=8)
            self.assertEqual((result.returncode, result.stderr), (expected, b''), result.stdout)
            for marker in [b'127.0.0.1', b'example.test', b'SECRET_SENTINEL']:
                self.assertNotIn(marker, result.stdout)
            return json.loads(result.stdout) if result.stdout else None
        finally:
            self.source.write_bytes(self.source_before)

    def test_ordinary_source_all_sections_validate_without_provider_calls_or_writes(self):
        report = self.validate()
        self.assertEqual(report['version'], identity()['normalized'])
        self.assertEqual(report['configuration_revision'], self.revision)
        self.assertEqual(report['sections'], dict.fromkeys(['homegate', 'dns_account', 'ddns_rule', 'certificate', 'web_rule', 'wol_host'], 1))
        self.assertFalse(report['health_checked'])
        self.unchanged_status()

    def test_extra_arguments_and_environment_cannot_open_closed_gate(self):
        self.validate(expected=2, args=('SECRET_SENTINEL',))
        self.config_entry.write_text(self.config_entry.read_text().replace('configuration_validation_enabled=true', 'configuration_validation_enabled=false'))
        self.validate(expected=2, env={**self.env, 'configuration_validation_enabled': 'true', 'HOMEGATE_CONFIG_PROTO_STORE': str(self.store)})
        self.unchanged_status()

    def test_common_locks_and_replaced_inode_refuse_before_source_read(self):
        import fcntl
        for lock in [self.native.lock, self.store / '.supervisor.lock']:
            with lock.open('rb') as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.validate(expected=4)
        self.config_entry.write_text(self.config_entry.read_text().replace('locks_match || fail 4',
            'rm -f "$run/frontend.lock"; : > "$run/frontend.lock"\nlocks_match || fail 4', 1))
        self.validate(expected=4)
        self.unchanged_status()

    def test_changed_source_and_missing_ordinary_marker_are_not_valid_configuration(self):
        self.source.write_bytes(self.source_before + b'\n')
        self.validate(expected=7)
        self.source.write_bytes(self.source_before)
        marker = self.store / f'gen-{self.revision}/source.conf'
        saved = self.base / 'r125-preserved-source'
        marker.rename(saved)
        try:
            self.validate(expected=7)
        finally:
            saved.rename(marker)
        self.unchanged_status()

    def test_source_change_between_passes_publishes_no_success(self):
        self.config_adapter.write_text(self.config_adapter.read_text().replace("io.write(model.report", 
            "local f=assert(io.open(" + json.dumps(str(self.source)) + ",'ab'));f:write('\\n');f:close()\nio.write(model.report"))
        self.validate(expected=7)
        self.source.write_bytes(self.source_before)
        self.unchanged_status()

    def test_real_lua_adapter_preserves_active_web_errors_and_disabled_target_semantics(self):
        self.assertTrue(self.direct(RAW)['ok'])
        missing = RAW.replace(" option target 'https://127.0.0.1:8443/a?q=1'\n", '')
        report = self.direct(missing, expected=1)
        self.assertEqual(report['error_kind'], 'invalid_web_target')
        self.assertFalse(report['health_checked'])
        self.assertTrue(self.direct(missing.replace("config web_rule 'web_a'\n option enabled '1'", "config web_rule 'web_a'\n option enabled '0'"))['ok'])
        self.unchanged_status()

    def test_corrupt_pipe_and_slot_mismatch_never_publish_success_or_private_data(self):
        for supplied in [b'', b'HGPRIVATE1\nSECRET_SENTINEL', b'X' * 1114113]:
            self.assertIsNone(self.direct(RAW, expected=7, supplied=supplied))
        lua, codec, model, ip = models()
        report = self.direct(RAW.replace('8443', '9443'), expected=1, supplied=frame(codec, RAW))
        self.assertEqual(report['error_kind'], 'source_mismatch')
        self.unchanged_status()


def suite(runtime):
    cls = Runtime if runtime else Static
    return unittest.TestSuite(cls(n) for n, v in cls.__dict__.items() if n.startswith('test_') and callable(v))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(suite(args.runtime))
    raise SystemExit(not result.wasSuccessful())
