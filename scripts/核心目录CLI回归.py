#!/usr/bin/env python3
"""Read-only catalog CLI compatibility with an audited, pinned Go reference."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from project import ROOT, identity

PROTO = ROOT / 'project/core/prototype'
GOLDEN = ROOT / 'scripts/fixtures/core-cli/catalogs.json'
MODEL = 'project/luci/lua/luasrc/model/homegate/backup.lua'
COMMANDS = ('dns-provider-catalog', 'acme-ca-catalog')


class Static(unittest.TestCase):
    def test_reference_snapshot_is_bound_to_current_go_sources(self):
        reference = json.loads(GOLDEN.read_text())
        for name, expected in reference['reference_source_sha256'].items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected,
                             'Review catalog fixture against changed Go reference: ' + name)
        contract = json.loads((ROOT / 'docs/核心CLI合同.json').read_text())
        self.assertTrue(set(COMMANDS) <= set(contract['cli_commands']))

    def test_catalog_grammar_and_no_business_execution(self):
        from lupa.lua51 import LuaRuntime
        body = (PROTO / 'homegate-cli-catalog.lua').read_bytes()
        self.assertNotIn(b'\r', body)
        LuaRuntime().compile(body)
        for forbidden in (b'io.popen', b'os.execute', b'os.getenv', b'credentials-read',
                          b'/etc/', b'/var/', b'homegate-ddns-', b'"wb"', b"'wb'"):
            self.assertNotIn(forbidden, body)
        cli = (PROTO / 'homegate-cli.sh').read_text()
        self.assertEqual(cli.count('native_cli_enabled=false'), 1)
        self.assertLess(cli.index('exec 3>&-'), cli.index('catalog=$(lua'))
        self.assertLess(cli.index('[ "$(id -u)" = 0 ]'), cli.index('catalog=$(lua'))
        self.assertNotIn('prototype/', (ROOT / 'project/core/Makefile').read_text())

    def test_existing_ci_entry_includes_both_catalog_partitions(self):
        body = (ROOT / 'scripts/DDNS生命周期CLI回归.py').read_text()
        self.assertIn('from 核心目录CLI回归 import Static as CatalogStatic, Runtime as CatalogRuntime', body)
        self.assertIn('[Static,CatalogStatic]', body)
        self.assertIn('Cold,CatalogRuntime]', body)


class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.busybox = shutil.which('busybox')
        cls.lua = shutil.which('lua5.1')
        if os.name != 'posix' or not cls.busybox or not cls.lua:
            raise RuntimeError('Real Linux BusyBox and Lua 5.1 are required')
        if os.getuid() == 0:
            raise RuntimeError('Catalog runtime tests must use the existing unprivileged fixture user')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='homegate-cli-catalog-')
        self.base = Path(self.temp.name)
        self.copy = self.base / 'source'
        for name in ('VERSION', 'RELEASE', MODEL,
                     'project/core/prototype/homegate-cli.sh',
                     'project/core/prototype/homegate-cli-catalog.lua'):
            dest = self.copy / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes((ROOT / name).read_bytes())
        self.cli = self.copy / 'project/core/prototype/homegate-cli.sh'
        self.helper = self.cli.with_name('homegate-cli-catalog.lua')
        self.bin = self.base / 'trusted-bin'
        self.bin.mkdir()
        for name in ('id', 'dirname'):
            (self.bin / name).symlink_to(self.busybox)
        (self.bin / 'lua').symlink_to(self.lua)
        self.trace = self.base / 'unexpected-business-call'
        for name in ('uci', 'curl', 'ubus', 'ip', 'flock', 'stat', 'ash', 'mkdir', 'rm'):
            tool = self.bin / name
            tool.write_text('#!/bin/sh\nprintf invoked >> ' + str(self.trace) + '\nexit 99\n')
            tool.chmod(0o700)
        # Only copied fixture paths/UID are adapted; source root/gates remain intact.
        self.cli.write_text(self.cli.read_text().replace(
            '[ "$(id -u)" = 0 ]', '[ "$(id -u)" = ' + str(os.getuid()) + ' ]').replace(
            'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'PATH=' + str(self.bin)))
        self.env = dict(os.environ, PATH='/nonexistent', HOMEGATE_CONFIG_PROTO_STORE='SECRET_SENTINEL',
                        LUA_INIT='error("SECRET_SENTINEL")', LUA_PATH='SECRET_SENTINEL',
                        LUA_CPATH='SECRET_SENTINEL', native_cli_enabled='true')

    def tearDown(self):
        self.temp.cleanup()

    def call(self, *args, expected=0, command=None, env=None):
        result = subprocess.run(command or [self.busybox, 'ash', str(self.cli), *args],
                                env=env or self.env, input=b'SECRET_SENTINEL',
                                capture_output=True, timeout=8)
        self.assertEqual((result.returncode, result.stderr), (expected, b''), result.stdout)
        self.assertLessEqual(len(result.stdout), 8192)
        self.assertNotIn(b'SECRET_SENTINEL', result.stdout)
        self.assertFalse(self.trace.exists(), 'Catalog command invoked a business/configuration tool')
        report = json.loads(result.stdout)
        self.assertEqual(report['ok'], expected == 0)
        self.assertTrue(report['prototype'])
        self.assertFalse(report['write_ready'])
        self.assertEqual(report['effect'], 'none')
        return report

    def compare_catalog(self, command):
        expected = json.loads(GOLDEN.read_text())['catalogs'][command]
        report = self.call(command)
        common = {'api_version': 1, 'ok': True, 'version': identity()['normalized'],
                  'prototype': True, 'write_ready': False, 'effect': 'none'}
        self.assertEqual(report, {**common, **expected})
        return report

    def test_dns_catalog_matches_reference_with_gate_closed_and_no_configuration(self):
        report = self.compare_catalog('dns-provider-catalog')
        self.assertEqual([p['name'] for p in report['providers']],
                         ['aliyun', 'cloudflare', 'dnspod', 'huaweicloud'])
        for provider in report['providers']:
            for field in provider['credentials']:
                self.assertNotIn('value', field)

    def test_ca_catalog_keeps_production_and_staging_distinct_without_http(self):
        report = self.compare_catalog('acme-ca-catalog')
        urls = report['cas'][0]['directories']
        self.assertNotEqual(urls['production'], urls['staging'])
        self.assertEqual(set(urls), {'production', 'staging'})

    def test_extra_arguments_and_unknown_commands_fail_before_helper(self):
        self.helper.unlink()
        for command in COMMANDS:
            for extra in ('', '--confirm', '../secret', 'SECRET_SENTINEL', '$(id)'):
                self.call(command, extra, expected=2)
        self.call(expected=2)
        self.call('unknown', expected=2)

    def test_invalid_source_identity_refuses_without_partial_catalog(self):
        for name, invalid in [('VERSION', [b'1.3.0\r\n', b'1.3.0', b'1.3.0\nSECRET_SENTINEL',
                                          b'1.3.0\n\n', b'1.' * 40 + b'0\n']),
                              ('RELEASE', [b'0\n', b'0121\n', b'121\r\n', b'121\nSECRET_SENTINEL'])]:
            file = self.copy / name
            original = file.read_bytes()
            for raw in invalid:
                file.write_bytes(raw)
                for command in COMMANDS:
                    self.assertNotIn('providers', self.call(command, expected=7))
            file.write_bytes(original)

    def test_missing_identity_or_helper_is_a_sanitized_failure(self):
        file = self.copy / 'VERSION'
        file.unlink()
        for command in COMMANDS:
            self.call(command, expected=7)
        file.write_bytes((ROOT / 'VERSION').read_bytes())
        self.helper.unlink()
        self.call('dns-provider-catalog', expected=7)

    def test_original_root_requirement_cannot_be_bypassed_by_metadata(self):
        self.cli.write_text(self.cli.read_text().replace(
            '[ "$(id -u)" = ' + str(os.getuid()) + ' ]', '[ "$(id -u)" = 0 ]'))
        for command in COMMANDS:
            self.call(command, expected=7)

    def test_inherited_descriptor_and_hostile_environment_are_discarded(self):
        self.helper.write_text("for fd=3,9 do local f=io.open('/proc/self/fd/'..fd,'rb'); "
                               "if f then f:close(); os.exit(91) end end\n" + self.helper.read_text())
        sentinel = self.base / 'private-frame'
        sentinel.write_text('SECRET_SENTINEL')
        script = 'exec 9<"$1"; exec "$2" ash "$3" "$4"'
        self.call(command=[self.busybox, 'ash', '-c', script, 'fixture', str(sentinel),
                           self.busybox, str(self.cli), 'dns-provider-catalog'])
        hostile = self.base / 'hostile-bin'
        hostile.mkdir()
        for name in ('lua', 'id'):
            file = hostile / name
            file.write_text('#!/bin/sh\nprintf SECRET_SENTINEL\nexit 90\n')
            file.chmod(0o700)
        self.call('acme-ca-catalog', env={**self.env, 'PATH': str(hostile)})

    def test_catalog_support_does_not_enable_existing_business_commands(self):
        for args in [('ddns-sync',), ('ddns-sync', 'ddns_a'), ('schedule-run', '--confirm'),
                     ('lifecycle-prepare',), ('daemon',)]:
            self.call(*args, expected=2)

    def test_direct_helper_rejects_other_modes_and_arguments_without_output(self):
        for args in [(), ('unknown',), ('dns-provider-catalog', 'SECRET_SENTINEL')]:
            result = subprocess.run([self.lua, str(self.helper), *args], env={'PATH': '/nonexistent'},
                                    capture_output=True, timeout=8)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b''))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', action='store_true')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if args.runtime else Static)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
