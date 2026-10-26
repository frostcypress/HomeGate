#!/usr/bin/env python3
"""Account-status CLI over real projected sources, original signatures and TLS."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import unittest
from project import ROOT, identity
from DDNS计划回归 import fixture_uid
from 生命周期业务集成回归 import Runtime as CFBase
from Aliyun只读回归 import Runtime as AliBase
from DNSPod只读回归 import Runtime as DNPBase
from 华为云只读回归 import Runtime as HWBase

PROTO = ROOT / 'project/core/prototype'
CAPABILITIES = ['credentials_validation', 'ddns', 'dns01', 'zone_discovery']


class Static(unittest.TestCase):
    def test_fixed_read_only_gates_and_changed_grammar(self):
        import tree_sitter, tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh', 'homegate-dns-status.sh', 'homegate-cloudflare-read.sh']:
            body = (PROTO / name).read_bytes()
            self.assertNotIn(b'\r', body)
            self.assertFalse(parser.parse(body).root_node.has_error, name)
        LuaRuntime().compile((PROTO / 'homegate-dns-status.lua').read_bytes())
        self.assertEqual((PROTO / 'homegate-dns-status.sh').read_text().count('dns_status_cli_enabled=false'), 1)
        self.assertEqual((PROTO / 'homegate-cloudflare-read.sh').read_text().count('dns_status_read_enabled=false'), 1)
        self.assertNotIn('prototype/', (PROTO.parent / 'Makefile').read_text())

    def test_original_transport_crypto_and_supervision_are_reused(self):
        body = (PROTO / 'homegate-dns-status.sh').read_text()
        self.assertIn('--runtime-check-internal "$provider" "$account"', body)
        self.assertIn('runtime-ddns-snapshot-read', body)
        self.assertLess(body.index('flock -n 6'), body.index('provider=$(select_provider)'))
        self.assertLess(body.index('exec 3>&-'), body.index('flock -n 6'))
        for word in ['curl ', 'openssl ', 'kill ', 'eval ', '--records', '--confirm', 'mktemp']:
            self.assertNotIn(word, body)
        self.assertIn('[ "$(select_provider)" = "$provider" ] || fail', body)

    def test_public_result_contract_still_has_original_required_fields(self):
        source = (ROOT / 'project/core/src/internal/app/app.go').read_text()
        fields = source.split('type DNSProviderReport struct {', 1)[1].split('\n}', 1)[0]
        expected = {'api_version', 'ok', 'version', 'phase', 'account', 'provider', 'capabilities',
                    'credentials_valid', 'error', 'error_kind', 'retryable', 'provider_code'}
        self.assertEqual(set(re.findall(r'json:"([^",]+)', fields)), expected)
        cli = (ROOT / 'scripts/DDNS生命周期CLI回归.py').read_text()
        from DDNS生命周期CLI回归 import build_suite
        self.assertEqual([test.id() for test in build_suite(False) if isinstance(test, Static)],
                         [test.id() for test in suite(False)])


class Cases:
    def setUp(self):
        super().setUp()
        self.migrated()
        # Real ordinary publication. This is the same disabled-service observer
        # contract used by the existing ordinary-DDNS fixture, with no service action.
        init = self.base / 'status-init'
        common = self.base / 'status-common'
        ubus = self.base / 'status-ubus'
        init.write_text('#!/bin/sh\n[ "$#" -eq 1 ] && [ "$1" = enabled ] || exit 99\nexit 1\n')
        common.write_text('#!/bin/sh\nexit 0\n')
        ubus.write_text('#!/bin/sh\nprintf "{}"\n')
        for file in (init, common, ubus):
            file.chmod(0o700)
        mapping = {'/etc/init.d/homegate': str(init), '/etc/rc.common': str(common), '/sbin/ubus': str(ubus)}
        for name in ['homegate-service-observer.lua', 'homegate-service-observer-watchdog.sh']:
            file = self.engine.parent / name
            body = file.read_text()
            body = re.sub('|'.join(re.escape(k) for k in mapping), lambda m: mapping[m[0]], body)
            body = body.replace('service_observer_enabled=false', 'service_observer_enabled=true')
            if name.endswith('.lua'):
                body = body.replace("local json= require('luci.jsonc')", 'package.cpath=' +
                                    json.dumps(str(ROOT / 'build/service-observer/?.so') + ';;') +
                                    "\nlocal json= require('luci.jsonc')")
            file.write_text(body)
        self.engine.write_text(self.engine.read_text().replace('production_writes_enabled=false',
                             'production_writes_enabled=true').replace('service_observer_enabled=false',
                             'service_observer_enabled=true').replace('ddns_authority_enabled=false',
                             'ddns_authority_enabled=true'))
        revision = self.cli('status')['revision']
        body = (self.store / f'gen-{revision}/public.conf').read_bytes()
        preview = self.cli('preview', payload=body)
        transaction = self.cli('commit-apply-projection', preview['confirmation'])
        self.cli('projection-publish', transaction['apply_handle'], 'apply')
        self.cli('apply-finish-projection', transaction['apply_handle'])
        self.revision = self.cli('status')['revision']
        self.candidate = self.engine.parent / 'homegate-cli.sh'
        self.status_entry = self.engine.parent / 'homegate-dns-status.sh'
        self.status_adapter = self.engine.parent / 'homegate-dns-status.lua'
        paths = {'/var/run/homegate': str(self.native.lockdir), '/etc/homegate/transactions': str(self.store)}
        for file in (self.candidate, self.status_entry):
            body = file.read_text().replace('native_cli_enabled=false', 'native_cli_enabled=true')
            body = body.replace('dns_status_cli_enabled=false', 'dns_status_cli_enabled=true')
            body = re.sub('|'.join(re.escape(k) for k in paths), lambda m: paths[m[0]], body)
            file.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'PATH=' + str(self.bin))))
        self.status_adapter.write_text(self.status_adapter.read_text().replace(
            "dir..'/../../../'..name", json.dumps(str(ROOT)) + "..'/'..name"))
        self.reader.write_text(self.reader.read_text().replace('dns_status_read_enabled=false',
                               'dns_status_read_enabled=true'))
        self.before = self.contents()
        self.source_before = self.source.read_bytes()

    def status(self, account='dns_a', expected=0, args=None, env=None):
        command = ['dns-provider-status', account] if args is None else args
        process = subprocess.run([self.busybox, 'ash', str(self.candidate), *command],
                                 env=env or self.env, capture_output=True, timeout=45)
        self.assertEqual((process.returncode, process.stderr), (expected, b''), process.stdout)
        self.assertLess(len(process.stdout), 8192)
        for marker in [b'SECRET_SENTINEL', b'PRIVATE_SENTINEL', b'OLD_ID', b'PRIVATE_ACCOUNT',
                       b'example.test', b'2001:db8', b'myhuaweicloud.com', os.fsencode(self.store)]:
            self.assertNotIn(marker, process.stdout)
        report = json.loads(process.stdout)
        self.assertEqual(report['ok'], expected == 0)
        self.assertFalse(report['write_ready'])
        self.assertEqual(report['effect'], 'none')
        return report

    def unchanged_status(self):
        self.assertEqual(self.contents(), self.before)
        self.assertEqual(self.source.read_bytes(), self.source_before)
        self.assertFalse(list(self.native.lockdir.glob('.dns-check-*')))
        self.assertFalse((self.store / 'dns-operation').exists())

    def test_actual_account_validation_uses_original_signature_and_ordinary_source(self):
        # The new route must not accidentally require the migration-only gate.
        self.reader.write_text(self.reader.read_text().replace('dns_migrated_read_enabled=true',
                               'dns_migrated_read_enabled=false'))
        report = self.status()
        self.assertEqual(report, {'api_version': 1, 'ok': True, 'version': identity()['normalized'],
                                 'phase': 'dns-provider', 'account': 'dns_a', 'provider': self.provider,
                                 'capabilities': CAPABILITIES, 'credentials_valid': True,
                                 'configuration_revision': self.revision, 'prototype': True,
                                 'effect': 'none', 'write_ready': False})
        self.assertEqual(len(self.calls), 1)
        if hasattr(self, 'signature_errors'):
            self.assertEqual(self.signature_errors, [])
        self.unchanged_status()

    def test_rate_limit_is_sanitized_and_never_retried(self):
        self.http_status = 429
        self.response = {'success': False, 'errors': [{'code': 1015, 'message': 'SECRET_SENTINEL'}],
                         'Code': 'Throttling', 'error_code': 'APIGW.0308', 'error_msg': 'SECRET_SENTINEL',
                         'Response': {'Error': {'Code': 'RequestLimitExceeded', 'Message': 'SECRET_SENTINEL'}}}
        report = self.status(expected=1)
        self.assertEqual((report['error_kind'], report['retryable'], report['credentials_valid']),
                         ('rate_limit', True, False))
        self.assertEqual(report['capabilities'], CAPABILITIES)
        self.assertEqual(len(self.calls), 1)
        self.unchanged_status()


class CF(Cases, CFBase): provider = 'cloudflare'
class Ali(Cases, AliBase): provider = 'aliyun'
class DNP(Cases, DNPBase): provider = 'dnspod'
class HW(Cases, HWBase): provider = 'huaweicloud'


class Boundaries(CF):
    def test_invalid_arguments_and_closed_gates_never_dispatch(self):
        for args in [['dns-provider-status'], ['dns-provider-status', ''], ['dns-provider-status', '../x'],
                     ['dns-provider-status', 'x' * 65], ['dns-provider-status', 'dns_a', '--zones'],
                     ['dns-provider-status', '$(id)']]:
            self.status(expected=2, args=args)
        self.candidate.write_text(self.candidate.read_text().replace('native_cli_enabled=true', 'native_cli_enabled=false'))
        self.status(expected=2, env={**self.env, 'native_cli_enabled': 'true'})
        self.candidate.write_text(self.candidate.read_text().replace('native_cli_enabled=false', 'native_cli_enabled=true'))
        self.reader.write_text(self.reader.read_text().replace('dns_status_read_enabled=true', 'dns_status_read_enabled=false'))
        self.status(expected=7, env={**self.env, 'dns_status_read_enabled': 'true'})
        self.assertEqual(self.calls, [])
        self.unchanged_status()

    def test_missing_account_returns_empty_capabilities_without_http(self):
        report = self.status(account='missing', expected=1)
        self.assertEqual((report['account'], report['capabilities'], report['credentials_valid'], report['error_kind']),
                         ('missing', [], False, 'not_found'))
        self.assertNotIn('provider', report)
        self.assertEqual(self.calls, [])
        self.unchanged_status()

    def test_both_shared_locks_and_replaced_inode_refuse_before_http(self):
        import fcntl
        for file in (self.native.lock, self.store / '.supervisor.lock'):
            with file.open('rb') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.status(expected=4)
        self.fault('flock', "if sys.argv[1:]==['-n','6']:\n from pathlib import Path\n p=Path(" +
                   repr(str(self.native.lock)) + ");p.unlink();p.touch(mode=0o600)")
        self.status(expected=4)
        self.assertEqual(self.calls, [])

    def test_changed_source_before_or_during_request_cannot_publish_success(self):
        self.source.write_bytes(self.source_before + b'\n')
        self.status(expected=7)
        self.assertEqual(self.calls, [])
        self.source.write_bytes(self.source_before)
        def reply(path):
            self.source.write_bytes(self.source_before + b'\n')
            return 200, {'success': True, 'errors': [], 'result': []}
        self.response = reply
        self.status(expected=7)
        self.assertEqual(len(self.calls), 1)

    def test_source_and_migration_are_not_interchangeable(self):
        published = self.store / f'gen-{self.revision}/source.conf'
        published.rename(published.with_name('extra.conf'))
        self.status(expected=7)
        self.assertEqual(self.calls, [])

    def test_root_requirement_and_inherited_lock_cannot_be_bypassed(self):
        import fcntl
        original = self.status_entry.read_text()
        self.status_entry.write_text(original.replace('[ "$(id -u)" = ' + str(os.getuid()) + ' ]',
                                                     '[ "$(id -u)" = 0 ]'))
        self.status(expected=7)
        self.status_entry.write_text(original)
        with self.native.lock.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            script = 'exec 6<&"$1";exec "$2" ash "$3" dns-provider-status dns_a'
            result = subprocess.run([self.busybox, 'ash', '-c', script, 'fixture', str(held.fileno()),
                                     self.busybox, str(self.candidate)], pass_fds=(held.fileno(),),
                                    env=self.env, capture_output=True, timeout=10)
            self.assertEqual((result.returncode, result.stderr), (4, b''))
        self.assertEqual(self.calls, [])

    def test_unbound_provider_result_and_false_success_are_rejected(self):
        valid = {'api_version': 1, 'prototype': True, 'ok': True, 'phase': 'dns-provider',
                 'provider': 'cloudflare', 'account': 'dns_a', 'configuration_revision': self.revision,
                 'credentials_valid': True, 'check_scope': 'zone-read', 'error_kind': '',
                 'retryable': False, 'provider_code': ''}
        for field, value in [('account', 'other'), ('provider', 'aliyun'), ('configuration_revision', 1),
                             ('check_scope', 'zone-list'), ('extra', 'SECRET_SENTINEL'),
                             ('credentials_valid', False), ('retryable', True)]:
            report = {**valid, field: value}
            result = subprocess.run([self.lua, str(self.status_adapter), 'result', str(self.revision),
                                     'dns_a', 'cloudflare', '0'], env=self.env,
                                    input=json.dumps(report).encode(), capture_output=True, timeout=8)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b''))
        self.assertEqual(self.calls, [])


def suite(runtime):
    result = unittest.TestSuite()
    for cls in ([CF, Ali, DNP, HW, Boundaries] if runtime else [Static]):
        members = Cases.__dict__ if cls in [CF, Ali, DNP, HW] else cls.__dict__
        result.addTests(cls(name) for name, value in members.items() if name.startswith('test_') and callable(value))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(suite(args.runtime))
    raise SystemExit(not result.wasSuccessful())
