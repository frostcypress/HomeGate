#!/usr/bin/env python3
"""Complete ordinary-source zone CLI over retained real TLS/provider fixtures."""
import argparse
import json
import math
import os
import re
import subprocess
import unittest
from urllib.parse import parse_qs, urlsplit
from project import ROOT, identity
from 核心账户CLI回归 import CF as StatusCF, Ali as StatusAli, DNP as StatusDNP, HW as StatusHW, CAPABILITIES

PROTO = ROOT / 'project/core/prototype'


class Static(unittest.TestCase):
    def test_cli_and_internal_modes_are_fixed_read_only(self):
        cli = (PROTO / 'homegate-cli.sh').read_text()
        self.assertIn('dns-provider-status|dns-zones)', cli)
        self.assertIn('dns-zones) exec ash "$dir/homegate-dns-status.sh" "$2" --zones', cli)
        coordinator = (PROTO / 'homegate-cloudflare-read.sh').read_text()
        self.assertIn('[ "$#" -eq 3 ] || fail 2', coordinator)
        self.assertIn('if [ "$1" = --runtime-zones-internal ]; then set -- "$3" --zones;else set -- "$3";fi', coordinator)
        self.assertEqual(coordinator.count('dns_status_read_enabled=false'), 1)

    def test_original_zone_limits_and_canonical_result_binding(self):
        body = (PROTO / 'homegate-dns-status.lua').read_text()
        self.assertIn("provider=='cloudflare' and 14350512 or 65536", body)
        self.assertIn('#d.zones>50000', body)
        self.assertIn("domain(name)~=name", body)
        self.assertIn('if raw~=expected then os.exit(1) end', body)
        self.assertIn('not d.ok and #d.zones~=0', body)
        self.assertNotIn('io.popen', body)

    def test_old_zone_report_fields_and_existing_ci_entry(self):
        text = (ROOT / 'project/core/src/internal/app/app.go').read_text()
        fields = text.split('type DNSZonesReport struct {', 1)[1].split('\n}', 1)[0]
        self.assertEqual(set(re.findall(r'json:"([^",]+)', fields)),
                         {'api_version', 'ok', 'version', 'phase', 'account', 'provider', 'capabilities',
                          'zones', 'error', 'error_kind', 'retryable', 'provider_code'})
        from DDNS生命周期CLI回归 import build_suite
        self.assertEqual([test.id() for test in build_suite(False) if isinstance(test, Static)],
                         [test.id() for test in suite(False)])


class Cases:
    def setUp(self):
        super().setUp()
        # Zones parse directly, before the shared codec installs its fixture
        # module path. Reuse the existing native jsonc in this copied adapter.
        self.status_adapter.write_text('package.cpath=' +
            json.dumps(str(ROOT / 'build/service-observer/?.so') + ';;') + '\n' + self.status_adapter.read_text())
        if self.provider == 'cloudflare':
            prefix = self.endpoint.split('?')[0] + '?'
            worker = self.engine.parent / 'homegate-cloudflare-worker.sh'
            worker.write_text(worker.read_text().replace('https://api.cloudflare.com/client/v4/zones?', prefix))
            adapter = self.engine.parent / 'cloudflare-zones.lua'
            adapter.write_text(adapter.read_text().replace("local json=require('luci.jsonc')",
                'package.cpath=' + json.dumps(str(ROOT / 'build/service-observer/?.so') + ';;') +
                "\nlocal json=require('luci.jsonc')"))
        self.configure()

    def configure(self, total=101, fail_later=False, change_source=False):
        self.total = total
        self.expected_zones = [f'z{i:05d}.example.test' for i in range(max(0, total - 1))]
        if total == 1:
            self.expected_zones = ['z00000.example.test']
        def reply(request):
            if self.provider == 'cloudflare':
                query = parse_qs(urlsplit(request).query)
                page, size = int(query['page'][0]), int(query['per_page'][0])
                self.assertEqual(size, 50)
                offset = (page - 1) * size
            elif self.provider == 'aliyun':
                page, size = int(request['PageNumber'][0]), int(request['PageSize'][0])
                offset = (page - 1) * size
            elif self.provider == 'dnspod':
                offset, size = request['Offset'], request['Limit']
            else:
                offset, size = int(request['offset'][0]), int(request['limit'][0])
            if offset and change_source:
                self.source.write_bytes(self.source_before + b'\n')
            if offset and fail_later:
                return 403, {'success': False, 'errors': [{'code': 9109, 'message': 'PRIVATE_SENTINEL'}],
                             'Code': 'Forbidden', 'error_code': 'APIGW.0301', 'error_msg': 'SECRET_SENTINEL',
                             'Response': {'Error': {'Code': 'AuthFailure.SignatureFailure', 'Message': 'SECRET_SENTINEL'}}}
            indexes = range(offset, min(offset + size, total))
            names = [' Z00000.Example.Test. ' if i == total - 1 else f'z{i:05d}.example.test' for i in indexes]
            if self.provider == 'cloudflare':
                rows = [{'id': format(i + 1, '032x'), 'name': name, 'account': {'name': 'PRIVATE_METADATA'}}
                        for i, name in zip(indexes, names)]
                return 200, {'success': True, 'errors': [], 'result': rows,
                             'result_info': {'page': page, 'per_page': size, 'count': len(rows),
                                             'total_pages': math.ceil(total / size), 'total_count': total}}
            if self.provider == 'aliyun':
                return 200, {'TotalCount': total, 'PageNumber': page, 'PageSize': size, 'RequestId': 'PRIVATE_METADATA',
                             'Domains': {'Domain': [{'DomainName': name} for name in names]}}
            if self.provider == 'dnspod':
                return 200, {'Response': {'DomainCountInfo': {'DomainTotal': total},
                                         'DomainList': [{'Name': name} for name in names], 'RequestId': 'PRIVATE_METADATA'}}
            return 200, {'zones': [{'id': str(i + 1), 'name': name, 'zone_type': 'public'}
                                  for i, name in zip(indexes, names)], 'metadata': {'total_count': total},
                         'links': {'next': 'https://private.invalid/never-follow'}}
        self.response = reply

    def zones(self, account='dns_a', expected=0, args=None, env=None):
        args = ['dns-zones', account] if args is None else args
        result = subprocess.run([self.busybox, 'ash', str(self.candidate), *args], env=env or self.env,
                                capture_output=True, timeout=45)
        self.assertEqual((result.returncode, result.stderr), (expected, b''), result.stdout)
        self.assertLess(len(result.stdout), 14351024)
        for marker in [b'SECRET_SENTINEL', b'PRIVATE_SENTINEL', b'PRIVATE_METADATA', b'OLD_ID',
                       b'PRIVATE_ACCOUNT', b'myhuaweicloud.com', b'private.invalid', os.fsencode(self.store)]:
            self.assertNotIn(marker, result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['ok'], expected == 0)
        self.assertFalse(report['write_ready'])
        self.assertEqual(report['effect'], 'none')
        return report

    def test_complete_pages_normalize_deduplicate_sort_and_keep_original_signatures(self):
        self.reader.write_text(self.reader.read_text().replace('dns_migrated_read_enabled=true',
                               'dns_migrated_read_enabled=false'))
        report = self.zones()
        self.assertEqual(report, {'api_version': 1, 'ok': True, 'version': identity()['normalized'],
                                 'phase': 'dns-provider', 'account': 'dns_a', 'provider': self.provider,
                                 'capabilities': CAPABILITIES, 'zones': self.expected_zones,
                                 'configuration_revision': self.revision, 'prototype': True,
                                 'effect': 'none', 'write_ready': False})
        self.assertEqual(len(self.calls), 3 if self.provider == 'cloudflare' else 2)
        if hasattr(self, 'signature_errors'):
            self.assertEqual(self.signature_errors, [])
        self.unchanged_status()

    def test_second_page_failure_discards_all_names_and_does_not_retry(self):
        self.configure(fail_later=True)
        report = self.zones(expected=1)
        self.assertEqual(report['zones'], [])
        self.assertEqual(report['error_kind'], 'authentication')
        self.assertNotIn('retryable', report)
        self.assertEqual(len(self.calls), 2)
        self.unchanged_status()

    def test_empty_zone_list_is_a_real_complete_result(self):
        self.configure(total=0)
        report = self.zones()
        self.assertEqual(report['zones'], [])
        self.assertNotIn('credentials_valid', report)
        self.assertEqual(len(self.calls), 1)
        self.unchanged_status()


class CF(Cases, StatusCF): pass
class Ali(Cases, StatusAli): pass
class DNP(Cases, StatusDNP): pass
class HW(Cases, StatusHW): pass


class Boundaries(CF):
    def test_invalid_arguments_and_closed_gate_do_not_start_discovery(self):
        for args in [['dns-zones'], ['dns-zones', ''], ['dns-zones', '../x'], ['dns-zones', 'x' * 65],
                     ['dns-zones', 'dns_a', '--records'], ['dns-zones', 'dns_a', 'aliyun']]:
            self.zones(expected=2, args=args)
        self.candidate.write_text(self.candidate.read_text().replace('native_cli_enabled=true', 'native_cli_enabled=false'))
        self.zones(expected=2, env={**self.env, 'native_cli_enabled': 'true'})
        self.assertEqual(self.calls, [])

    def test_missing_account_and_both_shared_locks_refuse_without_http(self):
        import fcntl
        report = self.zones(account='missing', expected=1)
        self.assertEqual((report['zones'], report['error_kind']), ([], 'not_found'))
        self.assertNotIn('capabilities', report)
        for path in [self.native.lock, self.store / '.supervisor.lock']:
            with path.open('rb') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.zones(expected=4)
        self.assertEqual(self.calls, [])
        self.unchanged_status()

    def test_changed_source_before_or_during_pagination_never_publishes_a_list(self):
        self.source.write_bytes(self.source_before + b'\n')
        self.zones(expected=7)
        self.assertEqual(self.calls, [])
        self.source.write_bytes(self.source_before)
        self.configure(change_source=True)
        report = self.zones(expected=7)
        self.assertNotIn('zones', report)
        self.assertGreaterEqual(len(self.calls), 2)

    def envelope(self, **changes):
        report = {'api_version': 1, 'prototype': True, 'ok': True, 'phase': 'dns-provider',
                  'provider': 'cloudflare', 'account': 'dns_a', 'configuration_revision': self.revision,
                  'check_scope': 'zone-list', 'error_kind': '', 'retryable': False, 'provider_code': '',
                  'zones': ['a.test']}
        report.update(changes)
        return json.dumps(report, separators=(',', ':')).encode() + b'\n'

    def adapt(self, raw, expected=1, provider='cloudflare'):
        result = subprocess.run([self.lua, str(self.status_adapter), 'zones-result', str(self.revision),
                                 'dns_a', provider, '0'], env=self.env, input=raw, capture_output=True, timeout=8)
        self.assertEqual((result.returncode, result.stderr), (expected, b''), result.stdout)
        if expected:
            self.assertEqual(result.stdout, b'')
            return None
        return json.loads(result.stdout)

    def test_forged_partial_unbound_duplicate_or_noncanonical_results_are_rejected(self):
        self.assertEqual(self.adapt(self.envelope(), 0)['zones'], ['a.test'])
        for changes in [{'account': 'other'}, {'configuration_revision': 1}, {'check_scope': 'zone-read'},
                        {'extra': 'SECRET_SENTINEL'}, {'zones': ['b.test', 'a.test']},
                        {'zones': ['a.test', 'a.test']}, {'zones': {}}, {'zones': ['bad..test']},
                        {'ok': False, 'error_kind': 'temporary'}, {'retryable': True}]:
            self.adapt(self.envelope(**changes))
        self.adapt(self.envelope().replace(b'"ok":true', b'"ok":false,"ok":true'))
        self.adapt(self.envelope() + b'{}')
        self.assertEqual(self.calls, [])

    def test_cloudflare_large_list_keeps_original_limit_instead_of_status_limit(self):
        names = [f'z{i:04d}.' + 'a' * 60 + '.test' for i in range(1000)]
        raw = self.envelope(zones=names)
        self.assertGreater(len(raw), 65536)
        self.assertEqual(self.adapt(raw, 0)['zones'], names)
        self.adapt(raw.replace(b'"provider":"cloudflare"', b'"provider":"aliyun"'), provider='aliyun')
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
