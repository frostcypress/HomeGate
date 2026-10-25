#!/usr/bin/env python3
"""Real isolated HTTP -> uhttpd -> rpcd authorization, with the candidate gate closed."""
import argparse
from contextlib import contextmanager
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from project import ROOT


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


rpc = module('rpcd_ddns_http_base', 'rpcd-ddns-regressions.py')
runtime = module('prepare_http', 'prepare-uhttpd.py')
HTTP = ROOT / 'build/uhttpd'
ZERO = '0' * 32
ERRORS = {-32700: 'Parse error', -32601: 'Method not found', -32602: 'Invalid parameters',
          -32000: 'Object not found', -32002: 'Access denied'}


class HostHTTP(rpc.HostRpcd):
    # Inherit the eight real RPC checks to keep the reused namespace launcher covered.
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                cls.port = listener.getsockname()[1]
            cls.http_command = [str(HTTP / 'prefix/bin/uhttpd'), '-f',
                                '-p', '127.0.0.1:' + str(cls.port), '-h', '/teststate/www',
                                '-c', '/etc/httpd.fixture.conf', '-u', '/ubus',
                                '-U', rpc.SOCKET, '-t', '3', '-T', '3']
            log = (rpc.STATE / 'uhttpd.log').open('wb')
            cls.logs.append(log)
            cls.processes.append(subprocess.Popen(cls.http_command, stdout=log, stderr=subprocess.STDOUT))
            cls.wait_for(cls.listening)
        except BaseException:
            cls.tearDownClass()
            # No login has occurred at this point.
            path = rpc.STATE / 'uhttpd.log'
            if path.is_file():
                print('uhttpd startup: ' + path.read_text(errors='replace')[-4000:], file=sys.stderr)
            raise

    @classmethod
    def listening(cls):
        try:
            with socket.create_connection(('127.0.0.1', cls.port), timeout=0.2):
                return True
        except OSError:
            return False

    def exchange(self, payload=None, *, path='/ubus', verb='POST', headers=None, raw=None):
        body = json.dumps(payload).encode() if raw is None else raw
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=getattr(self, 'HTTP_TIMEOUT', 6))
        try:
            connection.request(verb, path, body=body,
                               headers={'Content-Type': 'application/json', **(headers or {})})
            response = connection.getresponse()
            data = response.read(131073)
            self.assertLess(len(data), 131073, 'HTTP fixture response exceeded bound')
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data
        finally:
            connection.close()

    def response(self, payload=None, **kwargs):
        status, headers, body = self.exchange(payload, **kwargs)
        self.assertEqual(status, 200, 'Unexpected HTTP status; body suppressed')
        self.assertTrue(headers.get('content-type', '').startswith('application/json'))
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            raise AssertionError('HTTP fixture returned invalid JSON; body suppressed') from None
        return value

    @staticmethod
    def request(sid, obj, method, args, identity=83):
        return {'jsonrpc': '2.0', 'id': identity, 'method': 'call', 'params': [sid, obj, method, args]}

    def check_reply(self, data, identity=83, error=None, status=0):
        # Never emit login bodies or session ids through assertion diagnostics.
        self.assertTrue(isinstance(data, dict), 'JSON-RPC response must be an object')
        key = 'error' if error is not None else 'result'
        self.assertTrue(set(data) == {'jsonrpc', 'id', key} and data['jsonrpc'] == '2.0'
                        and data['id'] == identity, 'Unexpected JSON-RPC envelope; body suppressed')
        if error is not None:
            self.assertTrue(data['error'] == {'code': error, 'message': ERRORS[error]},
                            'Unexpected JSON-RPC error; body suppressed')
            return None
        result = data['result']
        self.assertTrue(isinstance(result, list) and result and result[0] == status,
                        'Unexpected legacy ubus status; body suppressed')
        if status:
            self.assertTrue(result == [status], 'Rejected call returned extra data; body suppressed')
            return None
        self.assertTrue(len(result) in (1, 2), 'Unexpected legacy result length; body suppressed')
        return result[1] if len(result) == 2 else None

    def http_call(self, sid, method, args=None, *, obj='homegate_ddns', error=None, status=0, headers=None):
        data = self.response(self.request(sid, obj, method, args or {}), headers=headers)
        return self.check_reply(data, error=error, status=status)

    def http_login(self, role):
        result = self.http_call(ZERO, 'login', {'username': 'fixture_' + role,
                               'password': rpc.FIXTURE_PASSWORD, 'timeout': 60}, obj='session')
        self.assertTrue(isinstance(result, dict), 'Login response missing; body suppressed')
        sid = result.get('ubus_rpc_session')
        self.assertTrue(isinstance(sid, str) and len(sid) == 32 and all(c in '0123456789abcdef' for c in sid),
                        'Login did not return a fixture session id')
        return sid

    @contextmanager
    def session(self, role):
        sid = self.http_login(role)
        try:
            yield sid
        finally:
            self.http_call(sid, 'destroy', obj='session')

    @staticmethod
    def denial(method):
        return {'api_version': 1, 'prototype': True, 'ok': False, 'phase': 'ddns-ui',
                'effect': 'unknown' if method == 'submit' else 'none', 'write_ready': False,
                'error': 'DDNS UI request refused'}

    def assert_gate(self, method, result):
        self.assertTrue(result == self.denial(method), 'Candidate denial changed; body suppressed')

    def test_http_01_loopback_listener_authentication_and_cors_defaults(self):
        self.assertNotIn('-a', self.http_command)
        self.assertNotIn('-X', self.http_command)
        status, _, body = self.exchange(path='/index.html', verb='GET', raw=b'')
        self.assertEqual((status, body), (200, b'HomeGate isolated HTTP fixture\n'))
        status, headers, _ = self.exchange(verb='OPTIONS', raw=b'',
                                          headers={'Origin': 'https://untrusted.invalid'})
        self.assertEqual(status, 200)
        self.assertFalse(any(k.startswith('access-control-') for k in headers))

    def test_http_02_anonymous_and_invalid_sessions_denied_all_methods(self):
        for sid in (ZERO, 'f' * 32, ''):
            for method in rpc.SIGNATURES:
                with self.subTest(session_kind='anonymous-or-invalid', method=method):
                    self.http_call(sid, method, error=-32002)

    def test_http_03_reader_all_methods(self):
        with self.session('reader') as sid:
            for method in rpc.SIGNATURES:
                if method in ('status', 'jobs'):
                    self.assert_gate(method, self.http_call(sid, method))
                else:
                    self.http_call(sid, method, error=-32002)

    def test_http_04_writer_all_methods(self):
        values = {'selection': 'ddns_fixture', 'confirmation': 'b' * 32,
                  'consent': '1', 'job': 'a' * 32, 'rule': 'ddns_fixture'}
        with self.session('writer') as sid:
            for method, fields in rpc.SIGNATURES.items():
                self.assert_gate(method, self.http_call(sid, method, {k: values[k] for k in fields}))

    def test_http_05_wrong_credentials_and_revocation(self):
        for username, password in (('fixture_reader', 'wrong-fixture'), ('absent_fixture', rpc.FIXTURE_PASSWORD)):
            self.http_call(ZERO, 'login', {'username': username, 'password': password}, obj='session', status=6)
        sid = self.http_login('reader')
        self.assert_gate('status', self.http_call(sid, 'status'))
        self.http_call(sid, 'destroy', obj='session')
        for method in rpc.SIGNATURES:
            self.http_call(sid, method, error=-32002)

    def test_http_06_rpcd_arguments_and_protocol_errors(self):
        with self.session('writer') as sid:
            for method, fields in rpc.SIGNATURES.items():
                self.http_call(sid, method, {'unregistered_field': 'PRIVATE_SENTINEL'}, status=2)
                for field in fields:
                    for bad in (False, 1, [], {}, None):
                        self.http_call(sid, method, {field: bad}, status=2)
            self.http_call(sid, 'unregistered_method', error=-32002)
            self.http_call(sid, 'status', obj='absent_fixture_object', error=-32000)
        data = self.response({'jsonrpc': '2.0', 'id': 83, 'method': 'unregistered_rpc'})
        self.check_reply(data, error=-32601)
        data = self.response({'jsonrpc': '2.0', 'id': 83, 'method': 'call', 'params': [ZERO, 'homegate_ddns']})
        self.check_reply(data, error=-32700)
        data = self.response(raw=b'{invalid-json')
        self.check_reply(data, identity=None, error=-32700)

    def test_http_07_session_argument_and_header_cannot_escalate_legacy_call(self):
        with self.session('writer') as writer, self.session('reader') as reader:
            self.http_call(reader, 'commit', {'ubus_rpc_session': writer}, error=-32002)
            self.http_call(ZERO, 'commit', {'ubus_rpc_session': writer}, error=-32002)
            self.http_call(writer, 'status', {'ubus_rpc_session': reader}, error=-32602)
            self.http_call(reader, 'commit', headers={'Authorization': 'Bearer ' + writer}, error=-32002)

    def test_http_08_batch_authorizes_each_element(self):
        with self.session('reader') as sid:
            requests = [self.request(sid, 'homegate_ddns', 'status', {}, 1),
                        self.request(sid, 'homegate_ddns', 'commit', {}, 2),
                        self.request('f' * 32, 'homegate_ddns', 'status', {}, 3),
                        self.request(sid, 'homegate_ddns', 'jobs', {'unregistered': 'PRIVATE_SENTINEL'}, 4)]
            results = self.response(requests)
            self.assertTrue(isinstance(results, list) and len(results) == 4, 'Batch response shape invalid')
            self.assert_gate('status', self.check_reply(results[0], identity=1))
            self.check_reply(results[1], identity=2, error=-32002)
            self.check_reply(results[2], identity=3, error=-32002)
            self.check_reply(results[3], identity=4, status=2)

    def test_http_09_modern_bearer_endpoint_also_enforces_acl(self):
        with self.session('reader') as reader, self.session('writer') as writer:
            for sid, method, error in ((reader, 'status', None), (reader, 'commit', -32002),
                                       (writer, 'commit', None), ('f' * 32, 'status', -32002),
                                       (None, 'status', -32002)):
                data = self.response({'jsonrpc': '2.0', 'id': 83, 'method': method, 'params': {}},
                                     path='/ubus/call/homegate_ddns',
                                     headers={'Authorization': 'Bearer ' + sid} if sid is not None else {})
                if error:
                    self.check_reply(data, error=error)
                else:
                    self.assertTrue(set(data) == {'jsonrpc', 'id', 'result'} and data['id'] == 83
                                    and data['jsonrpc'] == '2.0', 'Unexpected modern response envelope')
                    self.assert_gate(method, data['result'])
            data = self.response({'jsonrpc': '2.0', 'id': 83, 'method': 'status',
                                  'params': {'ubus_rpc_session': reader}}, path='/ubus/call/homegate_ddns',
                                 headers={'Authorization': 'Bearer ' + writer})
            self.check_reply(data, error=-32602)

    def test_http_10_http_methods_and_foreign_origin_do_not_grant_access(self):
        for verb, status in (('GET', 404), ('PUT', 400), ('DELETE', 400)):
            actual, _, _ = self.exchange(verb=verb, raw=b'')
            self.assertEqual(actual, status)
        with self.session('reader') as sid:
            status, headers, body = self.exchange(self.request(sid, 'homegate_ddns', 'commit', {}),
                                                 headers={'Origin': 'https://untrusted.invalid'})
            self.assertEqual(status, 200)
            self.assertFalse(any(k.startswith('access-control-') for k in headers))
            self.check_reply(json.loads(body), error=-32002)


def setup_state(state):
    # Only fixture plumbing ACLs are added; the candidate ACL file remains byte-for-byte original.
    (state / 'acl/http-fixture.json').write_text(json.dumps({
        'unauthenticated': {'read': {'ubus': {'session': ['login']}}},
        'homegate-http-fixture': {'read': {'ubus': {'session': ['destroy']}}},
    }))
    config = state / 'etc/config/rpcd'
    original = config.read_text()
    marker = " list read 'luci-app-homegate-ddns'\n"
    if original.count(marker) != 2:
        raise ValueError('Unexpected RPC login fixture')
    config.write_text(original.replace(marker, marker + " list read 'homegate-http-fixture'\n"))
    (state / 'etc/httpd.fixture.conf').write_text('')
    (state / 'www').mkdir()
    (state / 'www/index.html').write_bytes(b'HomeGate isolated HTTP fixture\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'build/rpcd')
    parser.add_argument('--http-runtime-dir', type=Path, default=HTTP)
    parser.add_argument('--inside-net', help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid', help=argparse.SUPPRESS)
    args = parser.parse_args()
    rpc.WORK, HTTP = args.runtime_dir.resolve(), args.http_runtime_dir.resolve()
    try:
        if args.inside_net:
            rpc.OUTER_NET, rpc.OUTER_UID = args.inside_net, args.inside_uid
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(HostHTTP)
            sys.exit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
        runtime.validate_runtime(HTTP, rpc.WORK)
        result = rpc.isolated(rpc.WORK, guest_script=Path(__file__).resolve(), extra_ro=(HTTP,),
                              state_setup=setup_state, guest_args=('--http-runtime-dir', str(HTTP)))
        runtime.validate_runtime(HTTP, rpc.WORK)
        sys.exit(result)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
