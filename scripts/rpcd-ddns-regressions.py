#!/usr/bin/env python3
"""Real isolated host rpcd/ubus checks; session ACL answers are not HTTP authorization."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from project import ROOT

spec = importlib.util.spec_from_file_location('prepare_rpcd', ROOT / 'scripts/prepare-rpcd.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
CANDIDATE = ROOT / 'project/luci/prototype/js/homegate-ddns.uc'
ACL = ROOT / 'project/luci/prototype/js/ddns-acl.json'
GATE = b'const native_ddns_rpc_enabled = false;'
SIGNATURES = {
    'status': {}, 'jobs': {}, 'preview': {'selection': 'String'},
    'commit': {'confirmation': 'String', 'consent': 'String'},
    'revoke': {'consent': 'String'},
    'submit': {'job': 'String', 'rule': 'String', 'consent': 'String'},
    'maintain_preview': {'job': 'String'},
    'maintain_commit': {'job': 'String', 'confirmation': 'String', 'consent': 'String'},
}
WORK = ROOT / 'build/rpcd'
FIXTURE_PASSWORD = 'homegate-rpc-fixture-only'
STATE = Path('/teststate')
SOCKET = str(STATE / 'ubus.sock')
OUTER_NET = None
OUTER_UID = None


class HostRpcd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or not OUTER_UID or not (STATE / 'isolation-marker').is_file():
            raise RuntimeError('Require the unprivileged private user namespace launcher')
        cls.processes, cls.logs = [], []
        try:
            for name, command in (
                ('ubusd', [str(WORK / 'prefix/sbin/ubusd'), '-s', SOCKET]),
                ('rpcd', [str(WORK / 'prefix/sbin/rpcd'), '-s', SOCKET, '-t', '3']),
            ):
                if name == 'rpcd':
                    cls.wait_for(lambda: Path(SOCKET).is_socket())
                log = (STATE / (name + '.log')).open('wb')
                cls.logs.append(log)
                cls.processes.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT))
            cls.wait_for(lambda: cls.bus(['list', 'homegate_ddns'], check=False).stdout.strip() == b'homegate_ddns')
        except BaseException:
            cls.tearDownClass()
            # Readiness happens before any login, so these diagnostics cannot contain session ids.
            for name in ('ubusd', 'rpcd'):
                path = STATE / (name + '.log')
                if path.is_file():
                    print(name + ' startup: ' + path.read_text(errors='replace')[-4000:], file=sys.stderr)
            raise

    @classmethod
    def tearDownClass(cls):
        for process in reversed(cls.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in cls.logs:
            log.close()

    @classmethod
    def wait_for(cls, predicate):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in cls.processes):
                raise AssertionError('Isolated RPC process exited before readiness')
            if predicate():
                return
            time.sleep(0.03)
        raise AssertionError('Isolated RPC readiness deadline exceeded')

    @classmethod
    def bus(cls, args, check=True):
        result = subprocess.run([str(WORK / 'prefix/bin/ubus'), '-s', SOCKET, '-t', '3', *args],
                                capture_output=True, timeout=6)
        if check and result.returncode:
            # Never include command arguments or login response/session ids in diagnostics.
            raise AssertionError('ubus call failed with exit status ' + str(result.returncode))
        return result

    def call(self, object_name, method, args, expected=0):
        result = self.bus(['call', object_name, method, json.dumps(args)], check=False)
        # The pinned CLI returns -UBUS_STATUS_*; POSIX exposes its low eight bits.
        self.assertEqual(result.returncode, (-expected) % 256, 'Unexpected ubus status; request/response suppressed')
        if expected:
            self.assertFalse(result.stdout.strip(), 'Failed call unexpectedly returned a JSON body')
            self.assertIn({2: b'Invalid argument', 3: b'Method not found', 4: b'Not found',
                           6: b'Permission denied'}[expected], result.stderr)
            return None
        self.assertFalse(result.stderr, 'Successful ubus call reported an error')
        return json.loads(result.stdout) if result.stdout.strip() else None

    def login(self, user):
        data = self.call('session', 'login', {'username': user, 'password': FIXTURE_PASSWORD, 'timeout': 60})
        sid = data.get('ubus_rpc_session', '')
        self.assertTrue(isinstance(sid, str) and re.fullmatch(r'[0-9a-f]{32}', sid) is not None,
                        'Login did not return a valid fixture session id')
        return sid

    def access(self, sid, method, expected=None):
        return self.call('session', 'access', {'ubus_rpc_session': sid, 'scope': 'ubus',
                         'object': 'homegate_ddns', 'function': method}, expected=expected or 0)

    def denied(self, method, args):
        self.assertEqual(self.call('homegate_ddns', method, args), {
            'api_version': 1, 'prototype': True, 'ok': False, 'phase': 'ddns-ui',
            'effect': 'unknown' if method == 'submit' else 'none', 'write_ready': False,
            'error': 'DDNS UI request refused',
        })

    def test_01_private_namespace_and_closed_gate(self):
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), OUTER_NET)
        self.assertEqual(Path('/proc/self/uid_map').read_text().split(), ['0', OUTER_UID, '1'])
        self.assertNotEqual(OUTER_UID, '0')
        self.assertEqual({p.name for p in Path('/etc/config').iterdir()}, {'rpcd'})
        self.assertFalse(Path('/usr/libexec/homegate/ddns-ui').exists())
        self.assertFalse(Path('/sys').exists())
        self.assertEqual(len(Path('/proc/net/route').read_text().splitlines()), 1)
        self.assertTrue(os.statvfs(ROOT).f_flag & os.ST_RDONLY)
        self.assertTrue(os.statvfs(WORK).f_flag & os.ST_RDONLY)
        self.assertEqual(CANDIDATE.read_bytes().count(GATE), 1)

    def test_02_exact_real_ubus_signatures(self):
        result = self.bus(['-v', 'list', 'homegate_ddns']).stdout.decode()
        signatures = {}
        for line in result.splitlines():
            if line.startswith('\t'):
                signatures.update(json.loads('{' + line.strip() + '}'))
        self.assertEqual(signatures, SIGNATURES)

    def test_03_all_real_methods_keep_gate_closed(self):
        values = {'selection': 'ddns_fixture', 'confirmation': 'b' * 32,
                  'consent': '1', 'job': 'a' * 32, 'rule': 'ddns_fixture'}
        for method, fields in SIGNATURES.items():
            with self.subTest(method=method):
                self.denied(method, {name: values[name] for name in fields})
                self.denied(method, {})

    def test_04_rpcd_argument_and_method_rejections(self):
        for method, fields in SIGNATURES.items():
            self.call('homegate_ddns', method, {'unregistered_field': 'fixture'}, expected=2)
            for field in fields:
                for bad in (False, 1, [], {}, None):
                    with self.subTest(method=method, field=field, bad_type=type(bad).__name__):
                        self.call('homegate_ddns', method, {field: bad}, expected=2)
        self.call('homegate_ddns', 'unregistered_method', {}, expected=3)

    def test_05_reader_acl_all_eight_methods(self):
        sid = self.login('fixture_reader')
        try:
            for method in SIGNATURES:
                self.assertEqual(self.access(sid, method), {'access': method in ('status', 'jobs')})
        finally:
            self.call('session', 'destroy', {'ubus_rpc_session': sid})

    def test_06_writer_acl_all_eight_methods(self):
        sid = self.login('fixture_writer')
        try:
            for method in SIGNATURES:
                self.assertEqual(self.access(sid, method), {'access': True})
            self.assertEqual(self.access(sid, 'unregistered_method'), {'access': False})
        finally:
            self.call('session', 'destroy', {'ubus_rpc_session': sid})

    def test_07_anonymous_invalid_login_and_revoked_session(self):
        for method in SIGNATURES:
            self.assertEqual(self.access('0' * 32, method), {'access': False})
        self.access('f' * 32, 'status', expected=4)
        self.call('session', 'login', {'username': 'fixture_reader', 'password': 'wrong-fixture'}, expected=6)
        self.call('session', 'login', {'username': 'absent_fixture', 'password': FIXTURE_PASSWORD}, expected=6)
        sid = self.login('fixture_reader')
        self.call('session', 'destroy', {'ubus_rpc_session': sid})
        self.access(sid, 'status', expected=4)

    def test_08_direct_bus_does_not_apply_http_session_acl(self):
        sid = self.login('fixture_reader')
        try:
            self.assertEqual(self.access(sid, 'commit'), {'access': False})
            # Direct local ubus still dispatches; only the candidate's false gate denies business work.
            for value in (sid, 'f' * 32, '0' * 32):
                self.denied('commit', {'ubus_rpc_session': value, 'confirmation': 'b' * 32, 'consent': '1'})
            self.call('homegate_ddns', 'commit', {'ubus_rpc_session': 7}, expected=2)
        finally:
            self.call('session', 'destroy', {'ubus_rpc_session': sid})


def isolated(work, *, guest_script=None, extra_ro=(), extra_mounts=(), extra_rw_mounts=(), state_setup=None, guest_args=()):
    if sys.platform != 'linux' or os.getuid() == 0:
        raise ValueError('Run isolated RPC checks as a non-root Linux user')
    if not shutil.which('bwrap'):
        raise ValueError('bubblewrap is required; do not fall back to host configuration')
    runtime.validate_runtime(work)
    if CANDIDATE.read_bytes().count(GATE) != 1:
        raise ValueError('Candidate gate must be explicitly false')
    original = {p: p.read_bytes() for p in (CANDIDATE, ACL)}
    (ROOT / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rpcd-ddns-', dir=ROOT / 'build') as scratch:
        state = Path(scratch).resolve()
        for name in ('etc/config', 'acl', 'ucode'):
            (state / name).mkdir(parents=True)
        (state / 'etc/passwd').write_text('fixture:x:0:0:fixture:/tmp:/bin/false\n')
        (state / 'etc/group').write_text('fixture:x:0:\n')
        (state / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\n')
        (state / 'isolation-marker').write_text('HomeGate private RPC fixture\n')
        shutil.copyfile(CANDIDATE, state / 'ucode/homegate-ddns.uc')
        shutil.copyfile(ACL, state / 'acl/homegate-ddns.json')
        crypt = ctypes.CDLL('libcrypt.so.1')
        crypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        crypt.crypt.restype = ctypes.c_char_p
        password_hash = crypt.crypt(FIXTURE_PASSWORD.encode(), b'$6$homegate_rpc$')
        if not password_hash or not password_hash.startswith(b'$6$'):
            raise ValueError('Fixture password hash unavailable')
        config = ''
        for role in ('reader', 'writer'):
            config += ("config login\n option username 'fixture_" + role + "'\n option password '" +
                       password_hash.decode() + "'\n list read 'luci-app-homegate-ddns'\n")
            if role == 'writer':
                config += " list write 'luci-app-homegate-ddns'\n"
        (state / 'etc/config/rpcd').write_text(config)
        if state_setup:
            state_setup(state)
        mounts = extra_mounts(state) if callable(extra_mounts) else extra_mounts
        writable = tuple(extra_rw_mounts(state) if callable(extra_rw_mounts) else extra_rw_mounts)
        # Only private fixture subdirectories may be made writable in the guest.
        for source, target in writable:
            if not Path(source).resolve().is_relative_to(state) or not Path(source).is_dir():
                raise ValueError('Writable guest mounts must be private fixture directories')
        command = ['bwrap', '--unshare-all', '--uid', '0', '--gid', '0', '--cap-drop', 'ALL',
                   '--die-with-parent', '--new-session', '--clearenv',
                   '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/tmp',
                   '--setenv', 'LC_ALL', 'C.UTF-8', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
                   '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
                   '--ro-bind-try', '/lib64', '/lib64', '--symlink', 'usr/bin', '/bin',
                   '--symlink', 'usr/sbin', '/sbin', '--proc', '/proc', '--dev', '/dev',
                   '--tmpfs', '/tmp', '--tmpfs', '/var', '--dir', '/var/run/rpcd',
                   '--ro-bind', str(ROOT), str(ROOT), '--ro-bind', str(work), str(work),
                   '--bind', str(state), str(STATE), '--ro-bind', str(state / 'etc'), '/etc',
                   '--ro-bind', str(state / 'acl'), str(work / 'prefix/share/rpcd/acl.d'),
                   '--ro-bind', str(state / 'ucode'), str(work / 'prefix/share/rpcd/ucode'),
                   '--tmpfs', '/usr/local', '--dir', '/usr/local/lib/ucode',
                   '--ro-bind', str(work / 'prefix/lib/ucode'), '/usr/local/lib/ucode',
                   *[item for path in extra_ro for item in ('--ro-bind', str(path), str(path))],
                   *[item for source, target in mounts for item in ('--ro-bind', str(source), str(target))],
                   *[item for source, target in writable for item in ('--bind', str(source), str(target))],
                   '--chdir', '/teststate', '/usr/bin/python3', str(guest_script or Path(__file__).resolve()),
                   '--runtime-dir', str(work), '--inside-net', os.readlink('/proc/self/ns/net'),
                   '--inside-uid', str(os.getuid()), *guest_args]
        result = subprocess.run(command, timeout=90)
    for path, body in original.items():
        if path.read_bytes() != body:
            raise ValueError('Candidate or ACL changed during RPC checks')
    runtime.validate_runtime(work)
    return result.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=WORK)
    parser.add_argument('--inside-net', help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid', help=argparse.SUPPRESS)
    args = parser.parse_args()
    WORK = args.runtime_dir.resolve()
    try:
        if args.inside_net:
            OUTER_NET = args.inside_net
            OUTER_UID = args.inside_uid
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(HostRpcd)
            sys.exit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
        sys.exit(isolated(WORK))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
