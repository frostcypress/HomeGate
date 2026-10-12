#!/usr/bin/env python3
"""Isolated generation/vault tests; real Linux BusyBox and real filesystem."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from project import ROOT, identity

SCRIPT = ROOT / 'project/core/prototype/homegate-config-prototype.sh'
APPLETS = ('expr', 'stat', 'flock', 'mkdir', 'mv', 'rm', 'id', 'dirname',
           'cat', 'cp', 'rmdir', 'sha256sum', 'head', 'ash', 'setsid', 'sleep', 'mkfifo', 'ls')


class Static(unittest.TestCase):
    def test_grammar_and_isolation(self):
        import tree_sitter
        import tree_sitter_bash
        body = SCRIPT.read_bytes()
        self.assertNotIn(b'\r', body)
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        tree = parser.parse(body)
        self.assertFalse(tree.root_node.has_error, str(tree.root_node))
        nodes = [tree.root_node]
        while nodes:
            node = nodes.pop()
            self.assertNotIn(node.type, {'process_substitution', 'herestring_redirect',
                                         'array', 'c_style_for_statement'})
            if node.type == 'command':
                name = node.child_by_field_name('name')
                if name:
                    command = body[name.start_byte:name.end_byte].decode()
                    self.assertNotIn('$', command)
                    self.assertNotIn(command, {'eval', '.', 'source', 'uci', 'curl', 'wget',
                        'service', 'nft', 'ip6tables', 'reboot', 'logger', 'go', 'python3'})
            nodes.extend(node.named_children)
        self.assertNotIn('prototype/', (ROOT / 'project/core/Makefile').read_text())


class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.busybox = shutil.which('busybox')
        if os.name != 'posix' or not cls.busybox:
            raise RuntimeError('Requires real Linux BusyBox; no simulated pass')
        available = subprocess.check_output([cls.busybox, '--list'], text=True).splitlines()
        missing = set(('ash', *APPLETS)) - set(available)
        if missing:
            raise RuntimeError('Missing BusyBox applets: ' + ', '.join(sorted(missing)))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='homegate-config-prototype-tests-', dir='/tmp')
        self.base = Path(self.temp.name)
        self.store = self.base / 'store'
        self.bin = self.base / 'bin'
        self.bin.mkdir(mode=0o700)
        for name in APPLETS:
            (self.bin / name).symlink_to(self.busybox)
        self.env = dict(os.environ, PATH=str(self.bin), HOMEGATE_CONFIG_PROTO_STORE=str(self.store))
        self.cli('init')
        self.default = self.export()

    def tearDown(self):
        self.temp.cleanup()

    def raw(self, *args, payload=None, env=None, expected=0):
        result = subprocess.run([self.busybox, 'ash', str(SCRIPT), *args], input=payload,
                                env=env or self.env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, expected, (args, result.stdout, result.stderr))
        self.assertEqual(result.stderr, b'', 'Unexpected diagnostics may expose input')
        self.assertLess(len(result.stdout), 4096)
        return result.stdout

    def cli(self, *args, payload=None, env=None, expected=0):
        data = json.loads(self.raw(*args, payload=payload, env=env, expected=expected))
        self.assertTrue(data['prototype'])
        self.assertEqual(data['ok'], expected == 0)
        return data

    def export(self):
        return self.raw('export')

    def preview(self, payload=None):
        return self.cli('preview', payload=payload if payload is not None else self.default)

    def put(self, value, provider='aliyun', account='dns_a', slot='secret', expected=0):
        return self.cli('credential-put', provider, account, slot, payload=value, expected=expected)

    def credential_path(self, revision, provider='aliyun', account='dns_a', slot='secret'):
        return self.store / f'gen-{revision}' / 'credentials' / f'{provider}.{account}.{slot}'

    def change(self, key, value):
        before = self.default.decode().splitlines(keepends=True)
        return ''.join(key + '=' + str(value) + '\n' if line.startswith(key + '=') else line
                       for line in before).encode()

    def test_version_paths_defaults_and_permissions(self):
        self.assertEqual(self.cli('version')['version'], identity()['normalized'])
        self.cli('init', expected=4)
        self.cli('status', env={**self.env, 'HOMEGATE_CONFIG_PROTO_STORE': '/etc/homegate'}, expected=2)
        self.cli('status', env={**self.env, 'HOMEGATE_CONFIG_PROTO_STORE': ''}, expected=2)
        self.assertTrue(self.default.startswith(b'homegate-prototype-config:1\nslug=homegate\n'))
        for path in [self.store, *(self.store.rglob('*'))]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600, path)
        self.assertEqual(self.cli('status')['revision'], 1)

    def test_preview_is_read_only_for_current_and_shows_real_diff(self):
        payload = self.change('https_port', '08443').replace(b'enabled=0\n', b'enabled=1\n')
        preview = self.preview(payload)
        self.assertEqual(self.export(), self.default)
        self.assertEqual(preview['changes'], [{'field': 'https_port', 'before': '443', 'after': '8443'}])
        self.assertFalse(preview['service_enabled'])
        self.assertEqual(len(preview['confirmation']), 32)
        self.assertEqual(self.cli('commit', preview['confirmation'])['revision'], 2)
        self.assertIn(b'https_port=8443\n', self.export())
        self.assertIn(b'enabled=0\n', self.export())
        self.cli('commit', preview['confirmation'], expected=5)

    def test_replacement_cancel_and_config_change_expire_confirmation(self):
        old = self.preview()['confirmation']
        new = self.preview(self.change('log_level', 'warn'))['confirmation']
        self.assertNotEqual(old, new)
        self.cli('commit', old, expected=5)
        self.cli('cancel')
        self.cli('commit', new, expected=5)
        latest = self.preview()['confirmation']
        self.put(b'NOT_A_REAL_CREDENTIAL')
        self.cli('commit', latest, expected=5)
        self.assertEqual(self.export(), self.default)

    def test_strict_schema_rejects_injection_duplicate_binary_and_limits(self):
        sentinel = self.base / 'not-executed'
        evil = '$(touch ' + str(sentinel) + ')'
        invalid = [self.default.replace(b'slug=homegate', b'slug=foreign'),
                   self.default.replace(b'schema=main-public-v1', b'schema=unknown'),
                   self.change('https_port', '65536'), self.change('ddns_interval', '59'),
                   self.change('log_max_lines', '63'), self.change('log_level', evil),
                   self.default + b'secret=NEVER_ECHO\n', self.default + b'\n',
                   self.default.replace(b'slug=', b'slug=\x00'), self.default[:-1],
                   self.default.replace(b'https_port=443', b'http_port=443'), b'X' * 1025]
        for payload in invalid:
            with self.subTest(payload=payload[:70]):
                result = self.cli('preview', payload=payload, expected=1)
                self.assertNotIn('NEVER_ECHO', json.dumps(result))
                self.assertNotIn(evil, json.dumps(result))
                self.assertEqual(self.export(), self.default)
        self.assertFalse(sentinel.exists())

    def test_secret_stdin_private_storage_and_export_omission(self):
        sentinel = self.base / 'not-executed'
        secret = ('NEVER_ECHO_SECRET\n$(touch ' + str(sentinel) + ')\x00OPAQUE').encode()
        response = self.put(secret)
        self.assertNotIn('NEVER_ECHO', json.dumps(response))
        file = self.credential_path(2)
        self.assertEqual(file.read_bytes(), secret)
        self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertFalse(sentinel.exists())
        preview = self.preview(self.change('log_level', 'warn'))
        self.assertNotIn('NEVER_ECHO', json.dumps(preview))
        self.cli('commit', preview['confirmation'])
        self.assertEqual(self.credential_path(3).read_bytes(), secret)
        self.assertNotIn(b'NEVER_ECHO', self.export())
        self.assertNotIn('dns_a', json.dumps(self.cli('status')))
        self.assertNotIn(hashlib.sha256(secret).hexdigest(), json.dumps(preview))

    def test_slot_and_byte_limits_and_delete(self):
        self.put(b'X' * 4096)
        self.put(b'X' * 4097, expected=1)
        self.put(b'', expected=1)
        self.assertEqual(self.cli('status')['revision'], 2)
        self.assertFalse((self.store / 'gen-3').exists())
        for provider, account, slot in [('unknown', 'a', 'secret'), ('aliyun', '../escape', 'secret'),
                                         ('aliyun', 'a', '../secret'), ('cloudflare', 'a' * 33, 'secret')]:
            self.put(b'NEVER_ECHO', provider, account, slot, expected=2)
        self.cli('credential-delete', 'aliyun', 'dns_a', 'secret')
        self.assertFalse(self.credential_path(3).exists())
        self.assertEqual(self.credential_path(2).read_bytes(), b'X' * 4096)

    def test_rollback_restores_both_config_and_credentials_as_new_revision(self):
        self.put(b'OLD_SECRET')
        plan = self.preview(self.change('https_port', 8443))
        self.cli('commit', plan['confirmation'])
        self.put(b'NEW_SECRET')
        rollback = self.cli('rollback-preview', '2')
        self.assertEqual(rollback['operation'], 'rollback')
        self.assertEqual(rollback['changes'], [{'field': 'https_port', 'before': '8443', 'after': '443'}])
        self.assertEqual(self.credential_path(4).read_bytes(), b'NEW_SECRET')
        self.assertEqual(self.cli('commit', rollback['confirmation'])['revision'], 5)
        self.assertEqual(self.export(), self.default)
        self.assertEqual(self.credential_path(5).read_bytes(), b'OLD_SECRET')
        self.cli('commit', rollback['confirmation'], expected=5)
        self.cli('rollback-preview', '5', expected=5)
        self.cli('rollback-preview', '32', expected=5)

    def test_permissions_symlinks_hardlinks_and_corrupt_generation(self):
        outside = self.base / 'outside'
        outside.write_bytes(b'UNCHANGED')
        outside.chmod(0o600)
        file = self.store / 'gen-1/public.conf'
        original = file.read_bytes()
        file.chmod(0o644)
        self.cli('status', expected=1)
        file.chmod(0o600)
        file.unlink()
        file.symlink_to(outside)
        self.cli('status', expected=1)
        file.unlink()
        os.link(outside, file)
        self.cli('status', expected=1)
        file.unlink()
        file.write_bytes(original)
        file.chmod(0o600)
        file.write_bytes(original.replace(b'log_level=info', b'log_level=warn'))
        self.cli('status', expected=1)
        self.assertEqual(outside.read_bytes(), b'UNCHANGED')

    def test_real_lock_conflict_and_concurrent_confirmations(self):
        import fcntl
        plan = self.preview(self.change('log_level', 'warn'))
        with (self.store / '.lock').open('a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.cli('commit', plan['confirmation'], expected=4)
        def commit(_):
            result = subprocess.run([self.busybox, 'ash', str(SCRIPT), 'commit', plan['confirmation']],
                                    env=self.env, capture_output=True, timeout=15)
            self.assertIn(result.returncode, (0, 4, 5), result.stdout)
            return result.returncode
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(commit, range(8)))
        self.assertEqual(results.count(0), 1)
        self.assertEqual(self.cli('status')['revision'], 2)

    def test_failed_pointer_rename_preserves_plan_config_and_secret(self):
        self.put(b'CURRENT_SECRET')
        plan = self.preview(self.change('https_port', 8443))
        mv = self.bin / 'mv'
        mv.unlink()
        # Fault only the final atomic pointer rename; normal tests use BusyBox mv.
        mv.write_text('#!' + sys.executable + '\nimport os,sys\n'
                      'if sys.argv[-1].endswith("/current"): sys.exit(1)\n'
                      'os.execv(' + repr(self.busybox) + ',["mv",*sys.argv[1:]])\n')
        mv.chmod(0o700)
        self.cli('commit', plan['confirmation'], expected=1)
        self.assertEqual(self.cli('status')['revision'], 2)
        self.assertEqual(self.export(), self.default)
        self.assertEqual(self.credential_path(2).read_bytes(), b'CURRENT_SECRET')
        self.assertFalse((self.store / 'gen-3').exists())
        mv.unlink()
        mv.symlink_to(self.busybox)
        self.cli('commit', plan['confirmation'])

    def test_process_death_before_pointer_does_not_publish_or_allow_orphan_rollback(self):
        plan = self.preview(self.change('https_port', 8443))
        mv = self.bin / 'mv'
        mv.unlink()
        mv.write_text('#!' + sys.executable + '\nimport os,signal,sys\n'
                      'if sys.argv[-1].endswith("/current"):\n'
                      '    os.kill(os.getppid(),signal.SIGKILL); sys.exit(1)\n'
                      'os.execv(' + repr(self.busybox) + ',["mv",*sys.argv[1:]])\n')
        mv.chmod(0o700)
        result = subprocess.run([self.busybox, 'ash', str(SCRIPT), 'commit', plan['confirmation']],
                                env=self.env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertEqual(self.cli('status')['revision'], 1)
        self.assertEqual(self.export(), self.default)
        self.assertTrue((self.store / 'gen-2').exists(), 'Crash must retain unpublished candidate for audit')
        self.cli('rollback-preview', '2', expected=5)
        mv.unlink()
        mv.symlink_to(self.busybox)
        self.assertEqual(self.cli('commit', plan['confirmation'])['revision'], 3)
        self.cli('rollback-preview', '2', expected=5)

    def test_explicit_storage_bounds(self):
        for index in range(16):
            self.put(b'PRIVATE', account='account_' + str(index))
        self.put(b'PRIVATE', account='overflow', expected=1)
        self.assertEqual(self.cli('status')['revision'], 17)
        for _ in range(15):
            self.put(b'REPLACED', account='account_0')
        self.assertEqual(self.cli('status')['revision'], 32)
        self.put(b'FULL', expected=4)
        self.assertEqual(self.cli('status')['revision'], 32)

    def test_randomness_short_read_fails_without_replacing_pending(self):
        original = self.preview()['confirmation']
        head = self.bin / 'head'
        head.unlink()
        head.write_text('#!' + sys.executable + '\nimport os,sys\n'
                        'if sys.argv[-1]=="/dev/urandom": sys.exit(0)\n'
                        'os.execv(' + repr(self.busybox) + ',["head",*sys.argv[1:]])\n')
        head.chmod(0o700)
        self.cli('preview', payload=self.default, expected=1)
        self.cli('commit', original)

    def test_preview_baseline_io_failure_returns_one_error_and_preserves_pending(self):
        self.preview()
        old_plan = (self.store / 'pending').read_bytes()
        head = self.bin / 'head'
        head.unlink()
        # Simulate a baseline disappearing after initial validation, before diff.
        head.write_text('#!' + sys.executable + '\nimport os,subprocess,sys\n'
                        'if sys.argv[-1]!="/dev/urandom":\n'
                        '    result=subprocess.run([' + repr(self.busybox) + ',"head",*sys.argv[1:]],'
                        'input=sys.stdin.buffer.read(),capture_output=True,check=True)\n'
                        '    os.unlink(' + repr(str(self.store / 'gen-1/public.conf')) + ')\n'
                        '    sys.stdout.buffer.write(result.stdout); sys.exit(0)\n'
                        'os.execv(' + repr(self.busybox) + ',["head",*sys.argv[1:]])\n')
        head.chmod(0o700)
        result = self.cli('preview', payload=self.default, expected=1)
        self.assertEqual(result['error'], 'Unable to read preview baseline')
        self.assertEqual((self.store / 'pending').read_bytes(), old_plan)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--static', action='store_true')
    choice.add_argument('--runtime', action='store_true')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Static if args.static else Runtime)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
