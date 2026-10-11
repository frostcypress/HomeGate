#!/usr/bin/env python3
"""Static parser checks locally; actual ash execution requires Linux + BusyBox."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from project import ROOT, identity

PROTOTYPE = ROOT / 'project/core/prototype/homegate-prototype.sh'
EVENTS = ['startup', 'config_changed', 'wan_changed', 'ddns_timer', 'acme_timer',
          'access_timer', 'firewall_retry', 'proxy_retry', 'ddns_retry', 'acme_retry', 'access_retry']


class Static(unittest.TestCase):
    def test_shell_grammar_and_portability(self):
        import tree_sitter
        import tree_sitter_bash
        body = PROTOTYPE.read_bytes()
        self.assertNotIn(b'\r', body)
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        tree = parser.parse(body)
        self.assertFalse(tree.root_node.has_error, str(tree.root_node))
        stack = [tree.root_node]
        forbidden_nodes = {'process_substitution', 'herestring_redirect', 'array', 'c_style_for_statement'}
        forbidden_commands = {'eval', 'source', '.', 'curl', 'wget', 'openssl', 'nc', 'ip6tables',
                              'nft', 'service', 'reboot', 'shutdown', 'go', 'python', 'python3'}
        while stack:
            node = stack.pop()
            self.assertNotIn(node.type, forbidden_nodes)
            if node.type == 'command':
                name = node.child_by_field_name('name')
                if name is not None:
                    command = body[name.start_byte:name.end_byte].decode()
                    self.assertNotIn(command, forbidden_commands)
                    self.assertNotIn('$', command, 'Dynamic executable name in isolated prototype')
            stack.extend(node.named_children)

    def test_prototype_excluded_from_production_install(self):
        recipe = (ROOT / 'project/core/Makefile').read_text(encoding='utf-8')
        self.assertNotIn('prototype/', recipe)
        project = json.loads((ROOT / 'project.json').read_text(encoding='utf-8'))
        self.assertFalse(project['core']['migration_complete'])

    def test_event_contract_covers_original_scheduler(self):
        body = (ROOT / 'project/core/src/internal/scheduler/queue.go').read_text(encoding='utf-8')
        import re
        self.assertEqual(set(re.findall(r'Kind = "([^"]+)"', body)), set(EVENTS))


class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.busybox = shutil.which('busybox')
        if os.name != 'posix' or not cls.busybox:
            raise RuntimeError('Runtime checks require Linux with BusyBox; no simulated pass')
        applets = subprocess.check_output([cls.busybox, '--list'], text=True).splitlines()
        for name in ('ash', 'expr', 'stat', 'flock', 'tr', 'mkdir', 'mv', 'rm', 'id'):
            if name not in applets:
                raise RuntimeError('Missing BusyBox applet: ' + name)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='homegate-prototype-tests-', dir='/tmp')
        self.base = Path(self.temp.name)
        self.state = self.base / 'state'
        self.config = self.base / 'config'
        self.config.mkdir(mode=0o700)
        self.bin = self.base / 'bin'
        self.bin.mkdir(mode=0o700)
        for name in ('expr', 'stat', 'flock', 'tr', 'mkdir', 'mv', 'rm', 'id', 'dirname'):
            (self.bin / name).symlink_to(self.busybox)
        # Mock only the UCI external interface; queue/file/ash operations are real.
        uci = self.bin / 'uci'
        uci.write_text('#!' + sys.executable + '\n' + '''import json, os, pathlib, sys
args=sys.argv[1:]
if len(args)!=5 or args[0]!="-c" or args[2:4]!=["-q","get"]:
    sys.exit(2)
try:
    data=json.loads((pathlib.Path(args[1])/"homegate").read_text())
except (OSError,ValueError):
    sys.exit(1)
key=args[4]
if key=="homegate.main":
    print(data.get("kind","homegate"))
elif key.startswith("homegate.main.") and key[14:] in data.get("main",{}):
    print(data["main"][key[14:]])
else:
    sys.exit(1)
''', encoding='utf-8')
        uci.chmod(0o700)
        self.write_config({})
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ.get('PATH', ''),
                        HOMEGATE_PROTO_STATE=str(self.state), HOMEGATE_PROTO_CONFIG_DIR=str(self.config))

    def tearDown(self):
        self.temp.cleanup()

    def write_config(self, main, kind='homegate'):
        (self.config / 'homegate').write_text(json.dumps({'kind': kind, 'main': main}), encoding='utf-8')
        (self.config / 'homegate').chmod(0o600)

    def run_cli(self, *args, expected=0, env=None):
        result = subprocess.run([self.busybox, 'ash', str(PROTOTYPE), *args], env=env or self.env,
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, expected, (args, result.stdout, result.stderr))
        data = json.loads(result.stdout)
        self.assertTrue(data['prototype'])
        self.assertEqual(data['ok'], expected == 0)
        self.assertLess(len(result.stdout.encode()), 2048)
        return data

    def test_version_and_explicit_paths(self):
        self.assertEqual(self.run_cli('version')['version'], identity()['normalized'])
        self.run_cli('state', expected=2, env={**self.env, 'HOMEGATE_PROTO_STATE': '/etc/homegate'})
        self.run_cli('check', expected=2, env={**self.env, 'HOMEGATE_PROTO_CONFIG_DIR': ''})
        self.run_cli('daemon', expected=2)

    def test_common_config_defaults_and_scope(self):
        data = self.run_cli('check')
        self.assertFalse(data['complete_validation'])
        self.assertEqual(data['main'], {'enabled': False, 'access_enabled': False, 'auto_firewall': True,
                         'log_level': 'info', 'log_max_lines': 1024, 'ddns_interval': 300, 'renew_days': 30,
                         'https_port': 443, 'http_port': 0, 'proxy_https_port': 10443, 'proxy_http_port': 10080})
        self.assertFalse(self.state.exists(), 'Read-only check wrote queue state')

    def test_normalization_limits_and_secret_omission(self):
        self.write_config({'enabled': ' YES ', 'access_enabled': '1', 'auto_firewall': 'no',
                           'https_port': '0080', 'ddns_interval': '-5', 'secret': 'NEVER_EXPORT_ME',
                           'acme_email': 'SECRET_EMAIL', 'log_level': 'WARN'})
        data = self.run_cli('check')
        self.assertTrue(data['main']['enabled'])
        self.assertEqual(data['main']['https_port'], 80)
        self.assertEqual(data['main']['ddns_interval'], 60)
        self.assertNotIn('SECRET', json.dumps(data))

    def test_bad_values_are_not_executed_or_echoed(self):
        sentinel = self.base / 'sentinel'
        for key, value in [('https_port', '65536'), ('log_max_lines', '63'), ('renew_days', '0'),
                           ('ddns_interval', '9' * 10000), ('log_level', 'BAD_SECRET'),
                           ('https_port', '$(touch ' + str(sentinel) + ')')]:
            with self.subTest(key=key, value=value[:40]):
                self.write_config({key: value})
                result = self.run_cli('check', expected=1)
                self.assertNotIn(value, json.dumps(result))
                self.assertFalse(sentinel.exists())
        self.write_config({}, kind='other')
        self.run_cli('check', expected=1)

    def test_fifo_deduplication_and_capacity(self):
        for event in EVENTS[:8]:
            self.run_cli('submit', event)
        self.assertTrue(self.run_cli('submit', EVENTS[0])['deduplicated'])
        self.run_cli('submit', EVENTS[8], expected=4)
        self.assertEqual(self.run_cli('state')['pending'], 8)
        for event in EVENTS[:8]:
            job = self.run_cli('next')
            self.assertEqual(job['event'], event)
            self.run_cli('next', expected=4)
            self.run_cli('complete', job['token'])
        self.assertFalse(self.run_cli('next')['claimed'])

    def test_stale_and_replayed_tokens_cannot_commit(self):
        self.run_cli('submit', 'startup')
        old = self.run_cli('next')['token']
        self.run_cli('advance')
        self.run_cli('complete', old, expected=5)
        self.run_cli('submit', 'startup')
        new = self.run_cli('next')['token']
        self.assertNotEqual(old, new)
        self.run_cli('complete', old, expected=5)
        self.run_cli('complete', new)
        self.run_cli('complete', new, expected=5)
        self.run_cli('complete', '../../outside', expected=2)

    def test_same_generation_replay_and_active_resubmit(self):
        self.run_cli('submit', 'startup')
        old = self.run_cli('next')['token']
        self.assertFalse(self.run_cli('submit', 'startup')['deduplicated'])
        self.run_cli('complete', old)
        new = self.run_cli('next')['token']
        self.assertNotEqual(old, new)
        self.run_cli('complete', old, expected=5)
        self.run_cli('complete', new)

    def test_permissions_links_and_corrupt_state(self):
        self.run_cli('state')
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.state / '.lock').stat().st_mode & 0o777, 0o600)
        self.state.chmod(0o755)
        self.run_cli('state', expected=1)
        self.state.chmod(0o700)
        self.run_cli('submit', 'startup')
        file = self.state / 'control.state'
        for content in ('bad\n0\n-\n', '1\n0\n-\nunknown\n', '1\n0\nstartup\n',
                        '1\n0\n-\nstartup\nstartup\n', 'x' * 513):
            file.write_text(content)
            self.run_cli('state', expected=1)
        file.unlink()
        external = self.base / 'external'
        external.write_text('UNCHANGED')
        external.chmod(0o600)
        file.symlink_to(external)
        self.run_cli('state', expected=1)
        self.assertEqual(external.read_text(), 'UNCHANGED')
        file.unlink()
        os.link(external, file)
        self.run_cli('state', expected=1)
        self.assertEqual(external.read_text(), 'UNCHANGED')

    def test_lock_contention_and_symlink_parent(self):
        import fcntl
        self.run_cli('state')
        with (self.state / '.lock').open('a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_cli('submit', 'startup', expected=4)
        self.assertEqual(self.run_cli('state')['pending'], 0)
        link = self.base / 'link'
        link.symlink_to(self.state, target_is_directory=True)
        self.run_cli('state', expected=1, env={**self.env, 'HOMEGATE_PROTO_STATE': str(link)})
        self.base.chmod(0o755)
        try:
            self.run_cli('state', expected=1)
        finally:
            self.base.chmod(0o700)

    def test_real_concurrent_submissions(self):
        self.run_cli('state')
        def submit(_):
            result = subprocess.run([self.busybox, 'ash', str(PROTOTYPE), 'submit', 'wan_changed'],
                                    env=self.env, capture_output=True, text=True, timeout=8)
            self.assertIn(result.returncode, (0, 4))
            return result.returncode
        with ThreadPoolExecutor(max_workers=6) as pool:
            codes = list(pool.map(submit, range(18)))
        self.assertIn(0, codes)
        self.assertEqual(self.run_cli('state')['pending'], 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--static', action='store_true')
    group.add_argument('--runtime', action='store_true')
    args = parser.parse_args()
    tests = unittest.defaultTestLoader.loadTestsFromTestCase(Static if args.static else Runtime)
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    sys.exit(0 if result.wasSuccessful() else 1)
