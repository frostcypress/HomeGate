#!/usr/bin/env python3
"""Ensure all real CLI choices run exactly once, failures stop, and CI gates build."""
import ast
import contextlib
import importlib.util
import io
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch
from project import ROOT

spec = importlib.util.spec_from_file_location('engineering_ci', ROOT/'scripts/engineering-ci.py')
dispatch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dispatch)


def choices(name):
    tree = ast.parse((ROOT/'scripts'/name).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == '--group':
            return next(ast.literal_eval(x.value) for x in node.keywords if x.arg == 'choices')
    raise AssertionError('Missing real parser choices')


class Coverage(unittest.TestCase):
    def test_real_scenario_parsers_partition_without_loss_or_duplicates(self):
        for kind, script in [('production', '生产接管回归.py'), ('web', '工程网页回归.py'), ('proxy', '工程代理回归.py'), ('wol', '工程WOL回归.py')]:
            actual = [case for k, cases in dispatch.GROUPS.values() if k == kind for case in cases]
            self.assertEqual(len(actual), len(set(actual)))
            self.assertEqual(set(actual), set(choices(script)))

    def test_every_prepare_and_business_failure_stops_real_runner(self):
        for group in dispatch.GROUPS:
            for prepare in (False, True):
                expected = dispatch.commands(group, ROOT/'build/runtime with spaces', prepare)
                for index in range(len(expected)):
                    calls = []
                    def run(command, **kwargs):
                        self.assertEqual(kwargs, {'check': True})
                        calls.append(command)
                        if len(calls) == index+1:
                            raise subprocess.CalledProcessError(19, command)
                    with patch.object(dispatch.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaises(subprocess.CalledProcessError):
                            dispatch.run_group(group, ROOT/'build/runtime with spaces', prepare)
                    self.assertEqual(calls, expected[:index+1])

    def test_workflow_matrix_and_build_dependency(self):
        body = (ROOT/'.github/workflows/编译发布.yml').read_text()
        block = body.split('  engineering:\n', 1)[1].split('  build:\n', 1)[0]
        self.assertEqual(re.search(r'group: \[([^\]]+)\]', block).group(1).split(', '), list(dispatch.GROUPS))
        self.assertIn('needs: [source, extended, native, engineering]', body)
        self.assertIn('scripts/engineering-ci.py', block)
        self.assertIn('--prepare', block)
        self.assertIn('prepare-ci-isolation.py', block)
        self.assertIn('engineering-ci-regressions.py', body.split('  extended:\n', 1)[0])
        self.assertNotIn('scripts/工程网页回归.py', (ROOT/'scripts/check-ddns-authority.sh').read_text())

    def test_component_preparation_order_and_proxy_fixture_only(self):
        for group, (kind, _) in dispatch.GROUPS.items():
            commands = dispatch.commands(group, ROOT/'build/runtime with spaces', True)
            self.assertEqual([Path(c[1]).name for c in commands[:4]], ['prepare-ucode.py', 'prepare-rpcd.py', 'prepare-uhttpd.py', 'prepare-luci.py'])
            self.assertEqual(len(commands), 8 if kind=='production' else 6 if kind in ('proxy','wol') else 4)
            if kind in ('proxy','production','wol'):
                self.assertEqual(commands[-1][-2], '--fixture-dir')
            for command in dispatch.commands(group, ROOT/'build/runtime with spaces'):
                self.assertIn(str(ROOT/'build/runtime with spaces/rpcd'), command)

    def test_real_cli_rejects_unknown_group_without_preparation(self):
        p = subprocess.run([sys.executable, str(ROOT/'scripts/engineering-ci.py'), 'unknown', '--prepare'], capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b'engineering-ci:', p.stdout)
        with patch.object(dispatch.subprocess, 'run') as run:
            with self.assertRaises(ValueError): dispatch.run_group('unknown', ROOT/'build')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
