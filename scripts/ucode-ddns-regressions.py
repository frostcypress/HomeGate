#!/usr/bin/env python3
"""Real host ucode execution with the DDNS gate closed; no real rpcd or DNS."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from project import ROOT

spec = importlib.util.spec_from_file_location('prepare_ucode', ROOT / 'scripts/prepare-ucode.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
CANDIDATE = ROOT / 'project/luci/prototype/js/homegate-ddns.uc'
GATE = b'const native_ddns_rpc_enabled = false;'
WORK = ROOT / 'build/ucode'
SIGNATURES = {
    'status': {}, 'jobs': {}, 'preview': {'selection': ''},
    'commit': {'confirmation': '', 'consent': ''}, 'revoke': {'consent': ''},
    'submit': {'job': '', 'rule': '', 'consent': ''},
    'maintain_preview': {'job': ''},
    'maintain_commit': {'job': '', 'confirmation': '', 'consent': ''},
}
CALLS = """
let service = loadfile(ARGV[0])().homegate_ddns;
let shapes = [{job:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',rule:'ddns_a',selection:'ddns_a',
 confirmation:'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',consent:'1',secret:'PRIVATE_SENTINEL'},
 null, [], {}, 'PRIVATE_SENTINEL', 123];
let out = [];
for (let name, method in service)
 for (let i, args in shapes)
  push(out, {method:name, shape:i, response:method.call({args:args})});
printf('%J\\n', out);
"""


class HostUcode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() == 0:
            raise RuntimeError('Run these host checks as a non-root user')
        runtime.validate_runtime(WORK)
        cls.original = CANDIDATE.read_bytes()
        if cls.original.count(GATE) != 1:
            raise RuntimeError('Candidate gate must remain explicitly false before execution')
        cls.scratch = tempfile.TemporaryDirectory(prefix='ucode-ddns-', dir=ROOT / 'build')
        cls.directory = Path(cls.scratch.name)
        cls.bytecode = cls.directory / 'candidate.ucb'
        cls.call_ucode(['-c', '-o', str(cls.bytecode), str(CANDIDATE)])
        cls.guard = cls.directory / 'guard'
        cls.guard.mkdir()
        (cls.guard / 'fs.uc').write_text(
            "export const guard_marker = 'GUARD_FS_ACTIVE';\n" + ''.join(
                "export const " + name + " = function() { print('UCODE_GUARD_FS_CALLED:" + name + "\\n'); die('fs guard'); };\n"
                for name in ['mkdir', 'open', 'unlink', 'rmdir', 'popen']), encoding='utf-8')

    @classmethod
    def tearDownClass(cls):
        assert CANDIDATE.read_bytes() == cls.original, 'Candidate source changed during checks'
        runtime.validate_runtime(WORK)
        cls.scratch.cleanup()

    @classmethod
    def call_ucode(cls, args, expected=0, guard=False):
        command = [str(WORK / 'out/ucode')]
        if guard:
            command += ['-L', str(cls.guard / '*.uc')]
            assert args[0] == '-e'
            args = ['-e', "import {guard_marker} from 'fs'; assert(guard_marker=='GUARD_FS_ACTIVE');\n" + args[1], *args[2:]]
        else:
            command += ['-L', str(WORK / 'out/*.so')]
        process = subprocess.run([*command, *args], cwd=ROOT, capture_output=True, timeout=20)
        if (process.returncode == 0) != (expected == 0):
            raise AssertionError((process.returncode, process.stdout, process.stderr))
        if expected == 0 and process.stderr:
            raise AssertionError(process.stderr)
        return process

    def assert_denials(self, output):
        data = json.loads(output)
        self.assertEqual(len(data), len(SIGNATURES) * 6)
        self.assertEqual({(r['method'], r['shape']) for r in data},
                         {(name, i) for name in SIGNATURES for i in range(6)})
        for row in data:
            self.assertEqual(row['response'], {
                'api_version': 1, 'prototype': True, 'ok': False, 'phase': 'ddns-ui',
                'effect': 'unknown' if row['method'] == 'submit' else 'none',
                'write_ready': False, 'error': 'DDNS UI request refused'})
        self.assertNotIn(b'PRIVATE_SENTINEL', output)

    def test_real_fs_named_imports(self):
        result = self.call_ucode(['-e', "import {mkdir,open,unlink,rmdir,popen} from 'fs'; printf('%J\\n',[type(mkdir),type(open),type(unlink),type(rmdir),type(popen)]);"])
        self.assertEqual(json.loads(result.stdout), ['function'] * 5)

    def test_actual_source_and_bytecode_rpc_signature(self):
        for candidate in [CANDIDATE, self.bytecode]:
            with self.subTest(bytecode=candidate == self.bytecode):
                body = "let s=loadfile(ARGV[0])(); assert(type(s)=='object' && length(keys(s))==1); let out={}; for(let n,m in s.homegate_ddns){assert(type(m.call)=='function');out[n]=m.args;} printf('%J\\n',out);"
                self.assertEqual(json.loads(self.call_ucode(['-e', body, str(candidate)]).stdout), SIGNATURES)

    def test_closed_gate_native_source_and_bytecode_denials(self):
        for candidate in [CANDIDATE, self.bytecode]:
            with self.subTest(bytecode=candidate == self.bytecode):
                self.assert_denials(self.call_ucode(['-e', CALLS, str(candidate)]).stdout)

    def test_closed_gate_does_not_touch_instrumented_fs(self):
        self.assert_denials(self.call_ucode(['-e', CALLS, str(CANDIDATE)], guard=True).stdout)

    def test_fs_instrumentation_detects_an_attempted_operation(self):
        result = self.call_ucode(['-e', "import {open} from 'fs'; open('never-created','w');"], expected=1, guard=True)
        self.assertEqual(result.stdout, b'UCODE_GUARD_FS_CALLED:open\n')
        self.assertFalse((ROOT / 'never-created').exists())

    def test_enabled_gate_control_cannot_escape_fs_guard(self):
        fixture = self.directory / 'candidate-enabled-control.uc'
        fixture.write_bytes(self.original.replace(GATE, b'const native_ddns_rpc_enabled = true;', 1))
        result = self.call_ucode(['-e', "loadfile(ARGV[0])().homegate_ddns.status.call({args:{}});", str(fixture)], expected=1, guard=True)
        self.assertEqual(result.stdout, b'UCODE_GUARD_FS_CALLED:open\n')
        self.assertEqual(CANDIDATE.read_bytes(), self.original)

    def test_changed_cached_runtime_is_refused(self):
        copied = self.directory / 'changed-runtime'
        copied.mkdir()
        for name in ['build-metadata.json', 'source.tar.gz', *runtime.ARTIFACTS]:
            target = copied / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(WORK / name, target)
        with (copied / 'out/fs.so').open('ab') as stream:
            stream.write(b'changed-cache-control')
        with self.assertRaisesRegex(ValueError, 'artifact changed'):
            runtime.validate_runtime(copied)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'build/ucode')
    args = parser.parse_args()
    WORK = args.runtime_dir.resolve()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(HostUcode))
    raise SystemExit(not result.wasSuccessful())
