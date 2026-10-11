#!/usr/bin/env python3
"""Meaningful migration tests: metadata spoofing, release gates, archive integrity."""
import ast
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile
from project import ROOT, generated_version, identity, verify_generated


def script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = script('检查三包')
gate = script('检查发布条件')
snapshot = script('生成接续包')


def tar_blob(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, body in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def package(name, version, arch, depends='', ar=False):
    control = f'Package: {name}\nVersion: {version}\nArchitecture: {arch}\nDepends: {depends}\n'.encode()
    members = {'debian-binary': b'2.0\n', 'control.tar.gz': tar_blob({'control': control}),
               'data.tar.gz': tar_blob({'usr/bin/test': b'fixture'})}
    if not ar:
        return tar_blob(members)
    output = b'!<arch>\n'
    for name, body in members.items():
        header = f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(body):<10}`\n'.encode()
        output += header + body + (b'\n' if len(body) % 2 else b'')
    return output


class Migration(unittest.TestCase):
    def test_version_single_source_and_drift(self):
        self.assertGreaterEqual(int(identity()['release']), 11)
        verify_generated()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            for name in ('VERSION', 'RELEASE', 'PROJECT_ID', 'scripts/install.sh', 'scripts/offline-verify.sh'):
                (root / name).write_bytes((ROOT / name).read_bytes())
            (root / 'homegate-version.mk').write_text(generated_version(root), encoding='utf-8')
            (root / 'RELEASE').write_text(str(int(identity(root)['release']) + 1) + '\n')
            with self.assertRaisesRegex(ValueError, 'drift'):
                verify_generated(root)

    def test_metadata_not_filename(self):
        for ar in (False, True):
            with self.subTest(ar=ar), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ('homegate-core', 'luci-app-homegate', 'luci-i18n-homegate-zh-cn'):
                    body = package(name, '1.3.0-r11', 'test_arch' if name == 'homegate-core' else 'all',
                                   '' if name == 'homegate-core' else 'homegate-core', ar)
                    (root / (name + '_misleading_version.ipk')).write_bytes(body)
                files, report = checker.inspect(root, 'homegate', '1.3.0-r11', 'ipk', 'test_arch')
                self.assertEqual(len(report), 3)
                core = next(file for file in files if file.name.startswith('homegate-core_'))
                for version, arch in [('1.3.0-r10', 'test_arch'), ('1.3.0-r11', 'wrong_arch')]:
                    core.write_bytes(package('homegate-core', version, arch, ar=ar))
                    with self.assertRaises(ValueError):
                        checker.inspect(root, 'homegate', '1.3.0-r11', 'ipk', 'test_arch')

    def test_duplicate_foreign_mixed_and_empty_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(3):
                (root / f'{index}.ipk').write_bytes(package('homegate-core', '1.3.0-r11', 'test_arch'))
            with self.assertRaises(ValueError):
                checker.inspect(root, 'homegate', '1.3.0-r11', 'ipk', 'test_arch')
            (root / '0.ipk').write_bytes(b'')
            with self.assertRaises((ValueError, tarfile.TarError)):
                checker.inspect(root, 'homegate', '1.3.0-r11', 'ipk', 'test_arch')
            (root / 'foreign.apk').write_bytes(b'')
            with self.assertRaises(ValueError):
                checker.inspect(root, 'homegate', '1.3.0-r11', 'ipk', 'test_arch')

    def test_missing_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('homegate-core', 'luci-app-homegate', 'luci-i18n-homegate-zh-cn'):
                (root / (name + '.ipk')).write_bytes(package(name, '1.3.0-r11', 'test_arch' if name == 'homegate-core' else 'all', 'unrelated'))
            with self.assertRaisesRegex(ValueError, 'Core'):
                checker.inspect(root, 'homegate', '1.3.0-r11', 'ipk', 'test_arch')

    def test_pending_target_and_go_cannot_release(self):
        target = json.loads((ROOT / 'targets/pending.json').read_text(encoding='utf-8'))
        for frontend in ('lua', 'js'):
            with self.assertRaisesRegex(ValueError, 'Go'):
                gate.validate(target, frontend, 'auto', True)

    def test_frontend_and_format_independence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            for name in ('VERSION', 'RELEASE', 'PROJECT_ID', 'homegate-version.mk', 'scripts/install.sh', 'scripts/offline-verify.sh'):
                (root / name).write_bytes((ROOT / name).read_bytes())
            (root / 'project.json').write_text(json.dumps({'core': {'implementation': 'c', 'migration_complete': True, 'package': 'homegate-core'}, 'release_ready': False}))
            target = {key: 'verified-test-fixture' for key in ('distribution', 'version', 'device', 'target', 'subtarget', 'architecture', 'abi', 'evidence')}
            target.update(schema=1, verified=True, package_format='ipk', luci={'lua': True, 'js': True, 'bootstrap': True},
                          sdk={'url': 'https://example.invalid/sdk', 'sha256': 'a' * 64},
                          resources={'ram_kib': 128 * 1024, 'overlay_available_kib': 8192})
            for fmt in ('ipk', 'apk'):
                target['package_format'] = fmt
                for frontend in ('lua', 'js'):
                    self.assertEqual(gate.validate(target, frontend, 'auto', root=root), fmt)
                    with self.assertRaises(ValueError):
                        gate.validate(target, frontend, 'apk' if fmt == 'ipk' else 'ipk', root=root)
                    with self.assertRaisesRegex(ValueError, '实机'):
                        gate.validate(target, frontend, fmt, release=True, root=root)

    def test_draft_contains_complete_sources_and_no_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            file = snapshot.create(ROOT, Path(directory), 'pending', 'test', True)
            with zipfile.ZipFile(file) as archive:
                self.assertIsNone(archive.testzip())
                names = archive.namelist()
                for name in ('源码/.github/workflows/编译发布.yml', '源码/LICENSE', '源码/THIRD_PARTY_NOTICES',
                             '源码/project/core/src/go.mod', '源码/project/luci/lua/luasrc/controller/homegate.lua',
                             '源码/project/luci/js/htdocs/luci-static/resources/view/homegate/overview.js', *snapshot.DOCS):
                    self.assertIn(name, names)
                self.assertFalse(any(name.endswith(('.ipk', '.apk', '.exe')) for name in names))
                manifest = archive.read('校验.md').decode('utf-8')
                for name in names:
                    if name != '校验.md':
                        digest = hashlib.sha256(archive.read(name)).hexdigest()
                        self.assertIn(f'`{name}`：`{digest}`', manifest)
                restored = Path(directory) / 'restore'
                archive.extractall(restored)
                roundtrip = snapshot.create(restored / '源码', Path(directory) / 'roundtrip', 'pending', 'restored', True)
                self.assertTrue(roundtrip.is_file())
                with zipfile.ZipFile(roundtrip) as rebuilt:
                    self.assertEqual(rebuilt.read('校验.md').decode('utf-8').count('## 自动快照清单'), 1)
            with self.assertRaises(FileExistsError):
                snapshot.create(ROOT, Path(directory), 'pending', 'test', True)
            with self.assertRaisesRegex(ValueError, '迁移'):
                snapshot.create(ROOT, Path(directory), 'pending', 'test', False)

    def test_python_syntax(self):
        for file in (ROOT / 'scripts').glob('*.py'):
            ast.parse(file.read_text(encoding='utf-8'), filename=str(file))


if __name__ == '__main__':
    unittest.main(verbosity=2)
