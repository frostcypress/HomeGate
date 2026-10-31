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
            (root / 'RELEASE').write_text(str(int(identity(root)['release']) + 1) + '\n', newline='\n')
            with self.assertRaisesRegex(ValueError, 'drift'):
                verify_generated(root)

    def test_version_framing_cannot_hide_crlf_or_extra_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('PROJECT_ID', 'VERSION', 'RELEASE'):
                (root / name).write_bytes((ROOT / name).read_bytes())
            original = (root / 'RELEASE').read_bytes()
            for body in (original.replace(b'\n', b'\r\n'), original.rstrip(b'\n'), original + b'\n'):
                (root / 'RELEASE').write_bytes(body)
                with self.assertRaisesRegex(ValueError, 'LF-terminated'):
                    identity(root)

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
            (root / 'targets').mkdir()
            (root / 'targets/sdk-selection-policy.json').write_bytes((ROOT / 'targets/sdk-selection-policy.json').read_bytes())
            for name in ('VERSION', 'RELEASE', 'PROJECT_ID', 'homegate-version.mk', 'scripts/install.sh', 'scripts/offline-verify.sh'):
                (root / name).write_bytes((ROOT / name).read_bytes())
            (root / 'project.json').write_text(json.dumps({'core': {'implementation': 'c', 'migration_complete': True, 'package': 'homegate-core'}, 'release_ready': False}))
            target = {key: 'verified-test-fixture' for key in ('distribution', 'version', 'device', 'target', 'subtarget', 'architecture', 'abi', 'evidence')}
            target.update(schema=1, verified=True, package_format='ipk', luci={'lua': True, 'js': True, 'bootstrap': True},
                          sdk={'url': 'https://example.invalid/sdk', 'sha256': 'a' * 64},
                          resources={'ram_kib': 128 * 1024, 'overlay_available_kib': 8192})
            for fmt in ('ipk', 'apk'):
                target['package_format'] = fmt
                target['sdk']['version']='24.10.6' if fmt=='ipk' else '25.12.0'
                for frontend in ('lua', 'js'):
                    self.assertEqual(gate.validate(target, frontend, 'auto', root=root), fmt)
                    with self.assertRaises(ValueError):
                        gate.validate(target, frontend, 'apk' if fmt == 'ipk' else 'ipk', root=root)
                    with self.assertRaisesRegex(ValueError, '实机'):
                        gate.validate(target, frontend, fmt, release=True, root=root)
                correct=target['sdk']['version'];target['sdk']['version']='25.12.0' if fmt=='ipk' else '24.10.6'
                with self.assertRaisesRegex(ValueError,'用户选定的 SDK'):gate.validate(target,'lua','auto',root=root)
                target['sdk']['version']=correct

    def test_draft_contains_complete_sources_and_no_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            # CI has no private handoff records. Exercise the local-only format
            # with explicit test documents rather than publishing real records.
            root = Path(directory) / 'fixture'
            self.copy_public_sources(root)
            for name in snapshot.DOCS:
                (root / name).write_text('# Synthetic handoff fixture: ' + name + '\n', encoding='utf-8')
            private = root / 'docs/验证/local-only.txt'
            private.parent.mkdir(parents=True)
            private.write_text('Local handoff keeps private fixture data.\n', encoding='utf-8')
            file = snapshot.create(root, Path(directory), 'pending', 'test', True)
            with zipfile.ZipFile(file) as archive:
                self.assertIsNone(archive.testzip())
                names = archive.namelist()
                for name in ('源码/.github/workflows/编译发布.yml', '源码/LICENSE', '源码/THIRD_PARTY_NOTICES',
                             '源码/project/core/src/go.mod', '源码/project/luci/lua/luasrc/controller/homegate.lua',
                             '源码/project/luci/js/htdocs/luci-static/resources/view/homegate/overview.js', *snapshot.DOCS):
                    self.assertIn(name, names)
                self.assertFalse(any(name.endswith(('.ipk', '.apk', '.exe')) for name in names))
                self.assertIn('源码/docs/验证/local-only.txt', names)
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
                snapshot.create(root, Path(directory), 'pending', 'test', True)
            with self.assertRaisesRegex(ValueError, '迁移'):
                snapshot.create(root, Path(directory), 'pending', 'test', False)

    @staticmethod
    def copy_public_sources(root):
        for file in snapshot.public_files(ROOT):
            destination = root / file.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(file.read_bytes())

    def test_public_source_excludes_local_data_and_restores_without_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fixture'
            self.copy_public_sources(root)
            marker = 'PRIVATE-SENTINEL-' + Path(directory).name
            for name in (*snapshot.DOCS, 'docs/验证/private.json', 'targets/evidence/report.txt',
                         '.github/reference/import.yml', 'scripts/unlisted-secret.txt'):
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(marker, encoding='utf-8')
            output = Path(directory) / 'public'
            file = snapshot.create_public(root, output, 'pending', 'test')
            with zipfile.ZipFile(file) as archive:
                self.assertIsNone(archive.testzip())
                expected = {'源码/' + p.relative_to(root).as_posix() for p in snapshot.public_files(root)}
                self.assertEqual(set(archive.namelist()), expected | {'源码清单.sha256'})
                hashes = dict(line.split('  ', 1)[::-1] for line in archive.read('源码清单.sha256').decode('utf-8').splitlines())
                self.assertEqual(set(hashes), expected)
                for name in expected:
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), hashes[name])
                    self.assertNotIn(marker.encode('utf-8'), archive.read(name))
                restored = Path(directory) / 'restore'
                archive.extractall(restored)
            verify_generated(restored / '源码')
            self.assertTrue(snapshot.create_public(restored / '源码', Path(directory) / 'roundtrip', 'pending', 'restore').is_file())
            with self.assertRaises(FileExistsError):
                snapshot.create_public(root, output, 'pending', 'test')
            with self.assertRaisesRegex(ValueError, 'handoff'):
                snapshot.create(restored / '源码', Path(directory) / 'private', 'pending', 'test', True)

    def test_public_manifest_rejects_private_unsafe_missing_and_duplicate_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fixture'
            self.copy_public_sources(root)
            manifest = root / snapshot.PUBLIC_MANIFEST
            original = json.loads(manifest.read_text(encoding='utf-8'))
            for name in ('接续.md', 'docs/验证/private.json', 'targets/evidence/report.txt',
                         '.github/reference/import.yml', 'scripts/.env', 'scripts/private.key',
                         '../escape', '/absolute', 'scripts/../escape', 'scripts\\escape', 'scripts/missing.py'):
                with self.subTest(name=name):
                    changed = dict(original, files=sorted(original['files'] + [name]))
                    manifest.write_text(json.dumps(changed, ensure_ascii=False), encoding='utf-8')
                    with self.assertRaises(ValueError):
                        snapshot.create_public(root, Path(directory) / 'invalid', 'pending', 'test')
                    self.assertFalse((Path(directory) / 'invalid').exists())
            for names in (original['files'] + [original['files'][-1]],
                          [p for p in original['files'] if p != 'LICENSE']):
                manifest.write_text(json.dumps(dict(original, files=names)), encoding='utf-8')
                with self.assertRaises(ValueError):
                    snapshot.public_files(root)

    def test_python_syntax(self):
        for file in (ROOT / 'scripts').glob('*.py'):
            ast.parse(file.read_text(encoding='utf-8'), filename=str(file))


if __name__ == '__main__':
    unittest.main(verbosity=2)
