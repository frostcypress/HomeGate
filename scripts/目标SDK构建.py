#!/usr/bin/env python3
"""Build with a verified SDK; refuse the transitional Go implementation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from project import ROOT, identity


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(target_file, frontend, fmt):
    target = json.loads(target_file.read_text(encoding='utf-8'))
    actual = load_script('检查发布条件').validate(target, frontend, fmt)
    item = identity()
    destination = ROOT / 'dist/target'
    if destination.exists():
        raise ValueError('Output exists; use a clean build workspace')
    with tempfile.TemporaryDirectory(prefix='homegate-sdk-') as directory:
        work = Path(directory)
        archive = work / 'sdk.tar'
        urllib.request.urlretrieve(target['sdk']['url'], archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != target['sdk']['sha256']:
            raise ValueError('SDK SHA-256 mismatch')
        extracted = work / 'sdk'
        extracted.mkdir()
        with tarfile.open(archive) as bundle:
            bundle.extractall(extracted, filter='data')
        roots = [p.parent for p in extracted.glob('*/rules.mk')]
        if len(roots) != 1:
            raise ValueError('SDK root is ambiguous')
        sdk = roots[0]
        packages = sdk / 'package'
        shutil.copytree(ROOT / 'project/core', packages / (item['slug'] + '-core'))
        shutil.copytree(ROOT / 'project/luci', packages / ('luci-app-' + item['slug']))
        shutil.copy2(ROOT / 'homegate-version.mk', sdk)
        shutil.copy2(ROOT / 'LICENSE', sdk)
        environment = dict(os.environ, HOMEGATE_LUCI_VARIANT=frontend)
        for command in (['./scripts/feeds', 'update', '-a'], ['./scripts/feeds', 'install', '-a'],
                        ['make', 'defconfig'], ['make', f"package/{item['slug']}-core/compile", 'V=s', '-j2'],
                        ['make', f"package/luci-app-{item['slug']}/compile", 'V=s', '-j2']):
            subprocess.run(command, cwd=sdk, env=environment, check=True)
        found = []
        names = (item['slug'] + '-core', 'luci-app-' + item['slug'], 'luci-i18n-' + item['slug'] + '-zh-cn')
        for file in (sdk / 'bin').rglob('*.' + actual):
            if any(file.name.startswith(name + ('_' if actual == 'ipk' else '-')) for name in names):
                found.append(file)
        if len(found) != 3:
            raise ValueError(f'SDK did not produce exactly three packages: {len(found)}')
        staged = work / 'packages'
        staged.mkdir()
        for file in found:
            shutil.copy2(file, staged)
        _, report = load_script('检查三包').inspect(staged, item['slug'], item['normalized'], actual,
                                                  target['architecture'], os.environ.get('HOMEGATE_APK_TOOL', 'apk'))
        destination.mkdir(parents=True)
        for file in staged.iterdir():
            shutil.copy2(file, destination)
        evidence = {'target': target, 'identity': item, 'luci': frontend, 'format': actual,
                    'source_commit': os.environ.get('GITHUB_SHA'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
                    'packages': report, 'status': 'compiled-metadata-verified-not-device-tested'}
        (destination / 'build-evidence.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--luci', choices=('lua', 'js'), required=True)
    parser.add_argument('--format', choices=('auto', 'ipk', 'apk'), default='auto')
    args = parser.parse_args()
    build(args.target, args.luci, args.format)
