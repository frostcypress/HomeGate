#!/usr/bin/env python3
"""Package a complete source draft or verified three-package milestone."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from pathlib import PurePosixPath
import sys
import subprocess
import zipfile
from project import ROOT, identity, verify_generated

DOCS = ('接续.md', '校验.md', '核实查漏修复.md')
SOURCE_DIRS = ('.github', 'project', 'scripts', 'packaging', 'legal', 'targets', 'docs')
SOURCE_FILES = ('PROJECT_ID', 'VERSION', 'RELEASE', 'project.json', 'homegate-version.mk',
                'Makefile', 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES', '.gitattributes', '.gitignore',
                '公开文件清单.json')
EXCLUDED = {'.git', '__pycache__', 'build', 'dist', 'node_modules', '.venv', '.aws', '.codex'}
PUBLIC_MANIFEST = '公开文件清单.json'
PRIVATE_PREFIXES = ('docs/验证/', 'targets/evidence/', '.github/reference/')
FORBIDDEN_SUFFIXES = ('.ipk', '.apk', '.exe', '.o', '.pyc', '.zip', '.pem', '.key', '.log', '.png')


def public_files(root):
    """Explicit publication list; local additions never silently become public."""
    data = json.loads((root / PUBLIC_MANIFEST).read_text(encoding='utf-8'))
    names = data.get('files') if isinstance(data, dict) else None
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ValueError('Invalid public source manifest')
    if data.get('schema') != 1 or names != sorted(set(names)):
        raise ValueError('Public source manifest must be sorted and unique')
    if not set(SOURCE_FILES).issubset(names):
        raise ValueError('Missing required public source')
    files = []
    for name in names:
        relative = PurePosixPath(name)
        if (not name or name != relative.as_posix() or relative.is_absolute()
                or '..' in relative.parts or '\\' in name or ':' in name
                or any(ord(c) < 32 for c in name)
                or name in DOCS or name.startswith(PRIVATE_PREFIXES)
                or set(relative.parts) & EXCLUDED
                or relative.name in ('.gitkeep', '.env')
                or relative.suffix.lower() in FORBIDDEN_SUFFIXES
                or (relative.parts[0] not in SOURCE_DIRS and name not in SOURCE_FILES)):
            raise ValueError('Forbidden public source: ' + name)
        file = root / name
        if any((root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
            raise ValueError('Symlink not allowed in public source: ' + name)
        if not file.is_file():
            raise ValueError('Missing public source: ' + name)
        files.append(file)
    return files


def create_public(root, output, target, stage):
    """Public source only, with hashes; deliberately not a private handoff."""
    verify_generated(root)
    item = identity(root)
    if not all(c.isalnum() or c in '._-' for c in target + stage) or not target or not stage:
        raise ValueError('Invalid target/stage')
    entries = {'源码/' + file.relative_to(root).as_posix(): file.read_bytes() for file in public_files(root)}
    entries['源码清单.sha256'] = ''.join(
        hashlib.sha256(body).hexdigest() + '  ' + name + '\n'
        for name, body in sorted(entries.items())
    ).encode('utf-8')
    output.mkdir(parents=True, exist_ok=True)
    result = output / f"{item['slug']}_{item['normalized']}_{target}_{stage}_公开源码.zip"
    with result.open('xb') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, body in sorted(entries.items()):
                info = zipfile.ZipInfo(name, (2026, 10, 11, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                executable = name.endswith('.sh') or body.startswith(b'#!/bin/sh')
                info.external_attr = (0o100755 if executable else 0o100644) << 16
                archive.writestr(info, body)
    return result


def check_public_tree(root):
    expected = {file.relative_to(root).as_posix() for file in public_files(root)}
    result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], check=True, stdout=subprocess.PIPE)
    tracked = set(result.stdout.decode('utf-8').strip('\0').split('\0'))
    if tracked != expected:
        raise ValueError('Public repository differs from manifest; extra=' + repr(sorted(tracked - expected))
                         + '; missing=' + repr(sorted(expected - tracked)))


def source_files(root):
    for name in SOURCE_FILES:
        item = root / name
        if not item.is_file():
            raise ValueError('Missing required source: ' + name)
        yield item
    for name in SOURCE_DIRS:
        directory = root / name
        if not directory.is_dir():
            raise ValueError('Missing source directory: ' + name)
        for file in sorted(directory.rglob('*')):
            if file.is_symlink():
                raise ValueError('Symlink not allowed in source snapshot: ' + str(file))
            if not file.is_file() or set(file.relative_to(root).parts) & EXCLUDED:
                continue
            if file.suffix.lower() in ('.ipk', '.apk', '.exe', '.o', '.pyc', '.zip', '.pem', '.key'):
                raise ValueError('Unexpected binary/secret/archive in source: ' + str(file))
            yield file


def create(root, output, target, stage, draft, packages_dir=None, fmt=None, architecture=None, apk='apk'):
    verify_generated(root)
    item = identity(root)
    document_root = root if all((root / name).is_file() for name in DOCS) else root.parent
    for name in DOCS:
        if not (document_root / name).is_file():
            raise ValueError('Missing handoff document: ' + name)
    if draft and packages_dir:
        raise ValueError('草稿不能携带安装包')
    project = json.loads((root / 'project.json').read_text(encoding='utf-8'))
    entries = {'源码/' + file.relative_to(root).as_posix(): file.read_bytes() for file in source_files(root)}
    for name in DOCS:
        entries[name] = (document_root / name).read_bytes()
    entries['校验.md'] = entries['校验.md'].decode('utf-8').split('\n## 自动快照清单', 1)[0].encode('utf-8')
    if draft:
        state = '草稿：未附安装包；完整产品迁移、正式目标三包及实机验收尚未完成。独立工程包状态见接续.md。'
    else:
        if not project.get('core', {}).get('migration_complete'):
            raise ValueError('核心迁移未完成，只允许草稿快照')
        if not packages_dir or not fmt or not architecture:
            raise ValueError('完整快照缺少真实三包、包格式或架构')
        spec = importlib.util.spec_from_file_location('package_checker', root / 'scripts/检查三包.py')
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        packages, _ = checker.inspect(packages_dir, item['slug'], item['normalized'], fmt, architecture, apk)
        for file in packages:
            entries['测试安装包/' + file.name] = file.read_bytes()
        state = '已含三包：元数据一致；实机验收状态见接续.md。'
    manifest = ['\n## 自动快照清单', '', '> ' + state, '']
    for name, body in sorted(entries.items()):
        if name != '校验.md':
            manifest.append(f'- `{name}`：`{hashlib.sha256(body).hexdigest()}`')
    entries['校验.md'] += ('\n'.join(manifest) + '\n').encode('utf-8')
    filename = f"{item['slug']}_{item['normalized']}_{target}_{stage}_{'草稿' if draft else '三包'}.zip"
    if not all(c.isalnum() or c in '._-' for c in target + stage) or not target or not stage:
        raise ValueError('Invalid target/stage')
    output.mkdir(parents=True, exist_ok=True)
    result = output / filename
    with result.open('xb') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, body in sorted(entries.items()):
                info = zipfile.ZipInfo(name, (2026, 10, 11, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                executable = name.endswith('.sh') or body.startswith(b'#!/bin/sh')
                info.external_attr = (0o100755 if executable else 0o100644) << 16
                archive.writestr(info, body)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    parser.add_argument('--target', required=True)
    parser.add_argument('--stage', required=True)
    parser.add_argument('--draft', action='store_true')
    parser.add_argument('--public-source', action='store_true', help='仅公开清单内源码，不读取本地接续/验证资料')
    parser.add_argument('--check-public-tree', action='store_true', help='同时要求 Git 跟踪文件与公开清单完全一致')
    parser.add_argument('--packages-dir', type=Path)
    parser.add_argument('--format', choices=('ipk', 'apk'))
    parser.add_argument('--architecture')
    parser.add_argument('--apk', default='apk')
    args = parser.parse_args()
    try:
        if args.public_source:
            if args.draft or args.packages_dir or args.format or args.architecture:
                raise ValueError('公开源码模式不能与接续草稿/三包参数混用')
            if args.check_public_tree:
                check_public_tree(args.root.resolve())
            result = create_public(args.root.resolve(), args.output_dir.resolve(), args.target, args.stage)
        else:
            if args.check_public_tree:
                raise ValueError('公开树检查仅用于公开源码模式')
            result = create(args.root.resolve(), args.output_dir.resolve(), args.target, args.stage,
                            args.draft, args.packages_dir, args.format, args.architecture, args.apk)
        print(result)
        print('SHA256: ' + hashlib.sha256(result.read_bytes()).hexdigest())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f'生成失败：{exc}', file=sys.stderr)
        sys.exit(2)
