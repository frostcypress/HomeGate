#!/usr/bin/env python3
"""Validate actual package metadata, not names. APK3 needs apk adbdump --format json."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import sys

LIMIT = 1024 * 1024


def fields(body, separator=':'):
    result = {}
    previous = None
    for line in body.decode('utf-8').splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        if separator == ':' and line[:1].isspace() and previous is not None:
            result[previous] += ' ' + line.strip()
            continue
        if separator not in line:
            raise ValueError('Malformed metadata')
        key, value = line.split(separator, 1)
        key, value = key.strip(), value.strip()
        if key in result:
            raise ValueError('Duplicate metadata field: ' + key)
        result[key] = value
        previous = key
    return result


def ar_members(blob):
    if not blob.startswith(b'!<arch>\n'):
        raise ValueError('Not an ar package')
    position, result = 8, {}
    while position < len(blob):
        header = blob[position:position + 60]
        if len(header) != 60 or header[58:60] != b'`\n':
            raise ValueError('Malformed ar header')
        try:
            name = header[:16].decode('ascii').strip().rstrip('/')
            size = int(header[48:58].decode('ascii').strip())
        except (ValueError, UnicodeError) as exc:
            raise ValueError('Malformed ar member') from exc
        position += 60
        if size < 0 or position + size > len(blob) or name in result:
            raise ValueError('Invalid ar member size/name')
        result[name] = blob[position:position + size]
        position += size + size % 2
    return result


def tar_member(blob, name, presence_only=False):
    found = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:*') as archive:
        for entry in archive:
            if entry.name.removeprefix('./') != name:
                continue
            if not entry.isfile() or entry.size > (32 * LIMIT if presence_only else LIMIT):
                raise ValueError('Unsafe metadata member')
            found.append(b'' if presence_only else archive.extractfile(entry).read(LIMIT + 1))
    if len(found) != 1 or len(found[0]) > LIMIT:
        raise ValueError('Missing/duplicate metadata member: ' + name)
    return found[0]


def metadata(file, fmt, apk='apk'):
    if file.stat().st_size > 32 * LIMIT:
        raise ValueError('Package exceeds inspection size limit')
    blob = file.read_bytes()
    if fmt == 'ipk':
        if blob.startswith(b'!<arch>\n'):
            members = ar_members(blob)
            if members.get('debian-binary') != b'2.0\n':
                raise ValueError('Wrong IPK format version')
            controls = [value for name, value in members.items() if name.startswith('control.tar.')]
            if len(controls) != 1 or sum(name.startswith('data.tar.') for name in members) != 1:
                raise ValueError('Missing/duplicate control/data archive')
            control = tar_member(controls[0], 'control')
        else:
            if tar_member(blob, 'debian-binary') != b'2.0\n':
                raise ValueError('Wrong IPK format version')
            tar_member(blob, 'data.tar.gz', presence_only=True)
            control = tar_member(tar_member(blob, 'control.tar.gz'), 'control')
        info = fields(control)
        return {'name': info.get('Package'), 'version': info.get('Version'),
                'arch': info.get('Architecture'), 'depends': info.get('Depends', '')}
    # Decoder is an official tool. Never infer APK3 metadata from its filename.
    result = subprocess.run([apk, 'adbdump', '--format', 'json', str(file)],
                            capture_output=True, timeout=30, check=True)
    if len(result.stdout) > 4 * LIMIT:
        raise ValueError('APK decoder output exceeds limit')
    document = json.loads(result.stdout)
    info = document.get('info') if isinstance(document, dict) else None
    if not isinstance(info, dict):
        raise ValueError('Unsupported APK3 metadata schema; verify apk-tools version')
    deps = info.get('depends', [])
    if not isinstance(deps, (str, list)):
        raise ValueError('Invalid APK dependencies')
    if isinstance(deps, list) and not all(isinstance(value, str) for value in deps):
        raise ValueError('Unsupported APK dependency encoding')
    return {'name': info.get('name'), 'version': info.get('version'),
            'arch': info.get('arch'), 'depends': deps if isinstance(deps, str) else ' '.join(deps)}


def inspect(directory, slug, version, fmt, architecture=None, apk='apk'):
    if not re.fullmatch(r'[a-z][a-z0-9-]*', slug) or fmt not in ('ipk', 'apk'):
        raise ValueError('Invalid project identity/format')
    names = {f'{slug}-core', f'luci-app-{slug}', f'luci-i18n-{slug}-zh-cn'}
    packages = sorted(p for p in Path(directory).rglob('*') if p.is_file() and p.suffix in ('.ipk', '.apk'))
    if len(packages) != 3 or any(p.suffix != '.' + fmt for p in packages):
        raise ValueError('输入必须只包含当前目标的三个同格式安装包')
    reports, seen = [], set()
    for file in packages:
        info = metadata(file, fmt, apk)
        name = info['name']
        if name not in names or name in seen or info['version'] != version:
            raise ValueError(f'包名/版本重复或不一致：{file.name}: {info}')
        seen.add(name)
        arch = info['arch']
        if not isinstance(arch, str) or not arch:
            raise ValueError('Missing package architecture')
        if name == slug + '-core':
            if architecture is None or arch != architecture:
                raise ValueError('Core 架构必须与核实目标完全一致')
        elif arch not in ('all', 'noarch'):
            raise ValueError('LuCI/语言包必须为无架构包')
        if name != slug + '-core' and not re.search(r'(?<![\w-])' + re.escape(slug + '-core') + r'(?![\w-])', info['depends']):
            raise ValueError('LuCI/语言包未声明 Core 依赖')
        reports.append({'file': file.name, **info,
                        'sha256': hashlib.sha256(file.read_bytes()).hexdigest()})
    return packages, reports


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', type=Path, required=True)
    parser.add_argument('--slug', required=True)
    parser.add_argument('--version', required=True, help='Exact native SDK metadata version')
    parser.add_argument('--format', choices=('ipk', 'apk'), required=True)
    parser.add_argument('--architecture', required=True)
    parser.add_argument('--apk', default='apk')
    parser.add_argument('--collect-to', type=Path)
    args = parser.parse_args()
    try:
        packages, report = inspect(args.dir, args.slug, args.version, args.format, args.architecture, args.apk)
        if args.collect_to:
            args.collect_to.mkdir(parents=True, exist_ok=True)
            for file in packages:
                destination = args.collect_to / file.name
                if file.resolve() != destination.resolve():
                    if destination.exists():
                        raise ValueError('Refusing to overwrite existing package: ' + str(destination))
                    shutil.copy2(file, destination)
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        print(f'校验失败：{exc}', file=sys.stderr)
        sys.exit(2)
