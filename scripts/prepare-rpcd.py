#!/usr/bin/env python3
"""Build pinned host rpcd/ubus dependencies in a private directory, without installing packages."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from project import ROOT

spec = importlib.util.spec_from_file_location('prepare_ucode', ROOT / 'scripts/prepare-ucode.py')
ucode = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ucode)

# OpenWrt v25.12.0 package source pins; host validation does not establish target compatibility.
COMPONENTS = {
    'libubox': ('2026-02-13', '1aa36ee774c8db4d7a396903e0d2e1fb79ee8bf1',
                'fb43a86d13bbbf16d47358caa2fe7eec3b802e3a57ba5142520add159469c927'),
    'ubus': ('2025-12-02', '3cc98db1a422dcf560f2d6347fd410f17565a89d',
             '25a204888b41e9a432ee0b8d03c1e0f09ae9aaae6a306c41781d680b632b82ae'),
    'uci': ('2025-12-02', '66127cd76c5d0bd46d5a90302cc6110f53a4e2f8',
            'ff23a9825aeac8da14a7142e985d598043c0287a463279f24863c580622bf18d'),
    'rpcd': ('2025-12-03', 'ffb9961c1f8bc50830fdd4e144570f11062c2601',
             '1a701b15746f34eb19532f195d738611364a18acaf45c0197626c31ab59976ce'),
}
RECIPE = 1
REQUIRED = ('prefix/sbin/rpcd', 'prefix/sbin/ubusd', 'prefix/bin/ubus',
            'prefix/lib/rpcd/ucode.so', 'prefix/lib/libucode.so.0', 'prefix/lib/ucode/fs.so')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_runtime(work):
    data = json.loads((work / 'build-metadata.json').read_text(encoding='utf-8'))
    if data.get('recipe') != RECIPE or data.get('components') != {k: list(v) for k, v in COMPONENTS.items()}:
        raise ValueError('Pinned RPC runtime metadata mismatch')
    for name, (_, _, digest) in COMPONENTS.items():
        if sha(work / (name + '.tar.zst')) != digest:
            raise ValueError('Pinned RPC archive changed: ' + name)
    artifacts = data.get('artifacts', {})
    if not set(REQUIRED).issubset(artifacts):
        raise ValueError('Incomplete RPC runtime metadata')
    actual = {str(p.relative_to(work)): sha(p) for p in (work / 'prefix').rglob('*') if p.is_file()}
    if actual != artifacts:
        raise ValueError('Pinned RPC installed artifacts changed')
    links = {str(p.relative_to(work)): os.readlink(p) for p in (work / 'prefix').rglob('*') if p.is_symlink()}
    if links != data.get('symlinks'):
        raise ValueError('Pinned RPC installed symlinks changed')
    return data


def prepare(work, native):
    if sys.platform != 'linux' or os.getuid() == 0:
        raise ValueError('Build the host RPC runtime as a non-root Linux user')
    work, native = work.resolve(), native.resolve()
    ucode.validate_runtime(native)
    if (work / 'build-metadata.json').is_file():
        data = validate_runtime(work)
        if data['ucode_artifacts'] != ucode.validate_runtime(native)['artifacts']:
            raise ValueError('Reused ucode runtime differs from RPC build')
        return {'runtime': str(work), 'reused': True}
    if (work / 'prefix').exists() or any(work.glob('*-source')):
        raise ValueError('Incomplete RPC build retained; choose a new runtime directory')
    for tool in ('cmake', 'make', 'cc', 'pkg-config', 'zstd'):
        if not shutil.which(tool):
            raise ValueError('Missing host build tool: ' + tool)
    work.mkdir(parents=True, exist_ok=True)
    prefix = work / 'prefix'
    (prefix / 'lib/ucode').mkdir(parents=True)
    shutil.copyfile(native / 'out/libucode.so.0', prefix / 'lib/libucode.so.0')
    (prefix / 'lib/libucode.so').symlink_to('libucode.so.0')
    shutil.copyfile(native / 'out/fs.so', prefix / 'lib/ucode/fs.so')
    # Extract headers from the verified archive, not from a mutable prior build tree.
    with tarfile.open(native / 'source.tar.gz') as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts
            if member.isfile() and len(parts) == 4 and parts[1:3] == ('include', 'ucode') and parts[-1].endswith('.h'):
                target = prefix / 'include/ucode' / parts[-1]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
    with (work / 'build.log').open('xb') as log:
        for name, (date, revision, digest) in COMPONENTS.items():
            print('Preparing pinned host component: ' + name, flush=True)
            archive = work / (name + '.tar.zst')
            if not archive.exists():
                pending = work / (name + '.tar.zst.pending')
                url = 'https://sources.openwrt.org/' + name + '-' + date.replace('-', '.') + '~' + revision[:8] + '.tar.zst'
                request = urllib.request.Request(url, headers={'User-Agent': 'HomeGate-host-rpc-check'})
                with pending.open('xb') as output, urllib.request.urlopen(request, timeout=60) as response:
                    shutil.copyfileobj(response, output)
                if sha(pending) != digest:
                    raise ValueError('RPC source SHA256 mismatch: ' + name)
                pending.rename(archive)
            if sha(archive) != digest:
                raise ValueError('Cached RPC source SHA256 mismatch: ' + name)
            plain = work / (name + '.tar')
            with plain.open('xb') as output:
                subprocess.run(['zstd', '-dc', str(archive)], stdout=output, stderr=log, check=True)
            staging = work / (name + '-extracting')
            staging.mkdir()
            with tarfile.open(plain) as bundle:
                bundle.extractall(staging, filter='data')
            roots = list(staging.iterdir())
            if len(roots) != 1 or not (roots[0] / 'CMakeLists.txt').is_file():
                raise ValueError('Unexpected RPC source layout: ' + name)
            source = work / (name + '-source')
            roots[0].rename(source)
            staging.rmdir()
            options = ['-DBUILD_LUA=OFF', '-DBUILD_EXAMPLES=OFF']
            if name == 'rpcd':
                options += ['-DFILE_SUPPORT=OFF', '-DIWINFO_SUPPORT=OFF', '-DRPCSYS_SUPPORT=OFF', '-DUCODE_SUPPORT=ON']
            commands = [
                ['cmake', '-S', str(source), '-B', str(work / (name + '-out')),
                 '-DCMAKE_INSTALL_PREFIX=' + str(prefix), '-DCMAKE_PREFIX_PATH=' + str(prefix),
                 '-DCMAKE_INSTALL_RPATH=' + str(prefix / 'lib'), *options],
                ['cmake', '--build', str(work / (name + '-out')), '-j2'],
                ['cmake', '--install', str(work / (name + '-out'))],
            ]
            for command in commands:
                log.write((json.dumps(command) + '\n').encode())
                log.flush()
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    for directory in ('share/rpcd/ucode', 'share/rpcd/acl.d'):
        (prefix / directory).mkdir(parents=True, exist_ok=True)
    data = {'recipe': RECIPE, 'components': {k: list(v) for k, v in COMPONENTS.items()},
            'scope': 'Isolated Linux host rpcd/ubus; no HTTP authorization or target SDK acceptance',
            'ucode_artifacts': ucode.validate_runtime(native)['artifacts'],
            'artifacts': {str(p.relative_to(work)): sha(p) for p in prefix.rglob('*') if p.is_file()},
            'symlinks': {str(p.relative_to(work)): os.readlink(p) for p in prefix.rglob('*') if p.is_symlink()}}
    (work / 'build-metadata.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    validate_runtime(work)
    return {'runtime': str(work), 'reused': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'build/rpcd')
    parser.add_argument('--ucode-runtime-dir', type=Path, default=ROOT / 'build/ucode')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.runtime_dir, args.ucode_runtime_dir)))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
