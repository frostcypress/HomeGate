#!/usr/bin/env python3
"""Build pinned HTTP/ubus host tools with existing verified RPC libraries; no system install."""
import argparse
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

spec = importlib.util.spec_from_file_location('prepare_rpcd', ROOT / 'scripts/prepare-rpcd.py')
rpcd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rpcd)
sha = rpcd.sha
REVISION = 'ebb92e6b339b88bbc6b76501b6603c52d4887ba1'
ARCHIVE_SHA256 = '2d00da72db0ec08132bb169f2bad0b153bd998ea1eee0700b4ec01e65c35127d'
URL = 'https://sources.openwrt.org/uhttpd-2025.10.03~ebb92e6b.tar.zst'
RECIPE = 1


def validate_runtime(work, rpc):
    base = rpcd.validate_runtime(rpc)
    data = json.loads((work / 'build-metadata.json').read_text(encoding='utf-8'))
    if (data.get('recipe') != RECIPE or data.get('revision') != REVISION
            or data.get('archive_sha256') != ARCHIVE_SHA256
            or sha(work / 'source.tar.zst') != ARCHIVE_SHA256
            or data.get('rpc_runtime') != str(rpc.resolve())
            or data.get('rpc_artifacts') != base['artifacts']):
        raise ValueError('Pinned HTTP runtime metadata mismatch')
    actual = {str(p.relative_to(work)): sha(p) for p in (work / 'prefix').rglob('*') if p.is_file()}
    if set(actual) != {'prefix/bin/uhttpd', 'prefix/lib/uhttpd_ubus.so'} or actual != data.get('artifacts'):
        raise ValueError('Pinned HTTP runtime artifacts changed')
    if any(p.is_symlink() for p in (work / 'prefix').rglob('*')):
        raise ValueError('Unexpected HTTP runtime symlink')
    return data


def prepare(work, rpc):
    if sys.platform != 'linux' or os.getuid() == 0:
        raise ValueError('Build host HTTP tools as a non-root Linux user')
    work, rpc = work.resolve(), rpc.resolve()
    base = rpcd.validate_runtime(rpc)
    if (work / 'build-metadata.json').is_file():
        validate_runtime(work, rpc)
        return {'runtime': str(work), 'reused': True}
    if any((work / name).exists() for name in ('source', 'out', 'prefix', 'extracting')):
        raise ValueError('Incomplete HTTP build retained; choose a new runtime directory')
    for tool in ('cmake', 'make', 'cc', 'pkg-config', 'zstd'):
        if not shutil.which(tool):
            raise ValueError('Missing host build tool: ' + tool)
    work.mkdir(parents=True, exist_ok=True)
    archive = work / 'source.tar.zst'
    if not archive.exists():
        pending = work / 'source.tar.zst.pending'
        request = urllib.request.Request(URL, headers={'User-Agent': 'HomeGate-host-HTTP-check'})
        with pending.open('xb') as output, urllib.request.urlopen(request, timeout=60) as response:
            shutil.copyfileobj(response, output)
        if sha(pending) != ARCHIVE_SHA256:
            raise ValueError('HTTP source SHA256 mismatch; evidence retained')
        pending.rename(archive)
    if sha(archive) != ARCHIVE_SHA256:
        raise ValueError('Cached HTTP source SHA256 mismatch')
    with (work / 'source.tar').open('xb') as output:
        subprocess.run(['zstd', '-dc', str(archive)], stdout=output, check=True)
    staging = work / 'extracting'
    staging.mkdir()
    with tarfile.open(work / 'source.tar') as bundle:
        bundle.extractall(staging, filter='data')
    roots = list(staging.iterdir())
    if len(roots) != 1 or not (roots[0] / 'CMakeLists.txt').is_file():
        raise ValueError('Unexpected pinned HTTP source layout')
    roots[0].rename(work / 'source')
    staging.rmdir()
    prefix = work / 'prefix'
    commands = [
        ['cmake', '-S', str(work / 'source'), '-B', str(work / 'out'),
         '-DCMAKE_INSTALL_PREFIX=' + str(prefix), '-DCMAKE_PREFIX_PATH=' + str(rpc / 'prefix'),
         '-DCMAKE_INSTALL_RPATH=' + str(prefix / 'lib') + ';' + str(rpc / 'prefix/lib'),
         '-DTLS_SUPPORT=OFF', '-DLUA_SUPPORT=OFF', '-DUCODE_SUPPORT=OFF', '-DUBUS_SUPPORT=ON'],
        ['cmake', '--build', str(work / 'out'), '-j2'],
        ['cmake', '--install', str(work / 'out')],
    ]
    with (work / 'build.log').open('xb') as log:
        for command in commands:
            log.write((json.dumps(command) + '\n').encode())
            log.flush()
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    data = {'recipe': RECIPE, 'revision': REVISION, 'archive_sha256': ARCHIVE_SHA256,
            'scope': 'Isolated host HTTP/ubus; TLS, Lua/LuCI and target not tested',
            'rpc_runtime': str(rpc), 'rpc_artifacts': base['artifacts'],
            'artifacts': {str(p.relative_to(work)): sha(p) for p in prefix.rglob('*') if p.is_file()}}
    (work / 'build-metadata.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    validate_runtime(work, rpc)
    return {'runtime': str(work), 'reused': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'build/uhttpd')
    parser.add_argument('--rpc-runtime-dir', type=Path, default=ROOT / 'build/rpcd')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.runtime_dir, args.rpc_runtime_dir)))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
