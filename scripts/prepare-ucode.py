#!/usr/bin/env python3
"""Build or verify the pinned host ucode runtime; never install system packages."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from project import ROOT

REVISION = '85922056ef7abeace3cca3ab28bc1ac2d88e31b1'
ARCHIVE_SHA256 = '54dda1e8a2757710c285659e42336f5054f1825f20d01a4016245bbf877f6da7'
URL = 'https://codeload.github.com/jow-/ucode/tar.gz/' + REVISION
ARTIFACTS = ('out/ucode', 'out/fs.so', 'out/libucode.so.0')
RECIPE = 1


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_runtime(work):
    data = json.loads((work / 'build-metadata.json').read_text(encoding='utf-8'))
    if (data.get('recipe') != RECIPE or data.get('revision') != REVISION
            or data.get('archive_sha256') != ARCHIVE_SHA256
            or sha(work / 'source.tar.gz') != ARCHIVE_SHA256
            or set(data.get('artifacts', {})) != set(ARTIFACTS)):
        raise ValueError('Pinned ucode runtime metadata mismatch')
    for name in ARTIFACTS:
        if sha(work / name) != data['artifacts'][name]:
            raise ValueError('Pinned ucode artifact changed: ' + name)
    return data


def prepare(work):
    if sys.platform != 'linux':
        raise ValueError('Prepare the host runtime on Linux')
    work = work.resolve()
    if (work / 'build-metadata.json').is_file():
        validate_runtime(work)
        return {'runtime': str(work), 'reused': True, 'revision': REVISION}
    if any((work / name).exists() for name in ('source', 'out', 'extracting')):
        raise ValueError('Incomplete or unverified build retained; use a new runtime directory')
    for tool in ('cmake', 'make', 'cc', 'pkg-config'):
        if not shutil.which(tool):
            raise ValueError('Missing host build tool: ' + tool)
    work.mkdir(parents=True, exist_ok=True)
    archive = work / 'source.tar.gz'
    if not archive.exists():
        pending = work / 'source.tar.gz.pending'
        request = urllib.request.Request(URL, headers={'User-Agent': 'HomeGate-host-ucode-check'})
        with pending.open('xb') as output, urllib.request.urlopen(request, timeout=60) as response:
            shutil.copyfileobj(response, output)
        if sha(pending) != ARCHIVE_SHA256:
            raise ValueError('ucode source SHA256 mismatch; downloaded evidence retained')
        pending.rename(archive)
    if sha(archive) != ARCHIVE_SHA256:
        raise ValueError('Cached ucode archive SHA256 mismatch')
    staging = work / 'extracting'
    staging.mkdir()
    with tarfile.open(archive) as bundle:
        bundle.extractall(staging, filter='data')
    roots = list(staging.iterdir())
    if len(roots) != 1 or not (roots[0] / 'CMakeLists.txt').is_file():
        raise ValueError('Unexpected pinned ucode source layout')
    roots[0].rename(work / 'source')
    staging.rmdir()
    options = ['-DFS_SUPPORT=ON'] + ['-D' + name + '_SUPPORT=OFF' for name in (
        'UBUS', 'UCI', 'ULOOP', 'NL80211', 'RESOLV', 'RTNL', 'DEBUG', 'LOG', 'DIGEST', 'SOCKET')]
    commands = [
        ['cmake', '-S', str(work / 'source'), '-B', str(work / 'out'), *options],
        ['cmake', '--build', str(work / 'out'), '-j2'],
    ]
    with (work / 'build.log').open('xb') as log:
        for command in commands:
            log.write((json.dumps(command) + '\n').encode())
            log.flush()
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    data = {'recipe': RECIPE, 'revision': REVISION, 'archive_sha256': ARCHIVE_SHA256,
            'scope': 'Linux host; fs only for candidate checks; no rpcd/ubus/target validation',
            'artifacts': {name: sha(work / name) for name in ARTIFACTS}}
    (work / 'build-metadata.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    validate_runtime(work)
    return {'runtime': str(work), 'reused': False, 'revision': REVISION}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'build/ucode')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.runtime_dir)))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
