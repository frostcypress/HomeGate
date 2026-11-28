#!/usr/bin/env python3
"""Pinned Lua LuCI host baseline; private builds, no system installation or target claim."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
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
REVISION = 'e4c46338b196e486a88b1a75b78e283708c82bc4'
SOURCES = {
    'luci': ('https://codeload.github.com/openwrt/luci/tar.gz/' + REVISION,
             '964157d74b0690ea5f9ed8b09284315cabe9edc74e451422dea5875a890e912f'),
    'lucihttp': ('https://sources.openwrt.org/lucihttp-2021-06-11-3dc89af4.tar.xz',
                 '6024a34c514a7231bcc36486abfb3e43e6c17490ac8d838f202a43ce259cda03'),
    'libnl-tiny': ('https://sources.openwrt.org/libnl-tiny-2025.12.02~40493a65.tar.zst',
                   'b45c72c26961fa6eafc14f73693c2fe463912c4cb0488ccea232d61b425c60d5'),
}
RECIPE = 1


def validate_runtime(work, rpc):
    base = rpcd.validate_runtime(rpc)
    data = json.loads((work / 'build-metadata.json').read_text(encoding='utf-8'))
    if (data.get('recipe') != RECIPE or data.get('revision') != REVISION
            or data.get('sources') != {k: list(v) for k, v in SOURCES.items()}
            or data.get('rpc_runtime') != str(rpc.resolve()) or data.get('rpc_artifacts') != base['artifacts']
            or data.get('lua_interpreter_sha256') != sha(Path('/usr/bin/lua5.1'))):
        raise ValueError('Pinned Lua LuCI runtime metadata mismatch')
    for name, (_, digest) in SOURCES.items():
        if sha(work / (name + '.archive')) != digest:
            raise ValueError('Pinned Lua LuCI archive changed: ' + name)
    artifacts = {str(p.relative_to(work)): sha(p) for p in (work / 'prefix').rglob('*') if p.is_file()}
    links = {str(p.relative_to(work)): os.readlink(p) for p in (work / 'prefix').rglob('*') if p.is_symlink()}
    if artifacts != data.get('artifacts') or links != data.get('symlinks'):
        raise ValueError('Pinned Lua LuCI artifacts changed')
    for name in ('nixio.so', 'ubus.so', 'lucihttp.so', 'luci/template/parser.so', 'luci/jsonc.so', 'luci/ip.so'):
        if 'prefix/lib/lua/' + name not in artifacts:
            raise ValueError('Missing Lua LuCI native module: ' + name)
    return data


def prepare(work, rpc):
    if sys.platform != 'linux' or os.getuid() == 0:
        raise ValueError('Build the Lua LuCI host baseline as a non-root Linux user')
    work, rpc = work.resolve(), rpc.resolve()
    base = rpcd.validate_runtime(rpc)
    if (work / 'build-metadata.json').is_file():
        validate_runtime(work, rpc)
        return {'runtime': str(work), 'reused': True}
    if (work / 'prefix').exists() or any(work.glob('*-source')):
        raise ValueError('Incomplete Lua LuCI build retained; choose a new runtime directory')
    for tool in ('cmake', 'make', 'cc', 'pkg-config', 'zstd', 'lua5.1'):
        if not shutil.which(tool):
            raise ValueError('Missing host tool: ' + tool)
    lua_flags = subprocess.check_output(['pkg-config', '--cflags', 'lua5.1'], text=True).strip()
    lua_libs = subprocess.check_output(['pkg-config', '--libs', 'lua5.1'], text=True).strip()
    work.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in SOURCES.items():
        archive = work / (name + '.archive')
        if not archive.exists():
            pending = work / (name + '.pending')
            request = urllib.request.Request(url, headers={'User-Agent': 'HomeGate-Lua-LuCI-host-check'})
            with pending.open('xb') as output, urllib.request.urlopen(request, timeout=60) as response:
                shutil.copyfileobj(response, output)
            if sha(pending) != digest:
                raise ValueError('Lua LuCI source SHA256 mismatch: ' + name)
            pending.rename(archive)
        if sha(archive) != digest:
            raise ValueError('Cached Lua LuCI source SHA256 mismatch: ' + name)
        plain = archive
        if url.endswith('.zst'):
            plain = work / (name + '.tar')
            with plain.open('xb') as output:
                subprocess.run(['zstd', '-dc', str(archive)], stdout=output, check=True)
        staging = work / (name + '-extracting')
        staging.mkdir()
        with tarfile.open(plain) as bundle:
            bundle.extractall(staging, filter='data')
        roots = list(staging.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError('Unexpected Lua LuCI source layout: ' + name)
        roots[0].rename(work / (name + '-source'))
        staging.rmdir()
    prefix = work / 'prefix'
    modules = prefix / 'lib/lua'
    modules.mkdir(parents=True)
    luci = work / 'luci-source'
    rpath = str(prefix / 'lib') + ';' + str(rpc / 'prefix/lib')
    with (work / 'build.log').open('xb') as log:
        def run(command):
            log.write((json.dumps(command) + '\n').encode());log.flush()
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
        for name, options in (
            ('libnl-tiny', []),
            ('lucihttp', ['-DBUILD_LUA=ON', '-DBUILD_TESTS=OFF', '-DLUAPATH=' + str(modules)]),
        ):
            run(['cmake', '-S', str(work / (name + '-source')), '-B', str(work / (name + '-out')),
                 '-DCMAKE_INSTALL_PREFIX=' + str(prefix), '-DCMAKE_PREFIX_PATH=' + str(rpc / 'prefix'),
                 '-DCMAKE_INSTALL_RPATH=' + rpath, *options])
            run(['cmake', '--build', str(work / (name + '-out')), '-j2'])
            run(['cmake', '--install', str(work / (name + '-out'))])
        linkflags = '-L' + str(prefix / 'lib') + ' -Wl,-rpath,' + str(prefix / 'lib') + ' ' + lua_libs + ' -lm'
        for directory, target, options in (
            ('libs/luci-lib-nixio/src', 'compile', ['NIXIO_TLS=', 'NIXIO_LDFLAGS=' + lua_libs + ' -lm -ldl -lcrypt -shared']),
            ('libs/luci-lib-jsonc/src', 'compile', ['JSONC_CFLAGS=-std=gnu99 -I/usr/include/json-c', 'JSONC_LDFLAGS=' + lua_libs + ' -lm -ljson-c']),
            ('libs/luci-lib-ip/src', 'compile', ['IP_CFLAGS=-std=gnu99 -I' + str(prefix / 'include/libnl-tiny'), 'IP_LDFLAGS=' + lua_libs + ' -lm -lnl-tiny']),
            ('modules/luci-base/src', 'parser.so', []),
        ):
            run(['make', '-C', str(luci / directory), '-j2', target, 'FPIC=-fPIC',
                 'CFLAGS=-O2 ' + lua_flags, 'LUA_CFLAGS=' + lua_flags, 'LDFLAGS=' + linkflags, *options])
        # The Lua ubus binding is compiled against the exact previously verified ubus archive.
        # Recreate its source independently of the mutable retained build tree.
        with (work / 'ubus-binding.tar').open('xb') as output:
            subprocess.run(['zstd', '-dc', str(rpc / 'ubus.tar.zst')], stdout=output, check=True)
        binding = work / 'ubus-binding-source';binding.mkdir()
        with tarfile.open(work / 'ubus-binding.tar') as bundle:
            bundle.extractall(binding, filter='data')
        ubus_source = next(binding.iterdir())
        run(['cc', '-shared', '-fPIC', '-Os', '-Wall', '-Werror', '-std=gnu99',
             *shlex.split(lua_flags), '-I' + str(rpc / 'prefix/include'),
             str(ubus_source / 'lua/ubus.c'), '-o', str(modules / 'ubus.so'),
             '-L' + str(rpc / 'prefix/lib'), '-Wl,-rpath,' + str(rpc / 'prefix/lib'), '-lubus', '-lubox'])
    for directory in ('libs/luci-lib-base/luasrc', 'modules/luci-base/luasrc'):
        shutil.copytree(luci / directory, modules / 'luci', dirs_exist_ok=True)
    shutil.copytree(luci / 'libs/luci-lib-nixio/root/usr/lib/lua', modules, dirs_exist_ok=True)
    for source, target in (
        ('libs/luci-lib-nixio/src/nixio.so', 'nixio.so'),
        ('libs/luci-lib-jsonc/src/jsonc.so', 'luci/jsonc.so'),
        ('libs/luci-lib-ip/src/ip.so', 'luci/ip.so'),
        ('modules/luci-base/src/parser.so', 'luci/template/parser.so'),
    ):
        (modules / target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(luci / source, modules / target)
    (modules / 'luci/version.lua').write_text("return {luciname='LuCI host baseline',luciversion='" + REVISION + "'}\n")
    data = {'recipe': RECIPE, 'revision': REVISION, 'sources': {k: list(v) for k, v in SOURCES.items()},
            'scope': 'Pinned official Lua LuCI host baseline; target 09ae68b unresolved; not target or TLS acceptance',
            'rpc_runtime': str(rpc), 'rpc_artifacts': base['artifacts'], 'lua_interpreter_sha256': sha(Path('/usr/bin/lua5.1')),
            'artifacts': {str(p.relative_to(work)): sha(p) for p in prefix.rglob('*') if p.is_file()},
            'symlinks': {str(p.relative_to(work)): os.readlink(p) for p in prefix.rglob('*') if p.is_symlink()}}
    (work / 'build-metadata.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    validate_runtime(work, rpc)
    return {'runtime': str(work), 'reused': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'build/luci')
    parser.add_argument('--rpc-runtime-dir', type=Path, default=ROOT / 'build/rpcd')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.runtime_dir, args.rpc_runtime_dir)))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr);sys.exit(2)
