#!/usr/bin/env python3
"""Build the native packages for a pinned candidate or an accepted target."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from project import ROOT, identity, selected_sdk_series, verify_generated
from production_runtime import stage_sdk
from native_transition import build_offline_bundle, write_offline_archive
from online_release import PUBLIC_KEY_PATH, describe_bundle, public_key

CANDIDATE_TARGET = ROOT / 'targets/qwrt-r26.3.8-ipq807x.json'
CANDIDATE_INPUTS = ROOT / 'targets/native-candidate-24.10.6-ipq807x.json'
SDK_HOST_BIN = ('staging_dir', 'host', 'bin')
SDK_HOST_TOOLS = frozenset('awk bash cp diff egrep file gcc g++ getopt git grep gzip install ldconfig perl python python3 realpath rsync seq stat unzip wget which xxd'.split())


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate_feeds(target_file, target, frontend, fmt):
    verify_generated(ROOT)
    if target_file.resolve() != CANDIDATE_TARGET or frontend != 'lua' or fmt not in ('ipk', 'auto'):
        raise ValueError('候选构建仅支持当前 QWRT 目标的 Lua/IPK 组合')
    if target.get('package_format') != 'ipk' or target.get('architecture') != 'aarch64_cortex-a53':
        raise ValueError('候选目标的包格式或架构与 SDK 配方不一致')
    pins = json.loads(CANDIDATE_INPUTS.read_text(encoding='utf-8'))
    if (pins['scope'] != 'native-source-candidate-package-verification'
        or pins['release_authorized'] is not False or pins['QWRT_runtime_ABI_verified'] is not False
        or pins['sdk']['version'].rsplit('.', 1)[0] != selected_sdk_series('ipk', ROOT)
        or any(target['sdk'].get(key) != pins['sdk'][key] for key in ('url', 'sha256', 'version'))):
        raise ValueError('候选构建的 SDK 固定输入与目标清单不一致')
    return pins['feeds']


def checked_input(work, filename, url, expected_hash, cache):
    path = (cache / filename) if cache else None
    if path is None or not path.is_file():
        path = work / filename
        with urllib.request.urlopen(url, timeout=120) as response, path.open('xb') as output:
            shutil.copyfileobj(response, output)
    with path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected_hash:
            raise ValueError('输入 SHA-256 校验失败：' + filename)
    return path.resolve()


def configure_candidate_feeds(work, sdk, feeds, cache):
    config = []
    for name, feed in feeds.items():
        archive = checked_input(work, name + '-' + feed['commit'] + '.tar.gz', feed['archive_url'], feed['archive_sha256'], cache)
        directory = work / 'feeds' / name
        directory.mkdir(parents=True)
        with tarfile.open(archive) as bundle:
            bundle.extractall(directory, filter='data')
        sources = list(directory.iterdir())
        if len(sources) != 1 or not sources[0].is_dir():
            raise ValueError('固定 feed 归档的目录布局不正确：' + name)
        source = sources[0] / 'package' if name == 'base' else sources[0]
        config.append(f'src-link {name} {source}\n')
    (sdk / 'feeds.conf').write_text(''.join(config), encoding='utf-8')


def unpack_sdk(archive, destination):
    host_links = set()

    def archive_filter(member, path):
        parts = PurePosixPath(member.name).parts
        if (member.issym() and member.linkname.startswith('/')
            and parts[1:-1] == SDK_HOST_BIN and parts[-1] in SDK_HOST_TOOLS):
            # The SDK records paths from its build host. Restore these tools
            # after extraction so an archive link cannot redirect any writes.
            host_links.add(parts[-1])
            return None
        return tarfile.data_filter(member, path)

    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter=archive_filter)
    roots = [p.parent for p in destination.glob('*/rules.mk')]
    if len(roots) != 1:
        raise ValueError('SDK root is ambiguous')
    sdk = roots[0]
    aliases = {'awk': 'gawk', 'python': 'python3'}
    for name in sorted(host_links):
        tool = sdk / 'scripts/noop.sh' if name == 'ldconfig' else shutil.which(aliases.get(name, name))
        if not tool or not os.access(tool, os.X_OK):
            raise ValueError('SDK 需要构建机工具：' + name)
        sdk.joinpath(*SDK_HOST_BIN, name).symlink_to(Path(tool).absolute())
    return sdk


def build(target_file, frontend, fmt, *, candidate=False, cache=None, update_public_key=None):
    target = json.loads(target_file.read_text(encoding='utf-8'))
    if candidate:
        if os.name != 'posix' or os.getuid() == 0:
            raise ValueError('候选构建需要非特权 Linux 用户')
        feeds = candidate_feeds(target_file, target, frontend, fmt)
        actual = 'ipk'
    else:
        actual = load_script('检查发布条件').validate(target, frontend, fmt)
    if (frontend, actual) != ('lua', 'ipk'):
        raise ValueError('当前原生配方只接通 Lua LuCI 与 IPK，所选组合尚未完成构建接合')
    item = identity()
    destination = ROOT / 'dist/target'
    if destination.exists():
        raise ValueError('Output exists; use a clean build workspace')
    with tempfile.TemporaryDirectory(prefix='homegate-sdk-') as directory:
        work = Path(directory)
        if update_public_key is not None:
            key_bytes = public_key(update_public_key)
            update_public_key = work / 'update-public.pem'
            update_public_key.write_bytes(key_bytes)
        archive = checked_input(work, 'sdk.tar', target['sdk']['url'], target['sdk']['sha256'], cache)
        extracted = work / 'sdk'
        extracted.mkdir()
        with archive.open('rb') as stream:
            compressed_with_zstd = stream.read(4) == b'\x28\xb5\x2f\xfd'
        if compressed_with_zstd:
            tar_path = work / 'sdk-uncompressed.tar'
            with tar_path.open('xb') as stream:
                subprocess.run(['zstd', '-d', '-c', str(archive)], stdout=stream, check=True, timeout=120)
            archive = tar_path
        sdk = unpack_sdk(archive, extracted)
        stage_sdk(ROOT, sdk, bundled=True, update_public_key=update_public_key)
        if candidate:
            configure_candidate_feeds(work, sdk, feeds, cache)
        names = (item['slug'] + '-core', 'luci-app-' + item['slug'], 'luci-i18n-' + item['slug'] + '-zh-cn')
        components = ('homegate-nginx', 'homegate-wol')
        packages = (*components, 'homegate-native-candidate')
        selected = (*names, *components)
        if candidate:
            packages = ('feeds/base/openssl', 'feeds/base/pcre2', *packages)
            selected += ('libopenssl', 'libpcre2')
        config = sdk / '.config'
        settings = config.read_text(encoding='utf-8') if config.exists() else ''
        if candidate:
            # The SDK defaults select all packages and kernel modules.
            for option in ('ALL', 'ALL_NONSHARED', 'ALL_KMODS'):
                settings = re.sub(rf'^(?:CONFIG_{option}=.*|# CONFIG_{option} is not set)\n?', '', settings, flags=re.M)
                settings += f'\n# CONFIG_{option} is not set\n'
        settings += '\n' + ''.join(f'CONFIG_PACKAGE_{name}=y\n' for name in selected)
        config.write_text(settings, encoding='utf-8')
        for command in (['./scripts/feeds', 'update', '-a'], ['./scripts/feeds', 'install', '-a'],
                        ['make', 'defconfig'],
                        *(['make', f'package/{package}/compile', 'V=s', '-j2']
                          for package in packages)):
            subprocess.run(command, cwd=sdk, check=True)
        found = []
        for file in (sdk / 'bin').rglob('*.' + actual):
            if any(file.name.startswith(name + ('_' if actual == 'ipk' else '-')) for name in names):
                found.append(file)
        if len(found) != 3:
            raise ValueError(f'SDK did not produce exactly three packages: {len(found)}')
        staged = work / 'packages'
        staged.mkdir()
        for file in found:
            shutil.copy2(file, staged)
        architecture=target['architecture']
        _, report = load_script('检查三包').inspect(staged, item['slug'], item['normalized'], actual, architecture)
        component_tree=work/'components'
        component_tree.mkdir()
        for name in components:
            candidates=list((sdk/'bin').rglob(f'{name}_*_{architecture}.ipk'))
            if len(candidates)!=1:
                raise ValueError(f'Expected one built target component: {name}')
            shutil.copy2(candidates[0],component_tree/candidates[0].name)
        receipt = build_offline_bundle(ROOT, staged, destination, architecture, component_tree,
                                       update_public_key=update_public_key)
        offline_archive = destination / f"homegate-r{item['release']}-offline-three.tar"
        write_offline_archive(destination, offline_archive, receipt)
        _, signed_input = describe_bundle(offline_archive, offline_archive.read_bytes())
        evidence = {'target': target, 'identity': item, 'luci': frontend, 'format': actual,
                    'source_commit': os.environ.get('GITHUB_SHA'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
                    'packages': report, 'status': 'compiled-metadata-verified-not-device-tested'}
        evidence['offline_archive'] = {'file': offline_archive.name, 'sha256': signed_input['sha256'],
                                       'bytes': signed_input['size']}
        evidence['update_public_key_sha256'] = receipt['installed_files_sha256'].get(PUBLIC_KEY_PATH)
        if candidate:
            evidence.update(scope='pinned-sdk-candidate-build', feeds=feeds, release_authorized=False)
        (destination / 'build-evidence.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--luci', choices=('lua', 'js'), required=True)
    parser.add_argument('--format', choices=('auto', 'ipk', 'apk'), default='auto')
    parser.add_argument('--candidate', action='store_true', help='使用固定 SDK 和 feed 构建候选三包')
    parser.add_argument('--input-cache', type=Path, help='含 sdk.tar 和固定 feed 归档的候选构建缓存')
    parser.add_argument('--update-public-key', type=Path, help='要嵌入 Core 的 PEM 公钥')
    args = parser.parse_args()
    if args.input_cache and not args.candidate:
        parser.error('--input-cache requires --candidate')
    build(args.target, args.luci, args.format, candidate=args.candidate, cache=args.input_cache,
          update_public_key=args.update_public_key)
