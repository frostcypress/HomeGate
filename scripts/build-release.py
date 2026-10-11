#!/usr/bin/env python3
"""Build all three QWRT IPKs from source, without an SDK or baseline IPKs.

Requires Python 3.10+ and Go. Linux generic ARM64; package architecture is selected with --arch.
SDK default_postinst/default_prerm wrappers are preserved as text templates;
package-specific lifecycle hooks are always read from the package Makefiles.
"""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
import runpy
profiles = runpy.run_path(str(ROOT/'scripts/package-profiles.py'))
ARCHITECTURES = profiles['ARCHITECTURES']
profiles['sync']()


def version():
    from project import identity, verify_generated
    verify_generated()
    item = identity()
    return item['version'], item['legacy']


def pack(files):
    """Deterministic gzip/GNU tar, root ownership, explicit Unix permissions."""
    output = io.BytesIO()
    directories = set()
    for name in files:
        parent = Path(name).parent
        while parent.as_posix() != '.':
            directories.add(parent.as_posix())
            parent = parent.parent
    with tarfile.open(fileobj=output, mode='w', format=tarfile.GNU_FORMAT) as archive:
        for name in sorted(directories):
            entry = tarfile.TarInfo('./' + name + '/')
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            entry.uname = entry.gname = 'root'
            archive.addfile(entry)
        for name, (data, mode) in sorted(files.items()):
            entry = tarfile.TarInfo('./' + name)
            entry.size, entry.mode = len(data), mode
            entry.uname = entry.gname = 'root'
            archive.addfile(entry, io.BytesIO(data))
    output_gz = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=output_gz, mtime=0) as compressed:
        compressed.write(output.getvalue())
    return output_gz.getvalue()


def hook(makefile, package, name):
    text = makefile.read_text(encoding='utf-8')
    found = re.search(r'^define Package/' + re.escape(package + '/' + name)
                      + r'\n(.*?)^endef$', text, re.M | re.S)
    return found[1].replace('$$', '$').encode() if found else None


def tree(path, prefix='', executable=False):
    result = {}
    for file in sorted(path.rglob('*')):
        if file.is_file():
            result[prefix + file.relative_to(path).as_posix()] = (
                file.read_bytes(), 0o755 if executable else 0o644)
    return result


def verify(path, expected_version):
    def unpack(blob):
        with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
            return {m.name.lstrip('./'): (archive.extractfile(m).read(), m.mode)
                    for m in archive if m.isfile()}
    outer = unpack(path.read_bytes())
    assert set(outer) == {'debian-binary', 'control.tar.gz', 'data.tar.gz'}
    assert outer['debian-binary'][0] == b'2.0\n'
    control, data = unpack(outer['control.tar.gz'][0]), unpack(outer['data.tar.gz'][0])
    assert ('Version: ' + expected_version + '\n').encode() in control['control'][0]
    for name, (_, mode) in control.items():
        assert mode == (0o644 if name in ('control', 'conffiles') else 0o755), name
    if path.name.startswith('homegate_'):
        binary = data['usr/bin/homegate'][0]
        assert binary[:6] == b'\x7fELF\x02\x01'
        assert int.from_bytes(binary[18:20], 'little') == 183
        assert expected_version.encode() in binary, 'compiled runtime release is missing'
        assert data['usr/bin/homegate'][1] == 0o755
        assert data['etc/config/homegate'][1] == 0o600
        assert b'@HOMEGATE_VERSION@' not in data['etc/config/homegate'][0]
        assert ("option version '" + expected_version + "'").encode() in data['etc/config/homegate'][0]
        assert control['conffiles'][0] == b'/etc/config/homegate\n'
        assert {'preinst', 'postinst-pkg', 'prerm-pkg', 'postrm'} <= control.keys()
    return control, data


def build(out, go, arch="aarch64_cortex-a53", include_source=True):
    if os.environ.get("HOMEGATE_ALLOW_LEGACY_GO") != "1":
        raise RuntimeError("Go reference builder only: explicitly set HOMEGATE_ALLOW_LEGACY_GO=1; output is not standards-compliant")
    assert arch in ARCHITECTURES, "Unsupported ARM64 package profile"
    for script in ('sync-frontend.py', 'build-js-views.py'):
        subprocess.run([os.sys.executable, str(ROOT / 'scripts' / script)], check=True)
    product, unified = version()
    out.mkdir(parents=True, exist_ok=True)
    work = ROOT / 'build'
    work.mkdir(exist_ok=True)
    binary = work / 'homegate-arm64'
    environment = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH='arm64',GOARM64='v8.0')
    subprocess.run([go, 'build', '-mod=vendor', '-buildvcs=false', '-trimpath',
                    '-ldflags=-s -w -X main.version=' + unified,
                    '-o', str(binary), './cmd/homegate'], cwd=ROOT / 'project/core/src',
                   env=environment, check=True)
    app = ROOT / 'project/luci'
    lmo = work / 'homegate.zh-cn.lmo'
    subprocess.run([os.sys.executable, str(app / 'common/tools/po2lmo.py'),
                    str(app / 'common/po/zh_Hans/homegate.po'), str(lmo)], check=True)
    core = tree(ROOT / 'project/core/files')
    for name, (blob, mode) in list(core.items()):
        if name == 'etc/config/homegate':
            core[name] = (blob.replace(b'@HOMEGATE_VERSION@', unified.encode()), 0o600)
        else:
            core[name] = (blob, 0o644 if name.startswith('usr/share/') else 0o755)
    core['usr/bin/homegate'] = (binary.read_bytes(), 0o755)
    ui = tree(app / 'lua/luasrc', 'usr/lib/lua/luci/')
    ui.update(tree(app / 'common/root', executable=True))
    translations = tree(app / 'common/root-i18n', executable=True)
    translations['usr/lib/lua/luci/i18n/homegate.zh-cn.lmo'] = (lmo.read_bytes(), 0o644)
    for package, data in [('homegate', core), ('luci-app-homegate', ui),
                          ('luci-i18n-homegate-zh-cn', translations)]:
        templates = ROOT / 'packaging/control-templates' / package
        control = tree(templates)
        for name in ('postinst', 'prerm'):
            control[name] = (control[name][0], 0o755)
        control['control'] = (control['control'][0].replace(b'@VERSION@', unified.encode())
                              .replace(b'@SIZE@', str(sum(len(b) for b, _ in data.values())).encode()), 0o644)
        makefile = ROOT / 'project/core/Makefile' if package == 'homegate' else app / 'Makefile'
        for name in ('preinst', 'postinst', 'prerm', 'postrm'):
            body = hook(makefile, package, name)
            if body:
                installed_name = name + '-pkg' if name in ('postinst', 'prerm') else name
                control[installed_name] = (body, 0o755)
        if package == 'homegate':
            control['conffiles'] = (b'/etc/config/homegate\n', 0o644)
        architecture = arch if package == 'homegate' else 'all'
        if package == 'homegate':
            control['control'] = (control['control'][0].replace(b'Architecture: aarch64_cortex-a53', ('Architecture: '+arch).encode()), 0o644)
        file = out / (package + '_' + unified + '_' + architecture + '.ipk')
        file.write_bytes(pack({'debian-binary': (b'2.0\n', 0o644),
                               'control.tar.gz': (pack(control), 0o644),
                               'data.tar.gz': (pack(data), 0o644)}))
        verify(file, unified)
        print(file.name)
    if include_source:
        # ZIP contents go directly at repository root, including .github/workflows.
        source_zip = out / ('HomeGate_' + unified + '_source.zip')
        with zipfile.ZipFile(source_zip, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(ROOT.rglob('*')):
                relative = file.relative_to(ROOT)
                if not file.is_file() or set(relative.parts) & {'build', 'dist', '.git', '__pycache__'}:
                    continue
                # Never recursively include an arbitrary output directory.
                if out.resolve() == file.parent.resolve() or out.resolve() in file.resolve().parents:
                    continue
                entry = zipfile.ZipInfo(relative.as_posix(), (2026, 10, 8, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = (0o100755 if file.suffix == '.sh' or file.read_bytes().startswith(b'#!/bin/sh') else 0o100644) << 16
                archive.writestr(entry, file.read_bytes())
    sums = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                   for p in sorted(out.iterdir()) if p.is_file() and p.name != 'SHA256SUMS')
    (out / 'SHA256SUMS').write_text(sums, encoding='ascii', newline='\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'dist')
    parser.add_argument('--go', default='go')
    parser.add_argument('--arch', choices=ARCHITECTURES, default='aarch64_cortex-a53')
    parser.add_argument('--packages-only', action='store_true', help='Do not duplicate the source ZIP in each architecture directory')
    args = parser.parse_args()
    build(args.out.resolve(), args.go, args.arch, not args.packages_only)
