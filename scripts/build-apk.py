#!/usr/bin/env python3
"""Build real APK3 packages with official apk-tools, for OpenWrt 25.12.

Unlike the legacy IPK profile, modern packages contain JS/menu/ACL/ucode files,
no LuCI Lua controller or HTM, and have no luci-compat dependency.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
import runpy
profiles = runpy.run_path(str(ROOT/'scripts/package-profiles.py'))
ARCHITECTURES = profiles['ARCHITECTURES']
profiles['sync']()
spec = importlib.util.spec_from_file_location('release', ROOT/'scripts/build-release.py')
release = importlib.util.module_from_spec(spec);spec.loader.exec_module(release)

def build(out, apk, binary, go, arch="aarch64_cortex-a53"):
    if os.environ.get("HOMEGATE_ALLOW_LEGACY_GO") != "1":
        raise RuntimeError("Go reference builder only: HOMEGATE_ALLOW_LEGACY_GO=1 required")
    assert arch in ARCHITECTURES, "Unsupported ARM64 package profile"
    product, unified = release.version()
    apk_version = product + '-r' + unified.rsplit('-',1)[1]
    out.mkdir(parents=True,exist_ok=True)
    for script in ('sync-frontend.py','build-js-views.py'):
        subprocess.run([os.sys.executable,str(ROOT/'scripts'/script)],check=True)
    work=ROOT/'build';work.mkdir(exist_ok=True)
    if binary is None:
        binary=work/'homegate-modern-arm64'
        subprocess.run([go,'build','-mod=vendor','-trimpath','-buildvcs=false','-ldflags=-s -w -X main.version='+unified,'-o',str(binary),'./cmd/homegate'],cwd=ROOT/'project/core/src',env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='arm64',GOARM64='v8.0'),check=True)
    blob=binary.read_bytes()
    assert blob[:6]==b'\x7fELF\x02\x01' and int.from_bytes(blob[18:20],'little')==183 and unified.encode() in blob,'Wrong binary architecture/release'
    app=ROOT/'project/luci'
    lmo=work/'homegate.zh-cn.lmo'
    subprocess.run([os.sys.executable,str(app/'common/tools/po2lmo.py'),str(app/'common/po/zh_Hans/homegate.po'),str(lmo)],check=True)
    core=release.tree(ROOT/'project/core/files',executable=True)
    for path, (body, mode) in list(core.items()):
        if path.startswith('usr/share/'):
            core[path]=(body,0o644)
    core['etc/config/homegate']=(core['etc/config/homegate'][0].replace(b'@HOMEGATE_VERSION@',unified.encode()),0o600)
    core['usr/bin/homegate']=(blob,0o755)
    ui=release.tree(app/'js/htdocs','www/')
    ui.update(release.tree(app/'common/root',executable=True))
    ui.update(release.tree(app/'js/root'))
    translations=release.tree(app/'common/root-i18n',executable=True)
    translations['usr/lib/lua/luci/i18n/homegate.zh-cn.lmo']=(lmo.read_bytes(),0o644)
    plans=[('homegate',core,arch,'uci ubus ip ip6tables-nft ca-bundle','MIT AND Apache-2.0',{'pre-upgrade':'core-pre-upgrade','post-upgrade':'core-post-install','post-install':'core-post-install','pre-deinstall':'core-pre-deinstall','post-deinstall':'core-post-deinstall'}),
           ('luci-app-homegate',ui,'noarch','homegate luci-base rpcd rpcd-mod-ucode ucode ucode-mod-fs','Apache-2.0',{'post-install':'ui-post-install','post-upgrade':'ui-post-install','post-deinstall':'ui-post-deinstall'}),
           ('luci-i18n-homegate-zh-cn',translations,'noarch','homegate','Apache-2.0',{'post-install':'ui-post-install','post-upgrade':'ui-post-install'})]
    for name,files,arch,depends,license_,hooks in plans:
        with tempfile.TemporaryDirectory(prefix='homegate-apk-') as temp:
            stage=Path(temp)/'files';stage.mkdir()
            for path,(body,mode) in files.items():
                target=stage/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body);target.chmod(mode);os.utime(target,(0,0))
            for directory in sorted(stage.rglob('*'),reverse=True):
                if directory.is_dir():os.utime(directory,(0,0))
            os.utime(stage,(0,0))
            target=out/(name+'-'+apk_version+'.apk')
            command=[apk,'mkpkg','--files',str(stage),'--output',str(target)]
            metadata={'name':name,'version':apk_version,'arch':arch,'license':license_,'origin':'homegate','maintainer':'HomeGate contributors','description':name,'depends':depends,'build-time':'0'}
            for key,value in metadata.items():command+=['--info',key+':'+value]
            for phase,hook in hooks.items():
                path=Path(temp)/phase
                body=(ROOT/'packaging/apk-hooks'/hook).read_bytes().replace(b'@VERSION@',unified.encode())
                assert b'\r' not in body,'Use Unix LF in lifecycle hooks'
                path.write_bytes(body);path.chmod(0o755)
                subprocess.run(['sh','-n',str(path)],check=True)
                command+=['--script',phase+':'+str(path)]
            subprocess.run(command,check=True)
            # APK3 must be decoded by the same official tool, never tar-renamed.
            subprocess.run([apk,'adbdump',str(target)],stdout=open(out/(name+'.metadata.txt'),'w'),check=True)
            extracted=Path(temp)/'extracted';extracted.mkdir()
            subprocess.run([apk,'extract','--allow-untrusted','--destination',str(extracted),str(target)],check=True)
            for path,(body,mode) in files.items():
                restored=extracted/path
                assert restored.read_bytes()==body, 'APK payload mismatch: '+path
                assert restored.stat().st_mode & 0o777 == mode, 'APK permissions: '+path
            assert not (extracted/'usr/lib/lua/luci/controller/homegate.lua').exists()
            print(target.name)
    (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(out.glob('*.apk'))),encoding='ascii',newline='\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=ROOT/'dist/modern-apk')
    parser.add_argument('--apk',default='apk')
    parser.add_argument('--go',default='go')
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--arch', choices=ARCHITECTURES, default='aarch64_cortex-a53')
    args=parser.parse_args();build(args.out.resolve(),args.apk,args.binary,args.go,args.arch)
