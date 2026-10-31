#!/usr/bin/env python3
"""Inspect existing native IPKs and stage a private, explicit migration kit.

This does not build packages, install them, access a router or run opkg.
"""
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,io,json,re,shutil,tarfile,tempfile
from production_runtime import stage_package

NAMES=('homegate-core','luci-app-homegate','luci-i18n-homegate-zh-cn')

def verify_version_dependencies(info,version):
    required={'luci-app-homegate':['homegate-core'],
              'luci-i18n-homegate-zh-cn':['homegate-core','luci-app-homegate']}.get(info['name'],[])
    rows=[x.strip() for x in info['depends'].split(',')]
    for name in required:
        if not any(re.fullmatch(re.escape(name)+r'\s*\(\s*=\s*'+re.escape(version)+r'\s*\)',x) for x in rows):
            raise ValueError('Missing exact native dependency: '+name+' = '+version)
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

def verify_lifecycle_hooks(control,make):
    hooks=('preinst','prerm','postinst','postrm');entries={};result={}
    with tarfile.open(fileobj=io.BytesIO(control),mode='r:*') as archive:
        for entry in archive:
            name=entry.name.removeprefix('./')
            if name not in hooks and name not in ('prerm-pkg','postinst-pkg'):continue
            if (name in entries or not entry.isfile() or entry.size>65536 or
                entry.uid!=0 or entry.gid!=0 or entry.mode&0o7777!=0o755):
                raise ValueError('Unsafe native lifecycle hook')
            entries[name]=archive.extractfile(entry).read()
    for hook in hooks:
        wanted=(make.split('define Package/homegate-core/'+hook+'\n')[1].split('\nendef')[0].replace('$$','$').strip()+'\n').encode()
        actual=entries.get(hook)
        if actual==wanted:
            if hook+'-pkg' in entries:raise ValueError('Unexpected duplicate native lifecycle body')
            result[hook]='direct';continue
        # The pinned OpenWrt/ImmortalWrt SDK moves these bodies into *-pkg.
        # Match both files exactly, including the standard dispatcher. An
        # arbitrary wrapper containing a wanted substring is never accepted.
        if hook not in ('prerm','postinst'):raise ValueError('Native lifecycle hook differs from source')
        wrapper='#!/bin/sh\n'
        if hook=='postinst':wrapper+='[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0\n'
        wrapper+='[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0\n. ${IPKG_INSTROOT}/lib/functions.sh\ndefault_'+hook+' $0 $@\n'
        if actual!=wrapper.encode() or entries.get(hook+'-pkg')!=wanted:
            raise ValueError('Native lifecycle dispatcher/body differs from source')
        result[hook]='SDK-default-and-exact-pkg-body'
    return result
def prepare_kit(root,packages,destination):
    root=Path(root);destination=Path(destination);packages=Path(packages)
    if destination.exists():raise ValueError('Kit destination must not exist')
    inspector=module(root/'scripts/检查三包.py','native_kit_packages')
    version=(root/'VERSION').read_text().strip()+'-r'+(root/'RELEASE').read_text().strip()
    paths=sorted(packages.glob('*.ipk'))
    if len(paths)!=3:raise ValueError('Exactly three native IPKs required')
    with tempfile.TemporaryDirectory() as temporary:
        feed=Path(temporary)/'feed';stage_package(root,feed)
        po=module(root/'project/luci/common/tools/po2lmo.py','native_kit_po')
        translated=Path(temporary)/'homegate.zh-cn.lmo';po.build(feed/'po/zh_Hans/homegate.po',translated)
        expected={name:{} for name in NAMES};permissions={name:{} for name in NAMES}
        for name,part in zip(NAMES,('core','web')):
            expected[name]={p.relative_to(feed/'payload'/part).as_posix():p.read_bytes() for p in (feed/'payload'/part).rglob('*') if p.is_file()}
            permissions[name]={p.relative_to(feed/'payload'/part).as_posix():p.stat().st_mode&0o777 for p in (feed/'payload'/part).rglob('*') if p.is_file()}
        expected[NAMES[2]]={'usr/lib/lua/luci/i18n/homegate.zh-cn.lmo':translated.read_bytes()}
        permissions[NAMES[2]]={'usr/lib/lua/luci/i18n/homegate.zh-cn.lmo':0o644}
        found={};controls={};hook_validation={};make=(feed/'Makefile').read_text()
        for path in paths:
            if path.is_symlink() or not path.is_file():raise ValueError('Unsafe package input')
            info=inspector.metadata(path,'ipk');name=info['name']
            if name not in expected or name in found or info['version']!=version or info['arch']!='all':raise ValueError('Wrong package/version/architecture')
            verify_version_dependencies(info,version)
            blob=path.read_bytes()
            # tarfile may stop after its final member without reading the gzip
            # trailer. Verify the whole compressed stream, including its CRC.
            def verify_gzip(raw):
                if raw.startswith(b'\x1f\x8b'):
                    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                        if len(stream.read(64*1024*1024+1))>64*1024*1024:raise ValueError('Oversized compressed archive')
            verify_gzip(blob)
            if blob.startswith(b'!<arch>\n'):
                members=inspector.ar_members(blob);bodies=[v for k,v in members.items() if k.startswith('data.tar.')]
                if len(bodies)!=1:raise ValueError('Ambiguous data archive')
                body=bodies[0]
                control=[v for k,v in members.items() if k.startswith('control.tar.')]
                if len(control)!=1:raise ValueError('Ambiguous control archive')
                control=control[0]
            else:body=inspector.tar_member(blob,'data.tar.gz');control=inspector.tar_member(blob,'control.tar.gz')
            verify_gzip(body);verify_gzip(control)
            if name==NAMES[0]:
                hook_validation=verify_lifecycle_hooks(control,make)
            controls[name]=hashlib.sha256(control).hexdigest()
            actual={}
            with tarfile.open(fileobj=io.BytesIO(body),mode='r:*') as archive:
                for entry in archive:
                    key=entry.name.removeprefix('./').rstrip('/')
                    if key in ('','.'):continue
                    if key.startswith('/') or '..' in Path(key).parts or not(entry.isfile() or entry.isdir()):raise ValueError('Unsafe payload entry')
                    if entry.isfile():
                        if key in actual or entry.size>16*1024*1024:raise ValueError('Duplicate/oversized payload')
                        if entry.uid!=0 or entry.gid!=0 or permissions[name].get(key)!=(entry.mode&0o777):raise ValueError('Payload owner/mode differs from source')
                        actual[key]=archive.extractfile(entry).read()
            if actual!=expected[name]:raise ValueError('Installed payload differs from frozen native source')
            found[name]=path
        destination.mkdir(mode=0o700)
        receipt={'format':'homegate-native-kit-v1','scope':'source-candidate-not-target-acceptance','version':version,'architecture':'all','source_payload_verified':True,'lifecycle_hook_validation':hook_validation,'control_archive_SHA256':controls,'sha256':{}}
        for name,path in found.items():shutil.copyfile(path,destination/(name+'.ipk'))
        for name in ('native-transition.sh','native-transition.lua','factory.config'):
            source=root/'packaging/production'/('homegate.config' if name=='factory.config' else name)
            shutil.copyfile(source,destination/name)
        for path in destination.iterdir():
            path.chmod(0o600);receipt['sha256'][path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        (destination/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (destination/'receipt.json').chmod(0o600)
        return receipt
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--packages',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();receipt=prepare_kit(Path(__file__).resolve().parents[1],args.packages,args.output)
    print(json.dumps({'staged':True,'version':receipt['version'],'installed':False,'target_verified':False}))
