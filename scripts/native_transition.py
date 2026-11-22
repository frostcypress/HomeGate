#!/usr/bin/env python3
"""Inspect existing native IPKs and stage a private, explicit migration kit.

This does not build packages, install them, access a router or run opkg.
"""
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,io,json,re,shutil,tarfile,tempfile
from production_runtime import COMPONENT_PACKAGES, stage_package

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

def verify_lifecycle_hooks(control,make,package='homegate-core',hooks=('preinst','prerm','postinst','postrm'),prerm_dispatcher=None):
    entries={};result={}
    with tarfile.open(fileobj=io.BytesIO(control),mode='r:*') as archive:
        for entry in archive:
            name=entry.name.removeprefix('./')
            if name not in hooks and name not in ('prerm-pkg','postinst-pkg'):continue
            if (name in entries or not entry.isfile() or entry.size>65536 or
                entry.uid!=0 or entry.gid!=0 or entry.mode&0o7777!=0o755):
                raise ValueError('Unsafe native lifecycle hook')
            entries[name]=archive.extractfile(entry).read()
    for hook in hooks:
        wanted=(make.split('define Package/'+package+'/'+hook+'\n')[1].split('\nendef')[0].replace('$$','$').strip()+'\n').encode()
        actual=entries.get(hook)
        if hook=='prerm' and prerm_dispatcher is not None:
            if actual!=prerm_dispatcher or entries.get('prerm-pkg')!=wanted:
                raise ValueError('Native prerm dispatcher/body differs from source')
            result[hook]='HomeGate-live-dispatcher-and-exact-pkg-body';continue
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
def verify_gzip(raw):
    # tarfile can stop before the gzip trailer. Read it to validate the CRC.
    if raw.startswith(b'\x1f\x8b'):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            if len(stream.read(64*1024*1024+1))>64*1024*1024:
                raise ValueError('Oversized compressed archive')


def ipk_archives(path, inspector):
    blob=path.read_bytes()
    verify_gzip(blob)
    if blob.startswith(b'!<arch>\n'):
        members=inspector.ar_members(blob)
        data=[raw for name,raw in members.items() if name.startswith('data.tar.')]
        controls=[raw for name,raw in members.items() if name.startswith('control.tar.')]
        if len(data)!=1 or len(controls)!=1:
            raise ValueError('Ambiguous data or control archive')
        body,control=data[0],controls[0]
    else:
        body=inspector.tar_member(blob,'data.tar.gz',limit=16*1024*1024)
        control=inspector.tar_member(blob,'control.tar.gz')
    verify_gzip(body)
    verify_gzip(control)
    return body,control


def ipk_files(body, permissions):
    files={}
    with tarfile.open(fileobj=io.BytesIO(body),mode='r:*') as archive:
        for entry in archive:
            key=entry.name.removeprefix('./').rstrip('/')
            if key in ('','.'):
                continue
            if key.startswith('/') or '..' in Path(key).parts or not(entry.isfile() or entry.isdir()):
                raise ValueError('Unsafe payload entry')
            if entry.isfile():
                if key in files or entry.size>16*1024*1024:
                    raise ValueError('Duplicate/oversized payload')
                if entry.uid!=0 or entry.gid!=0 or permissions.get(key)!=(entry.mode&0o7777):
                    raise ValueError('Payload owner/mode differs from source: '+key)
                files[key]=archive.extractfile(entry).read()
    return files


def matching_components(root, components, inspector, architecture):
    files, permissions = {}, {}
    for name, layout in COMPONENT_PACKAGES.items():
        recipe=(root/'packaging/components'/name/'Makefile').read_text(encoding='utf-8')
        version,release=(re.search(r'^'+key+r':=([0-9.]+)$',recipe,re.M).group(1)
                         for key in ('PKG_VERSION','PKG_RELEASE'))
        version += '-r'+release
        path=components/f'{name}_{version}_{architecture}.ipk'
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing compiled component: '+path.name)
        info=inspector.metadata(path,'ipk')
        if (info['name'],info['version'],info['arch'])!=(name,version,architecture):
            raise ValueError('Component package metadata mismatch: '+path.name)
        body,_=ipk_archives(path,inspector)
        payload=ipk_files(body,{source: mode for source, (_,mode) in layout.items()})
        if payload.keys()!=layout.keys():
            raise ValueError('Incomplete component package: '+name)
        for source,(target,mode) in layout.items():
            files[target]=payload[source]
            permissions[target]=mode
    return files,permissions


def prepare_kit(root,packages,destination, *, architecture='all', components=None):
    root=Path(root);destination=Path(destination);packages=Path(packages)
    if destination.exists():raise ValueError('Kit destination must not exist')
    inspector=module(root/'scripts/检查三包.py','native_kit_packages')
    version=(root/'VERSION').read_text().strip()+'-r'+(root/'RELEASE').read_text().strip()
    bundled=components is not None
    if bundled==(architecture=='all'):
        raise ValueError('Target architecture and build components must be supplied together')
    paths=sorted(packages.glob('*.ipk'))
    if len(paths)!=3:raise ValueError('Exactly three native IPKs required')
    with tempfile.TemporaryDirectory() as temporary:
        feed=Path(temporary)/'feed';stage_package(root,feed,bundled=bundled)
        po=module(root/'project/luci/common/tools/po2lmo.py','native_kit_po')
        translated=Path(temporary)/'homegate.zh-cn.lmo';po.build(feed/'po/zh_Hans/homegate.po',translated)
        expected={name:{} for name in NAMES};permissions={name:{} for name in NAMES}
        for name,part in zip(NAMES,('core','web')):
            expected[name]={p.relative_to(feed/'payload'/part).as_posix():p.read_bytes() for p in (feed/'payload'/part).rglob('*') if p.is_file()}
            permissions[name]={p.relative_to(feed/'payload'/part).as_posix():p.stat().st_mode&0o777 for p in (feed/'payload'/part).rglob('*') if p.is_file()}
        if bundled:
            binaries,modes=matching_components(root,Path(components),inspector,architecture)
            expected[NAMES[0]].update(binaries)
            permissions[NAMES[0]].update(modes)
        expected[NAMES[2]]={'usr/lib/lua/luci/i18n/homegate.zh-cn.lmo':translated.read_bytes()}
        permissions[NAMES[2]]={'usr/lib/lua/luci/i18n/homegate.zh-cn.lmo':0o644}
        found={};controls={};hook_validation={};make=(feed/'Makefile').read_text()
        for path in paths:
            if path.is_symlink() or not path.is_file():raise ValueError('Unsafe package input')
            info=inspector.metadata(path,'ipk');name=info['name']
            expected_arch=architecture if name==NAMES[0] else 'all'
            if name not in expected or name in found or info['version']!=version or info['arch']!=expected_arch:
                raise ValueError('Wrong package/version/architecture')
            verify_version_dependencies(info,version)
            if bundled and name==NAMES[0]:
                dependencies={item.strip().split()[0] for item in info['depends'].split(',') if item.strip()}
                if dependencies.intersection(COMPONENT_PACKAGES) or 'libpthread' not in dependencies:
                    raise ValueError('Bundled Core declares incompatible component dependencies')
            body,control=ipk_archives(path,inspector)
            if name==NAMES[0]:
                hook_validation=verify_lifecycle_hooks(control,make,prerm_dispatcher=(feed/'tools/homegate-core.prerm').read_bytes())
            elif name==NAMES[1]:
                verify_lifecycle_hooks(control,make,package=name,hooks=('postinst','postrm'))
            controls[name]=hashlib.sha256(control).hexdigest()
            actual=ipk_files(body,permissions[name])
            if actual!=expected[name]:raise ValueError('Installed payload differs from frozen native source')
            found[name]=path
        destination.mkdir(mode=0o700)
        receipt={'format':'homegate-native-kit-v1','scope':'source-candidate-not-target-acceptance','version':version,'architecture':architecture,'bundled_components':bundled,'source_payload_verified':True,'lifecycle_hook_validation':hook_validation,'control_archive_SHA256':controls,'sha256':{}}
        if bundled:
            receipt['installed_files_sha256'] = {
                name:hashlib.sha256(raw).hexdigest()
                for files in expected.values() for name,raw in files.items()
                if name!='etc/config/homegate'
            }
        for name,path in found.items():shutil.copyfile(path,destination/(name+'.ipk'))
        for name in ('native-transition.sh','native-transition.lua','factory.config'):
            source=root/'packaging/production'/('homegate.config' if name=='factory.config' else name)
            shutil.copyfile(source,destination/name)
        for path in destination.iterdir():
            path.chmod(0o600);receipt['sha256'][path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        (destination/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (destination/'receipt.json').chmod(0o600)
        return receipt
def build_offline_bundle(root, packages, destination, architecture, components):
    root, packages, destination = map(Path, (root,packages,destination))
    if destination.exists():
        raise ValueError('Offline bundle destination must be new')
    with tempfile.TemporaryDirectory() as work:
        receipt=prepare_kit(root,packages,Path(work)/'verified',architecture=architecture,components=components)
    version=receipt['version']
    nginx=json.loads((root/'packaging/components/homegate-nginx/sources.json').read_text(encoding='utf-8'))
    wol=(root/'packaging/components/homegate-wol/Makefile').read_text(encoding='utf-8')
    wol_version=re.search(r'^PKG_VERSION:=([0-9.]+)$',wol,re.M).group(1)
    wol_release=re.search(r'^PKG_RELEASE:=([0-9]+)$',wol,re.M).group(1)
    fields={'@VERSION@':version, '@ARCHITECTURE@':architecture, '@NGINX_VERSION@':nginx['version'],
            '@WOL_VERSION@':f'{wol_version}-r{wol_release}',
            '@PREVIOUS_RELEASE@':str(int(version.rsplit('-r',1)[1])-1), '@RELEASE@':version.rsplit('-r',1)[1]}
    if any(not re.fullmatch(r'[a-zA-Z0-9._-]+',value) for value in fields.values()):
        raise ValueError('Unsafe offline installer metadata')
    installer=(root/'packaging/production/offline-install.sh').read_text(encoding='utf-8')
    for marker,value in fields.items():
        if marker not in installer:
            raise ValueError('Missing offline installer template field: '+marker)
        installer=installer.replace(marker,value)
    if re.search(r'@[A-Z_]+@',installer):
        raise ValueError('Unresolved offline installer template field')
    destination.mkdir(mode=0o700,parents=True)
    package_hashes={}
    for path in sorted(packages.glob('*.ipk')):
        digest=receipt['sha256'][path.name.split('_')[0]+'.ipk']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('Verified package changed before delivery: '+path.name)
        shutil.copyfile(path,destination/path.name)
        package_hashes[path.name]=digest
    receipt.update(format='homegate-offline-three-v1', sha256=package_hashes)
    (destination/'install.sh').write_text(installer,encoding='utf-8',newline='\n')
    (destination/'install.sh').chmod(0o755)
    shutil.copyfile(root/'packaging/production/native-log.sh', destination/'upgrade-log.sh')
    (destination/'installed-SHA256SUMS').write_text(''.join(
        f'{digest}  {name}\n' for name,digest in sorted(receipt['installed_files_sha256'].items())))
    (destination/'SOURCE.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (destination/'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in sorted(destination.iterdir())))
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--packages',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--architecture',default='all');parser.add_argument('--components',type=Path)
    parser.add_argument('--offline-bundle',action='store_true')
    args=parser.parse_args()
    if args.offline_bundle and args.components is None:parser.error('--offline-bundle requires --components')
    build=build_offline_bundle if args.offline_bundle else prepare_kit
    receipt=build(Path(__file__).resolve().parents[1],args.packages,args.output,
                                                architecture=args.architecture,components=args.components)
    print(json.dumps({'staged':True,'version':receipt['version'],'installed':False,'target_verified':False}))
