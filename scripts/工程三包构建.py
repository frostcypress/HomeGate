#!/usr/bin/env python3
"""Verified-SDK engineering build in a clean directory; no production gate bypass."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from project import ROOT,identity,verify_generated
from engineering_runtime import SCOPE,stage as stage_runtime,web_payload

def sha(file):
    h=hashlib.sha256()
    with file.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def build(target_file,archive,work,output):
    if os.name!='posix' or os.getuid()==0:raise ValueError('Use an existing Linux environment and an unprivileged build UID')
    verify_generated()
    target=json.loads(target_file.read_text())
    if (target.get('schema')!=1 or target.get('scope')!=SCOPE or
        target.get('package_slug')!='homegate-engineering' or target.get('package_architecture')!='all' or
        target.get('package_format')!='ipk' or target.get('native_target_code') is not False or target.get('production_replacement') is not False):
        raise ValueError('Unsupported engineering scope; production conditions are separate')
    if sha(archive)!=target['sdk']['sha256']:raise ValueError('SDK SHA mismatch')
    if work.exists() or output.exists():raise ValueError('Use new work/output paths; never overwrite build evidence or packages')
    public=json.loads((ROOT/'公开文件清单.json').read_text())['files']
    frozen={name:sha(ROOT/name) for name in public}
    work.mkdir(parents=True)
    subprocess.run(['tar','--zstd','--no-same-owner','-xf',str(archive.resolve()),'-C',str(work)],check=True)
    roots=list(work.glob('*/rules.mk'))
    if len(roots)!=1:raise ValueError('SDK root ambiguous')
    sdk=roots[0].parent
    recipe=sdk/'package/homegate-engineering'
    shutil.copytree(ROOT/'packaging/engineering',recipe)
    # Native proxy is a separate, private-path dependency, never a renamed host
    # fixture or part of the architecture=all core payload.
    component=sdk/'package/homegate-nginx'
    shutil.copytree(ROOT/'packaging/components/homegate-nginx',component)
    shutil.copytree(ROOT/'packaging/components/homegate-wol',sdk/'package/homegate-wol')
    payload=recipe/'payload';runtime=payload/'runtime';runtime.mkdir(parents=True)
    stage_runtime(ROOT,runtime)
    for name in ['engineering.lua','ddns-control.sh','apply-handle.lua','service-disabled','config-web.lua','config-web.sh','schedule-control.sh']:
        dest=runtime/name;shutil.copyfile(ROOT/'packaging/engineering/files'/name,dest)
        dest.chmod(0o755 if name in ['ddns-control.sh','service-disabled','config-web.sh','schedule-control.sh'] else 0o644)
    for name,raw in web_payload(ROOT).items():
        dest=payload/'webroot'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
    shutil.copyfile(ROOT/'LICENSE',payload/'LICENSE')
    (recipe/'tools').mkdir();shutil.copyfile(ROOT/'project/luci/common/tools/po2lmo.py',recipe/'tools/po2lmo.py')
    shutil.copyfile(ROOT/'homegate-version.mk',sdk/'homegate-version.mk')
    with (sdk/'.config').open('a') as config:
        config.write('\nCONFIG_PACKAGE_homegate-nginx=m\nCONFIG_PACKAGE_homegate-wol=m\nCONFIG_PACKAGE_homegate-engineering-core=m\nCONFIG_PACKAGE_luci-app-homegate-engineering=m\nCONFIG_PACKAGE_luci-i18n-homegate-engineering-zh-cn=m\n')
    logs=work/'logs';logs.mkdir()
    environment=dict(os.environ,LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1')
    steps=[]
    for label,command in [('defconfig',['make','defconfig']),('proxy-component',['make','package/homegate-nginx/compile','V=s','-j2']),('wol-component',['make','package/homegate-wol/compile','V=s','-j2']),('compile',['make','package/homegate-engineering/compile','V=s','-j2'])]:
        if label=='proxy-component':
            import re
            metadata=(sdk/'tmp/.packageinfo').read_text()
            missing=[name for name in ['homegate-nginx','homegate-wol','libopenssl','libpcre2','libpthread','luci-lib-nixio']
                     if not re.search(r'^Package: '+re.escape(name)+r'$',metadata,re.M)]
            if missing:raise ValueError('Target runtime dependency recipes missing: '+', '.join(missing)+'; retain SDK/logs and provide matching pinned feeds before build')
        start=time.monotonic();log=logs/(label+'.log');print('SDK_step',label,flush=True)
        with log.open('xb') as out:
            process=subprocess.run(command,cwd=sdk,env=environment,stdout=out,stderr=subprocess.STDOUT,timeout=1200)
        steps.append({'name':label,'returncode':process.returncode,'duration_seconds':round(time.monotonic()-start,3),'log_sha256':sha(log)})
        if process.returncode:
            print(log.read_text(errors='replace')[-16000:],flush=True)
            raise RuntimeError('SDK step failed: '+label+'; retained '+str(log))
    names={'homegate-engineering-core','luci-app-homegate-engineering','luci-i18n-homegate-engineering-zh-cn'}
    packages=[p for p in (sdk/'bin').rglob('*.ipk') if any(p.name.startswith(name+'_') for name in names)]
    if len(packages)!=3:raise ValueError('SDK did not produce exactly three engineering IPKs')
    components=list((sdk/'bin').rglob('homegate-nginx_*.ipk'))
    wol_components=list((sdk/'bin').rglob('homegate-wol_*.ipk'))
    if len(wol_components)!=1:raise ValueError('Require exactly one actual target WOL component IPK')
    if len(components)!=1:raise ValueError('Require one actual native proxy dependency package')
    stage=work/'verified-packages';stage.mkdir()
    for p in packages:shutil.copyfile(p,stage/p.name)
    spec=importlib.util.spec_from_file_location('three_packages',ROOT/'scripts/检查三包.py')
    inspector=importlib.util.module_from_spec(spec);spec.loader.exec_module(inspector)
    item=identity();_,reports=inspector.inspect(stage,'homegate-engineering',item['normalized'],'ipk','all')
    if any(sha(ROOT/name)!=digest for name,digest in frozen.items()):raise ValueError('Public source changed during build')
    output.mkdir(parents=True)
    for p in stage.iterdir():shutil.copyfile(p,output/p.name)
    dependency_output=output/'runtime-dependencies';dependency_output.mkdir()
    shutil.copyfile(components[0],dependency_output/components[0].name)
    shutil.copyfile(wol_components[0],dependency_output/wol_components[0].name)
    evidence={'date':'2026-10-27','version':item['normalized'],'native_package_version':item['normalized'],
        'scope':target['scope'],'SDK':target['sdk'],'SDK_archive_SHA_verified':True,'sdk_root':str(sdk),
        'package_architecture':'all','native_target_code':False,'QWRT_runtime_ABI_verified':False,
        'production_target_manifest_modified':False,'production_core_replaced':False,'router_installation_performed':False,
        'source_sha256':frozen,'packages':reports,'steps':steps,'status':'SDK-built-metadata-verified-payload-tests-pending',
        'CI_triggered':False,'source_commit':os.environ.get('GITHUB_SHA'),
        'native_runtime_component':{'package':components[0].name,'sha256':sha(components[0]),'directory':'runtime-dependencies','target_execution_verified':False},
        'native_wol_component':{'package':wol_components[0].name,'sha256':sha(wol_components[0]),'directory':'runtime-dependencies','target_execution_verified':False}}
    (output/'build-evidence.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'packages':reports,'output':str(output),'sdk_root':str(sdk)},ensure_ascii=False),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',type=Path,default=ROOT/'targets/engineering-24.10.6-ipq807x.json')
    p.add_argument('--sdk-archive',type=Path,required=True)
    p.add_argument('--work-dir',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();build(a.target,a.sdk_archive,a.work_dir,a.output)
