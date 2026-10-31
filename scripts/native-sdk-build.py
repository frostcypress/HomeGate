#!/usr/bin/env python3
"""Build the native source candidate with pinned SDK/feed inputs.

This is a necessary package/component verification profile, not QWRT target
acceptance or a release path. Never install into the host or replace old SDKs.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess,tarfile,time
from pathlib import Path
from project import ROOT,identity,verify_generated
from production_runtime import stage_package
from native_transition import prepare_kit
from native_opkg import export_runtime_closure

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def verify_opkg_versions(opkg,work,version,others):
    # SDK opkg loads configuration and an offline-root lock even for version
    # comparisons. Keep both in a fresh private tree; never use /etc/opkg.conf.
    if work.exists():raise ValueError('Version-check directory must be new')
    work.mkdir(mode=0o700);root=work/'root';root.mkdir();(root/'tmp').mkdir()
    temp=work/'tmp';temp.mkdir();config=work/'opkg.conf'
    config.write_text('dest root /\narch all 1\n')
    checks=[]
    for candidate,expected in [(version,0),*((x,1) for x in others)]:
        command=[str(opkg),'-f',str(config),'-o',str(root),'-t',str(temp),'compare-versions',candidate,'=',version]
        p=subprocess.run(command,capture_output=True,timeout=20)
        if p.returncode!=expected:
            raise RuntimeError('opkg version check failed: '+candidate+' '+str(p.returncode)+' '+p.stderr.decode(errors='replace'))
        checks.append({'candidate':candidate,'required':version,'accepted':p.returncode==0})
    return checks

def build(target_file,archive,feed_cache,work,output):
    if os.name!='posix' or os.getuid()==0:raise ValueError('Use the existing unprivileged Linux build UID')
    verify_generated();target=json.loads(target_file.read_text())
    if (target.get('scope')!='native-source-candidate-package-verification' or target.get('QWRT_runtime_ABI_verified') is not False or
        target.get('release_authorized') is not False or target.get('package_architecture')!='all'):
        raise ValueError('Unsupported profile; target/release gates are separate')
    if work.exists() or output.exists():raise ValueError('Require new work and output paths')
    if sha(archive)!=target['sdk']['sha256']:raise ValueError('SDK SHA mismatch')
    for name,feed in target['feeds'].items():
        if sha(feed_cache/(name+'-'+feed['commit']+'.tar.gz'))!=feed['archive_sha256']:raise ValueError('Feed SHA mismatch: '+name)
    manifest=json.loads((ROOT/'公开文件清单.json').read_text())['files'];frozen={n:sha(ROOT/n) for n in manifest}
    work.mkdir(parents=True);logs=work/'logs';logs.mkdir();steps=[]
    build_home=work/'build-user-home';build_home.mkdir(mode=0o700)
    env=dict(os.environ,HOME=str(build_home),XDG_CACHE_HOME=str(build_home/'.cache'),LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1')
    def run(label,args,cwd,timeout=1200):
        print('SDK_STEP',label,flush=True);p=logs/(label+'.log');start=time.monotonic()
        with p.open('xb') as f:r=subprocess.run(args,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
        steps.append({'name':label,'returncode':r.returncode,'seconds':round(time.monotonic()-start,3),'log':str(p),'log_SHA256':sha(p)})
        if r.returncode:print(p.read_text(errors='replace')[-8000:],flush=True);raise RuntimeError(label+' failed; retained '+str(p))
    run('extract-sdk',['tar','--zstd','--no-same-owner','-xf',str(archive.resolve()),'-C',str(work)],work)
    sdk=next(work.glob('*/rules.mk')).parent
    feeds=work/'feed-sources';feeds.mkdir();config=[]
    for name,feed in target['feeds'].items():
        dest=feeds/name;dest.mkdir()
        with tarfile.open(feed_cache/(name+'-'+feed['commit']+'.tar.gz')) as t:t.extractall(dest,filter='data')
        children=list(dest.iterdir());assert len(children)==1
        source=children[0]/'package' if name=='base' else children[0]
        config.append('src-link '+name+' '+str(source))
    (sdk/'feeds.conf').write_text('\n'.join(config)+'\n')
    stage_package(ROOT,sdk/'package/homegate-native-candidate')
    for name in ['homegate-nginx','homegate-wol']:shutil.copytree(ROOT/'packaging/components'/name,sdk/'package'/name)
    shutil.copyfile(ROOT/'homegate-version.mk',sdk/'homegate-version.mk')
    run('feed-index',['./scripts/feeds','update','-a'],sdk)
    run('feed-install',['./scripts/feeds','install','-a'],sdk)
    settings=(sdk/'.config').read_text() if (sdk/'.config').exists() else ''
    for key in ['ALL','ALL_NONSHARED','ALL_KMODS']:
        settings=re.sub(r'^CONFIG_'+key+r'=y$',r'# CONFIG_'+key+' is not set',settings,flags=re.M)
        settings+='\n# CONFIG_'+key+' is not set\n'
    selected=['homegate-core','luci-app-homegate','luci-i18n-homegate-zh-cn','homegate-nginx','homegate-wol','libopenssl','libpcre2','liblua','luci-lib-nixio','busybox']
    settings+='\n'+''.join('CONFIG_PACKAGE_'+n+'=y\n' for n in selected)
    (sdk/'.config').write_text(settings)
    run('defconfig',['make','defconfig'],sdk)
    if 'error: recursive dependency' in (logs/'defconfig.log').read_text(errors='replace'):
        raise ValueError('SDK Kconfig has recursive dependencies; do not continue')
    text=(sdk/'tmp/.packageinfo').read_text();recipes={};providers={};source=None;package=None
    for line in text.splitlines():
        if line.startswith('Source-Makefile: '):source=line.split(': ',1)[1].removesuffix('/Makefile')
        if line.startswith('Package: '):package=line.split(': ',1)[1];recipes[package]=source
        if line.startswith('Provides: '):
            for alias in line.split(': ',1)[1].split():providers.setdefault(alias,[]).append(package)
    needed=selected+['busybox','lua','luci-lib-jsonc','curl','ca-bundle','openssl-util','flock','coreutils-stat','ip-full','ubus','ip6tables','luci-base']
    missing=[n for n in needed if n not in recipes and n not in providers]
    if missing:raise ValueError('Pinned runtime recipes missing: '+', '.join(missing))
    # Actually compile the complete TLS component. Never substitute the earlier
    # HTTP/SSL-disabled probe or link host OpenSSL/PCRE into target objects.
    for name in ['libopenssl','libpcre2','liblua','luci-lib-nixio','busybox','homegate-nginx','homegate-wol','homegate-core']:
        run('compile-'+name,['make',recipes[name]+'/compile','V=s','-j2'],sdk)
    names=['homegate-core','luci-app-homegate','luci-i18n-homegate-zh-cn'];packages={}
    for name in names:
        found=list((sdk/'bin').rglob(name+'_*.ipk'))
        if len(found)!=1:raise ValueError('Expected one actual SDK package: '+name)
        packages[name]=found[0]
    checked=work/'checked-three';checked.mkdir()
    for p in packages.values():shutil.copyfile(p,checked/p.name)
    kit=work/'checked-kit';receipt=prepare_kit(ROOT,checked,kit)
    opkg=sdk/'staging_dir/host/bin/opkg';version=identity()['normalized']
    item=identity();release=int(item['release'])
    others=[item['version']+'-r'+str(release+1),item['version']+'-r'+str(release-1 if release>1 else release+2)]
    compare=verify_opkg_versions(opkg,work/'opkg-version-check',version,others)
    if any(sha(ROOT/n)!=h for n,h in frozen.items()):raise ValueError('Source changed during build')
    output.mkdir(parents=True)
    for p in checked.iterdir():shutil.copyfile(p,output/p.name)
    closure=export_runtime_closure(ROOT,sdk,work/'dependency-closure-check',output/'runtime-dependencies',
        target['runtime_virtual_providers'])
    dependencies=closure['packages']
    evidence={'version':version,'scope':target['scope'],'SDK_archive_SHA_verified':True,'sdk_root':str(sdk),
      'source_sha256':frozen,'feeds':target['feeds'],'steps':steps,'package_files':[{'file':p.name,'sha256':sha(p)} for p in packages.values()],
      'actual_payload_and_hooks_verified':True,'kit_validation':receipt,'runtime_dependencies':dependencies,
      'declared_dependency_closure':closure,
      'opkg_exact_version_comparisons':compare,'full_TLS_component_compiled':True,
      'dependency_installation_complete':False,'router_installation_performed':False,'QWRT_runtime_ABI_verified':False,
      'production_core_replaced':False,'CI_triggered':False,'release_authorized':False}
    (output/'build-evidence.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'built_three':True,'version':version,'output':str(output)},ensure_ascii=False),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',type=Path,default=ROOT/'targets/native-candidate-24.10.6-ipq807x.json')
    p.add_argument('--sdk-archive',type=Path,required=True);p.add_argument('--feed-cache',type=Path,required=True)
    p.add_argument('--work-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();build(a.target,a.sdk_archive,a.feed_cache,a.work_dir,a.output)
