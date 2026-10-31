#!/usr/bin/env python3
"""Export actual SDK IPKs whose declared dependencies form a closed set.

This never installs a host package or treats SDK archives as device acceptance.
Virtual providers must be chosen explicitly; versions are checked by SDK opkg.
"""
from pathlib import Path
import hashlib,importlib.util,json,re,shutil,subprocess

ROOT_NAMES=('homegate-core','luci-app-homegate','luci-i18n-homegate-zh-cn')

def guarded_offline_install(opkg,config,offline,temporary,packages,logs,reinstall=False):
    """Preflight a private offline-root transaction before any payload write.

    Raw opkg can leave unpacked payloads after reporting missing dependencies.
    A failed preflight must never fall through to the mutating install command.
    Offline postinstall deferral is retained; this does not activate a service.
    """
    offline=Path(offline);logs=Path(logs);packages=[Path(p) for p in packages]
    if not offline.is_dir() or offline.is_symlink() or offline.resolve()==Path('/'):
        raise ValueError('Require an explicit private offline root')
    if not packages or any(p.is_symlink() or not p.is_file() for p in packages):raise ValueError('Unsafe/missing transaction package')
    if logs.exists():raise ValueError('Transaction log directory must be new')
    hashes={str(p):digest(p) for p in packages};logs.mkdir(mode=0o700)
    retained_config=offline/'etc/config/homegate'
    if retained_config.is_symlink() or (retained_config.exists() and not retained_config.is_file()):raise ValueError('Unsafe retained configuration')
    retained_before=(digest(retained_config),retained_config.stat().st_dev,retained_config.stat().st_ino) if retained_config.exists() else None
    base=[str(opkg),'-f',str(config),'-o',str(offline),'-t',str(temporary)]
    if reinstall:base+=['--force-reinstall']
    steps=[]
    for label,extra in [('preflight',['--noaction']),('install',[])]:
        if any(digest(p)!=hashes[str(p)] for p in packages):raise ValueError('Package changed during transaction')
        command=[*base,*extra,'install',*map(str,packages)]
        result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
        log=logs/(label+'.log');log.write_bytes(result.stdout)
        # This SDK can print unresolved dependencies and still exit zero after
        # treating an older installed package as "up to date". Exit status alone
        # cannot authorize the mutating command or establish installed versions.
        diagnostics=[line for line in result.stdout.decode(errors='replace').splitlines() if line.startswith(' * ')]
        # SDK opkg also uses its error collector for this successful conffile
        # preservation notice. Allow only its exact text AND verified unchanged
        # bytes/filesystem; offline opkg may replace the inode. Live migration's
        # stronger inode-preservation checks remain separate and unchanged.
        notice=' * resolve_conffiles: Existing conffile '+str(retained_config)+' is different from the conffile in the new package. The new conffile will be placed at '+str(retained_config)+'-opkg.'
        retained_unchanged=(retained_before is not None and not retained_config.is_symlink() and retained_config.is_file() and
            (digest(retained_config),retained_config.stat().st_dev)==retained_before[:2])
        allowed_notice=label=='install' and retained_unchanged
        reported_errors=b'Collected errors:' in result.stdout and (not diagnostics or any(x!=notice or not allowed_notice for x in diagnostics))
        steps.append({'step':label,'returncode':result.returncode,'opkg_diagnostic_collector_present':b'Collected errors:' in result.stdout,
            'unexpected_opkg_errors':reported_errors,'retained_conffile_notice_verified':notice in diagnostics and allowed_notice,
            'log':str(log),'log_SHA256':digest(log)})
        if result.returncode or reported_errors:
            receipt={'ok':False,'failed_phase':label,'mutating_install_attempted':label=='install','steps':steps,
                'offline_root':str(offline),'package_SHA256':hashes,'offline_activation':False}
            (logs/'transaction.json').write_text(json.dumps(receipt,indent=2)+'\n')
            return receipt
    spec=importlib.util.spec_from_file_location('offline_installed_versions',Path(__file__).with_name('检查三包.py'))
    inspector=importlib.util.module_from_spec(spec);spec.loader.exec_module(inspector)
    installed={};status=offline/'usr/lib/opkg/status'
    if status.is_file():
        for paragraph in status.read_text().split('\n\n'):
            fields=dict(line.split(': ',1) for line in paragraph.splitlines() if ': ' in line and not line.startswith((' ','\t')))
            if 'Package' in fields:installed[fields['Package']]=fields
    requested=[inspector.metadata(p,'ipk') for p in packages]
    mismatch=[row['name'] for row in requested if installed.get(row['name'],{}).get('Version')!=row['version'] or
        installed.get(row['name'],{}).get('Status','').split()[-1:] not in (['installed'],['unpacked'])]
    if mismatch or (retained_before is not None and not retained_unchanged):
        receipt={'ok':False,'failed_phase':'installed-state-verification','mutating_install_attempted':True,
            'mismatched_packages':mismatch,'steps':steps,'offline_root':str(offline),'package_SHA256':hashes,'offline_activation':False}
        (logs/'transaction.json').write_text(json.dumps(receipt,indent=2)+'\n');return receipt
    receipt={'ok':True,'mutating_install_attempted':True,'steps':steps,'offline_root':str(offline),
        'package_SHA256':hashes,'installed_versions_verified':True,'retained_config_bytes_verified':retained_before is None or retained_unchanged,
        'retained_config_inode_unchanged':None if retained_before is None else (retained_unchanged and retained_config.stat().st_ino==retained_before[2]),'offline_activation':False}
    (logs/'transaction.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
    return h.hexdigest()

def dependency(text):
    match=re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)(?:\s*\(\s*(=|>=|<=|>>|<<|>|<)\s*([^()\s]+)\s*\))?',text.strip())
    if not match:raise ValueError('Unsupported dependency expression: '+text)
    return match.groups()

def export_runtime_closure(root,sdk,work,destination,providers,exclude=ROOT_NAMES):
    root=Path(root);sdk=Path(sdk);work=Path(work);destination=Path(destination)
    if work.exists() or destination.exists():raise ValueError('Require new dependency work/output directories')
    spec=importlib.util.spec_from_file_location('native_dependency_inspector',root/'scripts/检查三包.py')
    inspector=importlib.util.module_from_spec(spec);spec.loader.exec_module(inspector)
    index={}
    for path in sorted((sdk/'bin').rglob('*.ipk')):
        if path.is_symlink() or not path.is_file():raise ValueError('Unsafe SDK package path')
        index.setdefault(path.name.split('_',1)[0],[]).append(path)
    work.mkdir(mode=0o700);offline=work/'root';offline.mkdir();(offline/'tmp').mkdir()
    temporary=work/'tmp';temporary.mkdir();config=work/'opkg.conf'
    config.write_text('dest root /\narch all 1\narch aarch64_cortex-a53 10\n')
    opkg=sdk/'staging_dir/host/bin/opkg';selected={};edges=[];comparisons={};cache={}
    def info(name):
        if name in cache:return cache[name]
        found=index.get(name,[])
        if len(found)!=1:raise ValueError('Missing/ambiguous real SDK package: '+name)
        path=found[0];row=inspector.metadata(path,'ipk')
        if row['name']!=name or row['arch'] not in ('all','aarch64_cortex-a53'):raise ValueError('Unexpected package identity/architecture')
        blob=path.read_bytes()
        if blob.startswith(b'!<arch>\n'):
            controls=[v for n,v in inspector.ar_members(blob).items() if n.startswith('control.tar.')]
            if len(controls)!=1:raise ValueError('Ambiguous control archive')
            control=controls[0]
        else:control=inspector.tar_member(blob,'control.tar.gz')
        fields={};key=None
        for line in inspector.tar_member(control,'control').decode().splitlines():
            if line.startswith((' ','\t')) and key:fields[key]+=' '+line.strip();continue
            if ': ' in line:
                key,value=line.split(': ',1)
                if key in fields:raise ValueError('Duplicate control field')
                fields[key]=value
        row.update(path=path,file=path.name,sha256=digest(path),
            provides=[dependency(x)[0] for x in fields.get('Provides','').split(',') if x.strip()],
            conflicts=[dependency(x) for x in fields.get('Conflicts','').split(',') if x.strip()])
        cache[name]=row;return row
    def compare(actual,op,wanted):
        key=(actual,op,wanted)
        if key not in comparisons:
            result=subprocess.run([str(opkg),'-f',str(config),'-o',str(offline),'-t',str(temporary),
                'compare-versions',actual,op,wanted],capture_output=True,timeout=20)
            if result.returncode not in (0,1):raise RuntimeError('SDK opkg comparison failed: '+result.stderr.decode(errors='replace'))
            comparisons[key]=result.returncode==0
        return comparisons[key]
    pending=[('root',name) for name in ROOT_NAMES]
    while pending:
        parent,expression=pending.pop(0);name,op,wanted=dependency(expression)
        actual=name if name in index else providers.get(name)
        if not actual:raise ValueError('Choose an actual SDK provider for '+name)
        row=info(actual)
        if actual!=name and name not in row['provides']:raise ValueError('Chosen package does not provide '+name)
        if op and not compare(row['version'],op,wanted):raise ValueError('Unsatisfied version: '+expression)
        edges.append({'from':parent,'dependency':expression,'resolved_package':actual,'version':row['version']})
        if actual in selected:continue
        selected[actual]=row
        pending.extend((actual,x.strip()) for x in row['depends'].split(',') if x.strip())
    for name,row in selected.items():
        for conflict,op,wanted in row['conflicts']:
            for other,target in selected.items():
                if other!=name and (other==conflict or conflict in target['provides']) and (not op or compare(target['version'],op,wanted)):
                    raise ValueError('Conflicting runtime packages: '+name+' / '+other)
    destination.mkdir(mode=0o700);packages=[]
    for name,row in sorted(selected.items()):
        copied=name not in exclude
        if copied:shutil.copyfile(row['path'],destination/row['file'])
        packages.append({k:v for k,v in row.items() if k!='path'}|{'exported':copied,'source':str(row['path'])})
    receipt={'format':'homegate-native-dependency-closure-v1','scope':'declared-SDK-package-dependencies-only',
        'root_packages':list(ROOT_NAMES),'providers':providers,'packages':packages,'edges':edges,
        'version_checks':[{'actual':a,'operator':o,'required':v,'satisfied':ok} for (a,o,v),ok in comparisons.items()],
        'declared_dependencies_closed':True,'installed':False,'QWRT_runtime_ABI_verified':False,'target_kernel_executed':False}
    (destination/'dependency-closure.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
    return receipt
