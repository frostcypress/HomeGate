#!/usr/bin/env python3
"""Offline installed-provider triage for exactly three native IPKs + two components.

Never downloads, installs, removes, updates or replaces a provider. Even a closed
dependency plan is not migration, ABI, function or release acceptance.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,io,json,re,subprocess,tarfile,tempfile

LIMIT=4*1024*1024
PRODUCTS={'homegate-core','luci-app-homegate','luci-i18n-homegate-zh-cn'}
COMPONENTS={'homegate-nginx','homegate-wol'}
FIELDS={'Package','Version','Status','Architecture','Provides','Depends','Conflicts'}
TOOLS={'ash','lua','uci','ubus','curl','openssl','sha256sum','stat','fsync','flock','ip','ip6tables','opkg','mkdir','mv','rm','sleep','cat'}
FRAMEWORK={'/etc/rc.common','/lib/functions.sh','/lib/functions/procd.sh'}

def dependency(text):
    # QSDK package names can contain underscores. Keep comparison operators
    # and version syntax bounded; never evaluate a dependency as shell text.
    m=re.fullmatch(r'([a-z0-9][a-z0-9+._-]*)(?:\s*\(\s*(=|>=|<=|>>|<<|>|<)\s*([A-Za-z0-9.+:~_-]{1,160})\s*\))?',text.strip())
    if not m:raise ValueError('Unsupported dependency expression: '+text)
    return m.groups()

def installed_status(row):
    # The middle opkg status word is a flag, not a success/error result.
    # Held packages remain reusable, but this planner never upgrades them.
    return row.get('Status') in ('install ok installed','install user installed','install hold installed')

def package_fields(raw):
    out={};key=None
    for line in raw.splitlines():
        if line.startswith((' ','\t')):
            if key is None:raise ValueError('Unattached continuation')
            out[key]+=' '+line.strip();continue
        m=re.fullmatch(r'([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)',line)
        if not m or m[1] not in FIELDS or m[1] in out:raise ValueError('Unexpected/duplicate package field')
        key=m[1];out[key]=m[2].strip()
    for field in ['Package','Version','Architecture']:
        if not out.get(field):raise ValueError('Missing '+field)
    if not re.fullmatch(r'[a-z0-9][a-z0-9+._-]*',out['Package']):raise ValueError('Invalid package name')
    if not re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,160}',out['Version']):raise ValueError('Invalid package version')
    for field in ['Depends','Provides','Conflicts']:
        for item in split(out.get(field,'')):dependency(item)
    return out

def split(text):return [x.strip() for x in text.split(',') if x.strip()]

def load_inventory(text):
    if len(text.encode())>LIMIT or '\0' in text:raise ValueError('Invalid/bounded inventory')
    sections={};section=None
    for line in text.splitlines():
        if len(line)>16384:raise ValueError('Oversized line')
        if line.startswith('[') and line.endswith(']'):
            section=line[1:-1]
            if section in sections:raise ValueError('Duplicate section')
            sections[section]=[]
        elif section:sections[section].append(line)
        elif line.strip():raise ValueError('Text before header')
    if set(sections)!= {'native_install_inventory','package_architectures','installed_package_metadata','commands','fixed_framework_files','boundary'}:raise ValueError('Missing/unknown inventory sections')
    if sections['native_install_inventory']!=['format=homegate-native-install-inventory-v1','read_only=true','acceptance=false','']:raise ValueError('Inventory format/boundary mismatch')
    architectures=[]
    for line in sections['package_architectures']:
        if not line:continue
        m=re.fullmatch(r'arch ([A-Za-z0-9_-]+) ([0-9]+)',line)
        if not m:raise ValueError('Invalid architecture')
        architectures.append(m[1])
    installed={}
    for block in '\n'.join(sections['installed_package_metadata']).strip().split('\n\n'):
        if not block.strip():continue
        row=package_fields(block)
        if row['Package'] in installed:raise ValueError('Duplicate installed package')
        installed[row['Package']]=row
    if not installed:raise ValueError('Empty installed database')
    commands={};files={}
    for line in sections['commands']:
        if not line:continue
        m=re.fullmatch(r'tool=([a-z0-9-]+);path=(missing|/[A-Za-z0-9_./+-]+)',line)
        if not m or m[1] not in TOOLS or m[1] in commands:raise ValueError('Invalid/duplicate tool evidence')
        commands[m[1]]=m[2]
    if set(commands)!=TOOLS:raise ValueError('Incomplete tool evidence')
    for line in sections['fixed_framework_files']:
        if not line:continue
        m=re.fullmatch(r'file=(/[A-Za-z0-9_./+-]+);state=(present|missing)',line)
        if not m or m[1] in files:raise ValueError('Invalid/duplicate framework evidence')
        files[m[1]]=m[2]
    return {'architectures':architectures,'installed':installed,'commands':commands,'files':files}

def inspect_ipk(path):
    spec=importlib.util.spec_from_file_location('install_plan_ipk',Path(__file__).with_name('检查三包.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>32*1024*1024:raise ValueError('Unsafe/bounded IPK')
    blob=path.read_bytes()
    if blob.startswith(b'!<arch>\n'):controls=[b for n,b in m.ar_members(blob).items() if n.startswith('control.tar.')]
    else:controls=[m.tar_member(blob,'control.tar.gz')]
    if len(controls)!=1:raise ValueError('Ambiguous control archive')
    info=m.fields(m.tar_member(controls[0],'control'));row=package_fields('\n'.join(k+': '+v for k,v in info.items() if k in FIELDS))
    row['file']=str(path);row['SHA256']=hashlib.sha256(blob).hexdigest();return row

def assess(candidates,inventory,version,compare):
    if len(candidates)!=5 or {x['Package'] for x in candidates}!=PRODUCTS|COMPONENTS:raise ValueError('Require exactly three native IPKs and two components')
    local={x['Package']:x for x in candidates};installed=inventory['installed'];issues=[];edges=[];selected={};seen=set()
    def issue(code,detail):issues.append({'code':code,'detail':detail})
    for name,row in local.items():
        if row['Architecture'] not in inventory['architectures']:issue('candidate-architecture-not-offered',name)
        if name in PRODUCTS and row['Version']!=version:issue('candidate-source-version-stale',{'name':name,'actual':row['Version'],'source':version})
    for tool,path in inventory['commands'].items():
        if path=='missing':issue('required-command-missing',tool)
    for path in FRAMEWORK:
        if inventory['files'].get(path)!='present':issue('required-framework-missing',path)
    def aliases(row):return [dependency(x) for x in split(row.get('Provides',''))]
    def available(row):return installed_status(row)
    pending=[('root',name) for name in sorted(PRODUCTS|COMPONENTS)]
    while pending:
        parent,expression=pending.pop(0);name,op,wanted=dependency(expression)
        row=local.get(name);origin='local-product-or-component';virtual_version=None
        if row is None:
            row=installed.get(name);origin='reuse-installed'
            if row is not None and not available(row):issue('installed-package-not-configured',name);continue
        if row is None:
            providers=[]
            for item in installed.values():
                if not available(item):continue
                for alias,aop,av in aliases(item):
                    if alias==name:providers.append((item,av if aop=='=' else None))
            if len(providers)!=1:
                issue('missing-installed-provider' if not providers else 'ambiguous-installed-provider',{'dependency':expression,'providers':[x[0]['Package'] for x in providers]});continue
            row,virtual_version=providers[0];origin='reuse-installed-virtual'
        if op:
            actual=virtual_version if origin=='reuse-installed-virtual' else row['Version']
            if actual is None or not compare(actual,op,wanted):issue('provider-version-unsatisfied',{'dependency':expression,'package':row['Package'],'actual':actual});continue
        key=(origin,row['Package']);edges.append({'from':parent,'dependency':expression,'provider':row['Package'],'version':row['Version'],'origin':origin})
        if key in seen:continue
        seen.add(key);selected[row['Package']]={'origin':origin,'version':row['Version']}
        if origin.startswith('reuse-installed'):selected[row['Package']]['installed_status']=row['Status']
        pending.extend((row['Package'],x) for x in split(row.get('Depends','')))
    # Local product files supersede previous same-name products, but never
    # silently remove an unrelated conflicting package or the old Go core.
    final_rows={**{n:x for n,x in installed.items() if available(x)},**local}
    for name,row in final_rows.items():
        for expression in split(row.get('Conflicts','')):
            conflict,op,wanted=dependency(expression)
            for other,target in final_rows.items():
                if other==name or (name not in local and other not in local):continue
                if other==conflict or any(x[0]==conflict for x in aliases(target)):
                    if not op or compare(target['Version'],op,wanted):issue('legacy-transition-required' if other=='homegate' or name=='homegate' else 'package-conflict',{'package':name,'conflict':other})
    return {'schema':1,'scope':'offline-installed-provider-triage-only','source_version':version,'candidate_packages':candidates,'selected_providers':selected,'edges':edges,'issues':issues,'declared_provider_set_closed':not issues,'automatic_additional_packages':[],'system_packages_to_replace':[],'kernel_modules_to_install':[],'opkg_mutation_attempted':False,'deployable':False,'target_verified':False,'release_authorized':False,'progress_recalculated':False,'boundary':'A metadata plan is not an opkg dry-run, migration authorization or ABI/function/resource acceptance. Installed providers are reused; no SDK closure is imported.'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--packages',type=Path,required=True);p.add_argument('--nginx',type=Path,required=True);p.add_argument('--wol',type=Path,required=True);p.add_argument('--inventory',type=Path,required=True);p.add_argument('--opkg',type=Path,required=True);p.add_argument('--version',required=True);a=p.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+-r\d+',a.version):p.error('Expected source version')
    paths=sorted(a.packages.glob('*.ipk'))+[a.nginx,a.wol]
    if len(paths)!=5:raise ValueError('Require three root package IPKs')
    with a.inventory.open('rb') as f:raw=f.read(LIMIT+1)
    if len(raw)>LIMIT:raise ValueError('Oversized inventory')
    inventory=load_inventory(raw.decode('utf-8-sig'));candidates=[inspect_ipk(x) for x in paths];checks={}
    # The SDK comparator uses only a fresh private offline root/config. Never
    # read the host opkg configuration, fetch indexes or issue install/remove.
    with tempfile.TemporaryDirectory(prefix='homegate-provider-compare-') as td:
        root=Path(td)/'root';root.mkdir();(root/'tmp').mkdir();tmp=Path(td)/'tmp';tmp.mkdir();config=Path(td)/'opkg.conf';config.write_text('dest root /\narch all 1\n')
        def compare(actual,op,wanted):
            key=(actual,op,wanted)
            if key not in checks:
                r=subprocess.run([str(a.opkg),'-f',str(config),'-o',str(root),'-t',str(tmp),'compare-versions',actual,op,wanted],capture_output=True,timeout=10)
                if r.returncode not in [0,1]:raise ValueError('Version comparator failed')
                checks[key]=r.returncode==0
            return checks[key]
        result=assess(candidates,inventory,a.version,compare)
    result['version_comparisons']=[{'actual':x,'operator':o,'wanted':y,'satisfied':ok} for (x,o,y),ok in checks.items()];result['inventory_SHA256']=hashlib.sha256(raw).hexdigest()
    print(json.dumps(result,ensure_ascii=False,indent=2));return 2

if __name__=='__main__':raise SystemExit(main())
