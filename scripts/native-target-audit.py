#!/usr/bin/env python3
"""Offline target/candidate evidence triage; never authorizes deployment."""
from pathlib import Path
import argparse,hashlib,json,re,sys
from project import selected_sdk_series

MAX_BYTES=1048576
def load_inventory(text):
    if len(text.encode('utf-8'))>MAX_BYTES or '\0' in text:raise ValueError('Inventory is oversized or contains NUL')
    packages={};kernels=[];libraries={};section=''
    for line in text.splitlines():
        if len(line)>8192:raise ValueError('Inventory line exceeds bound')
        if line.startswith('[') and line.endswith(']'):
            section=line[1:-1]
            if section.startswith('elf:'):
                name=section[4:]
                if name in libraries:raise ValueError('Duplicate ELF section')
                libraries[name]=[]
            continue
        if section=='kernel' and line.startswith('Linux '):
            match=re.fullmatch(r'Linux\s+(\S+)(?:\s+.*)?',line)
            if not match:raise ValueError('Invalid kernel observation')
            kernels.append(match.group(1))
        if section in ('dependency_packages','luci_packages'):
            match=re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9+_.-]*) - ([^\s]+)',line)
            if match:
                name,version=match.groups()
                if name in packages and packages[name]!=version:raise ValueError('Conflicting installed package versions')
                packages[name]=version
        if section.startswith('elf:'):libraries[section[4:]].append(line)
    if len(set(kernels))>1:raise ValueError('Conflicting kernel observations')
    return {'packages':packages,'kernel':kernels[0] if kernels else None,'libraries':libraries}

def merge(inventories):
    out={'packages':{},'kernel':None,'libraries':{}}
    for item in inventories:
        if out['kernel'] and item['kernel'] and out['kernel']!=item['kernel']:raise ValueError('Conflicting inventory kernels')
        out['kernel']=out['kernel'] or item['kernel']
        for name,version in item['packages'].items():
            if name in out['packages'] and out['packages'][name]!=version:raise ValueError('Conflicting inventory package versions')
            out['packages'][name]=version
        for name,lines in item['libraries'].items():
            if name in out['libraries']:raise ValueError('Duplicate library evidence')
            out['libraries'][name]=lines
    return out

def assess(target,candidate,closure,inventory):
    if not isinstance(target,dict) or target.get('schema')!=1 or not isinstance(candidate,dict) or candidate.get('schema')!=1:raise ValueError('Invalid target/candidate schema')
    if not isinstance(closure,dict):raise ValueError('Invalid dependency closure')
    rows=closure.get('declared_dependency_closure',closure.get('dependency_closure',closure)).get('packages')
    if not isinstance(rows,list) or len(rows)>512:raise ValueError('Missing/bounded package closure required')
    packages={}
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('name'),str) or not isinstance(row.get('version'),str) or row['name'] in packages:raise ValueError('Invalid/duplicate closure package')
        packages[row['name']]=row
    issues=[]
    def add(code,kind,detail):issues.append({'code':code,'kind':kind,'detail':detail})
    observed=inventory['packages'];kernel=observed.get('kernel') or inventory['kernel'];proposed=packages.get('kernel',{}).get('version')
    fmt=target.get('package_format');series=None
    if fmt in ('ipk','apk'):
        series=selected_sdk_series(fmt)
        version=(candidate.get('sdk') or {}).get('version','')
        if not isinstance(version,str) or not re.fullmatch(re.escape(series)+r'(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?',version):add('SDK-series-selection-mismatch','blocked',{'package_format':fmt,'user_selected_series':series,'candidate_version':version})
    def base(v):
        m=re.match(r'^(\d+\.\d+\.\d+)',v or '');return m.group(1) if m else None
    kernel_modules=[p['name'] for p in rows if re.search(r'\bkernel\s*\(=',p.get('depends',''))]
    if kernel_modules and (not kernel or not proposed):add('kernel-evidence-missing','missing','Exact target kernel and kmod ABI metadata required')
    elif kernel_modules and base(kernel)!=base(proposed):add('kernel-version-mismatch','blocked',{'target_reported':kernel,'candidate':proposed,'kernel_module_packages':kernel_modules,'scope':'full exported SDK closure, not a resolved target installation plan','selected_SDK_rejected':False,'target_provider_may_be_reused':observed.get('ip6tables'),'action':'Resolve actual installed providers; do not infer that SDK kernel modules can replace target modules'})
    elif kernel_modules:add('kernel-ABI-hash-unverified','missing','Matching base version does not establish exact kmod ABI/hash')
    for name in ('libc','libopenssl3'):
        old=observed.get(name);new=packages.get(name,{}).get('version')
        if old and new and old!=new:add(name+'-ABI-unverified','missing',{'target_reported':old,'candidate':new,'package_version_is_not_ABI_proof':True})
        elif not old:add(name+'-inventory-missing','missing','Package presence is not a substitute for actual ELF identity')
    ssl=observed.get('libopenssl3','')
    if ssl and not ssl.startswith('3.'):add('openssl-package-name-ambiguous','blocked',{'package':'libopenssl3','reported_version':ssl,'need':'Actual SONAME/NEEDED/symbol evidence; do not infer OpenSSL 3 from this name'})
    sdk=target.get('sdk') or {}
    if not isinstance(sdk,dict) or not isinstance(sdk.get('url'),str) or not sdk.get('url','').startswith('https://') or not re.fullmatch('[a-f0-9]{64}',str(sdk.get('sha256',''))):add('target-SDK-not-pinned','missing','Target firmware build source and matching SDK URL/SHA256 remain required')
    elif sdk.get('selection')=='user-approved-candidate' and sdk.get('runtime_abi_verified') is not True:add('selected-SDK-runtime-ABI-unverified','missing','User approved this SDK for builds; this project native component/runtime acceptance remains separate')
    if not isinstance(target.get('abi'),str) or not target['abi'].strip():add('target-ABI-not-frozen','missing','Compiler/libc/loader/SONAME/symbol provenance required')
    if target.get('verified') is not True:add('target-not-accepted','missing','Historical inventory does not establish current device acceptance')
    if candidate.get('QWRT_runtime_ABI_verified') is not True:add('candidate-target-ABI-unverified','missing','Engineering SDK profile does not establish QWRT ABI')
    present={name:lines for name,lines in inventory['libraries'].items() if 'state=present' in lines}
    if not present:add('actual-ELF-evidence-missing','missing','Run read-only scripts/核实原生ABI.sh on the authorized device; absent readelf must not trigger installation')
    for name,lines in present.items():
        headers=[x.split('=',1)[1] for x in lines if x.startswith('elf_header_hex=')]
        if not headers or headers==['unavailable']:add('ELF-header-missing','missing',name)
        elif len(headers)!=1 or not re.fullmatch('[a-fA-F0-9]{128}',headers[0]):add('ELF-header-invalid','blocked',name)
        else:
            header=bytes.fromhex(headers[0])
            if header[:4]!=b'\x7fELF' or header[4] not in (1,2) or header[5] not in (1,2):add('ELF-header-invalid','blocked',name)
            elif 'aarch64' in str(target.get('architecture','')) and (header[4]!=2 or int.from_bytes(header[18:20],'little' if header[5]==1 else 'big')!=183):add('ELF-machine-mismatch','blocked',name)
        if name.endswith(('/libssl.so.3','/libcrypto.so.3','/libssl.so.1.1','/libcrypto.so.1.1')) and not any('(SONAME)' in x for x in lines):add('TLS-SONAME-evidence-missing','missing',name)
    changed=[]
    for name,lines in inventory['libraries'].items():
        a=[x.split('=',1)[1] for x in lines if x.startswith('identity_before=')];b=[x.split('=',1)[1] for x in lines if x.startswith('identity_after=')]
        if a and b and a!=b:changed.append(name)
    if changed:add('ELF-changed-during-observation','blocked',changed)
    add('runtime-and-resource-acceptance-pending','missing','Actual component ABI execution, target procd/opkg, functional/fault/resource acceptance and final review remain separate')
    return {'schema':1,'scope':'offline-evidence-triage-only','target_id':target.get('id'),'target_reported_kernel':kernel,'package_format':fmt,'user_selected_SDK_series':series,
            'candidate_SDK_version':(candidate.get('sdk') or {}).get('version'),'candidate_kernel':proposed,
            'candidate_native_components':[p['name'] for p in rows if p['name'] in ('homegate-nginx','homegate-wol')],
            'issues':issues,'deployable':False,'target_verified':False,'release_authorized':False,'progress_recalculated':False,
            'boundary':'This report never changes target manifests or authorizes installation. Inputs may be historical. Matching names/CPU/flags are insufficient.'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--target',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--closure',type=Path,required=True);p.add_argument('--inventory',type=Path,action='append',required=True);args=p.parse_args()
    try:
        def raw(path):
            with path.open('rb') as f:b=f.read(MAX_BYTES+1)
            if len(b)>MAX_BYTES:raise ValueError('Input exceeds bound')
            return b
        files=[args.target,args.candidate,args.closure,*args.inventory];data={str(x):raw(x) for x in files}
        report=assess(json.loads(data[str(args.target)]),json.loads(data[str(args.candidate)]),json.loads(data[str(args.closure)]),merge([load_inventory(data[str(x)].decode('utf-8-sig')) for x in args.inventory]))
        report['input_SHA256']={str(x):hashlib.sha256(data[str(x)]).hexdigest() for x in files};print(json.dumps(report,ensure_ascii=False,indent=2));return 2
    except (ValueError,TypeError,KeyError,OSError,AttributeError) as exc:
        print(json.dumps({'scope':'offline-evidence-triage-only','deployable':False,'error':str(exc)},ensure_ascii=False));return 2
if __name__=='__main__':sys.exit(main())
