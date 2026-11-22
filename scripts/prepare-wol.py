#!/usr/bin/env python3
"""Build the changed private transport for native verification; no installation."""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
COMPONENT=ROOT/'packaging/components/homegate-wol'
RECIPE=(COMPONENT/'Makefile').read_text()
VERSION=re.search(r'^PKG_VERSION:=([0-9]+\.[0-9]+\.[0-9]+)$',RECIPE,re.M).group(1)
RELEASE=re.search(r'^PKG_RELEASE:=([0-9]+)$',RECIPE,re.M).group(1)
VERSION=f'{VERSION}-r{RELEASE}'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def validate(work):
 d=json.loads((work/'metadata.json').read_text());assert d['recipe']==2 and d['version']==VERSION and d['source_sha256']==sha(COMPONENT/'src/send.c') and d['binary_sha256']==sha(work/'send');return d
def prepare(work):
 if os.getuid()==0:raise ValueError('Build as existing non-root verification user')
 if (work/'metadata.json').exists():return validate(work)
 work.mkdir(parents=True);src=COMPONENT/'src/send.c'
 command=['cc','-O2',f'-DHOMEGATE_WOL_VERSION="{VERSION}"','-std=c11','-Wall','-Wextra','-Werror','-Wl,-z,relro,-z,now','-o',str(work/'send'),str(src)]
 subprocess.run(command,check=True);assert subprocess.run([str(work/'send'),'--version'],capture_output=True,check=True).stdout==f'homegate-wol {VERSION}\n'.encode()
 (work/'metadata.json').write_text(json.dumps({'recipe':2,'version':VERSION,'source_sha256':sha(src),'binary_sha256':sha(work/'send'),'command':command,'system_installed':False,'target_execution_verified':False},indent=2)+'\n');return validate(work)
def fixture(work):
 if os.getuid()==0:raise ValueError('Build as existing non-root verification user')
 src=ROOT/'scripts/wol-syscall-fixture.c'
 if (work/'metadata.json').exists():
  d=json.loads((work/'metadata.json').read_text());assert d['source_sha256']==sha(src) and d['library_sha256']==sha(work/'transport.so');return d
 work.mkdir(parents=True)
 subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-Wl,-z,relro,-z,now','-o',str(work/'transport.so'),str(src)],check=True)
 d={'source_sha256':sha(src),'library_sha256':sha(work/'transport.so'),'real_packets_sent':False,'credentials_or_capabilities_changed':False,'system_installed':False};(work/'metadata.json').write_text(json.dumps(d,indent=2)+'\n');return d
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runtime-dir',type=Path);p.add_argument('--fixture-dir',type=Path);a=p.parse_args()
 if bool(a.runtime_dir)==bool(a.fixture_dir):p.error('Choose one runtime or fixture directory')
 print(json.dumps(prepare(a.runtime_dir) if a.runtime_dir else fixture(a.fixture_dir)))
