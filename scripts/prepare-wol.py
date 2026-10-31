#!/usr/bin/env python3
"""Build the changed private transport for native verification; no installation."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def validate(work):
 d=json.loads((work/'metadata.json').read_text());assert d['recipe']==1 and d['source_sha256']==sha(ROOT/'packaging/components/homegate-wol/src/send.c') and d['binary_sha256']==sha(work/'send');return d
def prepare(work):
 if os.getuid()==0:raise ValueError('Build as existing non-root verification user')
 if (work/'metadata.json').exists():return validate(work)
 work.mkdir(parents=True);src=ROOT/'packaging/components/homegate-wol/src/send.c'
 command=['cc','-O2','-std=c11','-Wall','-Wextra','-Werror','-Wl,-z,relro,-z,now','-o',str(work/'send'),str(src)]
 subprocess.run(command,check=True);assert subprocess.run([str(work/'send'),'--version'],capture_output=True,check=True).stdout==b'homegate-wol 1\n'
 (work/'metadata.json').write_text(json.dumps({'recipe':1,'source_sha256':sha(src),'binary_sha256':sha(work/'send'),'command':command,'system_installed':False,'target_execution_verified':False},indent=2)+'\n');return validate(work)
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
