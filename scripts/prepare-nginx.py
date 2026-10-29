#!/usr/bin/env python3
"""Pinned native nginx for private protocol tests; never installs system files."""
import argparse,hashlib,json,os,shutil,subprocess,sys,tarfile,urllib.request
from pathlib import Path
VERSION='1.30.6'
SOURCES={
 'nginx.tar.gz':('https://nginx.org/download/nginx-1.30.6.tar.gz','3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8'),
 'pcre2.tar.bz2':('https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.47/pcre2-10.47.tar.bz2','47fe8c99461250d42f89e6e8fdaeba9da057855d06eb7fc08d9ca03fd08d7bc7')}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def validate_runtime(work):
 d=json.loads((work/'build-metadata.json').read_text())
 if d.get('recipe')!=1 or d.get('version')!=VERSION:raise ValueError('nginx metadata mismatch')
 for n,(_,h) in SOURCES.items():
  if sha(work/n)!=h:raise ValueError('nginx source changed')
 if d['binary_sha256']!=sha(work/'nginx'):raise ValueError('nginx executable changed')
 return d
def prepare(work):
 if sys.platform!='linux' or os.getuid()==0:raise ValueError('Require non-root Linux builder')
 work=work.resolve()
 if (work/'build-metadata.json').exists():validate_runtime(work);return {'runtime':str(work),'reused':True}
 if (work/'nginx-source').exists() or (work/'pcre2-source').exists():raise ValueError('Retain partial build; choose another directory')
 work.mkdir(parents=True,exist_ok=True)
 for name,(url,digest) in SOURCES.items():
  p=work/name
  if not p.exists():
   tmp=work/(name+'.pending')
   with urllib.request.urlopen(url,timeout=60) as q,tmp.open('xb') as f:shutil.copyfileobj(q,f)
   if sha(tmp)!=digest:raise ValueError('Source checksum mismatch')
   tmp.rename(p)
  if sha(p)!=digest:raise ValueError('Cached source checksum mismatch')
  dest=work/(name.split('.')[0]+'-extract');dest.mkdir()
  with tarfile.open(p) as bundle:bundle.extractall(dest,filter='data')
  roots=list(dest.iterdir())
  if len(roots)!=1:raise ValueError('Source layout mismatch')
  roots[0].rename(work/(name.split('.')[0]+'-source'));dest.rmdir()
 args=['./configure','--with-http_ssl_module','--with-pcre='+str(work/'pcre2-source'),
       '--without-http_gzip_module','--without-http_autoindex_module','--without-http_ssi_module',
       '--user=root','--group=root','--with-cc-opt=-O2']
 with (work/'build.log').open('xb') as log:
  subprocess.run(args,cwd=work/'nginx-source',stdout=log,stderr=subprocess.STDOUT,check=True)
  subprocess.run(['make','-j2'],cwd=work/'nginx-source',stdout=log,stderr=subprocess.STDOUT,check=True)
 shutil.copyfile(work/'nginx-source/objs/nginx',work/'nginx');(work/'nginx').chmod(0o755)
 info=subprocess.run([str(work/'nginx'),'-V'],capture_output=True,text=True,check=True).stderr
 d={'recipe':1,'version':VERSION,'sources':{n:h for n,(_,h) in SOURCES.items()},'binary_sha256':sha(work/'nginx'),
    'configure':args,'version_output':info,'system_installed':False,
    'boundary':'host test binary only; root is the mapped outer UID65534. The external fixture profile selects process mode; r149 same-credential adapter supports real master/workers without new outer privileges. Target nginx defaults/workers/ABI remain unverified.'}
 (work/'build-metadata.json').write_text(json.dumps(d,indent=2)+'\n');validate_runtime(work)
 return {'runtime':str(work),'reused':False,'version':VERSION}
# Test-only adapter: initgroups(root,0) requests no additional authority when
# effective/real IDs and every existing supplementary group are already zero.
# Linux denies even that redundant setgroups after cap-drop ALL. Do exactly
# this no-op and reject every other identity/request. Never ship with an IPK.
FIXTURE_C=r"""
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
int initgroups(const char *name, gid_t gid) {
 gid_t groups[32]; int n;
 if (!name || strcmp(name,"root") || gid || getuid() || geteuid() || getgid() || getegid()) { errno=EPERM; return -1; }
 n=getgroups(32,groups); if(n<0) return -1;
 for(int i=0;i<n;i++) if(groups[i]) { errno=EPERM; return -1; }
 return 0;
}
"""
def validate_fixture(work):
 d=json.loads((work/'metadata.json').read_text())
 if d.get('source_sha256')!=hashlib.sha256(FIXTURE_C.encode()).hexdigest() or d.get('library_sha256')!=sha(work/'same-credentials.so') or (work/'same-credentials.c').read_text()!=FIXTURE_C:raise ValueError('External identity no-op adapter changed')
 return d

def prepare_fixture(work):
 if sys.platform!='linux' or os.getuid()==0:raise ValueError('Require non-root Linux builder')
 if (work/'metadata.json').exists():return validate_fixture(work)
 work.mkdir(parents=True,exist_ok=True);(work/'same-credentials.c').write_text(FIXTURE_C)
 subprocess.run(['cc','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-Wl,-z,relro,-z,now','-o',str(work/'same-credentials.so'),str(work/'same-credentials.c')],check=True)
 d={'source_sha256':hashlib.sha256(FIXTURE_C.encode()).hexdigest(),'library_sha256':sha(work/'same-credentials.so'),'system_installed':False,'target_privilege_drop_verified':False,'scope':'test external nginx component only; same existing UID/GID/groups and zero outer capabilities; reject every credential-changing request'}
 (work/'metadata.json').write_text(json.dumps(d,indent=2)+'\n');return validate_fixture(work)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runtime-dir',type=Path);p.add_argument('--fixture-dir',type=Path);a=p.parse_args()
 if bool(a.runtime_dir)==bool(a.fixture_dir):p.error('Choose one runtime or fixture directory')
 print(json.dumps(prepare(a.runtime_dir) if a.runtime_dir else prepare_fixture(a.fixture_dir)))
