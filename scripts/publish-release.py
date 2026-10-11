#!/usr/bin/env python3
"""Publish only staged flat assets. Never replace a different commit or asset."""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess
def gh(*args,check=True):return subprocess.run(['gh',*args],text=True,capture_output=True,check=check)
def publish(folder,repo,commit):
 if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or not re.fullmatch(r'[0-9a-f]{40}',commit):raise ValueError('Invalid repository or commit')
 files=sorted(folder.iterdir());packages=[p for p in files if p.suffix in ('.ipk','.apk')]
 if not packages or any(not p.is_file() or p.name.endswith('.zip') for p in files):raise ValueError('Invalid Release asset set')
 core=next(p for p in packages if p.name.startswith('homegate_') or p.name.startswith('homegate-'))
 match=re.search(r'homegate[_-]([0-9.]+)[_-](?:r)?([0-9]+)[_-]',core.name)
 if not match:raise ValueError('Missing complete release')
 version=match[1]+'-'+match[2];tag='v'+version
 ref_result=gh('api',f'repos/{repo}/git/ref/tags/{tag}',check=False)
 if ref_result.returncode==0:
  ref=json.loads(ref_result.stdout)['object']
  if ref['type']=='tag':ref=json.loads(gh('api',f'repos/{repo}/git/tags/{ref["sha"]}').stdout)['object']
  if ref['type']!='commit' or ref['sha']!=commit:raise ValueError('Existing tag belongs to another commit; refusing to publish')
 elif '404' not in ref_result.stderr:raise RuntimeError('Cannot verify release tag: '+ref_result.stderr)
 result=gh('release','view',tag,'--repo',repo,'--json','isDraft',check=False)
 existing=result.returncode==0
 if existing:
  ref=json.loads(gh('api',f'repos/{repo}/git/ref/tags/{tag}').stdout)['object']
  if ref['type']=='tag':ref=json.loads(gh('api',f'repos/{repo}/git/tags/{ref["sha"]}').stdout)['object']
  if ref['type']!='commit' or ref['sha']!=commit:raise ValueError('Existing release tag belongs to another commit; refusing to replace')
 else:
  # Creating with --target pins a new tag to the tested SHA; no unverified
  # interpolation in a shell, and a failed upload leaves a draft.
  gh('release','create',tag,'--repo',repo,'--target',commit,'--draft','--title','HomeGate '+version,'--notes','按架构下载核心包，另下载同格式的通用LuCI和中文组件；详见安装说明.txt。完整归档和验收工具仅在Actions。')
 remote=json.loads(gh('api',f'repos/{repo}/releases/tags/{tag}').stdout)
 known={a['name']:a for a in remote.get('assets',[])}
 # Check every collision before uploading anything, independent of platform
 # filename sorting. Never partially append to a conflicting release.
 for path in files:
  if path.name in known:
   if known[path.name].get('digest')!='sha256:'+hashlib.sha256(path.read_bytes()).hexdigest():raise ValueError('Existing asset has different or unavailable digest: '+path.name)
 for path in files:
  if path.name not in known:gh('release','upload',tag,str(path),'--repo',repo)
 if not existing or json.loads(result.stdout)['isDraft']:gh('release','edit',tag,'--repo',repo,'--draft=false')
 print('Published '+tag+' without replacing existing assets')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--assets',type=Path,required=True);a=p.parse_args();publish(a.assets,os.environ['GITHUB_REPOSITORY'],os.environ['GITHUB_SHA'])
