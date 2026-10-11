#!/usr/bin/env python3
"""Package selection, unique architectures, hashes and safe rerun guards."""
from pathlib import Path
import runpy,tempfile,json,re,hashlib,subprocess
ROOT=Path(__file__).resolve().parents[1]
mod=runpy.run_path(str(ROOT/'scripts/release-assets.py'));stage=mod['stage']
text=(ROOT/'homegate-version.mk').read_text(encoding='utf-8');v=re.search(r'^HOMEGATE_VERSION:=(.+)$',text,re.M)[1]+'-'+re.search(r'^HOMEGATE_RELEASE:=(.+)$',text,re.M)[1];av=v.rsplit('-',1)[0]+'-r'+v.rsplit('-',1)[1]
arches=json.loads((ROOT/'packaging/arm64-profiles.json').read_text(encoding='utf-8'))['package_architectures']
with tempfile.TemporaryDirectory() as tmp:
 tmp=Path(tmp);dist=tmp/'dist'
 for arch in arches:
  for ext,folder in [('ipk','legacy-ipk'),('apk','modern-apk')]:
   d=dist/'packages'/folder/arch;d.mkdir(parents=True)
   names=[f'homegate_{v}_{arch}.ipk',f'luci-app-homegate_{v}_all.ipk',f'luci-i18n-homegate-zh-cn_{v}_all.ipk'] if ext=='ipk' else [f'homegate-{av}.apk',f'luci-app-homegate-{av}.apk',f'luci-i18n-homegate-zh-cn-{av}.apk']
   for i,n in enumerate(names):(d/n).write_bytes((arch if i==0 else str(i)).encode())
   (d/'SHA256SUMS').write_text(''.join(hashlib.sha256((d/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names))
 for choice,count in [('IPK',8),('APK',8),('两者',15)]:
  out=tmp/choice;_,actual=stage(dist,out,choice);assert actual==count
  assert not list(out.glob('*.zip'))
  assert len(list(out.glob('homegate*.apk')))==(4 if choice!='IPK' else 0)
  for manifest in out.glob('SHA256SUMS*.txt'):
   for line in manifest.read_text(encoding='utf-8').splitlines():h,n=line.split('  ',1);assert hashlib.sha256((out/n).read_bytes()).hexdigest()==h
 publisher=runpy.run_path(str(ROOT/'scripts/publish-release.py'))['publish']
 calls=[];state={'tag':False,'release':False,'wrong':False,'digest_bad':False}
 def fake_gh(*args,check=True):
  calls.append(args)
  if args[:2]==('api','repos/owner/repo/git/ref/tags/v'+v):
   return subprocess.CompletedProcess(args,0,json.dumps({'object':{'type':'commit','sha':('b' if state['wrong'] else 'a')*40}}),'') if state['tag'] else subprocess.CompletedProcess(args,1,'','HTTP 404')
  if args[:2]==('release','view'):return subprocess.CompletedProcess(args,0 if state['release'] else 1,'{"isDraft":false}' if state['release'] else '','not found')
  if args[0]=='api':
   assets=[{'name':next((tmp/'IPK').glob('*.ipk')).name,'digest':'sha256:bad'}] if state['digest_bad'] else []
   return subprocess.CompletedProcess(args,0,json.dumps({'assets':assets}),'')
  return subprocess.CompletedProcess(args,0,'','')
 publisher.__globals__['gh']=fake_gh
 publisher(tmp/'IPK','owner/repo','a'*40)
 assert sum(a[:2]==('release','upload') for a in calls)==8
 assert any(a[:2]==('release','create') and '--draft' in a for a in calls)
 assert any(a[:2]==('release','edit') and '--draft=false' in a for a in calls)
 calls.clear();state.update(tag=True,release=True,wrong=True)
 try:publisher(tmp/'IPK','owner/repo','a'*40)
 except ValueError:pass
 else:raise AssertionError('Different commit tag accepted')
 assert not any(a[0]=='release' for a in calls)
 calls.clear();state.update(wrong=False,digest_bad=True)
 try:publisher(tmp/'IPK','owner/repo','a'*40)
 except ValueError:pass
 else:raise AssertionError('Different existing asset accepted')
 assert not any(a[:2]==('release','upload') for a in calls)
 victim=next((dist/'packages/legacy-ipk'/arches[0]).glob('*.ipk'));victim.write_bytes(b'corrupt')
 try:stage(dist,tmp/'bad','IPK')
 except ValueError:pass
 else:raise AssertionError('Corrupt package accepted')
publisher=runpy.run_path(str(ROOT/'scripts/publish-release.py'))['publish']
assert '--clobber' not in (ROOT/'scripts/publish-release.py').read_text(encoding='utf-8')
try:publisher(Path('.'),'bad repo','bad sha')
except ValueError:pass
else:raise AssertionError('Invalid target accepted')
print('PASS Release selection IPK/APK/both, four core architectures, shared packages, manifests, corruption/target guards')
