#!/usr/bin/env python3
"""Stage flat, checksummed Release assets without ZIPs or private diagnostics."""
from pathlib import Path
import argparse,hashlib,json,re,shutil,tempfile
ROOT=Path(__file__).resolve().parents[1]
def stage(dist,out,kind):
 if kind not in ('IPK','APK','两者'):raise ValueError('Invalid release format')
 v=(ROOT/'homegate-version.mk').read_text(encoding='utf-8')
 version=re.search(r'^HOMEGATE_VERSION:=(.+)$',v,re.M)[1]+'-'+re.search(r'^HOMEGATE_RELEASE:=(.+)$',v,re.M)[1]
 apk_version=version.rsplit('-',1)[0]+'-r'+version.rsplit('-',1)[1]
 arches=json.loads((ROOT/'packaging/arm64-profiles.json').read_text(encoding='utf-8'))['package_architectures']
 assets={}
 for ext,folder in [('ipk','legacy-ipk'),('apk','modern-apk')]:
  if kind not in (ext.upper(),'两者'):continue
  for arch in arches:
   directory=dist/'packages'/folder/arch
   sums={name:digest for digest,name in (line.split('  ',1) for line in (directory/'SHA256SUMS').read_text(encoding='utf-8').splitlines())}
   sources=[f'homegate_{version}_{arch}.ipk',f'luci-app-homegate_{version}_all.ipk',f'luci-i18n-homegate-zh-cn_{version}_all.ipk'] if ext=='ipk' else [f'homegate-{apk_version}.apk',f'luci-app-homegate-{apk_version}.apk',f'luci-i18n-homegate-zh-cn-{apk_version}.apk']
   for index,name in enumerate(sources):
    blob=(directory/name).read_bytes()
    if hashlib.sha256(blob).hexdigest()!=sums.get(name):raise ValueError('Package checksum mismatch: '+name)
    target=name if ext=='ipk' else name[:-4]+'-'+(arch if index==0 else 'noarch')+'.apk'
    if target in assets and assets[target]!=blob:raise ValueError('Common package differs between profiles: '+target)
    assets[target]=blob
  assets['SHA256SUMS-'+ext.upper()+'.txt']=''.join(hashlib.sha256(b).hexdigest()+'  '+n+'\n' for n,b in sorted(assets.items()) if n.endswith('.'+ext)).encode()
 assets['安装说明.txt']=(f'''HomeGate {version}
核心包选与你的包管理器有效架构匹配的一份，并下载同格式的luci-app和中文翻译两份通用包，共三个组件。
IPK为旧Lua/OPKG；APK为原生JS/APK。不要混装。APK文件名增加架构方便下载，包内原始架构与元数据未改变。
架构：{', '.join(arches)}。不能仅根据uname -m或apk --print-arch判断；APK核对/etc/apk/arch及固件DISTRIB_ARCH。
SHA256SUMS-IPK/APK.txt含该格式全部架构文件；只下载三个组件时请逐项核对这三个文件的SHA256，不把其他未下载文件当成损坏。
下载的包全部使用本地文件路径安装；APK属于自行构建包，需--allow-untrusted，先--simulate检查依赖和架构。
完整自动安装器、离线验收套件及大压缩包仅在Actions Artifacts，不上传到Releases。
本发布由同一提交的通过构建产生；资源登记地区不等于地理位置，现有公网入口仍是IPv6。
''').encode()
 if out.exists():raise ValueError('Output must be a fresh directory')
 out.mkdir(parents=True)
 for name,blob in assets.items():(out/name).write_bytes(blob)
 return version,len(assets)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dist',type=Path,default=ROOT/'dist');p.add_argument('--out',type=Path,default=ROOT/'build/release-assets');p.add_argument('--format',choices=['IPK','APK','两者'],required=True);a=p.parse_args()
 v,count=stage(a.dist,a.out,a.format);print(f'Release {v}: {count} files ({a.format})')
