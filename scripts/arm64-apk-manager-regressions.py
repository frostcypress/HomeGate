#!/usr/bin/env python3
"""Install the actual ARM64 packages in private APK databases; never run hooks/binaries."""
from pathlib import Path
import argparse,os,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--packages-root',type=Path,default=ROOT/'dist/packages/modern-apk');parser.add_argument('--baseline-root',type=Path);args=parser.parse_args()
apk=os.environ.get('HOMEGATE_APK_TOOL','apk')
profiles=('aarch64','aarch64_generic','aarch64_cortex-a53','aarch64_cortex-a72')
with tempfile.TemporaryDirectory(prefix='hg-arm64-apk-db-') as temp:
 root=Path(temp);empty=root/'empty';empty.mkdir();stubs=[]
 for name in ('uci','ubus','ip-tiny','ip6tables-nft','ca-bundle','luci-base','rpcd','rpcd-mod-ucode','ucode','ucode-mod-fs'):
  file=root/(name+'-1-r0.apk')
  command=[apk,'mkpkg','--files',str(empty),'--output',str(file),'--info','name:'+name,'--info','version:1-r0','--info','arch:noarch']
  if name=='ip-tiny':command+=['--info','provides:ip']
  subprocess.run(command,check=True)
  stubs.append(str(file))
 for arch in profiles:
  db=root/arch
  (db/'etc/apk').mkdir(parents=True);(db/'etc/apk/arch').write_text(arch+'\n')
  files=list((args.packages_root/arch).glob('*.apk'));assert len(files)==3,(arch,files)
  common=[apk,'--root',str(db),'--allow-untrusted','--no-scripts']
  subprocess.run([*common,'add','--force-non-repository','--initdb',*stubs],check=True)
  world=db/'etc/apk/world';before=world.read_bytes()
  subprocess.run([apk,'--root',str(db),'--simulate','--allow-untrusted','add','--force-non-repository',*map(str,files)],check=True)
  assert world.read_bytes()==before,'simulation changed world'
  if args.baseline_root and arch=='aarch64_cortex-a53':
   baseline=list((args.baseline_root/arch).glob('*.apk'));assert len(baseline)==3
   subprocess.run([*common,'add','--force-non-repository',*map(str,baseline)],check=True)
   catalog=db/'usr/lib/lua/luci/i18n/homegate.zh-cn.lmo';catalog.parent.mkdir(parents=True,exist_ok=True)
   old_catalog=db/'usr/share/luci/i18n/homegate.zh-cn.lmo'
   if old_catalog.exists():catalog.write_bytes(old_catalog.read_bytes())
   else:assert catalog.stat().st_size>1000
   (db/'www/luci-static/resources/homegate/common.js').write_text("'use strict'; return {render:function(){}};\n")
  subprocess.run([*common,'add','--force-non-repository','--initdb',*stubs,*map(str,files)],check=True)
  result=subprocess.check_output([apk,'--root',str(db),'list','-I','homegate'],text=True)
  assert 'homegate-1.3.0-r11 '+arch+' ' in result,result
  catalog=db/'usr/lib/lua/luci/i18n/homegate.zh-cn.lmo';assert catalog.stat().st_size>1000
  assert not (db/'usr/share/luci/i18n/homegate.zh-cn.lmo').exists()
  assert 'return baseclass.extend(' in (db/'www/luci-static/resources/homegate/common.js').read_text(encoding='utf-8')
  language=subprocess.check_output([apk,'--root',str(db),'info','-L','luci-i18n-homegate-zh-cn'],text=True)
  assert 'usr/lib/lua/luci/i18n/homegate.zh-cn.lmo' in language
  if args.baseline_root and arch=='aarch64_cortex-a53':print('PASS real APK upgrade replaces modified JS/LMO; old catalog absent',flush=True)
  print('PASS real ARM64 APK database install (hooks disabled)',arch,flush=True)
 wrong=root/'wrong-profile'
 (wrong/'etc/apk').mkdir(parents=True);(wrong/'etc/apk/arch').write_text('aarch64\n')
 result=subprocess.run([apk,'--root',str(wrong),'--allow-untrusted','--no-scripts','--force-non-repository','add','--initdb',*stubs,str(args.packages_root/'aarch64_cortex-a53/homegate-1.3.0-r11.apk')],capture_output=True,text=True)
 assert result.returncode!=0,'Mismatched architecture was accepted'
 print(result.stderr.strip())
 print('PASS real APK manager rejects mismatched architecture')
