#!/usr/bin/env python3
"""Execute installer selection/integrity checks with isolated package-manager fixtures."""
from pathlib import Path
import hashlib, os, subprocess, tempfile, shutil
ROOT=Path(__file__).resolve().parents[1]
profiles=('aarch64','aarch64_generic','aarch64_cortex-a53','aarch64_cortex-a72')
with tempfile.TemporaryDirectory(prefix='hg-arm64-install-') as temp:
 root=Path(temp);tools=root/'bin';tools.mkdir();shutil.copy2(ROOT/'scripts/install.sh',root/'install.sh');shutil.copy2(ROOT/'scripts/arm64-profile.sh',root/'arm64-profile.sh')
 scripts={'id':'echo 0','uname':'echo "${TEST_KERNEL:-aarch64}"',
 'apk':'case "$1" in --print-arch) echo aarch64;;--simulate) [ -z "${TEST_FAIL:-}" ] || { echo "$TEST_FAIL" >&2;exit 1; }; exit 0;;add) printf "%s\\n" "$@" >"$TEST_TRACE";;*) exit 1;;esac',
 'opkg':'case "$1" in print-architecture) printf "arch all 1\\narch aarch64 10\\narch %s 20\\n" "$TEST_ARCH";;install) printf "%s\\n" "$@" >"$TEST_TRACE";;*) exit 1;;esac'}
 for name,body in scripts.items():
  p=tools/name;p.write_text('#!/bin/sh\n'+body+'\n');p.chmod(0o755)
 # The host must not have an installed opkg command: fixtures explicitly select it.
 for manager in ('apk','opkg'):
  apk=tools/'apk';opkg=tools/'opkg'
  if manager=='apk':opkg.rename(tools/'opkg-hidden')
  else:(tools/'opkg-hidden').rename(opkg);apk.rename(tools/'apk-hidden')
  for arch in profiles:
   folder=root/'packages'/('modern-apk' if manager=='apk' else 'legacy-ipk')/arch;folder.mkdir(parents=True)
   names=[f'{p}-1.3.0-r11.apk' for p in ('homegate','luci-app-homegate','luci-i18n-homegate-zh-cn')] if manager=='apk' else [f'homegate_1.3.0-11_{arch}.ipk','luci-app-homegate_1.3.0-11_all.ipk','luci-i18n-homegate-zh-cn_1.3.0-11_all.ipk']
   for name in names:(folder/name).write_bytes(b'fixture')
   (folder/'SHA256SUMS').write_text(''.join(hashlib.sha256(b'fixture').hexdigest()+'  '+n+'\n' for n in names))
   configured=root/'arch';configured.write_text(arch+'\n')
   trace=root/'trace';env=dict(os.environ,PATH=str(tools)+':'+os.environ['PATH'],TEST_ARCH=arch,TEST_TRACE=str(trace),HOMEGATE_APK_ARCH_FILE=str(configured),HOMEGATE_RELEASE_FILE=str(root/'missing-release'))
   result=subprocess.run(['sh',str(root/'install.sh')],env=env,capture_output=True,text=True)
   assert result.returncode==0,(manager,arch,result.stdout,result.stderr)
   assert str(folder/names[0]) in trace.read_text(encoding='utf-8');assert len(trace.read_text(encoding='utf-8').splitlines())==(6 if manager=='apk' else 4)
   print('PASS automatic-selection',manager,arch)
   trace.unlink();(folder/names[0]).write_bytes(b'tampered')
   assert subprocess.run(['sh',str(root/'install.sh')],env=env,capture_output=True).returncode!=0
   assert not trace.exists();print('PASS reject-tampered',manager,arch)
   (folder/names[0]).write_bytes(b'fixture')
  env.update(TEST_KERNEL='armv7l');assert subprocess.run(['sh',str(root/'install.sh')],env=env,capture_output=True).returncode!=0;assert not trace.exists()
  print('PASS reject-32bit-kernel',manager)
 (tools/'apk-hidden').rename(tools/'apk');opkg.rename(tools/'opkg-hidden')
 env.pop('TEST_KERNEL',None)
 for reason in ('error: uninstallable; arch: aarch64','network error: Failed to fetch index','ip (no such package)'):
  env['TEST_FAIL']=reason
  result=subprocess.run(['sh',str(root/'install.sh')],env=env,capture_output=True,text=True)
  assert result.returncode!=0 and not trace.exists(),(result.stdout,result.stderr)
  print('PASS installer preflight rejects',reason)
 print('ARM64 installer: PASS 21 cases')
