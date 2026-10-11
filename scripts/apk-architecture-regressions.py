#!/usr/bin/env python3
"""APK defaults differ from configured architectures; never guess on conflict."""
from pathlib import Path
import os,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
 root=Path(temp);tools=root/'bin';tools.mkdir();p=tools/'apk';p.write_text('#!/bin/sh\necho aarch64\n');p.chmod(0o755)
 arch=root/'arch';release=root/'release'
 cases=[('现场默认与固件不同','aarch64_cortex-a53\n','aarch64_cortex-a53','aarch64_cortex-a53'),('多架构','unknown_valid\naarch64_generic\naarch64\n','aarch64_generic','aarch64_generic'),('空文件一致','','aarch64','aarch64'),('文件缺失',None,'aarch64','aarch64'),('空文件冲突','','aarch64_cortex-a53',None),('非法架构','aarch64; echo BAD\n','aarch64',None),('未支持','x86_64\n','x86_64',None),('非法固件元数据','','aarch64; echo BAD',None)]
 for name,text,firmware,expected in cases:
  if text is None:
   if arch.exists():arch.unlink()
  else:arch.write_text(text)
  release.write_text("DISTRIB_ARCH='"+firmware+"'\n")
  env=dict(os.environ,PATH=str(tools)+':'+os.environ['PATH'],HOMEGATE_APK_ARCH_FILE=str(arch),HOMEGATE_RELEASE_FILE=str(release))
  command='. "$1"; hg_apk_arch || exit 1; printf "%s" "$HG_ARCH"'
  result=subprocess.run(['sh','-c',command,'fixture',str(ROOT/'scripts/arm64-profile.sh')],env=env,capture_output=True,text=True)
  if expected:assert result.returncode==0 and result.stdout==expected,(name,result.stdout,result.stderr)
  else:assert result.returncode!=0,(name,result.stdout)
  print('PASS architecture',name)
