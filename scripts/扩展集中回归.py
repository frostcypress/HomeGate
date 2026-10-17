#!/usr/bin/env python3
"""Explicit isolated CI groups; tests within each runner remain serial."""
import argparse,subprocess,sys
from pathlib import Path
GROUPS={
 'Aliyun':['Aliyun只读回归.py','Aliyun记录回归.py','Aliyun恢复回归.py','Aliyun终态回归.py','Aliyun维护回归.py','Aliyun检查点回归.py'],
 'DNSPod':['DNSPod只读回归.py','DNSPod记录回归.py','DNSPod恢复回归.py','DNSPod终态回归.py','DNSPod维护回归.py','DNSPod检查点回归.py'],
 'Huawei':['华为云只读回归.py','华为云记录回归.py','华为云恢复回归.py','华为云终态回归.py','华为云维护回归.py','华为云检查点回归.py'],
 'DDNS执行':['DDNS计划回归.py','DDNS执行回归.py','DDNS外层恢复回归.py'],
 'DDNS授权状态':['DDNS运行授权回归.py','DDNS普通运行回归.py','DDNS状态退避回归.py'],
}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('group',choices=GROUPS);a=p.parse_args();root=Path(__file__).resolve().parent
 for name in GROUPS[a.group]:
  for args in [[],['--runtime']]:
   print('RUN '+name+' '+' '.join(args),flush=True)
   subprocess.run([sys.executable,str(root/name),*args],check=True)
