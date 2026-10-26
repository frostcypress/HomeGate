#!/usr/bin/env python3
"""Explicit isolated CI groups; tests within each runner remain serial."""
import argparse,subprocess,sys
from pathlib import Path
GROUPS={
 'Aliyun':['Aliyun只读回归.py','Aliyun记录回归.py','Aliyun恢复回归.py','Aliyun终态回归.py','Aliyun维护回归.py','Aliyun检查点回归.py'],
 'DNSPod':['DNSPod只读回归.py','DNSPod记录回归.py','DNSPod恢复回归.py','DNSPod终态回归.py','DNSPod维护回归.py','DNSPod检查点回归.py'],
 'Huawei':['华为云只读回归.py','华为云记录回归.py','华为云恢复回归.py','华为云终态回归.py','华为云维护回归.py','华为云检查点回归.py'],
 'DDNS执行':['DDNS计划回归.py','DDNS执行回归.py','DDNS外层恢复回归.py'],
 # Keep the original serial order across two bounded jobs; do not skip any suite.
 'DDNS授权状态':['DDNS运行授权回归.py','DDNS普通运行回归.py'],
 'DDNS状态退避':['DDNS状态退避回归.py'],
 'DDNS授权收尾':['DDNS普通收尾回归.py','DDNS多规则授权回归.py'],
 'DDNS全批':['DDNS全批协调回归.py'],
 'DDNS混合全批':['DDNS全批协调回归.py'],
 'DDNS批次收尾':['DDNS批次收尾回归.py'],
 'DDNS有界调度':['DDNS有界调度回归.py'],
 'DDNS混合调度':['DDNS有界调度回归.py'],
 'DDNS生命周期CLI':['DDNS生命周期CLI回归.py'],
 '核心DNS只读CLI':['DDNS生命周期CLI回归.py'],
 '核心网络配置CLI':['DDNS生命周期CLI回归.py'],
 '核心健康恢复CLI':['DDNS生命周期CLI回归.py'],
 'DDNS恢复摘要CLI':['DDNS生命周期CLI回归.py'],
 'DDNS原生授权UI':['DDNS原生授权UI回归.py'],
 'DDNS异步任务':['DDNS异步任务回归.py'],
 'DDNS明确维护':['DDNS明确维护回归.py'],
}
# Static checks run once; runtime source partitions are disjoint and exhaustive.
MODES={
 'DDNS生命周期CLI':((),('--runtime','--partition','lifecycle')),
 '核心DNS只读CLI':(('--runtime','--partition','dns'),),
 '核心网络配置CLI':(('--runtime','--partition','network-config'),),
 '核心健康恢复CLI':(('--runtime','--partition','health-recovery'),),
 'DDNS恢复摘要CLI':(('--runtime','--partition','ddns-recovery'),),
 'DDNS全批':((),('--runtime','--auto-only')),
 'DDNS混合全批':(('--runtime','--mixed-only'),),
 'DDNS有界调度':((),('--runtime','--auto-only')),
 'DDNS混合调度':(('--runtime','--mixed-only'),),
}

def commands(group,root):
 if group not in GROUPS:raise ValueError('Unknown CI group')
 for name in GROUPS[group]:
  for args in MODES.get(group,((),('--runtime',))):
   yield [sys.executable,str(root/name),*args]

def run_group(group,root):
 for command in commands(group,root):
  print('RUN '+' '.join(command[1:]),flush=True)
  subprocess.run(command,check=True)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('group',choices=GROUPS);a=p.parse_args()
 run_group(a.group,Path(__file__).resolve().parent)
