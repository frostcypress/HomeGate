#!/usr/bin/env python3
"""Verify actual extended dispatch commands and disjoint runtime selections."""
import collections
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from project import ROOT

spec=importlib.util.spec_from_file_location('extended_dispatch',ROOT/'scripts/扩展集中回归.py')
dispatch=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch)
ORIGINAL_GROUPS={'Aliyun': ['Aliyun只读回归.py', 'Aliyun记录回归.py', 'Aliyun恢复回归.py', 'Aliyun终态回归.py', 'Aliyun维护回归.py', 'Aliyun检查点回归.py'], 'DNSPod': ['DNSPod只读回归.py', 'DNSPod记录回归.py', 'DNSPod恢复回归.py', 'DNSPod终态回归.py', 'DNSPod维护回归.py', 'DNSPod检查点回归.py'], 'Huawei': ['华为云只读回归.py', '华为云记录回归.py', '华为云恢复回归.py', '华为云终态回归.py', '华为云维护回归.py', '华为云检查点回归.py'], 'DDNS执行': ['DDNS计划回归.py', 'DDNS执行回归.py', 'DDNS外层恢复回归.py'], 'DDNS授权状态': ['DDNS运行授权回归.py', 'DDNS普通运行回归.py', 'DDNS状态退避回归.py'], 'DDNS授权收尾': ['DDNS普通收尾回归.py', 'DDNS多规则授权回归.py'], 'DDNS全批': ['DDNS全批协调回归.py'], 'DDNS批次收尾': ['DDNS批次收尾回归.py'], 'DDNS有界调度': ['DDNS有界调度回归.py'], 'DDNS生命周期CLI': ['DDNS生命周期CLI回归.py'], 'DDNS原生授权UI': ['DDNS原生授权UI回归.py'], 'DDNS异步任务': ['DDNS异步任务回归.py'], 'DDNS明确维护': ['DDNS明确维护回归.py']}
PARTITIONS={
    'DDNS全批协调回归.py':(('--auto-only',),('--mixed-only',)),
    'DDNS有界调度回归.py':(('--auto-only',),('--mixed-only',)),
    'DDNS生命周期CLI回归.py':tuple(('--partition',name) for name in
        ('lifecycle','dns','network-config','health-recovery','ddns-recovery')),
}

class Dispatch(unittest.TestCase):
    def commands(self,group):return list(dispatch.commands(group,ROOT/'scripts'))
    def test_01_all_original_suites_have_exactly_one_static_and_runtime_partition(self):
        expected=[]
        for names in ORIGINAL_GROUPS.values():
            for name in names:
                expected.append((name,()))
                for args in (tuple(('--runtime',*flags) for flags in PARTITIONS[name]) if name in PARTITIONS else (('--runtime',),)):
                    expected.append((name,args))
        actual=[(Path(c[1]).name,tuple(c[2:])) for g in dispatch.GROUPS for c in self.commands(g)]
        self.assertEqual(collections.Counter(actual),collections.Counter(expected))
        self.assertEqual(len(actual),len(set(actual)))
    def test_02_real_suite_discovery_proves_runtime_union_and_no_overlap(self):
        for name,flags in PARTITIONS.items():
            def discover(*flags):
                result=subprocess.run([sys.executable,str(ROOT/'scripts'/name),'--runtime',*flags,'--list-tests'],capture_output=True,timeout=30,check=True)
                return json.loads(result.stdout)
            with self.subTest(suite=name):
                original=discover();parts=[discover(*args) for args in flags]
                self.assertTrue(all(parts));self.assertEqual(original,[case for part in parts for case in part])
                self.assertEqual(len(original),len(set(original)))
                for i,part in enumerate(parts):
                    self.assertEqual(len(part),len(set(part)))
                    for other in parts[i+1:]:self.assertFalse(set(part)&set(other))
    def test_03_invalid_source_modes_fail_before_running_scenarios(self):
        for name,modes in PARTITIONS.items():
            invalid=[args for args in modes]
            if name=='DDNS生命周期CLI回归.py':invalid += [('--runtime','--partition','unknown'),('--runtime','--auto-only')]
            else:invalid += [('--runtime','--auto-only','--mixed-only')]
            for flags in invalid:
                result=subprocess.run([sys.executable,str(ROOT/'scripts'/name),*flags,'--list-tests'],capture_output=True,timeout=30)
                self.assertEqual(result.returncode,2);self.assertNotIn(b'Ran ',result.stderr)
    def test_04_failure_in_every_command_stops_the_real_runner(self):
        for group in dispatch.GROUPS:
            commands=self.commands(group)
            for index in range(len(commands)):
                calls=[]
                def run(command,**kwargs):
                    self.assertEqual(kwargs,{'check':True});calls.append(command)
                    if len(calls)==index+1:raise subprocess.CalledProcessError(17,command)
                with patch.object(dispatch.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(subprocess.CalledProcessError):dispatch.run_group(group,ROOT/'scripts')
                self.assertEqual(calls,commands[:index+1])
    def test_05_workflow_matrix_and_sdk_gate_cover_every_group(self):
        body=(ROOT/'.github/workflows/编译发布.yml').read_text()
        extended=body.split('  extended:\n',1)[1].split('  native:\n',1)[0]
        matrix=re.search(r'group: \[([^\]]+)\]',extended).group(1).split(', ')
        self.assertEqual(matrix,list(dispatch.GROUPS));self.assertEqual(len(matrix),20)
        self.assertEqual(len(matrix),len(set(matrix)))
        native=body.split('  native:\n',1)[1].split('  build:\n',1)[0]
        self.assertEqual(len(re.search(r'group: \[([^\]]+)\]',native).group(1).split(', ')),6)
        self.assertIn('needs: [source, extended, native]',body)
        self.assertIn('build/verify-venv/bin/python scripts/ci-extended-groups-regressions.py',body)
    def test_06_other_groups_keep_original_commands_and_order(self):
        for group,names in ORIGINAL_GROUPS.items():
            if group in ('DDNS全批','DDNS有界调度','DDNS授权状态','DDNS生命周期CLI'):continue
            expected=[[sys.executable,str(ROOT/'scripts'/name),*args] for name in names for args in ((),('--runtime',))]
            self.assertEqual(self.commands(group),expected)
        original=ORIGINAL_GROUPS['DDNS授权状态']
        actual=self.commands('DDNS授权状态')+self.commands('DDNS状态退避')
        self.assertEqual(actual,[[sys.executable,str(ROOT/'scripts'/name),*args] for name in original for args in ((),('--runtime',))])
    def test_07_unknown_group_executes_nothing(self):
        with patch.object(dispatch.subprocess,'run') as run:
            with self.assertRaises(ValueError):dispatch.run_group('unknown',ROOT/'scripts')
            run.assert_not_called()

    def test_08_real_cli_dispatch_processes_preserve_static_once_and_all_runtime_ids(self):
        # Execute the unchanged dispatcher and actual argument parser without
        # invoking fixtures: the adjacent recorder forwards only --list-tests.
        groups=('DDNS生命周期CLI','核心DNS只读CLI','核心网络配置CLI','核心健康恢复CLI','DDNS恢复摘要CLI')
        real=ROOT/'scripts/DDNS生命周期CLI回归.py'
        with tempfile.TemporaryDirectory(prefix='homegate CLI dispatch ') as tmp:
            root=Path(tmp);entry=root/'扩展集中回归.py'
            entry.write_bytes((ROOT/'scripts/扩展集中回归.py').read_bytes())
            (root/real.name).write_text('import os,sys\nos.execv(sys.executable,[sys.executable,'+repr(str(real))+',*sys.argv[1:],"--list-tests"])\n')
            outputs=[]
            for group in groups:
                result=subprocess.run([sys.executable,str(entry),group],capture_output=True,timeout=30,check=True)
                self.assertEqual(result.stderr,b'')
                outputs.append([json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith('[')])
            def discover(*args):
                return json.loads(subprocess.run([sys.executable,str(real),*args,'--list-tests'],capture_output=True,timeout=30,check=True).stdout)
            self.assertEqual([len(v) for v in outputs],[2,1,1,1,1])
            self.assertEqual(outputs[0][0],discover())
            runtime=[case for i,blocks in enumerate(outputs) for cases in (blocks[1:] if i==0 else blocks) for case in cases]
            self.assertEqual(runtime,discover('--runtime'))
            self.assertEqual(len(runtime),140);self.assertEqual(len(runtime),len(set(runtime)))

if __name__=='__main__':unittest.main(verbosity=2)
