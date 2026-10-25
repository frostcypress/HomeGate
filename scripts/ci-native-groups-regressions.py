#!/usr/bin/env python3
"""Exercise the real shell dispatcher without starting provider/runtime tests."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from project import ROOT


# Fixed coverage contract: moving a suite must not silently drop or duplicate it.
GROUPS={
    'authority':('luci-ddns-authority-regressions.py','rpc-ddns-authority-regressions.py'),
    'tasks':('luci-ddns-jobs-regressions.py','rpc-ddns-jobs-regressions.py',
             'luci-ddns-maintenance-regressions.py','rpc-ddns-maintenance-regressions.py'),
    'receipts':('luci-ddns-provider-jobs-regressions.py','luci-ddns-archive-regressions.py',
                'rpc-ddns-archive-regressions.py'),
}
PREPARE=('prepare-ucode.py','prepare-rpcd.py','prepare-uhttpd.py','prepare-luci.py')
ALL=tuple(name for group in GROUPS.values() for name in group)


class Dispatch(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='homegate-ci-dispatch-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'source with spaces'
        self.scripts=self.root/'scripts';self.scripts.mkdir(parents=True)
        self.entry=self.scripts/'check-ddns-authority.sh'
        self.entry.write_bytes((ROOT/'scripts/check-ddns-authority.sh').read_bytes())
        self.bin=Path(self.temp.name)/'bin';self.bin.mkdir()
        self.log=Path(self.temp.name)/'calls.jsonl'
        shim=self.bin/'python3'
        shim.write_text('#!'+sys.executable+'\n'+r'''
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['HOMEGATE_DISPATCH_LOG'],'a') as log:log.write(json.dumps(args)+'\n')
if args and args[0]=='-c':
    assert len(args)==3 and args[1]=='import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())'
    print(Path(args[2]).resolve())
else:
    assert args and Path(args[0]).parent.name=='scripts'
    if Path(args[0]).name==os.environ.get('HOMEGATE_DISPATCH_FAIL'):sys.exit(17)
''',encoding='utf-8',newline='\n')
        shim.chmod(0o755)
        self.sh=shutil.which('sh')
        if not self.sh:raise RuntimeError('A real POSIX shell is required')

    def run_entry(self,*args,fail=''):
        self.log.unlink(missing_ok=True)
        env={**os.environ,'PATH':str(self.bin)+os.pathsep+os.defpath,
             'HOMEGATE_DISPATCH_LOG':str(self.log),'HOMEGATE_DISPATCH_FAIL':fail}
        result=subprocess.run([self.sh,str(self.entry),*args],cwd=self.root,env=env,
                              capture_output=True,timeout=20)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        scripts=[Path(args[0]).name for args in calls if args[0]!='-c']
        return result,calls,scripts

    def test_01_three_groups_partition_all_nine_suites(self):
        collected=[]
        for group,names in GROUPS.items():
            with self.subTest(group=group):
                result,calls,scripts=self.run_entry('--group',group)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                self.assertEqual(scripts,list(PREPARE+names))
                self.assertEqual(len([c for c in calls if c[0]=='-c']),4)
                collected.extend(scripts[4:])
        self.assertEqual(collected,list(ALL));self.assertEqual(len(set(collected)),9)

    def test_02_default_and_explicit_all_preserve_original_order(self):
        for args in [(),('--group','all')]:
            result,_,scripts=self.run_entry(*args)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertEqual(scripts,list(PREPARE+ALL))

    def test_03_custom_runtime_paths_preserve_quoting_and_dependency_order(self):
        paths=[str(Path(self.temp.name)/(name+' runtime with spaces')) for name in ('lua','http','rpc','ucode')]
        for args,names in [(paths,ALL),(['--group','tasks',*paths],GROUPS['tasks'])]:
            result,calls,scripts=self.run_entry(*args)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertEqual(scripts,list(PREPARE+names))
            commands=calls[4:];lua,http,rpc,native=paths
            expected=[['--runtime-dir',native],['--runtime-dir',rpc,'--ucode-runtime-dir',native],
                      ['--runtime-dir',http,'--rpc-runtime-dir',rpc],['--runtime-dir',lua,'--rpc-runtime-dir',rpc]]
            self.assertEqual([c[1:] for c in commands[:4]],expected)
            for command in commands[4:]:
                self.assertEqual(command[1:],['--runtime-dir',rpc,'--http-runtime-dir',http,'--luci-runtime-dir',lua])

    def test_04_invalid_group_or_arity_cannot_prepare_or_run(self):
        for args in [('--group',),('--group','unknown'),('--group',''),('--unknown',),
                     tuple('abcde'),('--group','receipts',*tuple('abcde'))]:
            result,calls,_=self.run_entry(*args)
            self.assertEqual(result.returncode,2)
            self.assertEqual(calls,[])

    def test_05_every_suite_failure_stops_its_group(self):
        for group,names in GROUPS.items():
            for index,name in enumerate(names):
                with self.subTest(group=group,failure=name):
                    result,_,scripts=self.run_entry('--group',group,fail=name)
                    self.assertEqual(result.returncode,17)
                    self.assertEqual(scripts,list(PREPARE+names[:index+1]))
                    self.assertEqual(result.stdout.count(b'checks passed'),index)

    def test_06_prepare_failure_never_enters_business_suites(self):
        for index,name in enumerate(PREPARE):
            result,_,scripts=self.run_entry('--group','receipts',fail=name)
            self.assertEqual(result.returncode,17)
            self.assertEqual(scripts,list(PREPARE[:index+1]))

    def test_07_real_shell_syntax_and_lf(self):
        self.assertNotIn(b'\r',self.entry.read_bytes())
        result=subprocess.run([self.sh,'-n',str(self.entry)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=='__main__':unittest.main(verbosity=2)
