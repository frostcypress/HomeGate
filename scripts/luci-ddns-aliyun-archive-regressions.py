#!/usr/bin/env python3
"""Real Aliyun task -> fresh Lua consent -> original Aliyun receipt archive."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from project import ROOT


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


aliyun=module('ali_archive_tasks','luci-ddns-aliyun-jobs-regressions.py')
scenario=module('ali_archive_protocol','luci-ddns-archive-regressions.py')
read,luci,rpc=aliyun.read,aliyun.luci,aliyun.rpc
scenario.read,scenario.luci,scenario.rpc=read,luci,rpc
CASES=('01','02','03','04','05','06')


def setup_state(state):
    aliyun.setup_state(state)
    scenario.enable_archive(state,'aliyun')


class AliyunArchive(aliyun.AliyunJobs):
    ARCHIVE_RULE='ddns_0'
    confirmed=scenario.Archive.confirmed
    maintain=scenario.Archive.maintain
    preview=scenario.Archive.preview
    commit=scenario.Archive.commit
    refused=scenario.Archive.refused
    tree=staticmethod(scenario.Archive.tree)
    archived=scenario.Archive.archived

    # Reuse the original source/consent/failure checks with real HGALIJOURNAL1.
    test_ali_archive_01_original_retained=scenario.Archive.test_archive_01_explicit_archive_retains_original_receipt_and_task
    test_ali_archive_02_source_and_nonce=scenario.Archive.test_archive_02_nonce_and_original_source_binding
    test_ali_archive_03_locks_and_gate=scenario.Archive.test_archive_03_all_locks_and_closed_maintenance_gate_preserve_source
    test_ali_archive_04_collector_refused=scenario.Archive.test_archive_04_collector_refusal_consumes_old_consent_but_keeps_receipt
    test_ali_archive_05_interrupted_marker=scenario.Archive.test_archive_05_archive_before_final_marker_requires_fresh_consent
    test_ali_archive_06_unknown_refused=scenario.Archive.test_archive_06_unknown_attempt_cannot_be_collected


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd')
    parser.add_argument('--http-runtime-dir',type=Path,default=luci.HTTP)
    parser.add_argument('--luci-runtime-dir',type=Path,default=luci.LUA)
    parser.add_argument('--inside-net',help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid',help=argparse.SUPPRESS)
    parser.add_argument('--case',choices=CASES)
    args=parser.parse_args()
    rpc.WORK,luci.HTTP,luci.LUA=args.runtime_dir.resolve(),args.http_runtime_dir.resolve(),args.luci_runtime_dir.resolve()
    if args.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID=args.inside_net,args.inside_uid
        names=[n for n in sorted(AliyunArchive.__dict__) if n.startswith('test_ali_archive_') and n.split('_')[3]==args.case]
        if len(names)!=1:raise ValueError('Expected one original Aliyun archive scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(AliyunArchive(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    curl=subprocess.run([str(aliyun.provider.CURL),'--version'],capture_output=True,check=True)
    if not curl.stdout.startswith(b'curl 7.83.1 '):raise ValueError('Use pinned curl7.83.1')
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER] if p.is_file()}
    result=0
    for case in ((args.case,) if args.case else CASES):
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
            extra_mounts=lambda state:((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),(state/'libexec','/usr/libexec'),
                (state/'tools','/usr/sbin'),(state/'curl-transport','/usr/bin/curl'),(state/'openssl-real','/usr/bin/openssl')),
            extra_rw_mounts=lambda state:((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
            state_setup=setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--case',case))
        if result:break
    if any(p.read_bytes()!=body for p,body in original.items()):raise ValueError('Original source changed during Aliyun archive checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(str(error),file=sys.stderr);sys.exit(2)
