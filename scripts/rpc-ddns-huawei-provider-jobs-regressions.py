#!/usr/bin/env python3
"""Real signed Huawei HTTP/rpcd mixed grants and selected-interface tasks."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from project import ROOT

def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value

huawei=module('rpc_hw_mixed_tasks','luci-ddns-huawei-jobs-regressions.py')
common=module('rpc_hw_mixed_transport','rpc-ddns-provider-jobs-regressions.py')
read,luci,rpc=huawei.read,huawei.luci,huawei.rpc
http=luci.http
common.rpc_read.read,common.rpc_read.luci,common.rpc_read.rpc,common.rpc_read.http=read,luci,rpc,http
STORE,RUN,STATE=huawei.STORE,huawei.RUN,huawei.STATE
CASES=common.CASES

def setup_state(state):
    huawei.setup_mixed_state(state)
    common.rpc_read.enable_rpc(state)

class HTTPHuaweiMixedJobs(common.MixedTaskTransport,huawei.HuaweiMixedJobs):
    TASK_RULE='ddns_3'

    def job_result(self,action,sid,result,expected=200):
        raw=json.dumps(result).encode()
        for marker in (huawei.DOMAIN.encode(),huawei.HOST.encode(),b'FIXTURE_ID',b'SECRET_SENTINEL'):
            self.assertNotIn(marker,raw,'Private Huawei configuration escaped the public RPC result')
        return super().job_result(action,sid,result,expected)

    test_rpc_mixed_01_noop=huawei.HuaweiMixedJobs.test_huawei_05_mixed_interface_noop_retains_scoped_task
    test_rpc_mixed_02_original_receipt=huawei.HuaweiMixedJobs.test_huawei_06_interface_create_keeps_original_signed_receipt
    test_rpc_mixed_03_missing_interface=huawei.HuaweiMixedJobs.test_huawei_07_missing_interface
    test_rpc_mixed_04_unknown_barrier=huawei.HuaweiMixedJobs.test_huawei_09_unknown_interface_attempt_keeps_original_evidence

    def seed_interface_noop(self):
        self.db['1']=huawei.record(1,['2001:db8:2::9'])


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
        names=[n for n in dir(HTTPHuaweiMixedJobs) if n.startswith('test_rpc_mixed_') and n.split('_')[3]==args.case]
        if len(names)!=1:raise ValueError('Expected one mixed-interface RPC task scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(HTTPHuaweiMixedJobs(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER,rpc.CANDIDATE,rpc.ACL] if p.is_file()}
    if rpc.CANDIDATE.read_bytes().count(rpc.GATE)!=1:raise ValueError('Original RPC gate must remain closed')
    curl=subprocess.run([str(huawei.signed.provider.CURL),'--version'],capture_output=True,check=True)
    if not curl.stdout.startswith(b'curl 7.83.1 '):raise ValueError('Use pinned curl7.83.1')
    result=0
    for case in ((args.case,) if args.case else CASES):
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
            extra_mounts=lambda state:((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),(state/'libexec','/usr/libexec'),
                (state/'tools','/usr/sbin'),(state/'curl-transport','/usr/bin/curl'),(state/'openssl-real','/usr/bin/openssl')),
            extra_rw_mounts=lambda state:((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
            state_setup=setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--case',case))
        if result:break
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original source or ACL changed during RPC mixed-interface checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
