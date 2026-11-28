#!/usr/bin/env python3
"""Real DNSPod HTTP/rpcd tasks and fresh-consent original receipt archive."""
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


dnspod=module('rpc_dnp_archive_source','luci-ddns-dnspod-archive-regressions.py')
transport=module('rpc_dnp_archive_transport','rpc-ddns-archive-regressions.py')
read,luci,rpc=dnspod.read,dnspod.luci,dnspod.rpc
http=luci.http
transport.rpc_read.read,transport.rpc_read.luci,transport.rpc_read.rpc,transport.rpc_read.http=read,luci,rpc,http
CASES=transport.CASES


def setup_state(state):
    dnspod.setup_state(state)
    transport.rpc_read.enable_rpc(state)


class HTTPDNSPodArchive(transport.ArchiveTransport,dnspod.DNSPodArchive):
    RPC_ARCHIVE_RULE='ddns_2'


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
        names=[n for n in sorted(transport.ArchiveTransport.__dict__) if n.startswith('test_rpc_archive_') and n.split('_')[3]==args.case]
        if len(names)!=1:raise ValueError('Expected one DNSPod RPC archive scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(HTTPDNSPodArchive(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER,rpc.CANDIDATE,rpc.ACL] if p.is_file()}
    if rpc.CANDIDATE.read_bytes().count(rpc.GATE)!=1:raise ValueError('Original RPC gate must remain closed')
    curl=subprocess.run([str(dnspod.dnspod.signed.provider.CURL),'--version'],capture_output=True,check=True)
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
    if any(p.read_bytes()!=body for p,body in original.items()):raise ValueError('Original business or ACL source changed during DNSPod RPC checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(str(error),file=sys.stderr);sys.exit(2)
