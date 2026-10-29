#!/usr/bin/env python3
"""Bounded CI partitions for real engineering LuCI/certificate/proxy scenarios."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    'engineering-core': ('web', ('security', 'configuration', 'async', 'schedule', 'contracts', 'continuous', 'lifecycle', 'intent_recovery', 'intent_cleanup', 'intent_frames')),
    'engineering-copy': ('web', ('production_copy', 'production_copy_sources', 'production_copy_recovery', 'production_copy_rollback')),
    'engineering-certificate': ('web', ('certificate', 'certificate_invalid', 'certificate_recovery', 'certificate_timeout')),
    'engineering-acme-providers': ('web', ('acme', 'acme_accounts', 'acme_aliyun', 'acme_dnspod', 'acme_huawei')),
    'engineering-acme-failure': ('web', ('acme_failure', 'acme_unknown', 'acme_preexisting', 'acme_stop')),
    'engineering-acme-schedule': ('web', ('acme_schedule', 'acme_schedule_unknown', 'acme_cold', 'acme_due', 'acme_schedule_stop', 'acme_race', 'acme_schedule_timeout', 'acme_publication_recovery')),
    'engineering-proxy': ('proxy', ('routing', 'streaming', 'upstream_tls', 'acl', 'lifecycle_proxy', 'security_proxy')),
    'engineering-proxy-reload': ('proxy', ('reload', 'reload_reject', 'reload_rollback', 'reload_stop')),
    'engineering-access': ('proxy', ('cn_policy', 'cn_cache', 'access_audit', 'access_stop')),
}


def commands(group, base, prepare=False):
    if group not in GROUPS:
        raise ValueError('Unknown engineering CI group')
    kind, cases = GROUPS[group]
    base = Path(base).resolve()
    script = ROOT / 'scripts'
    if prepare:
        result = [
            [sys.executable, str(script/'prepare-ucode.py'), '--runtime-dir', str(base/'ucode')],
            [sys.executable, str(script/'prepare-rpcd.py'), '--runtime-dir', str(base/'rpcd'), '--ucode-runtime-dir', str(base/'ucode')],
            [sys.executable, str(script/'prepare-uhttpd.py'), '--runtime-dir', str(base/'uhttpd'), '--rpc-runtime-dir', str(base/'rpcd')],
            [sys.executable, str(script/'prepare-luci.py'), '--runtime-dir', str(base/'luci'), '--rpc-runtime-dir', str(base/'rpcd')],
        ]
        if kind == 'proxy':
            result += [[sys.executable, str(script/'prepare-nginx.py'), '--runtime-dir', str(base/'nginx')],
                       [sys.executable, str(script/'prepare-nginx.py'), '--fixture-dir', str(base/'nginx-fixture')]]
        return result
    flags = ['--runtime-dir', str(base/'rpcd'), '--http-runtime-dir', str(base/'uhttpd'), '--luci-runtime-dir', str(base/'luci')]
    if kind == 'proxy':
        flags += ['--nginx-runtime-dir', str(base/'nginx'), '--nginx-fixture-dir', str(base/'nginx-fixture')]
    return [[sys.executable, str(script/('工程代理回归.py' if kind == 'proxy' else '工程网页回归.py')), *flags, '--group', case] for case in cases]


def run_group(group, base, prepare=False):
    for command in commands(group, base, prepare):
        print('engineering-ci: '+Path(command[1]).name+' '+command[-1], flush=True)
        subprocess.run(command, check=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('group', choices=GROUPS)
    p.add_argument('--runtime-base', type=Path, default=ROOT/'build')
    p.add_argument('--prepare', action='store_true')
    p.add_argument('--list', action='store_true')
    a = p.parse_args()
    if a.list:
        import json
        print(json.dumps(commands(a.group, a.runtime_base, a.prepare)))
    else:
        run_group(a.group, a.runtime_base, a.prepare)
