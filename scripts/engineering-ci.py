#!/usr/bin/env python3
"""Bounded CI partitions for real engineering LuCI/certificate/proxy scenarios."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    'native-production': ('production', ('deployment', 'migration', 'backup', 'rollback', 'recovery', 'security', 'diagnostics', 'daemon', 'daemon_ddns', 'daemon_source', 'daemon_security', 'daemon_web', 'daemon_acme', 'daemon_acme_unknown', 'daemon_proxy', 'package_source', 'cli_compat', 'cli_acme', 'cli_ca_logs', 'cli_acme_unknown', 'cli_acme_all', 'transition_source', 'transition_identity', 'web_forms', 'web_http', 'web_security', 'web_public', 'web_certificate', 'web_acme', 'web_unknown', 'web_admission', 'web_apply', 'cert_adopt', 'cert_ownership', 'cli_arity', 'web_owner_refusal', 'cert_purge_resume', 'web_reapply', 'web_apply_ddns', 'web_apply_proxy', 'cert_adopt_acme', 'cli_reports', 'cli_selftest', 'cli_ddns', 'cli_ddns_unknown', 'cli_ddns_batch', 'cli_queue', 'cli_actions', 'web_access_actions', 'web_maintenance_actions','cli_firewall','daemon_component_failure')),
    'engineering-core': ('web', ('security', 'configuration', 'async', 'schedule', 'contracts', 'continuous', 'lifecycle', 'intent_recovery', 'intent_cleanup', 'intent_frames')),
    'engineering-copy': ('web', ('production_copy', 'production_copy_sources', 'production_copy_recovery', 'production_copy_rollback')),
    'engineering-certificate': ('web', ('certificate', 'certificate_invalid', 'certificate_recovery', 'certificate_timeout')),
    'engineering-acme-providers': ('web', ('acme', 'acme_accounts', 'acme_aliyun', 'acme_dnspod', 'acme_huawei')),
    'engineering-acme-failure': ('web', ('acme_failure', 'acme_unknown', 'acme_preexisting', 'acme_stop')),
    'engineering-acme-schedule': ('web', ('acme_schedule', 'acme_schedule_unknown', 'acme_cold', 'acme_due', 'acme_schedule_stop', 'acme_race', 'acme_schedule_timeout', 'acme_publication_recovery')),
    'engineering-proxy': ('proxy', ('routing', 'streaming', 'upstream_tls', 'upstream_ip', 'upstream_ip_trust', 'component_profile', 'firewall_apply', 'firewall_reload', 'firewall_failure', 'firewall_safety', 'acl', 'lifecycle_proxy', 'security_proxy')),
    'engineering-proxy-reload': ('proxy', ('reload', 'reload_reject', 'reload_rollback', 'reload_stop')),
    'engineering-access': ('proxy', ('cn_policy', 'cn_cache', 'access_audit', 'access_stop')),
    'engineering-wol': ('wol', ('saved', 'direct', 'failures', 'security', 'bounds')),
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
        if kind in ('proxy','production'):
            result += [[sys.executable, str(script/'prepare-nginx.py'), '--runtime-dir', str(base/'nginx')],
                       [sys.executable, str(script/'prepare-nginx.py'), '--fixture-dir', str(base/'nginx-fixture')]]
        if kind in ('wol','production'):
            result += [[sys.executable, str(script/'prepare-wol.py'), '--runtime-dir', str(base/'wol')],
                       [sys.executable, str(script/'prepare-wol.py'), '--fixture-dir', str(base/'wol-fixture')]]
        return result
    flags = ['--runtime-dir', str(base/'rpcd'), '--http-runtime-dir', str(base/'uhttpd'), '--luci-runtime-dir', str(base/'luci')]
    if kind in ('proxy','production'):
        flags += ['--nginx-runtime-dir', str(base/'nginx'), '--nginx-fixture-dir', str(base/'nginx-fixture')]
    if kind in ('wol','production'):
        flags += ['--wol-runtime-dir', str(base/'wol'), '--wol-fixture-dir', str(base/'wol-fixture')]
    return [[sys.executable, str(script/('生产接管回归.py' if kind == 'production' else '工程WOL回归.py' if kind == 'wol' else '工程代理回归.py' if kind == 'proxy' else '工程网页回归.py')), *flags, '--group', case] for case in cases]


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
