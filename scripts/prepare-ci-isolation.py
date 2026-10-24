#!/usr/bin/env python3
"""Probe unchanged bwrap boundaries; repair only a hosted runner's known AppArmor prerequisite."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import urllib.request
from project import ROOT

RESTRICTION = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
PACKAGE_URL = ('https://archive.ubuntu.com/ubuntu/pool/main/a/apparmor/'
               'apparmor-profiles_4.0.1really4.0.1-0ubuntu0.24.04.9_all.deb')
PACKAGE_SHA256 = '90b02aa006eea7702cd4e851343e469e41365dda42145a3cb035de1d6c773b8c'
PROFILE_NAME = 'usr/share/apparmor/extra-profiles/bwrap-userns-restrict'
PROFILE_SHA256 = '11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9'


def restriction():
    return RESTRICTION.read_text().strip() if RESTRICTION.exists() else None


def inside_probe(outer_net, outer_uid):
    if os.getuid() != 0 or not outer_uid or outer_uid == '0':
        raise ValueError('Require a non-root outer user mapped to private UID0')
    if Path('/proc/self/uid_map').read_text().split() != ['0', outer_uid, '1']:
        raise ValueError('Unexpected user namespace mapping')
    if os.readlink('/proc/self/ns/net') == outer_net:
        raise ValueError('Host network must not be shared')
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps = {name: int(fields[name].strip(), 16) for name in ('CapEff', 'CapPrm', 'CapBnd')}
    if any(caps.values()):
        raise ValueError('Probe payload must have no capabilities')
    if not os.statvfs(ROOT).f_flag & os.ST_RDONLY:
        raise ValueError('Source mount must be read-only')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0));listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=2):
            accepted, _ = listener.accept();accepted.close()
    try:
        label = Path('/proc/self/attr/current').read_text().strip()
    except OSError:
        label = 'not_exposed'
    print(json.dumps({'private_uid':0,'outer_uid':int(outer_uid),'private_network':True,
                      'loopback_connect':True,'source_read_only':True,'capabilities':caps,'apparmor_label':label}))


def probe():
    command = ['/usr/bin/bwrap', '--unshare-all', '--uid', '0', '--gid', '0', '--cap-drop', 'ALL',
               '--die-with-parent', '--new-session', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
               '--setenv', 'LC_ALL', 'C.UTF-8', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
               '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
               '/usr/bin/python3', str(Path(__file__).resolve()), '--inside-net', os.readlink('/proc/self/ns/net'),
               '--outer-uid', str(os.getuid())]
    result = subprocess.run(command, capture_output=True, timeout=15)
    doc = {'returncode':result.returncode,'stderr':result.stderr.decode(errors='replace')[:4000]}
    if result.returncode == 0:
        doc['verified'] = json.loads(result.stdout)
    return doc


def verified_profile(work):
    work.mkdir(parents=True, exist_ok=True)
    package = work / 'apparmor-profiles.deb'
    if not package.exists():
        with urllib.request.urlopen(PACKAGE_URL, timeout=30) as response:
            body = response.read(1048577)
        if len(body) > 1048576 or hashlib.sha256(body).hexdigest() != PACKAGE_SHA256:
            raise ValueError('Distribution AppArmor package checksum mismatch')
        package.write_bytes(body)
    if hashlib.sha256(package.read_bytes()).hexdigest() != PACKAGE_SHA256:
        raise ValueError('Cached AppArmor package checksum mismatch')
    extraction = work / 'package'
    subprocess.run(['dpkg-deb', '-x', str(package), str(extraction)], check=True)
    profile = extraction / PROFILE_NAME
    if profile.is_symlink() or not profile.is_file() or hashlib.sha256(profile.read_bytes()).hexdigest() != PROFILE_SHA256:
        raise ValueError('Distribution bwrap profile checksum mismatch')
    parser = shutil.which('apparmor_parser')
    if not parser:
        raise ValueError('The runner needs its distribution AppArmor parser')
    # Parse only; no kernel or cache writes in this step.
    subprocess.run([parser, '--skip-kernel-load', '--skip-cache', str(profile)], check=True)
    return parser, profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside-net', help=argparse.SUPPRESS)
    parser.add_argument('--outer-uid', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside_net:
        inside_probe(args.inside_net, args.outer_uid);return 0
    if sys.platform != 'linux' or os.getuid() == 0:
        raise ValueError('Run the probe as the normal non-root Linux test user')
    if shutil.which('bwrap') != '/usr/bin/bwrap':
        raise ValueError('Use the distribution /usr/bin/bwrap')
    work = ROOT / 'build/ci-isolation'
    work.mkdir(parents=True, exist_ok=True)
    before_setting = restriction()
    before = probe()
    record = {'bwrap_version':subprocess.check_output(['/usr/bin/bwrap','--version'], text=True).strip(),
              'restriction_before':before_setting,'before':before,'profile_loaded':False,
              'global_restriction_changed':False,'host_network_shared':False}
    if before['returncode']:
        (work / 'before.json').write_text(json.dumps(record, indent=2)+'\n')
        known = ('Failed RTM_NEWADDR: Operation not permitted' in before['stderr'])
        hosted = os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
        if not known or before_setting != '1' or not hosted:
            raise ValueError('Private bwrap probe failed; no general sandbox bypass: ' + before['stderr'])
        executable, profile = verified_profile(work)
        # Load only Ubuntu's pinned bwrap-specific profile on the disposable hosted runner.
        # Its unpriv_bwrap child profile denies capabilities; no global sysctl/service change.
        subprocess.run(['sudo','-n',executable,'--replace','--skip-cache',str(profile)], check=True)
        record.update(profile_loaded=True,package_url=PACKAGE_URL,package_sha256=PACKAGE_SHA256,profile_sha256=PROFILE_SHA256)
    after = probe()
    record.update(after=after,restriction_after=restriction())
    if after['returncode'] or record['restriction_after'] != before_setting:
        raise ValueError('Private isolation still unavailable or global restriction changed')
    if record['profile_loaded'] and 'unpriv_bwrap' not in after['verified']['apparmor_label']:
        raise ValueError('Expected distribution capability-denying child profile')
    (work / 'verification.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
