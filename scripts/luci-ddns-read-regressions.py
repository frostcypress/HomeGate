#!/usr/bin/env python3
"""Real LuCI HTTP -> private request -> Shell DDNS status/jobs; fixture only."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import unittest
from project import ROOT
import importlib.util


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


luci = module('luci_read_base', 'luci-ddns-regressions.py')
rpc = luci.rpc
PROTO = ROOT / 'project/core/prototype'
STATE = rpc.STATE
GUEST_PROTO = STATE / 'project/core/prototype'
STORE = Path('/etc/homegate/transactions')
RUN = Path('/var/run/homegate')
BUSYBOX = ROOT / 'build/busybox-runtime/busybox-1.33.2/busybox'
PROVIDERS = ('aliyun', 'cloudflare', 'dnspod', 'huaweicloud')
GATES = {
    'homegate-ddns-ui.sh': ('ddns_ui_enabled',),
    'homegate-cli.sh': ('native_cli_enabled',),
    'homegate-ddns-state.sh': ('ddns_state_enabled',),
    'homegate-ddns-job.sh': ('ddns_ui_jobs_enabled',),
    'homegate-store-bootstrap-prototype.sh': ('bootstrap_enabled',),
    'homegate-config-prototype.sh': ('persistent_namespace_enabled', 'production_writes_enabled',
                                      'dns_recovery_read_enabled', 'lifecycle_migration_enabled', 'ddns_authority_enabled'),
}


def legacy():
    body = "package 'homegate'\nconfig homegate 'main'\n option enabled '0'\n"
    for i, provider in enumerate(PROVIDERS):
        body += ("config dns_account 'dns_%d'\n option provider '%s'\n option id 'FIXTURE_ID'\n"
                 " option secret 'SECRET_SENTINEL'\n option account_id 'PRIVATE_ACCOUNT'\n"
                 "config ddns_rule 'ddns_%d'\n option enabled '1'\n option account 'dns_%d'\n"
                 " option zone 'example.test'\n option host 'www'\n" % (i, provider, i, i))
    return body


def setup_state(state):
    luci.setup_state(state)
    shutil.copytree(PROTO, state / 'project/core/prototype')
    backup = state / 'project/luci/lua/luasrc/model/homegate/backup.lua'
    backup.parent.mkdir(parents=True);shutil.copyfile(ROOT / 'project/luci/lua/luasrc/model/homegate/backup.lua', backup)
    for name, flags in GATES.items():
        path = state / 'project/core/prototype' / name
        body = path.read_text()
        for flag in flags:
            old = flag + '=false'
            if body.count(old) != 1:
                raise ValueError('Expected one original closed gate: ' + name + ':' + flag)
            body = body.replace(old, flag + '=true')
        path.write_text(body)
    # These are real libraries used for model-side validation, not replacement responses.
    for name in ('ddns-schedule.lua', 'ddns-job.lua'):
        shutil.copyfile(PROTO / name, state / 'libexec/homegate' / name)
    backend = state / 'libexec/homegate/ddns-ui'
    backend.write_text(r"""#!/usr/bin/python3
import os,stat,sys
p=sys.argv[1]
assert stat.S_IMODE(os.stat(os.path.dirname(p)).st_mode)==0o700
assert stat.S_IMODE(os.stat(p).st_mode)==0o600
with open('/teststate/entry-calls','ab') as f:f.write(b'private-request:700:600\n')
os.execv('/usr/sbin/ash',['ash','/teststate/project/core/prototype/homegate-ddns-ui.sh',*sys.argv[1:]])
""")
    backend.chmod(0o755)
    config = state / 'libexec/homegate/config-transaction'
    config.write_text('#!/bin/sh\nexec /usr/sbin/ash /teststate/project/core/prototype/homegate-config-prototype.sh "$@"\n');config.chmod(0o755)
    tools = state / 'tools';tools.mkdir()
    shutil.copyfile(BUSYBOX, tools / 'busybox');(tools / 'busybox').chmod(0o755)
    for name in ('ash', 'fsync'):
        (tools / name).symlink_to('busybox')
    lua = tools / 'lua'
    lua.write_text('#!/bin/sh\nexec /usr/bin/lua5.1 /teststate/lua-runner.lua "$@"\n');lua.chmod(0o755)
    modules = luci.LUA / 'prefix/lib/lua'
    (state / 'lua-runner.lua').write_text('package.path=' + json.dumps(str(modules / '?.lua') + ';' + str(modules / '?/init.lua')) +
        '\npackage.cpath=' + json.dumps(str(modules / '?.so')) +
        "\nlocal file=table.remove(arg,1);arg[0]=file;assert(loadfile(file))(unpack(arg))\n")
    # Only bootstrap/projection setup consults these fixed, disabled-service fixtures.
    init = state / 'etc/init.d/homegate';init.parent.mkdir()
    init.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> /teststate/service-calls\n[ "$#" = 1 ] && [ "$1" = enabled ] || exit 99\nexit 1\n');init.chmod(0o755)
    (state / 'etc/rc.common').write_text('#!/bin/sh\nexit 99\n');(state / 'etc/rc.common').chmod(0o755)
    ubus = tools / 'ubus'
    ubus.write_text("#!/bin/sh\n[ \"$*\" = '-t 2 -S call service list {\"name\":\"homegate\",\"verbose\":true}' ] || exit 99\nprintf '{}\\n'\n");ubus.chmod(0o755)
    for name in ('curl', 'wget'):
        tool = tools / name
        tool.write_text('#!/bin/sh\nprintf "unexpected-network-tool\\n" >> /teststate/network-calls\nexit 99\n');tool.chmod(0o755)
    (state / 'etc/homegate').mkdir(mode=0o700)
    source = state / 'etc/config/homegate';source.write_text(legacy());source.chmod(0o600)


class ReadOnly(luci.LuaLuCI):
    @classmethod
    def command(cls, name, *args, payload=None):
        p = subprocess.run(['/usr/sbin/ash', str(GUEST_PROTO / name), *args], input=payload,
                           capture_output=True, timeout=20)
        # Output is never emitted: migration handles and credentials stay in the fixture.
        if p.returncode or p.stderr:
            try:
                error = json.loads(p.stdout).get('error', 'invalid fixture response')
            except ValueError:
                error = 'invalid fixture response'
            raise RuntimeError('Private setup failed: ' + name + ':' + (args[1] if len(args) > 1 else args[0]) + ':' + error)
        return json.loads(p.stdout)

    @classmethod
    def engine(cls, *args, **kwargs):
        return cls.command('homegate-config-prototype.sh', '--persistent', *args, **kwargs)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            RUN.mkdir(mode=0o700)
            (RUN / 'frontend.lock').touch(mode=0o600)
            cls.command('homegate-store-bootstrap-prototype.sh', 'bootstrap')
            plan = cls.engine('migration-source-preview')
            cls.engine('migration-source-commit', plan['confirmation'])
            migrated = int((STORE / 'current').read_text())
            public = (STORE / ('gen-%d/public.conf' % migrated)).read_bytes()
            plan = cls.engine('preview', payload=public)
            transaction = cls.engine('commit-apply-projection', plan['confirmation'])
            handle = transaction['apply_handle']
            cls.engine('projection-publish', handle, 'apply')
            cls.engine('apply-finish-projection', handle)
            cls.revision = int((STORE / 'current').read_text())
            if cls.revision != migrated + 1:
                raise RuntimeError('Fixture did not reach the real projected generation')
            if not any(b'SECRET_SENTINEL' in p.read_bytes() for p in (STORE / ('gen-%d/credentials' % cls.revision)).iterdir()):
                raise RuntimeError('Fixture private credentials absent; redaction test would be vacuous')
            cls.interval = int(re.search(rb"option ddns_interval '([0-9]+)'", public).group(1))
            cls.baseline = cls.snapshot()
        except BaseException:
            cls.tearDownClass();raise

    @staticmethod
    def snapshot():
        result = {}
        for root in (STORE, RUN, Path('/etc/config/homegate')):
            for path in ([root, *sorted(root.rglob('*'))] if root.is_dir() else [root]):
                s = path.lstat()
                result[str(path)] = (stat.S_IMODE(s.st_mode), s.st_ino, s.st_nlink,
                                     os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None)
        return result

    def setUp(self):
        super().setUp()
        (STATE / 'models/homegate/ddns.lua').write_bytes(luci.MODEL.read_bytes().replace(luci.MODEL_GATE, b'local native_ddns_ui_enabled=true'))
        self.initial_service = (STATE / 'service-calls').read_bytes()
        self.initial_calls = (STATE / 'entry-calls').read_bytes() if (STATE / 'entry-calls').exists() else b''

    def tearDown(self):
        self.assertTrue(self.snapshot() == self.baseline, 'Read fixture did not restore its baseline; private bytes suppressed')
        self.assertEqual((STATE / 'service-calls').read_bytes(), self.initial_service)
        self.assertFalse((STATE / 'network-calls').exists(), 'Read path invoked an external network tool')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')), [])
        self.assertEqual(list(Path('/tmp').glob('homegate-config-prototype-*')), [])

    def read(self, action, sid, *, expected=200, suffix='', verb='GET'):
        before = self.snapshot()
        status, _, body = self.cgi(luci.BASE + '/ddns_native/' + action + suffix, cookie=sid, verb=verb)
        self.assertEqual(status, expected, 'Read HTTP status changed; body suppressed')
        for value in (b'SECRET_SENTINEL', b'PRIVATE_ACCOUNT', b'FIXTURE_ID', b'example.test', b'/teststate', b'credentials', sid.encode()):
            self.assertTrue(value not in body, 'Private value escaped into HTTP response')
        self.assertTrue(self.snapshot() == before, 'Read changed private configuration/state bytes, modes or inodes; private bytes suppressed')
        result = json.loads(body)
        if expected == 200:
            self.assertEqual(set(result), {'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
            self.assertEqual({k: result[k] for k in result if k != 'report'}, {
                'api_version':1,'prototype':True,'ok':True,'phase':'ddns-ui','operation':action,'effect':'none','write_ready':False})
            return result['report']
        self.gate_response(action, status, body)

    @contextmanager
    def cache(self, mode=0o700):
        path = RUN / 'ddns-state';path.mkdir(mode=mode)
        try:
            yield path
        finally:
            shutil.rmtree(path)

    @contextmanager
    def job(self):
        root = RUN / 'ddns-ui-jobs';root.mkdir(mode=0o700)
        lock = RUN / 'ddns-ui-jobs.lock';lock.touch(mode=0o600)
        path = root / ('a' * 32);path.mkdir(mode=0o700)
        now = int(Path('/proc/uptime').read_text().split('.')[0])
        data = ':'.join(['a'*32,'ddns_0','aliyun',str(self.revision),'b'*64,'c'*64,'d'*64,
                         Path('/proc/sys/kernel/random/boot_id').read_text().strip(),str(now),str(now+300)])
        payload = ('HGDDNSUIJOB1\n' + data + '\n').encode()
        (path / 'meta').write_bytes(payload + hashlib.sha256(payload).hexdigest().encode() + b'\n')
        (path / 'meta').chmod(0o600);(path / 'lock').touch(mode=0o600)
        try:
            yield path
        finally:
            shutil.rmtree(root);lock.unlink()

    def test_read_01_real_four_provider_status_and_empty_jobs_are_read_only(self):
        self.assertEqual(Path('/proc/self/uid_map').read_text().split(), ['0', rpc.OUTER_UID, '1'])
        self.assertNotEqual(rpc.OUTER_UID, '0')
        caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        for name in ('CapEff', 'CapPrm', 'CapBnd'):
            self.assertEqual(int(caps[name].strip(), 16), 0)
        with self.session() as (sid, _):
            result = self.read('status', sid)
            self.assertEqual(result, {'api_version':1,'prototype':True,'ok':True,'phase':'ddns-status',
                'configuration_revision':self.revision,'effect':'none','write_ready':False,'rules':[
                    {'rule':'ddns_'+str(i),'provider':provider,'status':'unauthorized','effect':'none',
                     'error_kind':'','retryable':False,'retry_in':0,'last_result':'none','last_effect':'none'} for i, provider in enumerate(PROVIDERS)]})
            self.assertEqual(self.read('jobs', sid), {'api_version':1,'prototype':True,'ok':True,
                              'phase':'ddns-jobs','jobs':[],'effect':'none','write_ready':False})
        self.assertFalse((RUN / 'ddns-state').exists());self.assertFalse((RUN / 'ddns-ui-jobs').exists())
        self.assertEqual((STATE / 'entry-calls').read_bytes(), self.initial_calls + b'private-request:700:600\n'*2)

    def test_read_02_real_job_pending_and_interrupted_preserve_unknown(self):
        with self.job() as path, self.session() as (sid, _):
            for pending in (True, False):
                with (path / 'lock').open('rb') as lock:
                    if pending:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    result = self.read('jobs', sid)
                self.assertEqual(len(result['jobs']), 1)
                row = result['jobs'][0]
                self.assertEqual(set(row), {'api_version','prototype','ok','phase','job','rule','configuration_revision',
                                           'pending','state','result','last_effect','reason','effect','write_ready'})
                self.assertEqual((row['pending'],row['state'],row['reason'],row['last_effect'],row['result']),
                                 (pending,'pending' if pending else 'interrupted','accepted' if pending else 'interrupted','unknown',False))
                self.assertEqual((row['job'],row['rule'],row['configuration_revision'],row['effect'],row['write_ready']),
                                 ('a'*32,'ddns_0',self.revision,'none',False))

    def test_read_03_shared_locks_busy_fail_closed_without_partial_rows(self):
        with self.session() as (sid, _):
            for path in (RUN / 'frontend.lock', STORE / '.supervisor.lock'):
                with path.open('rb') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.read('status', sid, expected=503)
            self.read('status', sid)

    def test_read_04_config_drift_and_unsafe_permissions_refuse(self):
        path = Path('/etc/config/homegate');original = path.read_bytes()
        with self.session() as (sid, _):
            try:
                path.write_bytes(original + b'\n');self.read('status', sid, expected=503)
                path.write_bytes(original);path.chmod(0o644);self.read('status', sid, expected=503)
            finally:
                path.write_bytes(original);path.chmod(0o600)

    def test_read_05_corrupt_linked_and_unsafe_status_cache_refuse(self):
        with self.session() as (sid, _), self.cache() as cache:
            file = cache / 'ddns_0';file.write_bytes(b'SECRET_SENTINEL\n');file.chmod(0o600)
            self.read('status', sid, expected=503)
            file.unlink();file.symlink_to(STORE / ('gen-%d/credentials/aliyun.dns_0.secret' % self.revision))
            self.read('status', sid, expected=503)
            file.unlink();cache.chmod(0o755);self.read('status', sid, expected=503);cache.chmod(0o700)

    def test_read_06_job_catalog_busy_and_malformed_result_refuse(self):
        with self.session() as (sid, _), self.job() as path:
            with (RUN / 'ddns-ui-jobs.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB);self.read('jobs', sid, expected=503)
            (path / 'result').write_bytes(b'SECRET_SENTINEL\n');(path / 'result').chmod(0o600)
            self.read('jobs', sid, expected=503)
            (path / 'result').unlink();(path / 'meta').write_bytes(b'SECRET_SENTINEL\n')
            self.read('jobs', sid, expected=503)

    def test_read_07_invalid_method_and_fields_never_invoke_backend(self):
        with self.session() as (sid, _):
            for action in ('status', 'jobs'):
                self.read(action, sid, expected=503, verb='POST')
                for suffix in ('?selection=ddns_0', '?rule=ddns_0', '?unexpected=SECRET_SENTINEL'):
                    self.read(action, sid, expected=503, suffix=suffix)
        self.assertEqual((STATE / 'entry-calls').read_bytes(), self.initial_calls)

    def test_read_08_auth_and_original_model_gate_still_refuse(self):
        for action in ('status', 'jobs'):
            for cookie in (None, 'f'*32):
                status, _, _ = self.cgi(luci.BASE + '/ddns_native/' + action, cookie=cookie)
                self.assertEqual(status, 403)
        with self.session() as (sid, _):
            (STATE / 'models/homegate/ddns.lua').write_bytes(luci.MODEL.read_bytes())
            for action in ('status', 'jobs'):
                self.read(action, sid, expected=503)
        self.assertEqual((STATE / 'entry-calls').read_bytes(), self.initial_calls)

    def test_read_09_historical_unknown_and_unfinished_files_remain_conservative(self):
        # A fixture cache is observation evidence, never proof that a DNS operation ran.
        with self.session() as (sid, _), self.cache() as cache:
            row = {'schema':'HGDDNSSTATE1','rule':'ddns_0','provider':'aliyun','revision':self.revision,
                   'identity':hashlib.sha256((STORE/'identity').read_bytes()).hexdigest(),
                   'generation':hashlib.sha256((STORE/('gen-%d/manifest' % self.revision)).read_bytes()).hexdigest(),
                   'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'interval':self.interval,
                   'updated':int(Path('/proc/uptime').read_text().split('.')[0]),'failures':1,'delay':0,
                   'outcome':'unknown','error_kind':'timeout','last_effect':'unknown'}
            file = cache / 'ddns_0';file.write_text(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');file.chmod(0o600)
            result = self.read('status', sid)['rules'][0]
            self.assertEqual((result['status'],result['effect'],result['retryable'],result['retry_in']),
                             ('reconciliation_required','none',False,0))
            pending = cache / '.ddns_0.next';pending.touch(mode=0o600)
            result = self.read('status', sid)['rules'][0]
            self.assertEqual((result['status'],result['effect'],result['retryable'],result['retry_in']),
                             ('blocked','none',False,0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'build/rpcd')
    parser.add_argument('--http-runtime-dir', type=Path, default=luci.HTTP)
    parser.add_argument('--luci-runtime-dir', type=Path, default=luci.LUA)
    parser.add_argument('--inside-net', help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid', help=argparse.SUPPRESS)
    args = parser.parse_args()
    rpc.WORK, luci.HTTP, luci.LUA = args.runtime_dir.resolve(), args.http_runtime_dir.resolve(), args.luci_runtime_dir.resolve()
    if args.inside_net:
        rpc.OUTER_NET, rpc.OUTER_UID = args.inside_net, args.inside_uid
        suite = unittest.TestSuite(ReadOnly(name) for name in sorted(ReadOnly.__dict__) if name.startswith('test_read_'))
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA, rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP, rpc.WORK)
    original = {p:p.read_bytes() for p in [*PROTO.rglob('*'), luci.MODEL, luci.CONTROLLER] if p.is_file()}
    for path, marker in ((luci.MODEL, luci.MODEL_GATE), (luci.CONTROLLER, luci.PAGE_GATE)):
        if path.read_bytes().count(marker) != 1:
            raise ValueError('Original Lua candidate gate must remain false')
    # The native BusyBox path is the same pinned dependency used by the business regressions.
    busybox = subprocess.run([str(BUSYBOX), '--help'], capture_output=True)
    if busybox.returncode or not busybox.stdout.startswith(b'BusyBox v1.33.2 '):
        raise ValueError('Reuse the verified BusyBox 1.33.2 runtime before running this check')
    result = rpc.isolated(rpc.WORK, guest_script=Path(__file__).resolve(), extra_ro=(luci.HTTP, luci.LUA),
        extra_mounts=lambda state: ((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                                   (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),
                                   (state/'libexec','/usr/libexec'),(state/'tools','/usr/sbin')),
        extra_rw_mounts=lambda state: ((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
        state_setup=setup_state, guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA)))
    if any(p.read_bytes() != body for p, body in original.items()):
        raise ValueError('Original candidate/business source changed during read checks')
    luci.runtime.validate_runtime(luci.LUA, rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP, rpc.WORK)
    return result


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr);sys.exit(2)
