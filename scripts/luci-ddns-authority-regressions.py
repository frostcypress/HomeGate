#!/usr/bin/env python3
"""Real LuCI POST/CSRF -> Shell grant preview/commit/revoke; private fixture only."""
import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from project import ROOT

spec = importlib.util.spec_from_file_location('authority_read_base', ROOT/'scripts/luci-ddns-read-regressions.py')
read = importlib.util.module_from_spec(spec);spec.loader.exec_module(read)
luci, rpc = read.luci, read.rpc
STORE, RUN, STATE = read.STORE, read.RUN, read.STATE
AUTHORITY_FILES = ('ddns-authority', 'ddns-authority-pending', '.ddns-authority-next', '.ddns-authority-preview')


def setup_state(state):
    read.setup_state(state)
    enable_authority(state)


def enable_authority(state):
    path = state/'project/core/prototype/homegate-ddns-authority.sh'
    body = path.read_text()
    for name in ('ddns_authority_enabled', 'ddns_multi_authority_enabled'):
        marker = name+'=false'
        if body.count(marker) != 1:
            raise ValueError('Original authority gate must be closed')
        body = body.replace(marker, name+'=true')
    path.write_text(body)


class Authority(read.ReadOnly):
    # The frozen read contract is 18s. Four real grant checks measured 7-10s;
    # the 6s gate-only fixture limit cannot cover that authorized read path.
    HTTP_TIMEOUT = 18
    CGI_TIMEOUT = 18

    def tearDown(self):
        # Only the grant records created by this test are disposable fixture state.
        # Every negative request compares the entire snapshot before this cleanup.
        for name in AUTHORITY_FILES:
            path = STORE/name
            if path.exists() or path.is_symlink():
                path.unlink()
        super().tearDown()

    def post(self, action, session, *, expected=200, **fields):
        sid, token = session
        status, _, body = self.cgi(luci.BASE+'/ddns_native/'+action, cookie=sid,
                                    verb='POST', fields={'token':token, **fields})
        self.assertEqual(status, expected, 'Authority HTTP status changed; body suppressed')
        for value in (b'SECRET_SENTINEL', b'PRIVATE_ACCOUNT', b'FIXTURE_ID', b'example.test',
                      b'/teststate', b'credentials', sid.encode(), token.encode()):
            self.assertTrue(value not in body, 'Private value escaped; body suppressed')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')), [])
        if expected != 200:
            self.gate_response(action, status, body)
            return None
        result = json.loads(body)
        self.assertEqual(set(result), {'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertTrue(result['ok'] is True and result['prototype'] is True and
                        result['api_version'] == 1 and result['phase'] == 'ddns-ui' and
                        result['operation'] == action and result['effect'] == 'none' and
                        result['write_ready'] is False, 'Invalid grant envelope; body suppressed')
        report = result['report']
        self.assertTrue(report['service_started'] is False, 'Grant started a service')
        return report

    def refused(self, action, session, **fields):
        before = self.snapshot()
        self.post(action, session, expected=503, **fields)
        self.assertTrue(before == self.snapshot(), 'Refusal changed private state; bytes suppressed')

    def states(self, sid):
        return [row['status'] for row in self.read('status', sid)['rules']]

    def test_write_01_single_grant_status_and_explicit_revoke(self):
        self.assertEqual(Path('/proc/self/uid_map').read_text().split(), ['0', rpc.OUTER_UID, '1'])
        self.assertNotEqual(rpc.OUTER_UID, '0')
        caps = dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        for name in ('CapEff','CapPrm','CapBnd'):
            self.assertEqual(int(caps[name].strip(),16), 0)
        with self.session() as session:
            preview = self.post('preview', session, selection='ddns_0')
            self.assertEqual((preview['rule'],preview['provider'],preview['configuration_revision'],preview['expires_in']),
                             ('ddns_0','aliyun',self.revision,300))
            self.assertFalse(preview['authorized'])
            self.assertEqual(self.states(session[0]), ['unauthorized']*4)
            result = self.post('commit', session, confirmation=preview['confirmation'], consent='1')
            self.assertTrue(result['authorized']);self.assertEqual(result['rule'], 'ddns_0')
            record = STORE/'ddns-authority';metadata = record.stat()
            self.assertEqual((stat.S_IMODE(metadata.st_mode),metadata.st_nlink), (0o600,1))
            self.assertEqual(self.states(session[0]), ['ready','unauthorized','unauthorized','unauthorized'])
            result = self.post('revoke', session, consent='1')
            self.assertTrue(result['revoked']);self.assertFalse(result['authorized'])
            self.assertEqual(self.states(session[0]), ['unauthorized']*4)
            self.assertFalse((RUN/'ddns-state').exists());self.assertFalse((RUN/'ddns-ui-jobs').exists())

    def test_write_02_canonical_multi_selection_and_narrow_replacement(self):
        with self.session() as session:
            preview = self.post('preview', session, selection='ddns_2,ddns_0')
            self.assertEqual(preview['rules'], ['ddns_0','ddns_2'])
            self.assertEqual(preview['provider'], 'multiple')
            self.post('commit', session, confirmation=preview['confirmation'], consent='1')
            self.assertEqual(self.states(session[0]), ['ready','unauthorized','ready','unauthorized'])
            preview = self.post('preview', session, selection='ddns_1')
            self.post('commit', session, confirmation=preview['confirmation'], consent='1')
            self.assertEqual(self.states(session[0]), ['unauthorized','ready','unauthorized','unauthorized'])
            self.post('revoke', session, consent='1')

    def test_write_03_real_csrf_and_request_policy_before_backend(self):
        with self.session() as session, self.session() as other:
            sid, token = session
            before = self.snapshot();calls = (STATE/'entry-calls').read_bytes() if (STATE/'entry-calls').exists() else b''
            for action in ('preview','commit','revoke'):
                status, _, _ = self.cgi(luci.BASE+'/ddns_native/'+action, cookie=sid)
                self.assertEqual(status,405)
                for fields in ({}, {'token':'wrong-fixture'}, {'token':other[1]}, {'token':[token,'wrong-fixture']}):
                    status, _, _ = self.cgi(luci.BASE+'/ddns_native/'+action, cookie=sid, verb='POST', fields=fields)
                    self.assertEqual(status,403)
            for action, fields in [('preview',{'selection':'ddns_0;touch /tmp/escaped'}),
                                   ('preview',{'selection':'ddns_0,ddns_0'}),
                                   ('commit',{'confirmation':'a'*32}),
                                   ('commit',{'confirmation':'a'*32,'consent':'0'}),
                                   ('revoke',{}),('revoke',{'consent':'1','rule':'ddns_0'})]:
                self.refused(action,session,**fields)
            after = (STATE/'entry-calls').read_bytes() if (STATE/'entry-calls').exists() else b''
            self.assertEqual(calls,after)
            self.assertTrue(before == self.snapshot(), 'Invalid requests changed state; bytes suppressed')
            self.assertFalse(Path('/tmp/escaped').exists())

    def test_write_04_confirmation_replacement_and_replay_preserve_grant(self):
        with self.session() as session:
            first = self.post('preview',session,selection='ddns_0')
            second = self.post('preview',session,selection='ddns_2')
            self.assertTrue(first['confirmation'] != second['confirmation'], 'Preview reused nonce')
            self.refused('commit',session,confirmation=first['confirmation'],consent='1')
            self.post('commit',session,confirmation=second['confirmation'],consent='1')
            self.refused('commit',session,confirmation=second['confirmation'],consent='1')
            self.assertEqual(self.states(session[0]), ['unauthorized','unauthorized','ready','unauthorized'])
            self.post('revoke',session,consent='1')
            self.refused('commit',session,confirmation=second['confirmation'],consent='1')

    def test_write_05_changed_or_unsafe_source_rejects_confirmation(self):
        path = Path('/etc/config/homegate');original = path.read_bytes()
        with self.session() as session:
            preview = self.post('preview',session,selection='ddns_0')
            try:
                path.write_bytes(original+b'\n# changed fixture source\n')
                self.refused('commit',session,confirmation=preview['confirmation'],consent='1')
                path.write_bytes(original);path.chmod(0o640)
                self.refused('commit',session,confirmation=preview['confirmation'],consent='1')
            finally:
                path.write_bytes(original);path.chmod(0o600)

    def test_write_06_locks_and_unsafe_pending_are_preserved(self):
        with self.session() as session:
            for path in (RUN/'frontend.lock',STORE/'.supervisor.lock'):
                with path.open('rb') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.refused('preview',session,selection='ddns_0')
            preview = self.post('preview',session,selection='ddns_0')
            pending = STORE/'ddns-authority-pending'
            try:
                pending.chmod(0o640)
                self.refused('commit',session,confirmation=preview['confirmation'],consent='1')
                self.refused('preview',session,selection='ddns_1')
            finally:
                pending.chmod(0o600)

    def test_write_07_closed_model_or_backend_preserves_pending(self):
        model = STATE/'models/homegate/ddns.lua'
        with self.session() as session:
            preview = self.post('preview',session,selection='ddns_0')
            opened = model.read_bytes()
            try:
                model.write_bytes(luci.MODEL.read_bytes())
                self.refused('commit',session,confirmation=preview['confirmation'],consent='1')
            finally:
                model.write_bytes(opened)
            for name, flag in [('homegate-ddns-ui.sh','ddns_ui_enabled'),
                               ('homegate-ddns-authority.sh','ddns_authority_enabled')]:
                path = read.GUEST_PROTO/name;opened = path.read_text()
                self.assertEqual(opened.count(flag+'=true'),1)
                try:
                    path.write_text(opened.replace(flag+'=true',flag+'=false'))
                    self.refused('commit',session,confirmation=preview['confirmation'],consent='1')
                finally:
                    path.write_text(opened)

    def test_write_08_changed_private_credentials_reject_confirmation(self):
        path = next((STORE/('gen-%d/credentials'%self.revision)).iterdir());original = path.read_bytes()
        with self.session() as session:
            preview = self.post('preview',session,selection='ddns_0')
            try:
                path.write_bytes(original+b'changed-fixture')
                self.refused('commit',session,confirmation=preview['confirmation'],consent='1')
            finally:
                path.write_bytes(original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd')
    parser.add_argument('--http-runtime-dir',type=Path,default=luci.HTTP)
    parser.add_argument('--luci-runtime-dir',type=Path,default=luci.LUA)
    parser.add_argument('--inside-net',help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid',help=argparse.SUPPRESS)
    parser.add_argument('--group',choices=('grant','barriers'))
    args = parser.parse_args()
    rpc.WORK,luci.HTTP,luci.LUA = args.runtime_dir.resolve(),args.http_runtime_dir.resolve(),args.luci_runtime_dir.resolve()
    if args.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID = args.inside_net,args.inside_uid
        names = [name for name in sorted(Authority.__dict__) if name.startswith('test_write_')]
        names = names[:4] if args.group == 'grant' else names[4:]
        suite = unittest.TestSuite(Authority(name) for name in names)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original = {p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER] if p.is_file()}
    for path,marker in ((luci.MODEL,luci.MODEL_GATE),(luci.CONTROLLER,luci.PAGE_GATE)):
        if path.read_bytes().count(marker) != 1:
            raise ValueError('Original candidate gates must remain false')
    for marker in ('ddns_authority_enabled=false','ddns_multi_authority_enabled=false'):
        if (read.PROTO/'homegate-ddns-authority.sh').read_text().count(marker) != 1:
            raise ValueError('Original authority gates must remain false')
    busybox = subprocess.run([str(read.BUSYBOX),'--help'],capture_output=True)
    if busybox.returncode or not busybox.stdout.startswith(b'BusyBox v1.33.2 '):
        raise ValueError('Reuse the verified BusyBox 1.33.2 runtime')
    result = 0
    # Each private namespace retains the existing 90s whole-suite bound.
    # Keep all eight cases while avoiding one long, shared mutable fixture.
    for group in ((args.group,) if args.group else ('grant','barriers')):
        result = rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
            extra_mounts=lambda state: ((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                                       (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),
                                       (state/'libexec','/usr/libexec'),(state/'tools','/usr/sbin')),
            extra_rw_mounts=lambda state: ((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
            state_setup=setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--group',group))
        if result:
            break
    if any(p.read_bytes()!=body for p,body in original.items()):
        raise ValueError('Original candidate/business source changed during grant checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
