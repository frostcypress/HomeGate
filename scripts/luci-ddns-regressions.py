#!/usr/bin/env python3
"""Real pinned Lua LuCI CGI sessions and POST/CSRF; fixture routes never enable production."""
import argparse
from contextlib import contextmanager
from http.cookies import SimpleCookie
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import unittest
from urllib.parse import urlencode
from project import ROOT


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


rpc = module('rpc_luci_base', 'rpcd-ddns-regressions.py')
http = module('http_luci_base', 'http-ddns-regressions.py')
runtime = module('prepare_luci', 'prepare-luci.py')
LUA = ROOT / 'build/luci'
HTTP = ROOT / 'build/uhttpd'
CONTROLLER = ROOT / 'project/luci/prototype/lua/controller/ddns.lua'
MODEL = ROOT / 'project/luci/prototype/lua/model/ddns.lua'
WRITER = ROOT / 'project/luci/lua/luasrc/model/homegate/writer.lua'
PAGE_GATE = b'local native_ddns_page_enabled=false'
MODEL_GATE = b'local native_ddns_ui_enabled=false'
BASE = '/cgi-bin/luci/admin/services/homegate'
PAGE = BASE + '/settings/ddns'
WRITES = ('preview', 'commit', 'revoke', 'submit', 'maintain_preview', 'maintain_commit')


class LuaLuCI(unittest.TestCase):
    wait_for = classmethod(rpc.HostRpcd.wait_for.__func__)
    bus = classmethod(rpc.HostRpcd.bus.__func__)
    tearDownClass = classmethod(rpc.HostRpcd.tearDownClass.__func__)
    call = rpc.HostRpcd.call
    exchange = http.HostHTTP.exchange

    @classmethod
    def setUpClass(cls):
        rpc.HostRpcd.setUpClass.__func__(cls)
        try:
            Path('/var/run/ubus').mkdir(exist_ok=True)
            Path('/var/run/ubus/ubus.sock').symlink_to(rpc.SOCKET)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0));cls.port = listener.getsockname()[1]
            command = [str(HTTP / 'prefix/bin/uhttpd'), '-f', '-p', '127.0.0.1:' + str(cls.port),
                       '-h', '/teststate/www', '-c', '/etc/httpd.fixture.conf',
                       '-t', str(getattr(cls, 'CGI_TIMEOUT', 6)), '-T', str(getattr(cls, 'CGI_TIMEOUT', 6))]
            log = (rpc.STATE / 'uhttpd.log').open('wb');cls.logs.append(log)
            cls.processes.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT))
            cls.wait_for(lambda: http.HostHTTP.listening.__func__(cls))
            probe = cls('test_01_original_page_and_model_gates_remain_closed')
            status, _, body = probe.cgi(PAGE)
            if status == 500:
                raise RuntimeError('LuCI pre-login startup failed: ' + body.decode(errors='replace')[:4000])
        except BaseException:
            cls.tearDownClass();raise

    def setUp(self):
        # Only these private copies are changed; upstream dispatcher/http/session logic is untouched.
        (rpc.STATE / 'controllers/homegate_ddns.lua').write_bytes(CONTROLLER.read_bytes().replace(PAGE_GATE, b'local native_ddns_page_enabled=true'))
        (rpc.STATE / 'models/homegate/ddns.lua').write_bytes(MODEL.read_bytes())
        (rpc.STATE / 'models/homegate/writer.lua').write_bytes(WRITER.read_bytes())

    def cgi(self, path, *, cookie=None, fields=None, verb='GET'):
        headers = {'Cookie': 'sysauth=' + cookie} if cookie else {}
        body = urlencode(fields or {}, doseq=True).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return self.exchange(path=path, verb=verb, headers=headers, raw=body)

    def login(self):
        status, headers, _ = self.cgi(PAGE, verb='POST', fields={
            'luci_username': 'fixture_writer', 'luci_password': rpc.FIXTURE_PASSWORD})
        self.assertEqual(status, 302, 'LuCI login failed; response suppressed')
        self.assertTrue(headers.get('location', '').endswith('/admin/services/homegate/settings/ddns'))
        cookies = SimpleCookie();cookies.load(headers.get('set-cookie', ''))
        self.assertTrue('sysauth' in cookies, 'Missing LuCI session cookie')
        cookie = cookies['sysauth']
        self.assertTrue(cookie['httponly'] and cookie['samesite'].lower() == 'strict')
        sid = cookie.value
        self.assertTrue(re.fullmatch(r'[0-9a-f]{32}', sid) is not None, 'Invalid fixture cookie')
        status, _, body = self.cgi(PAGE, cookie=sid)
        self.assertEqual(status, 200, 'LuCI candidate page failed; response suppressed')
        match = re.search(rb'data-token="([0-9a-f]+)"', body)
        self.assertTrue(match is not None, 'Real LuCI template did not expose its CSRF token')
        token = match.group(1).decode()
        values = self.call('session', 'get', {'ubus_rpc_session': sid})
        self.assertTrue(values.get('values', {}).get('token') == token,
                        'Page token is not bound to real rpcd session; values suppressed')
        return sid, token

    @contextmanager
    def session(self):
        sid, token = self.login()
        try:
            yield sid, token
        finally:
            self.call('session', 'destroy', {'ubus_rpc_session': sid})

    def gate_response(self, method, status, body):
        self.assertEqual(status, 503, 'Candidate gate response status changed; body suppressed')
        try:
            result = json.loads(body)
        except (ValueError, UnicodeError):
            raise AssertionError('Candidate returned invalid JSON; body suppressed') from None
        self.assertTrue(result == http.HostHTTP.denial(method), 'Candidate denial fields changed; body suppressed')

    def test_01_original_page_and_model_gates_remain_closed(self):
        self.assertEqual(CONTROLLER.read_bytes().count(PAGE_GATE), 1)
        self.assertEqual(MODEL.read_bytes().count(MODEL_GATE), 1)
        with self.session() as (sid, _):
            (rpc.STATE / 'controllers/homegate_ddns.lua').write_bytes(CONTROLLER.read_bytes())
            status, _, body = self.cgi('/cgi-bin/luci/admin/fixture/routes', cookie=sid)
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body) == {'candidate_registered': False})
        self.assertEqual(Path('/proc/self/uid_map').read_text().split(), ['0', rpc.OUTER_UID, '1'])
        self.assertNotEqual(rpc.OUTER_UID, '0')
        caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        for name in ('CapEff', 'CapPrm', 'CapBnd'):
            self.assertEqual(int(caps[name].strip(), 16), 0)
        self.assertTrue(os.statvfs(LUA).f_flag & os.ST_RDONLY)

    def test_02_real_login_cookie_token_and_wrong_password(self):
        status, headers, _ = self.cgi(PAGE)
        self.assertEqual(status, 403);self.assertEqual(headers.get('x-luci-login-required'), 'yes')
        status, _, _ = self.cgi(PAGE, verb='POST', fields={'luci_username': 'fixture_writer', 'luci_password': 'wrong-fixture'})
        self.assertEqual(status, 403)
        with self.session():
            pass

    def test_03_no_cookie_invalid_cookie_and_posted_authorization_fail(self):
        for cookie in (None, 'f' * 32):
            for method in rpc.SIGNATURES:
                status, headers, _ = self.cgi(BASE + '/ddns_native/' + method, cookie=cookie,
                                              verb='POST', fields={'token': 'self-reported', 'authorized': 'true'})
                self.assertEqual(status, 403)
                self.assertEqual(headers.get('x-luci-login-required'), 'yes')

    def test_04_authenticated_read_methods_keep_business_gate_closed(self):
        with self.session() as (sid, _):
            for method in ('status', 'jobs'):
                status, _, body = self.cgi(BASE + '/ddns_native/' + method, cookie=sid)
                self.gate_response(method, status, body)

    def test_05_all_write_get_requests_require_post(self):
        with self.session() as (sid, token):
            for method in WRITES:
                status, headers, _ = self.cgi(BASE + '/ddns_native/' + method + '?token=' + token, cookie=sid)
                self.assertEqual(status, 405);self.assertEqual(headers.get('allow'), 'POST')

    def test_06_missing_wrong_cross_session_and_duplicate_csrf_denied(self):
        with self.session() as (sid, token), self.session() as (_, other):
            self.assertTrue(token != other, 'Distinct sessions reused a CSRF token')
            for method in WRITES:
                for fields in ({}, {'token': 'wrong-fixture'}, {'token': other}, {'token': [token, 'wrong-fixture']}):
                    status, _, _ = self.cgi(BASE + '/ddns_native/' + method, cookie=sid, verb='POST', fields=fields)
                    self.assertEqual(status, 403)

    def test_07_valid_csrf_reaches_only_closed_candidate(self):
        with self.session() as (sid, token):
            for method in WRITES:
                status, _, body = self.cgi(BASE + '/ddns_native/' + method, cookie=sid, verb='POST', fields={'token': token})
                self.gate_response(method, status, body)

    def test_08_form_session_fields_cannot_replace_cookie(self):
        with self.session() as (sid, token):
            status, headers, _ = self.cgi(BASE + '/ddns_native/commit', verb='POST', fields={
                'token': token, 'ubus_rpc_session': sid, 'authsession': sid, 'authorized': 'true'})
            self.assertEqual(status, 403);self.assertEqual(headers.get('x-luci-login-required'), 'yes')

    def test_09_destroyed_real_session_rejects_old_cookie_and_token(self):
        sid, token = self.login()
        self.call('session', 'destroy', {'ubus_rpc_session': sid})
        for method in rpc.SIGNATURES:
            status, headers, _ = self.cgi(BASE + '/ddns_native/' + method, cookie=sid, verb='POST', fields={'token': token})
            self.assertEqual(status, 403);self.assertEqual(headers.get('x-luci-login-required'), 'yes')

    def test_10_model_post_csrf_guard_has_independent_positive_control(self):
        # The fixture-only call route deliberately bypasses dispatcher's post() wrapper.
        # A temporary enabled model must still reject bad method/token before private transport.
        (rpc.STATE / 'models/homegate/ddns.lua').write_bytes(MODEL.read_bytes().replace(MODEL_GATE, b'local native_ddns_ui_enabled=true'))
        counter = rpc.STATE / 'backend-calls'
        initial = counter.read_bytes() if counter.exists() else b''
        with self.session() as (sid, token), self.session() as (_, other):
            for verb, fields in (('GET', {'token': token}), ('POST', {}), ('POST', {'token': 'wrong-fixture'}), ('POST', {'token': other})):
                status, _, body = self.cgi('/cgi-bin/luci/admin/fixture/model_probe', cookie=sid, verb=verb,
                                           fields={**fields, 'selection': 'ddns_fixture'})
                self.gate_response('preview', status, body)
                self.assertTrue((counter.read_bytes() if counter.exists() else b'') == initial)
            status, _, body = self.cgi('/cgi-bin/luci/admin/fixture/model_probe', cookie=sid, verb='POST',
                                       fields={'token': token, 'selection': 'ddns_fixture'})
            if status == 500:
                diagnostic = body.decode(errors='replace')
                for value in (sid, token, other):
                    diagnostic = diagnostic.replace(value, '[fixture-session-redacted]')
                raise AssertionError('Model positive control failed: ' + diagnostic[:3000])
            self.gate_response('preview', status, body)
            self.assertTrue(counter.read_bytes() == initial + b'ddns:700:600\n', 'Model control failed to preserve private modes')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')), [])
        (rpc.STATE / 'models/homegate/ddns.lua').write_bytes(MODEL.read_bytes())

    def test_11_common_writer_uses_real_private_file_modes_and_remains_gated(self):
        counter = rpc.STATE / 'backend-calls'
        initial = counter.read_bytes() if counter.exists() else b''
        with self.session() as (sid, token):
            for enabled in (False, True):
                source = WRITER.read_bytes()
                if enabled:
                    source = source.replace(b'local native_dispatch_enabled = false', b'local native_dispatch_enabled = true')
                (rpc.STATE / 'models/homegate/writer.lua').write_bytes(source)
                status, _, body = self.cgi('/cgi-bin/luci/admin/fixture/writer_probe', cookie=sid,
                                           verb='POST', fields={'token': token})
                self.assertEqual(status, 503)
                self.assertTrue(json.loads(body).get('ok') is False)
                self.assertTrue((counter.read_bytes() if counter.exists() else b'') ==
                                initial + (b'writer:700:600\n' if enabled else b''))
        self.assertEqual(list(Path('/tmp').glob('homegate-luci-*')), [])
        (rpc.STATE / 'models/homegate/writer.lua').write_bytes(WRITER.read_bytes())


def setup_state(state):
    modules = LUA / 'prefix/lib/lua'
    (state / 'controllers').mkdir()
    (state / 'controllers/fixture.lua').write_text("""module('luci.controller.fixture',package.seeall)
function index()
 local p=entry({'admin'},firstchild(),'Fixture',1);p.sysauth={'fixture_writer'};p.sysauth_authenticator='htmlauth'
 entry({'admin','fixture','model_probe'},call('model_probe')).leaf=true
 entry({'admin','fixture','writer_probe'},post('writer_probe')).leaf=true
 entry({'admin','fixture','routes'},call('routes')).leaf=true
end
function model_probe()return require('luci.controller.homegate_ddns').preview()end
function writer_probe()return require('luci.model.homegate.writer').run('basic_apply',function()error('unexpected callback')end)end
function routes()
 local n=require('luci.dispatcher').menu_json()
 for _,k in ipairs({'admin','services','homegate','settings','ddns'})do n=n and n.children and n.children[k]end
 local h=require('luci.http');h.prepare_content('application/json');h.write(require('luci.jsonc').stringify({candidate_registered=n~=nil}))
end
""")
    (state / 'controllers/homegate_ddns.lua').write_bytes(CONTROLLER.read_bytes())
    shutil.copytree(modules / 'luci/model', state / 'models')
    (state / 'models/homegate').mkdir(exist_ok=True)
    shutil.copyfile(MODEL, state / 'models/homegate/ddns.lua')
    shutil.copyfile(WRITER, state / 'models/homegate/writer.lua')
    shutil.copyfile(ROOT / 'project/luci/lua/luasrc/model/homegate/backup.lua', state / 'models/homegate/backup.lua')
    (state / 'view/homegate').mkdir(parents=True)
    (state / 'view/themes/fixture').mkdir(parents=True)
    (state / 'view/themes/fixture/header.htm').write_text('<!doctype html><title>LuCI fixture</title>')
    shutil.copyfile(ROOT / 'project/luci/prototype/lua/view/ddns.htm', state / 'view/homegate/ddns.htm')
    for name, body in {'header': '<!doctype html><title>LuCI fixture</title>', 'footer': '',
                       'sysauth': 'LuCI fixture login required', 'csrftoken': 'LuCI fixture CSRF rejected',
                       'error404': 'LuCI fixture route unavailable'}.items():
        (state / ('view/' + name + '.htm')).write_text(body)
    (state / 'etc/config/luci').write_text("config core 'main'\n option lang 'en'\n option mediaurlbase '/luci-static/fixture'\n option resourcebase '/luci-static/resources'\nconfig internal 'sauth'\n option sessiontime '60'\nconfig internal 'template'\n option viewdir '/teststate/view'\nconfig internal 'themes'\nconfig internal 'languages'\n")
    (state / 'etc/httpd.fixture.conf').write_text('')
    cgi = state / 'www/cgi-bin/luci';cgi.parent.mkdir(parents=True)
    cgi.write_text('#!/usr/bin/lua5.1\npackage.path=' + json.dumps(str(modules / '?.lua') + ';' + str(modules / '?/init.lua')) +
                   '\npackage.cpath=' + json.dumps(str(modules / '?.so')) + "\nrequire('luci.sgi.cgi').run()\n")
    cgi.chmod(0o755)
    backend = state / 'libexec/homegate';backend.mkdir(parents=True)
    for name in ('ddns-ui-policy.lua', 'ddns-authority.lua', 'ddns-plan.lua'):
        shutil.copyfile(ROOT / 'project/core/prototype' / name, backend / name)
    tool = backend / 'ddns-ui'
    tool.write_text("#!/usr/bin/python3\nimport os,stat,sys\np=sys.argv[1]\na=stat.S_IMODE(os.stat(os.path.dirname(p)).st_mode)\nb=stat.S_IMODE(os.stat(p).st_mode)\nassert (a,b)==(0o700,0o600)\nwith open('/teststate/backend-calls','ab') as f:f.write(b'ddns:700:600\\n')\nprint('{}')\n");tool.chmod(0o755)
    writer_tool = backend / 'frontend-write'
    writer_tool.write_text(tool.read_text().replace('ddns:700:600', 'writer:700:600'));writer_tool.chmod(0o755)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir', type=Path, default=ROOT / 'build/rpcd')
    parser.add_argument('--http-runtime-dir', type=Path, default=HTTP)
    parser.add_argument('--luci-runtime-dir', type=Path, default=LUA)
    parser.add_argument('--inside-net', help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid', help=argparse.SUPPRESS)
    args = parser.parse_args()
    rpc.WORK, HTTP, LUA = args.runtime_dir.resolve(), args.http_runtime_dir.resolve(), args.luci_runtime_dir.resolve()
    try:
        if args.inside_net:
            rpc.OUTER_NET, rpc.OUTER_UID = args.inside_net, args.inside_uid
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(LuaLuCI)
            sys.exit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
        runtime.validate_runtime(LUA, rpc.WORK);http.runtime.validate_runtime(HTTP, rpc.WORK)
        for path, marker in ((CONTROLLER, PAGE_GATE), (MODEL, MODEL_GATE), (WRITER, b'local native_dispatch_enabled = false')):
            if path.read_bytes().count(marker) != 1:
                raise ValueError('Original Lua candidate gates must remain false')
        original = {p: p.read_bytes() for p in (CONTROLLER, MODEL, WRITER)}
        result = rpc.isolated(rpc.WORK, guest_script=Path(__file__).resolve(), extra_ro=(HTTP, LUA),
                              extra_mounts=lambda state: ((state / 'controllers', LUA / 'prefix/lib/lua/luci/controller'),
                                                          (state / 'models', LUA / 'prefix/lib/lua/luci/model'),
                                                          (state / 'libexec', '/usr/libexec')),
                              state_setup=setup_state, guest_args=('--http-runtime-dir', str(HTTP), '--luci-runtime-dir', str(LUA)))
        if any(p.read_bytes() != body for p, body in original.items()):
            raise ValueError('Original Lua candidate changed during checks')
        runtime.validate_runtime(LUA, rpc.WORK);http.runtime.validate_runtime(HTTP, rpc.WORK)
        sys.exit(result)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr);sys.exit(2)
