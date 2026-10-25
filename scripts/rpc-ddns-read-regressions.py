#!/usr/bin/env python3
"""Real HTTP/session ACL -> rpcd ucode -> Shell DDNS reads, private fixtures only."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from project import ROOT
import importlib.util

spec = importlib.util.spec_from_file_location('shell_read_base', ROOT/'scripts/luci-ddns-read-regressions.py')
read = importlib.util.module_from_spec(spec);spec.loader.exec_module(read)
luci, rpc = read.luci, read.rpc
http = luci.http
BaseReadOnly = read.ReadOnly


def setup_state(state):
    read.setup_state(state)
    enable_rpc(state)


def enable_rpc(state):
    # Plumbing ACLs only. The actual HomeGate reader/writer ACL is copied unchanged.
    (state/'acl/http-fixture.json').write_text(json.dumps({
        'unauthenticated':{'read':{'ubus':{'session':['login']}}},
        'homegate-http-fixture':{'read':{'ubus':{'session':['destroy']}}}}))
    config = state/'etc/config/rpcd';body=config.read_text()
    marker=" list read 'luci-app-homegate-ddns'\n"
    if body.count(marker)!=2:
        raise ValueError('Unexpected login fixture')
    config.write_text(body.replace(marker,marker+" list read 'homegate-http-fixture'\n"))
    candidate=state/'ucode/homegate-ddns.uc'
    candidate.write_bytes(candidate.read_bytes().replace(rpc.GATE,b'const native_ddns_rpc_enabled = true;'))
    (state/'www/index.html').write_bytes(b'HomeGate isolated HTTP fixture\n')


def start_rpc_http(cls):
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));cls.port=listener.getsockname()[1]
        command=[str(luci.HTTP/'prefix/bin/uhttpd'),'-f','-p','127.0.0.1:'+str(cls.port),
                 '-h','/teststate/www','-c','/etc/httpd.fixture.conf','-u','/ubus','-U',rpc.SOCKET,
                 '-t',str(getattr(cls,'CGI_TIMEOUT',6)),'-T',str(getattr(cls,'CGI_TIMEOUT',6))]
        log=(rpc.STATE/'uhttpd-rpc-read.log').open('wb');cls.logs.append(log)
        cls.processes.append(subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT))
        cls.wait_for(lambda:http.HostHTTP.listening.__func__(cls))
    except BaseException:
        cls.tearDownClass();raise


class HTTPRead(BaseReadOnly):
    response=http.HostHTTP.response
    request=staticmethod(http.HostHTTP.request)
    check_reply=http.HostHTTP.check_reply
    http_call=http.HostHTTP.http_call
    http_login=http.HostHTTP.http_login

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        start_rpc_http(cls)

    @contextmanager
    def rpc_session(self,role='reader'):
        sid=self.http_login(role)
        try:
            yield sid
        finally:
            self.http_call(sid,'destroy',obj='session')

    @contextmanager
    def session(self):
        # Reused Shell scenarios consume the LuCI (session, token) shape.
        with self.rpc_session() as sid:
            yield sid,None

    def calls(self):
        path=rpc.STATE/'entry-calls'
        return path.read_bytes() if path.exists() else b''

    def read(self,action,sid,*,expected=200,modern=False):
        before=self.snapshot()
        if modern:
            result=self.response({'jsonrpc':'2.0','id':83,'method':action,'params':{}},
                path='/ubus/call/homegate_ddns',headers={'Authorization':'Bearer '+sid})
            self.assertTrue(set(result)=={'jsonrpc','id','result'} and result['id']==83 and result['jsonrpc']=='2.0',
                            'Unexpected modern envelope; body suppressed')
            result=result['result']
        else:
            result=self.http_call(sid,action)
        raw=json.dumps(result).encode()
        for value in (b'SECRET_SENTINEL',b'PRIVATE_ACCOUNT',b'FIXTURE_ID',b'example.test',b'/teststate',b'credentials',sid.encode()):
            self.assertTrue(value not in raw,'Private value escaped into RPC result')
        self.assertTrue(self.snapshot()==before,'Read changed private configuration/state; bytes suppressed')
        if expected==503:
            self.assertTrue(result==http.HostHTTP.denial(action),'Business rejection changed; body suppressed')
            return
        self.assertEqual(set(result),{'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertEqual({k:result[k] for k in result if k!='report'},
            {'api_version':1,'prototype':True,'ok':True,'phase':'ddns-ui','operation':action,'effect':'none','write_ready':False})
        return result['report']

    # Same real Shell scenarios through RPC, not duplicate claims of new backend business.
    test_rpc_read_01_status_and_empty_jobs=BaseReadOnly.test_read_01_real_four_provider_status_and_empty_jobs_are_read_only
    test_rpc_read_02_pending_and_interrupted=BaseReadOnly.test_read_02_real_job_pending_and_interrupted_preserve_unknown
    test_rpc_read_03_business_lock_busy=BaseReadOnly.test_read_03_shared_locks_busy_fail_closed_without_partial_rows
    test_rpc_read_04_config_drift=BaseReadOnly.test_read_04_config_drift_and_unsafe_permissions_refuse
    test_rpc_read_05_invalid_cache=BaseReadOnly.test_read_05_corrupt_linked_and_unsafe_status_cache_refuse
    test_rpc_read_06_invalid_jobs=BaseReadOnly.test_read_06_job_catalog_busy_and_malformed_result_refuse
    test_rpc_read_07_historical_unknown=BaseReadOnly.test_read_09_historical_unknown_and_unfinished_files_remain_conservative

    def test_rpc_read_08_reader_write_acl_and_anonymous_revoked_sessions_stop_before_backend(self):
        with self.rpc_session() as sid:
            for method in rpc.SIGNATURES:
                if method not in ('status','jobs'):
                    self.http_call(sid,method,error=-32002)
        for sid in (http.ZERO,'f'*32,''):
            for method in rpc.SIGNATURES:
                self.http_call(sid,method,error=-32002)
        sid=self.http_login('reader');self.http_call(sid,'destroy',obj='session')
        for method in rpc.SIGNATURES:
            self.http_call(sid,method,error=-32002)
        self.assertEqual(self.calls(),self.initial_calls)

    def test_rpc_read_09_argument_and_session_injection_refuse_before_backend(self):
        with self.rpc_session() as sid,self.rpc_session('writer') as writer:
            for method in ('status','jobs'):
                for args in ({'rule':'ddns_0'},{'unregistered':'SECRET_SENTINEL'}):
                    self.http_call(sid,method,args,status=2)
                self.http_call(sid,method,{'ubus_rpc_session':writer},error=-32602)
            self.http_call(sid,'commit',{'ubus_rpc_session':writer},error=-32002)
            self.http_call(http.ZERO,'status',{'ubus_rpc_session':sid},error=-32002)
        self.assertEqual(self.calls(),self.initial_calls)

    def test_rpc_read_10_modern_bearer_roles_and_source_gate_remain_separate(self):
        with self.rpc_session() as reader,self.rpc_session('writer') as writer:
            for sid in (reader,writer):
                for method in ('status','jobs'):
                    self.assertEqual(self.read(method,sid),self.read(method,sid,modern=True))
            before=self.calls()
            for sid,method in ((reader,'commit'),('f'*32,'status'),(None,'status')):
                data=self.response({'jsonrpc':'2.0','id':83,'method':method,'params':{}},
                    path='/ubus/call/homegate_ddns',headers={'Authorization':'Bearer '+sid} if sid else {})
                self.check_reply(data,error=-32002)
            self.assertEqual(self.calls(),before)
            # A temporary Shell gate is independent of successful HTTP session authorization.
            path=read.GUEST_PROTO/'homegate-ddns-ui.sh';original=path.read_bytes()
            try:
                path.write_bytes(original.replace(b'ddns_ui_enabled=true',b'ddns_ui_enabled=false'))
                for method in ('status','jobs'):
                    self.read(method,reader,expected=503)
                    self.read(method,writer,expected=503,modern=True)
            finally:
                path.write_bytes(original)

    def test_rpc_read_11_batch_authorization_is_per_element_with_real_backend(self):
        with self.rpc_session() as sid:
            before=self.snapshot()
            data=self.response([self.request(sid,'homegate_ddns','status',{},1),
                self.request(sid,'homegate_ddns','commit',{},2),
                self.request('f'*32,'homegate_ddns','jobs',{},3),
                self.request(sid,'homegate_ddns','jobs',{},4)])
            self.assertTrue(isinstance(data,list) and len(data)==4,'Unexpected batch; body suppressed')
            status=self.check_reply(data[0],identity=1)
            self.assertTrue(status.get('ok') is True and len(status['report']['rules'])==4)
            self.check_reply(data[1],identity=2,error=-32002);self.check_reply(data[2],identity=3,error=-32002)
            jobs=self.check_reply(data[3],identity=4)
            self.assertTrue(jobs.get('ok') is True and jobs['report']['jobs']==[])
            self.assertTrue(self.snapshot()==before,'Batch changed private state; bytes suppressed')
        self.assertEqual(self.calls(),self.initial_calls+b'private-request:700:600\n'*2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd')
    parser.add_argument('--http-runtime-dir',type=Path,default=luci.HTTP)
    parser.add_argument('--luci-runtime-dir',type=Path,default=luci.LUA)
    parser.add_argument('--inside-net',help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid',help=argparse.SUPPRESS)
    args=parser.parse_args()
    rpc.WORK,luci.HTTP,luci.LUA=args.runtime_dir.resolve(),args.http_runtime_dir.resolve(),args.luci_runtime_dir.resolve()
    if args.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID=args.inside_net,args.inside_uid
        suite=unittest.TestSuite(HTTPRead(name) for name in sorted(HTTPRead.__dict__) if name.startswith('test_rpc_read_'))
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER,rpc.CANDIDATE,rpc.ACL] if p.is_file()}
    if rpc.CANDIDATE.read_bytes().count(rpc.GATE)!=1:
        raise ValueError('Original RPC candidate must stay gated')
    busybox=subprocess.run([str(read.BUSYBOX),'--help'],capture_output=True)
    if busybox.returncode or not busybox.stdout.startswith(b'BusyBox v1.33.2 '):
        raise ValueError('Reuse the verified BusyBox1.33.2 runtime')
    result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
        extra_mounts=lambda state:((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
            (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),(state/'libexec','/usr/libexec'),(state/'tools','/usr/sbin')),
        extra_rw_mounts=lambda state:((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
        state_setup=setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA)))
    if any(p.read_bytes()!=body for p,body in original.items()):
        raise ValueError('Original project or ACL changed during checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:
        sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
