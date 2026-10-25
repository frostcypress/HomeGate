#!/usr/bin/env python3
"""Real HTTP ACL -> rpcd ucode/fs -> Shell grant writes; private fixture only."""
import argparse
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from project import ROOT


def module(name, filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


base=module('rpc_authority_read','rpc-ddns-read-regressions.py')
grant=module('rpc_authority_scenarios','luci-ddns-authority-regressions.py')
read,luci,rpc,http=base.read,base.luci,base.rpc,base.http
# Reused scenario functions must observe this launcher's runtime and namespace.
grant.read,grant.luci,grant.rpc=read,luci,rpc
STORE,RUN,STATE=read.STORE,read.RUN,read.STATE
GROUPS={
    'grant':('01','02'),
    'barriers':('03','04','05','06','07','08'),
    'transport':('09','10','11'),
}


def setup_state(state):
    base.setup_state(state)
    grant.enable_authority(state)


class HTTPAuthority(base.HTTPRead):
    HTTP_TIMEOUT=18
    CGI_TIMEOUT=18

    @contextmanager
    def session(self):
        with self.rpc_session('writer') as sid:
            yield sid,None

    def tearDown(self):
        for name in grant.AUTHORITY_FILES:
            path=STORE/name
            if path.exists() or path.is_symlink():
                path.unlink()
        super().tearDown()

    def modern(self,action,sid,fields=None):
        data=self.response({'jsonrpc':'2.0','id':90,'method':action,'params':fields or {}},
            path='/ubus/call/homegate_ddns',headers={'Authorization':'Bearer '+sid})
        self.assertTrue(set(data)=={'jsonrpc','id','result'} and data['id']==90 and data['jsonrpc']=='2.0',
                        'Invalid modern envelope; body suppressed')
        return data['result']

    def post(self,action,session,*,expected=200,**fields):
        sid,_=session
        result=self.http_call(sid,action,fields)
        return self.grant_result(action,sid,result,expected)

    def grant_result(self,action,sid,result,expected=200):
        raw=json.dumps(result).encode()
        for value in (b'SECRET_SENTINEL',b'PRIVATE_ACCOUNT',b'FIXTURE_ID',b'example.test',
                      b'/teststate',b'credentials',sid.encode()):
            self.assertTrue(value not in raw,'Private value escaped into RPC result')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')),[])
        if expected!=200:
            self.assertTrue(result==http.HostHTTP.denial(action),'Business refusal changed; body suppressed')
            return None
        self.assertEqual(set(result),{'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertTrue(result['api_version']==1 and result['prototype'] is True and result['ok'] is True and
                        result['phase']=='ddns-ui' and result['operation']==action and
                        result['effect']=='none' and result['write_ready'] is False,'Invalid grant envelope; body suppressed')
        report=result['report']
        self.assertTrue(report['service_started'] is False,'Grant started a service')
        return report

    refused=grant.Authority.refused
    states=grant.Authority.states
    # Six existing backend scenarios exercised through a different real transport.
    test_rpc_write_01_single_grant=grant.Authority.test_write_01_single_grant_status_and_explicit_revoke
    test_rpc_write_02_multi_scope=grant.Authority.test_write_02_canonical_multi_selection_and_narrow_replacement
    test_rpc_write_04_replay=grant.Authority.test_write_04_confirmation_replacement_and_replay_preserve_grant
    test_rpc_write_05_source=grant.Authority.test_write_05_changed_or_unsafe_source_rejects_confirmation
    test_rpc_write_06_locks_and_permissions=grant.Authority.test_write_06_locks_and_unsafe_pending_are_preserved
    test_rpc_write_08_credentials=grant.Authority.test_write_08_changed_private_credentials_reject_confirmation

    def test_rpc_write_03_writer_arguments_and_explicit_consent(self):
        with self.rpc_session('writer') as sid:
            before=self.snapshot();calls=self.calls()
            for action,args in [('preview',{'selection':[]}),('preview',{'selection':1}),
                                ('preview',{'selection':'ddns_0','unexpected':'SECRET_SENTINEL'}),
                                ('commit',{'confirmation':'a'*32,'consent':True}),
                                ('commit',{'confirmation':'a'*32,'consent':'1','rule':'ddns_0'}),
                                ('revoke',{'consent':1})]:
                self.http_call(sid,action,args,status=2)
            for action,args in [('preview',{'selection':'ddns_0;touch /tmp/escaped'}),
                                ('commit',{'confirmation':'a'*32}),
                                ('commit',{'confirmation':'a'*32,'consent':'0'}),('revoke',{})]:
                self.refused(action,(sid,None),**args)
            self.assertEqual(self.calls(),calls)
            self.assertTrue(before==self.snapshot(),'Invalid arguments changed state; bytes suppressed')
            self.assertFalse(Path('/tmp/escaped').exists())

    def test_rpc_write_07_closed_shell_preserves_pending(self):
        with self.session() as session:
            preview=self.post('preview',session,selection='ddns_0')
            paths=[(read.GUEST_PROTO/'homegate-ddns-ui.sh',b'ddns_ui_enabled=true',b'ddns_ui_enabled=false'),
                   (read.GUEST_PROTO/'homegate-ddns-authority.sh',b'ddns_authority_enabled=true',b'ddns_authority_enabled=false')]
            for path,opened,closed in paths:
                original=path.read_bytes();self.assertEqual(original.count(opened),1)
                try:
                    path.write_bytes(original.replace(opened,closed))
                    self.refused('commit',session,confirmation=preview['confirmation'],consent='1')
                finally:
                    path.write_bytes(original)

    def test_rpc_write_09_acl_anonymous_and_revoked_stop_before_backend(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            preview=self.post('preview',(writer,None),selection='ddns_0')
            methods={'preview':{'selection':'ddns_1'},'commit':{'confirmation':preview['confirmation'],'consent':'1'},'revoke':{'consent':'1'}}
            revoked=self.http_login('writer');self.http_call(revoked,'destroy',obj='session')
            before=self.snapshot();calls=self.calls()
            for sid in (reader,http.ZERO,'f'*32,revoked,''):
                for action,args in methods.items():self.http_call(sid,action,args,error=-32002)
            self.http_call(reader,'commit',{**methods['commit'],'ubus_rpc_session':writer},error=-32002)
            self.assertEqual(self.calls(),calls)
            self.assertTrue(before==self.snapshot(),'Denied identity changed state; bytes suppressed')
            self.post('commit',(writer,None),**methods['commit'])
            self.post('revoke',(writer,None),consent='1')

    def test_rpc_write_10_modern_bearer_and_legacy_share_scope(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            preview=self.grant_result('preview',writer,self.modern('preview',writer,{'selection':'ddns_1'}))
            self.post('commit',(writer,None),confirmation=preview['confirmation'],consent='1')
            self.assertEqual([row['status'] for row in self.read('status',reader,modern=True)['rules']],
                             ['unauthorized','ready','unauthorized','unauthorized'])
            before=self.snapshot();calls=self.calls()
            for sid in (reader,'f'*32,None):
                data=self.response({'jsonrpc':'2.0','id':83,'method':'revoke','params':{'consent':'1'}},
                    path='/ubus/call/homegate_ddns',headers={'Authorization':'Bearer '+sid} if sid else {})
                self.check_reply(data,error=-32002)
            self.assertEqual(self.calls(),calls);self.assertTrue(before==self.snapshot(),'Bearer refusal changed state')
            self.grant_result('revoke',writer,self.modern('revoke',writer,{'consent':'1'}))

    def test_rpc_write_11_batch_authorizes_each_real_write(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            calls=self.calls()
            requests=[self.request(reader,'homegate_ddns','preview',{'selection':'ddns_0'},1),
                      self.request(writer,'homegate_ddns','preview',{'selection':'ddns_2'},2),
                      self.request('f'*32,'homegate_ddns','revoke',{'consent':'1'},3)]
            data=self.response(requests);self.assertTrue(isinstance(data,list) and len(data)==3,'Invalid batch')
            self.check_reply(data[0],identity=1,error=-32002);self.check_reply(data[2],identity=3,error=-32002)
            preview=self.grant_result('preview',writer,self.check_reply(data[1],identity=2))
            self.assertEqual(self.calls(),calls+b'private-request:700:600\n')
            args={'confirmation':preview['confirmation'],'consent':'1'}
            calls=self.calls()
            data=self.response([self.request(reader,'homegate_ddns','commit',args,1),
                self.request(writer,'homegate_ddns','commit',args,2),
                self.request(writer,'homegate_ddns','revoke',{'consent':'1'},3)])
            self.check_reply(data[0],identity=1,error=-32002)
            self.grant_result('commit',writer,self.check_reply(data[1],identity=2))
            self.grant_result('revoke',writer,self.check_reply(data[2],identity=3))
            self.assertEqual(self.calls(),calls+b'private-request:700:600\n'*2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd')
    parser.add_argument('--http-runtime-dir',type=Path,default=luci.HTTP)
    parser.add_argument('--luci-runtime-dir',type=Path,default=luci.LUA)
    parser.add_argument('--inside-net',help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid',help=argparse.SUPPRESS)
    parser.add_argument('--group',choices=tuple(GROUPS))
    args=parser.parse_args()
    rpc.WORK,luci.HTTP,luci.LUA=args.runtime_dir.resolve(),args.http_runtime_dir.resolve(),args.luci_runtime_dir.resolve()
    if args.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID=args.inside_net,args.inside_uid
        names=[n for n in sorted(HTTPAuthority.__dict__) if n.startswith('test_rpc_write_') and n.split('_')[3] in GROUPS[args.group]]
        if len(names)!=len(GROUPS[args.group]):raise ValueError('Incomplete authority scenario group')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(HTTPAuthority(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER,rpc.CANDIDATE,rpc.ACL] if p.is_file()}
    if rpc.CANDIDATE.read_bytes().count(rpc.GATE)!=1:
        raise ValueError('Original RPC candidate must remain gated')
    busybox=subprocess.run([str(read.BUSYBOX),'--help'],capture_output=True)
    if busybox.returncode or not busybox.stdout.startswith(b'BusyBox v1.33.2 '):raise ValueError('Verified BusyBox1.33.2 required')
    result=0
    for group in ((args.group,) if args.group else tuple(GROUPS)):
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
            extra_mounts=lambda state:((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),(state/'libexec','/usr/libexec'),(state/'tools','/usr/sbin')),
            extra_rw_mounts=lambda state:((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
            state_setup=setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--group',group))
        if result:break
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original project or ACL changed during grant checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
