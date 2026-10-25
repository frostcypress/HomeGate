#!/usr/bin/env python3
"""Real HTTP/rpcd confirmed task archive with original provider receipts."""
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


scenario=module('rpc_archive_original','luci-ddns-archive-regressions.py')
transport=module('rpc_archive_transport','rpc-ddns-jobs-regressions.py')
read,luci,rpc=scenario.read,scenario.luci,scenario.rpc
http=luci.http
rpc_read=transport.authority.base
rpc_read.read,rpc_read.luci,rpc_read.rpc,rpc_read.http=read,luci,rpc,http
STORE,RUN,STATE=scenario.STORE,scenario.RUN,scenario.STATE
CASES=tuple('%02d'%n for n in range(1,11))


def setup_state(state):
    scenario.setup_state(state)
    rpc_read.enable_rpc(state)


class HTTPArchive(scenario.Archive):
    HTTP_TIMEOUT=18
    CGI_TIMEOUT=18

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        rpc_read.start_rpc_http(cls)

    response=http.HostHTTP.response
    request=staticmethod(http.HostHTTP.request)
    check_reply=http.HostHTTP.check_reply
    http_call=http.HostHTTP.http_call
    http_login=http.HostHTTP.http_login
    rpc_session=rpc_read.HTTPRead.rpc_session
    calls=rpc_read.HTTPRead.calls
    session=transport.authority.HTTPAuthority.session
    modern=transport.authority.HTTPAuthority.modern
    post=transport.authority.HTTPAuthority.post
    grant_result=transport.authority.HTTPAuthority.grant_result
    request_job=transport.HTTPJobs.request_job
    job_result=transport.HTTPJobs.job_result

    def maintain(self,action,session,*,expected=200,modern=False,**fields):
        sid,_=session
        result=self.modern(action,sid,fields) if modern else self.http_call(sid,action,fields)
        return self.archive_result(action,sid,result,fields,expected)

    def archive_result(self,action,sid,result,fields,expected=200):
        raw=json.dumps(result).encode()
        for value in (b'SECRET_SENTINEL',b'PRIVATE_ACCOUNT',b'FIXTURE_ID',b'example.test',
                      b'2001:db8',b'/teststate',b'credentials',sid.encode()):
            self.assertTrue(value not in raw,'Private value escaped; body suppressed')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')),[])
        if expected!=200:
            self.assertTrue(result==http.HostHTTP.denial(action),'Business archive refusal changed; body suppressed')
            return None
        self.assertEqual(set(result),{'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertTrue(result['api_version']==1 and result['prototype'] is True and result['ok'] is True and
                        result['phase']=='ddns-ui' and result['operation']==action and result['effect']=='none' and
                        result['write_ready'] is False,'Invalid archive envelope; body suppressed')
        report=result['report'];keys={'api_version','prototype','ok','phase','job','rule','operation','effect','write_ready'}
        keys |= {'confirmation','expires_in'} if action=='maintain_preview' else {'completed'}
        self.assertEqual(set(report),keys)
        self.assertTrue(report['api_version']==1 and report['prototype'] is True and report['ok'] is True and
                        report['phase']=='ddns-maintenance' and report['job']==fields['job'] and report['rule']=='ddns_1' and
                        report['operation']=='archive' and report['effect']=='none' and report['write_ready'] is False,
                        'Unexpected original archive scope; body suppressed')
        if action=='maintain_preview':
            self.assertTrue(len(report['confirmation'])==32 and report['expires_in']==300,'Invalid archive confirmation')
        else:self.assertTrue(report['completed'] is True)
        return report

    # Same original receipt, source, nonce, locking and interrupted archive checks.
    test_rpc_archive_01_original_retained=scenario.Archive.test_archive_01_explicit_archive_retains_original_receipt_and_task
    test_rpc_archive_02_source_and_consent=scenario.Archive.test_archive_02_nonce_and_original_source_binding
    test_rpc_archive_03_locks_and_gate=scenario.Archive.test_archive_03_all_locks_and_closed_maintenance_gate_preserve_source
    test_rpc_archive_04_collector_refusal=scenario.Archive.test_archive_04_collector_refusal_consumes_old_consent_but_keeps_receipt
    test_rpc_archive_05_interrupted_marker=scenario.Archive.test_archive_05_archive_before_final_marker_requires_fresh_consent
    test_rpc_archive_06_unknown_refusal=scenario.Archive.test_archive_06_unknown_attempt_cannot_be_collected

    def test_rpc_archive_07_typed_arguments_and_explicit_consent(self):
        with self.session() as session:
            writer,_=session;path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation')
            preview=self.preview(session);valid={'job':'a'*32,'confirmation':preview['confirmation'],'consent':'1'}
            before=self.snapshot();calls=self.calls();requests=list(self.requests)
            for action,args in [('maintain_preview',{'job':[]}),('maintain_preview',{'job':'a'*32,'rule':'ddns_1'}),
                ('maintain_commit',{**valid,'confirmation':True}),('maintain_commit',{**valid,'consent':1}),
                ('maintain_commit',{**valid,'command':'cleanup'})]:
                self.http_call(writer,action,args,status=2)
            for action,args in [('maintain_preview',{'job':'../bad'}),
                ('maintain_commit',{'job':'a'*32,'confirmation':preview['confirmation']}),
                ('maintain_commit',{**valid,'consent':'0'}),('maintain_commit',{**valid,'confirmation':'short'})]:
                self.maintain(action,session,expected=503,**args)
            self.assertEqual(self.calls(),calls)
            self.assertTrue(before==self.snapshot(),'Invalid RPC arguments consumed original consent or receipt')
            self.commit(session,preview['confirmation']);self.archived(session,path,row,original)
            self.assertEqual(self.requests,requests)

    def test_rpc_archive_08_reader_anonymous_revoked_and_session_injection(self):
        with self.session() as session,self.rpc_session() as reader:
            writer,_=session;path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation')
            preview=self.preview(session);args={'job':'a'*32,'confirmation':preview['confirmation'],'consent':'1'}
            revoked=self.http_login('writer');self.http_call(revoked,'destroy',obj='session')
            before=self.snapshot();calls=self.calls();requests=list(self.requests)
            for sid in (reader,http.ZERO,'f'*32,revoked,''):
                self.http_call(sid,'maintain_preview',{'job':'a'*32},error=-32002)
                self.http_call(sid,'maintain_commit',args,error=-32002)
            self.http_call(reader,'maintain_commit',{**args,'ubus_rpc_session':writer},error=-32002)
            self.assertEqual(self.calls(),calls)
            self.assertTrue(before==self.snapshot(),'Denied identity consumed archive evidence')
            self.commit(session,preview['confirmation']);current=self.archived(session,path,row,original)
            before=self.snapshot();self.assertEqual(self.jobs((reader,None)),[current])
            self.assertTrue(before==self.snapshot(),'Reader changed retained archive')
            self.assertEqual(self.requests,requests)

    def test_rpc_archive_09_bearer_preview_legacy_commit_and_replay(self):
        with self.session() as session,self.rpc_session() as reader:
            writer,_=session;path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation');requests=list(self.requests)
            preview=self.maintain('maintain_preview',session,modern=True,job='a'*32)
            args={'job':'a'*32,'confirmation':preview['confirmation'],'consent':'1'};before=self.snapshot();calls=self.calls()
            for sid in (reader,'f'*32,None):
                data=self.response({'jsonrpc':'2.0','id':83,'method':'maintain_commit','params':args},
                    path='/ubus/call/homegate_ddns',headers={'Authorization':'Bearer '+sid} if sid else {})
                self.check_reply(data,error=-32002)
            self.assertEqual(self.calls(),calls)
            self.assertTrue(before==self.snapshot(),'Denied Bearer consumed original confirmation')
            self.commit(session,preview['confirmation']);current=self.archived(session,path,row,original);before=self.snapshot()
            self.maintain('maintain_commit',session,modern=True,expected=503,**args)
            rows=self.request_job('jobs',(reader,None),modern=True)['jobs'];self.assertEqual(rows,[current])
            self.assertTrue(before==self.snapshot(),'Cross-entry replay changed original archive')
            self.assertEqual(self.requests,requests)

    def test_rpc_archive_10_batch_acl_and_single_confirmation(self):
        with self.session() as session,self.rpc_session() as reader:
            writer,_=session;path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation');requests=list(self.requests)
            calls=self.calls()
            data=self.response([self.request(reader,'homegate_ddns','maintain_preview',{'job':'a'*32},1),
                self.request(writer,'homegate_ddns','maintain_preview',{'job':'a'*32},2),
                self.request('f'*32,'homegate_ddns','maintain_commit',{'job':'a'*32,'confirmation':'b'*32,'consent':'1'},3)])
            self.assertTrue(isinstance(data,list) and len(data)==3,'Unexpected archive preview batch')
            self.check_reply(data[0],identity=1,error=-32002);self.check_reply(data[2],identity=3,error=-32002)
            preview=self.archive_result('maintain_preview',writer,self.check_reply(data[1],identity=2),{'job':'a'*32})
            self.assertEqual(self.calls(),calls+b'private-request:700:600\n')
            consent=(path/'maintenance').read_bytes();retained={n:(path/n).read_bytes() for n in ('meta','result','proof','raw','lock')}
            args={'job':'a'*32,'confirmation':preview['confirmation'],'consent':'1'};calls=self.calls()
            data=self.response([self.request(reader,'homegate_ddns','maintain_commit',args,1),
                self.request(writer,'homegate_ddns','maintain_commit',args,2),
                self.request(writer,'homegate_ddns','maintain_commit',args,3)])
            self.assertTrue(isinstance(data,list) and len(data)==3,'Unexpected archive commit batch')
            self.check_reply(data[0],identity=1,error=-32002)
            self.archive_result('maintain_commit',writer,self.check_reply(data[1],identity=2),args)
            self.archive_result('maintain_commit',writer,self.check_reply(data[2],identity=3),args,expected=503)
            self.assertEqual(self.calls(),calls+b'private-request:700:600\n'*2)
            self.assertTrue((path/'maintenance-used').read_bytes()==consent,'Wrong original confirmation consumed')
            self.assertTrue(all((path/n).read_bytes()==b for n,b in retained.items()),'Batch changed retained original evidence')
            self.archived(session,path,row,original);self.assertEqual(self.requests,requests)


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
        names=[n for n in sorted(HTTPArchive.__dict__) if n.startswith('test_rpc_archive_') and n.split('_')[3]==args.case]
        if len(names)!=1:raise ValueError('Expected one original RPC archive scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(HTTPArchive(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER,rpc.CANDIDATE,rpc.ACL] if p.is_file()}
    if rpc.CANDIDATE.read_bytes().count(rpc.GATE)!=1:raise ValueError('Original RPC gate must remain closed')
    curl=subprocess.run([str(scenario.provider.CURL),'--version'],capture_output=True,check=True)
    if not curl.stdout.startswith(b'curl 7.83.1 '):raise ValueError('Use pinned curl7.83.1')
    result=0
    for case in ((args.case,) if args.case else CASES):
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
            extra_mounts=lambda state:((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),(state/'libexec','/usr/libexec'),
                (state/'tools','/usr/sbin'),(state/'curl-transport','/usr/bin/curl')),
            extra_rw_mounts=lambda state:((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
            state_setup=setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--case',case))
        if result:break
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original source or ACL changed during RPC archive checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
