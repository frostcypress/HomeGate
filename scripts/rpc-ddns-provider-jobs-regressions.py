#!/usr/bin/env python3
"""Real HTTP/rpcd mixed grants and selected-interface jobs with original receipts."""
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

transport=module('rpc_mixed_tasks_transport','rpc-ddns-archive-regressions.py')
scenario=transport.scenario
provider=scenario.provider
read,luci,rpc=provider.read,provider.luci,provider.rpc
rpc_read=transport.rpc_read
http=luci.http
STORE,RUN,STATE=provider.STORE,provider.RUN,provider.STATE
CASES=tuple('%02d'%n for n in range(1,9))

def setup_state(state):
    provider.setup_mixed_state(state)
    rpc_read.enable_rpc(state)

class MixedTaskTransport(transport.ArchiveTransport):
    TASK_RULE='ddns_1'

    def job_result(self,action,sid,result,expected=200):
        raw=json.dumps(result).encode()
        for marker in (b'2001:db8',b'odd-uplink',b'pppoe-wan'):
            self.assertNotIn(marker,raw,'Interface/address escaped the public RPC job result')
        return super().job_result(action,sid,result,expected)

    def seed_interface_noop(self):
        self.db['c'*32]={'id':'c'*32,'type':'AAAA','name':'www.example.test','content':'2001:db8:2::9','ttl':600}

    def test_rpc_mixed_05_typed_parameters_cannot_override_interface(self):
        with self.session() as session:
            writer,_=session;calls=self.calls();before=self.snapshot()
            valid={'job':'a'*32,'rule':self.TASK_RULE,'consent':'1'}
            for args in ({**valid,'job':[]},{**valid,'rule':1},{**valid,'consent':True},
                         {**valid,'interface':'pppoe-wan'},{**valid,'address':'2001:db8::2'}):
                self.http_call(writer,'submit',args,status=2)
            for args in ({'job':'a'*32,'rule':self.TASK_RULE},{**valid,'consent':'0'},{**valid,'rule':self.TASK_RULE+';bad'}):
                self.request_job('submit',session,expected=503,**args)
            self.assertEqual(self.calls(),calls);self.assertEqual(before,self.snapshot());self.assertEqual(self.requests,[])
            self.assertFalse(provider.jobs.JOBS.exists())

    def test_rpc_mixed_06_denied_identities_and_reader_observation(self):
        self.seed_interface_noop()
        with self.session() as session,self.rpc_session() as reader:
            writer,_=session;self.authorize(session)
            revoked=self.http_login('writer');self.http_call(revoked,'destroy',obj='session')
            args={'job':'a'*32,'rule':self.TASK_RULE,'consent':'1'};calls=self.calls();before=self.snapshot()
            for sid in (reader,http.ZERO,'f'*32,revoked,''):
                self.http_call(sid,'submit',args,error=-32002)
            self.http_call(reader,'submit',{**args,'ubus_rpc_session':writer},error=-32002)
            self.assertEqual(self.calls(),calls);self.assertEqual(before,self.snapshot());self.assertFalse(provider.jobs.JOBS.exists())
            self.submit(session);row=self.settled(session);self.assertEqual((row['last_effect'],row['result']['status']),('none','unchanged'))
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.jobs((reader,None)),[row])
            self.assertEqual(before,self.snapshot());self.assertEqual(requests,self.requests)

    def test_rpc_mixed_07_bearer_submit_and_legacy_replay_preserve_job(self):
        self.seed_interface_noop()
        with self.session() as session,self.rpc_session() as reader:
            writer,_=session;self.authorize(session)
            ack=self.request_job('submit',session,modern=True,job='a'*32,rule=self.TASK_RULE,consent='1');self.assertTrue(ack['pending'])
            row=self.settled(session);self.assertEqual((row['last_effect'],row['result']['status']),('none','unchanged'))
            before=self.snapshot();requests=list(self.requests);calls=self.calls()
            self.assertEqual(self.submit(session),row);self.assertEqual(self.request_job('jobs',(reader,None),modern=True)['jobs'],[row])
            for sid in (reader,'f'*32,None):
                reply=self.response({'jsonrpc':'2.0','id':83,'method':'submit','params':{'job':'b'*32,'rule':self.TASK_RULE,'consent':'1'}},path='/ubus/call/homegate_ddns',headers={'Authorization':'Bearer '+sid} if sid else {})
                self.check_reply(reply,error=-32002)
            self.assertEqual(self.calls(),calls+b'private-request:700:600\n'*2);self.assertEqual(before,self.snapshot());self.assertEqual(requests,self.requests)
            self.assertEqual((STATE/'network-samples').read_text().splitlines(),['addresses'])

    def test_rpc_mixed_08_batch_acl_and_duplicate_submit_execute_once(self):
        self.seed_interface_noop()
        with self.session() as session,self.rpc_session() as reader:
            writer,_=session;self.authorize(session);args={'job':'a'*32,'rule':self.TASK_RULE,'consent':'1'}
            calls=self.calls()
            reply=self.response([self.request(reader,'homegate_ddns','submit',args,1),self.request(writer,'homegate_ddns','submit',args,2),self.request(writer,'homegate_ddns','submit',args,3),self.request('f'*32,'homegate_ddns','jobs',{},4)])
            self.assertTrue(isinstance(reply,list) and len(reply)==4)
            self.check_reply(reply[0],identity=1,error=-32002);self.check_reply(reply[3],identity=4,error=-32002)
            first=self.job_result('submit',writer,self.check_reply(reply[1],identity=2));second=self.job_result('submit',writer,self.check_reply(reply[2],identity=3))
            self.assertEqual((first['job'],second['job']),('a'*32,'a'*32));self.assertEqual(self.calls(),calls+b'private-request:700:600\n'*2)
            row=self.settled(session);self.assertEqual((row['last_effect'],row['result']['status']),('none','unchanged'))
            self.assertEqual([p.name for p in provider.jobs.JOBS.iterdir() if p.is_dir()],['a'*32]);self.assertEqual((STATE/'network-samples').read_text().splitlines(),['addresses'])
            before=self.snapshot();requests=list(self.requests)
            reply=self.response([self.request(writer,'homegate_ddns','submit',args,5),self.request(writer,'homegate_ddns','submit',args,6)])
            for result,identity in zip(reply,[5,6]):self.assertEqual(self.job_result('submit',writer,self.check_reply(result,identity=identity)),row)
            self.assertEqual(before,self.snapshot());self.assertEqual(requests,self.requests)


class HTTPMixedJobs(MixedTaskTransport,provider.MixedJobs):
    # Reuse transport, authority and genuine selected-interface worker scenarios.
    test_rpc_mixed_01_noop=provider.MixedJobs.test_provider_05_mixed_grant_and_interface_noop_stay_scoped
    test_rpc_mixed_02_original_receipt=provider.MixedJobs.test_provider_06_interface_create_keeps_real_receipt_and_replay_barrier
    test_rpc_mixed_03_missing_interface=provider.MixedJobs.test_provider_07_missing_interface_finishes_without_wan_fallback_or_proof
    test_rpc_mixed_04_unknown_barrier=provider.MixedJobs.test_provider_09_unknown_interface_attempt_keeps_original_evidence



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
        names=[n for n in dir(HTTPMixedJobs) if n.startswith('test_rpc_mixed_') and n.split('_')[3]==args.case]
        if len(names)!=1:raise ValueError('Expected one mixed-interface RPC task scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(HTTPMixedJobs(n) for n in names)).wasSuccessful() else 1
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
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original source or ACL changed during RPC mixed-interface checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
