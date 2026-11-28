#!/usr/bin/env python3
"""Real HTTP ACL/rpcd -> retained Shell task admission and observations."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import unittest
from project import ROOT
import importlib.util


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


authority=module('rpc_jobs_authority','rpc-ddns-authority-regressions.py')
tasks=module('rpc_jobs_scenarios','luci-ddns-jobs-regressions.py')
read,luci,rpc,http=authority.read,authority.luci,authority.rpc,authority.http
tasks.read,tasks.luci,tasks.rpc,tasks.grant=read,luci,rpc,authority.grant
STORE,RUN,STATE=read.STORE,read.RUN,read.STATE
GROUPS={'dispatch':('01','02','03'),'guards':('04','05','06','07'),'transport':('08','09','10')}


def setup_state(state):
    authority.setup_state(state)
    tasks.setup_launch_control(state)


class HTTPJobs(authority.HTTPAuthority):
    def setUp(self):
        super().setUp()
        self.held=False
        (STATE/'launch-mode').write_text('fail')
        (STATE/'launch-entered').unlink(missing_ok=True)

    def tearDown(self):
        self.cleanup_jobs()
        super().tearDown()

    cleanup_jobs=tasks.Jobs.cleanup_jobs
    release=tasks.Jobs.release
    events=tasks.Jobs.events
    authorize=tasks.Jobs.authorize
    submit=tasks.Jobs.submit
    jobs=tasks.Jobs.jobs
    settled=tasks.Jobs.settled
    hold=tasks.Jobs.hold
    accepted_held=tasks.Jobs.accepted_held
    changed_result=tasks.Jobs.changed_result

    def request_job(self,action,session,*,expected=200,modern=False,**fields):
        sid,_=session
        result=self.modern(action,sid,fields) if modern else self.http_call(sid,action,fields)
        return self.job_result(action,sid,result,expected)

    def job_result(self,action,sid,result,expected=200):
        raw=json.dumps(result).encode()
        for value in (b'SECRET_SENTINEL',b'PRIVATE_ACCOUNT',b'FIXTURE_ID',b'example.test',
                      b'/teststate',b'credentials',sid.encode()):
            self.assertTrue(value not in raw,'Private value escaped; body suppressed')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')),[])
        if expected!=200:
            self.assertTrue(result==http.HostHTTP.denial(action),'Business task refusal changed; body suppressed')
            return None
        self.assertEqual(set(result),{'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertTrue(result['api_version']==1 and result['prototype'] is True and result['ok'] is True and
                        result['phase']=='ddns-ui' and result['operation']==action and result['write_ready'] is False and
                        result['effect']==('unknown' if action=='submit' else 'none'),'Invalid task envelope; body suppressed')
        return result['report']

    # Same actual backend scenarios, independently checked through HTTP/RPC.
    test_rpc_job_01_pending_duplicate=tasks.Jobs.test_job_01_pending_duplicate_and_busy_business_observation
    test_rpc_job_02_failed_spawn=tasks.Jobs.test_job_02_failed_spawn_retains_unknown_and_never_relaunches
    test_rpc_job_03_known_no_dispatch=tasks.Jobs.test_job_03_real_worker_publishes_known_no_dispatch_after_source_change
    test_rpc_job_05_corrupt_or_linked_result=tasks.Jobs.test_job_05_corrupt_or_linked_real_result_is_preserved
    test_rpc_job_06_closed_gate=tasks.Jobs.test_job_06_closed_job_gate_preserves_retained_evidence
    test_rpc_job_07_catalog_busy=tasks.Jobs.test_job_07_catalog_busy_and_read_refresh_do_not_allocate_or_retry

    def test_rpc_job_04_typed_arguments_and_explicit_consent(self):
        with self.rpc_session('writer') as writer:
            calls=self.calls();before=self.snapshot()
            valid={'job':'a'*32,'rule':'ddns_0','consent':'1'}
            for args in ({**valid,'job':[]},{**valid,'rule':1},{**valid,'consent':True},
                         {**valid,'unexpected':'SECRET_SENTINEL'}):
                self.http_call(writer,'submit',args,status=2)
            self.http_call(writer,'jobs',{'job':'a'*32},status=2)
            for args in ({'job':'a'*32,'rule':'ddns_0'},{**valid,'consent':'0'},
                         {**valid,'job':'../bad'},{**valid,'rule':'ddns_0;bad'}):
                self.request_job('submit',(writer,None),expected=503,**args)
            self.assertEqual(self.calls(),calls)
            self.assertFalse(tasks.JOBS.exists())
            self.assertTrue(before==self.snapshot(),'Invalid RPC arguments changed private state; bytes suppressed')

    def test_rpc_job_08_reader_anonymous_revoked_and_injected_session(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            self.authorize((writer,None))
            revoked=self.http_login('writer');self.http_call(revoked,'destroy',obj='session')
            args={'job':'a'*32,'rule':'ddns_0','consent':'1'}
            calls=self.calls();before=self.snapshot();events=self.events()
            for sid in (reader,http.ZERO,'f'*32,revoked,''):
                self.http_call(sid,'submit',args,error=-32002)
            self.http_call(reader,'submit',{**args,'ubus_rpc_session':writer},error=-32002)
            self.assertEqual(self.calls(),calls);self.assertEqual(self.events(),events)
            self.assertFalse(tasks.JOBS.exists())
            self.assertTrue(before==self.snapshot(),'Denied session allocated a task; bytes suppressed')
            self.submit((writer,None));row=self.settled((writer,None))
            self.assertTrue(row['state']=='interrupted' and row['last_effect']=='unknown')
            before=self.snapshot();self.assertEqual(self.jobs((reader,None)),[row])
            self.assertTrue(before==self.snapshot(),'Reader observation changed a task; bytes suppressed')

    def test_rpc_job_09_bearer_submission_legacy_replay_and_reader_results(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            session=(writer,None);self.authorize(session);events=self.events()
            with self.hold():
                row=self.request_job('submit',session,modern=True,job='a'*32,rule='ddns_0',consent='1')
                self.assertTrue(row['pending'] and row['last_effect']=='unknown')
                self.wait_for(lambda:(STATE/'launch-entered').exists())
                before=self.snapshot()
                self.assertEqual(self.submit(session),row)
                observed=self.request_job('jobs',(reader,None),modern=True)['jobs']
                self.assertTrue(len(observed)==1 and observed[0]['pending'] and observed[0]['last_effect']=='unknown')
                for sid in (reader,'f'*32,None):
                    data=self.response({'jsonrpc':'2.0','id':83,'method':'submit',
                        'params':{'job':'b'*32,'rule':'ddns_0','consent':'1'}},
                        path='/ubus/call/homegate_ddns',headers={'Authorization':'Bearer '+sid} if sid else {})
                    self.check_reply(data,error=-32002)
                self.assertTrue(before==self.snapshot(),'Bearer replay/refusal changed task records; bytes suppressed')
                self.assertEqual(self.events(),events+b'job-launch\n')
            row=self.settled(session);before=self.snapshot()
            self.assertEqual(self.request_job('jobs',(reader,None),modern=True)['jobs'],[row])
            self.assertTrue(row['state']=='interrupted' and row['last_effect']=='unknown')
            self.assertTrue(before==self.snapshot(),'Bearer result read changed history; bytes suppressed')

    def test_rpc_job_10_batch_checks_acl_and_deduplicates_each_element(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            session=(writer,None);self.authorize(session)
            args={'job':'a'*32,'rule':'ddns_0','consent':'1'}
            with self.hold():
                calls=self.calls();events=self.events()
                data=self.response([self.request(reader,'homegate_ddns','submit',args,1),
                    self.request(writer,'homegate_ddns','submit',args,2),
                    self.request(writer,'homegate_ddns','submit',args,3),
                    self.request('f'*32,'homegate_ddns','jobs',{},4)])
                self.assertTrue(isinstance(data,list) and len(data)==4,'Unexpected task batch')
                self.check_reply(data[0],identity=1,error=-32002);self.check_reply(data[3],identity=4,error=-32002)
                first=self.job_result('submit',writer,self.check_reply(data[1],identity=2))
                second=self.job_result('submit',writer,self.check_reply(data[2],identity=3))
                self.assertTrue(first['pending'] and second['pending'] and first['job']==second['job']=='a'*32)
                self.wait_for(lambda:(STATE/'launch-entered').exists())
                self.assertEqual(self.calls(),calls+b'private-request:700:600\n'*2)
                self.assertEqual(self.events(),events+b'job-launch\n')
                before=self.snapshot();new={**args,'job':'b'*32}
                data=self.response([self.request(reader,'homegate_ddns','jobs',{},1),
                    self.request(reader,'homegate_ddns','submit',new,2),
                    self.request(writer,'homegate_ddns','submit',new,3)])
                rows=self.job_result('jobs',reader,self.check_reply(data[0],identity=1))['jobs']
                self.assertTrue(len(rows)==1 and rows[0]['pending'])
                self.check_reply(data[1],identity=2,error=-32002)
                self.job_result('submit',writer,self.check_reply(data[2],identity=3),expected=503)
                self.assertTrue(before==self.snapshot(),'Batch changed original pending evidence; bytes suppressed')
                self.assertEqual(self.events(),events+b'job-launch\n')
            row=self.settled(session)
            self.assertTrue(row['state']=='interrupted' and row['last_effect']=='unknown')


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
        names=[n for n in sorted(HTTPJobs.__dict__) if n.startswith('test_rpc_job_') and n.split('_')[3] in GROUPS[args.group]]
        if len(names)!=len(GROUPS[args.group]):raise ValueError('Incomplete RPC task group')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(HTTPJobs(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER,rpc.CANDIDATE,rpc.ACL] if p.is_file()}
    if rpc.CANDIDATE.read_bytes().count(rpc.GATE)!=1 or (read.PROTO/'homegate-ddns-job.sh').read_bytes().count(b'ddns_ui_jobs_enabled=false')!=1:
        raise ValueError('Original RPC/task gates must remain closed')
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
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original project or ACL changed during task checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
