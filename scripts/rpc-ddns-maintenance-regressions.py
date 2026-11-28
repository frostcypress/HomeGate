#!/usr/bin/env python3
"""Real HTTP ACL/rpcd fresh-consent maintenance; known-none compact only."""
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


base=module('rpc_maintenance_jobs','rpc-ddns-jobs-regressions.py')
scenario=module('rpc_maintenance_scenarios','luci-ddns-maintenance-regressions.py')
read,luci,rpc,http=base.read,base.luci,base.rpc,base.http
scenario.jobs,scenario.read,scenario.luci,scenario.rpc=base.tasks,read,luci,rpc
STORE,RUN,STATE=read.STORE,read.RUN,read.STATE
GROUPS={'consent':('01','02','03','04'),'barriers':('05','06','07','08'),'transport':('09','10','11')}


def setup_state(state):
    base.setup_state(state)
    scenario.enable_maintenance(state)


class HTTPMaintenance(base.HTTPJobs):
    known_none=scenario.Maintenance.known_none
    preview=scenario.Maintenance.preview
    commit=scenario.Maintenance.commit
    refused_maintenance=scenario.Maintenance.refused_maintenance
    assert_originals=scenario.Maintenance.assert_originals

    def maintain(self,action,session,*,expected=200,modern=False,**fields):
        sid,_=session
        result=self.modern(action,sid,fields) if modern else self.http_call(sid,action,fields)
        return self.maintenance_result(action,sid,result,fields,expected)

    def maintenance_result(self,action,sid,result,fields,expected=200):
        raw=json.dumps(result).encode()
        for value in (b'SECRET_SENTINEL',b'PRIVATE_ACCOUNT',b'FIXTURE_ID',b'PRIVATE_RAW_SENTINEL',
                      b'example.test',b'/teststate',b'credentials',sid.encode()):
            self.assertTrue(value not in raw,'Private value escaped; body suppressed')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')),[])
        if expected!=200:
            self.assertTrue(result==http.HostHTTP.denial(action),'Business maintenance refusal changed; body suppressed')
            return None
        self.assertEqual(set(result),{'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertTrue(result['api_version']==1 and result['prototype'] is True and result['ok'] is True and
                        result['phase']=='ddns-ui' and result['operation']==action and result['effect']=='none' and
                        result['write_ready'] is False,'Invalid maintenance envelope; body suppressed')
        report=result['report'];keys={'api_version','prototype','ok','phase','job','rule','operation','effect','write_ready'}
        keys |= {'confirmation','expires_in'} if action=='maintain_preview' else {'completed'}
        self.assertEqual(set(report),keys)
        self.assertTrue(report['api_version']==1 and report['prototype'] is True and report['ok'] is True and
                        report['phase']=='ddns-maintenance' and report['job']==fields['job'] and report['rule']=='ddns_0' and
                        report['operation']=='compact' and report['effect']=='none' and report['write_ready'] is False,
                        'Unexpected maintenance scope; body suppressed')
        if action=='maintain_preview':
            self.assertTrue(len(report['confirmation'])==32 and report['expires_in']==300,'Invalid confirmation; body suppressed')
        else:self.assertTrue(report['completed'] is True)
        return report

    # Seven original backend scenarios via a separately authorized transport.
    test_rpc_maintain_01_explicit_compact=scenario.Maintenance.test_maintain_01_preview_then_explicit_compact_preserves_task
    test_rpc_maintain_02_nonce_and_consent=scenario.Maintenance.test_maintain_02_fresh_nonce_consent_and_replay
    test_rpc_maintain_03_source_binding=scenario.Maintenance.test_maintain_03_detail_and_grant_binding_before_consuming_nonce
    test_rpc_maintain_04_pending_and_unknown=scenario.Maintenance.test_maintain_04_pending_and_unknown_never_become_maintainable
    test_rpc_maintain_06_locks_and_gate=scenario.Maintenance.test_maintain_06_busy_locks_and_closed_gate_preserve_preview
    test_rpc_maintain_07_fresh_staged_consent=scenario.Maintenance.test_maintain_07_staged_confirmation_requires_fresh_preview_and_consent
    test_rpc_maintain_08_corrupt_or_linked_stage=scenario.Maintenance.test_maintain_08_corrupt_or_linked_stage_is_preserved

    def test_rpc_maintain_05_typed_arguments_and_explicit_consent(self):
        with self.rpc_session('writer') as writer:
            before=self.snapshot();calls=self.calls()
            valid={'job':'a'*32,'confirmation':'b'*32,'consent':'1'}
            for action,args in [('maintain_preview',{'job':[]}),('maintain_preview',{'job':'a'*32,'rule':'ddns_0'}),
                ('maintain_commit',{**valid,'confirmation':True}),('maintain_commit',{**valid,'consent':1}),
                ('maintain_commit',{**valid,'command':'cleanup'})]:
                self.http_call(writer,action,args,status=2)
            for action,args in [('maintain_preview',{'job':'../bad'}),
                ('maintain_commit',{'job':'a'*32,'confirmation':'b'*32}),
                ('maintain_commit',{**valid,'consent':'0'}),('maintain_commit',{**valid,'confirmation':'short'})]:
                self.maintain(action,(writer,None),expected=503,**args)
            self.assertEqual(self.calls(),calls)
            self.assertTrue(before==self.snapshot(),'Invalid maintenance arguments changed state; bytes suppressed')

    def test_rpc_maintain_09_reader_anonymous_revoked_and_session_injection(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            session=(writer,None);path,_=self.known_none(session);preview=self.preview(session)
            args={'job':'a'*32,'confirmation':preview['confirmation'],'consent':'1'}
            revoked=self.http_login('writer');self.http_call(revoked,'destroy',obj='session')
            before=self.snapshot();calls=self.calls();events=self.events()
            for sid in (reader,http.ZERO,'f'*32,revoked,''):
                self.http_call(sid,'maintain_preview',{'job':'a'*32},error=-32002)
                self.http_call(sid,'maintain_commit',args,error=-32002)
            self.http_call(reader,'maintain_commit',{**args,'ubus_rpc_session':writer},error=-32002)
            self.assertEqual(self.calls(),calls);self.assertEqual(self.events(),events)
            self.assertTrue(before==self.snapshot(),'Denied identity consumed maintenance evidence; bytes suppressed')
            self.assertTrue((path/'raw').is_file())
            self.commit(session,preview['confirmation'])
            self.assertTrue(self.jobs((reader,None))[0]['reason']=='compacted')

    def test_rpc_maintain_10_bearer_preview_legacy_commit_and_replay(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            session=(writer,None);path,_=self.known_none(session);events=self.events()
            preview=self.maintain('maintain_preview',session,modern=True,job='a'*32)
            args={'job':'a'*32,'confirmation':preview['confirmation'],'consent':'1'}
            before=self.snapshot();calls=self.calls()
            for sid in (reader,'f'*32,None):
                data=self.response({'jsonrpc':'2.0','id':83,'method':'maintain_commit','params':args},
                    path='/ubus/call/homegate_ddns',headers={'Authorization':'Bearer '+sid} if sid else {})
                self.check_reply(data,error=-32002)
            self.assertEqual(self.calls(),calls)
            self.assertTrue(before==self.snapshot(),'Bearer refusal changed pending consent; bytes suppressed')
            self.commit(session,preview['confirmation']);before=self.snapshot()
            self.maintain('maintain_commit',session,modern=True,expected=503,**args)
            self.assertTrue(before==self.snapshot(),'Cross-entry replay changed compacted task; bytes suppressed')
            rows=self.request_job('jobs',(reader,None),modern=True)['jobs']
            self.assertTrue(len(rows)==1 and rows[0]['reason']=='compacted' and rows[0]['last_effect']=='none')
            self.assertFalse((path/'raw').exists());self.assertEqual(self.events(),events)

    def test_rpc_maintain_11_batch_checks_acl_and_consumes_nonce_once(self):
        with self.rpc_session('writer') as writer,self.rpc_session() as reader:
            session=(writer,None);path,_=self.known_none(session);calls=self.calls();events=self.events()
            data=self.response([self.request(reader,'homegate_ddns','maintain_preview',{'job':'a'*32},1),
                self.request(writer,'homegate_ddns','maintain_preview',{'job':'a'*32},2),
                self.request('f'*32,'homegate_ddns','maintain_commit',{'job':'a'*32,'confirmation':'b'*32,'consent':'1'},3)])
            self.assertTrue(isinstance(data,list) and len(data)==3,'Unexpected maintenance batch')
            self.check_reply(data[0],identity=1,error=-32002);self.check_reply(data[2],identity=3,error=-32002)
            preview=self.maintenance_result('maintain_preview',writer,self.check_reply(data[1],identity=2),{'job':'a'*32})
            self.assertEqual(self.calls(),calls+b'private-request:700:600\n')
            original=(path/'maintenance').read_bytes();retained={n:(path/n).read_bytes() for n in ('meta','result','lock')}
            args={'job':'a'*32,'confirmation':preview['confirmation'],'consent':'1'};calls=self.calls()
            data=self.response([self.request(reader,'homegate_ddns','maintain_commit',args,1),
                self.request(writer,'homegate_ddns','maintain_commit',args,2),
                self.request(writer,'homegate_ddns','maintain_commit',args,3)])
            self.check_reply(data[0],identity=1,error=-32002)
            self.maintenance_result('maintain_commit',writer,self.check_reply(data[1],identity=2),args)
            self.maintenance_result('maintain_commit',writer,self.check_reply(data[2],identity=3),args,expected=503)
            self.assertEqual(self.calls(),calls+b'private-request:700:600\n'*2)
            self.assertTrue((path/'maintenance-used').read_bytes()==original,'Wrong consent frame consumed; bytes suppressed')
            self.assertTrue(all((path/n).read_bytes()==b for n,b in retained.items()),'Batch changed retained evidence')
            self.assertFalse((path/'raw').exists());self.assertTrue((path/'maintained').is_file())
            self.assertEqual(self.events(),events)


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
        names=[n for n in sorted(HTTPMaintenance.__dict__) if n.startswith('test_rpc_maintain_') and n.split('_')[3] in GROUPS[args.group]]
        if len(names)!=len(GROUPS[args.group]):raise ValueError('Incomplete RPC maintenance group')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(HTTPMaintenance(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER,rpc.CANDIDATE,rpc.ACL] if p.is_file()}
    if rpc.CANDIDATE.read_bytes().count(rpc.GATE)!=1 or (read.PROTO/'homegate-ddns-job.sh').read_bytes().count(b'ddns_ui_maintenance_enabled=false')!=1:
        raise ValueError('Original RPC/maintenance gates must remain closed')
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
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original project or ACL changed during maintenance checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
