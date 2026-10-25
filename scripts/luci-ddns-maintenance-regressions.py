#!/usr/bin/env python3
"""Real LuCI fresh-consent maintenance of genuine known-none task results."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from project import ROOT

spec=importlib.util.spec_from_file_location('maintenance_jobs_base',ROOT/'scripts/luci-ddns-jobs-regressions.py')
jobs=importlib.util.module_from_spec(spec);spec.loader.exec_module(jobs)
read,luci,rpc=jobs.read,jobs.luci,jobs.rpc
STORE,RUN,STATE=jobs.STORE,jobs.RUN,jobs.STATE
GROUPS={'consent':('01','02','03','04'),'barriers':('05','06','07','08')}


def setup_state(state):
    jobs.setup_state(state)
    enable_maintenance(state)


def enable_maintenance(state):
    path=state/'project/core/prototype/homegate-ddns-job.sh';body=path.read_bytes()
    if body.count(b'ddns_ui_maintenance_enabled=false')!=1:raise ValueError('Original maintenance gate must be closed')
    path.write_bytes(body.replace(b'ddns_ui_maintenance_enabled=false',b'ddns_ui_maintenance_enabled=true'))


class Maintenance(jobs.Jobs):
    def known_none(self,session):
        self.authorize(session)
        row=self.changed_result(session)
        path=jobs.JOBS/('a'*32)
        # Only a disposable detail specimen is added. The original meta/result
        # were produced by the real worker; no successful DNS receipt is seeded.
        fd=os.open(path/'raw',os.O_WRONLY | os.O_CREAT | os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(b'PRIVATE_RAW_SENTINEL\n')
        return path,row

    def maintain(self,action,session,*,expected=200,**fields):
        sid,token=session
        status,_,body=self.cgi(luci.BASE+'/ddns_native/'+action,cookie=sid,verb='POST',fields={'token':token,**fields})
        self.assertEqual(status,expected,'Maintenance HTTP status changed; body suppressed')
        for value in (b'SECRET_SENTINEL',b'PRIVATE_ACCOUNT',b'FIXTURE_ID',b'PRIVATE_RAW_SENTINEL',
                      b'example.test',b'/teststate',b'credentials',sid.encode(),token.encode()):
            self.assertTrue(value not in body,'Private value escaped; body suppressed')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')),[])
        if expected!=200:
            self.gate_response(action,status,body)
            return None
        result=json.loads(body)
        self.assertEqual(set(result),{'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertTrue(result['api_version']==1 and result['prototype'] is True and result['ok'] is True and
                        result['phase']=='ddns-ui' and result['operation']==action and
                        result['effect']=='none' and result['write_ready'] is False,'Invalid maintenance envelope; body suppressed')
        report=result['report']
        keys={'api_version','prototype','ok','phase','job','rule','operation','effect','write_ready'}
        keys |= {'confirmation','expires_in'} if action=='maintain_preview' else {'completed'}
        self.assertEqual(set(report),keys)
        self.assertTrue(report['api_version']==1 and report['prototype'] is True and report['ok'] is True and
                        report['phase']=='ddns-maintenance' and report['effect']=='none' and report['write_ready'] is False and
                        report['job']==fields['job'] and report['rule']=='ddns_0' and report['operation']=='compact',
                        'Unexpected maintenance scope; body suppressed')
        if action=='maintain_preview':
            self.assertTrue(len(report['confirmation'])==32 and report['expires_in']==300,'Invalid confirmation; body suppressed')
        else:self.assertTrue(report['completed'] is True)
        return report

    def preview(self,session,**kwargs):
        return self.maintain('maintain_preview',session,job='a'*32,**kwargs)

    def commit(self,session,nonce,**kwargs):
        return self.maintain('maintain_commit',session,job='a'*32,confirmation=nonce,consent='1',**kwargs)

    def refused_maintenance(self,action,session,**fields):
        before=self.snapshot()
        self.maintain(action,session,expected=503,**fields)
        self.assertTrue(before==self.snapshot(),'Rejected maintenance changed evidence; bytes suppressed')

    def assert_originals(self,before):
        after=self.snapshot()
        self.assertTrue(all(after.get(k)==v for k,v in before.items()),'Preview changed preexisting evidence; bytes suppressed')

    def test_maintain_01_preview_then_explicit_compact_preserves_task(self):
        with self.session() as session:
            path,row=self.known_none(session);before=self.snapshot();events=self.events()
            preview=self.preview(session);self.assert_originals(before)
            self.assertTrue((path/'raw').is_file());self.assertFalse((path/'maintained').exists())
            retained={n:(path/n).read_bytes() for n in ('meta','result','lock','start')}
            self.commit(session,preview['confirmation'])
            self.assertFalse((path/'raw').exists());self.assertTrue((path/'maintained').is_file())
            self.assertTrue(all((path/n).read_bytes()==b for n,b in retained.items()),'Compaction changed retained task; bytes suppressed')
            current=self.jobs(session)[0]
            self.assertTrue(current['reason']=='compacted' and current['last_effect']=='none' and current['result']==row['result'])
            before=self.snapshot();self.assertEqual(self.submit(session),current)
            self.assertTrue(before==self.snapshot(),'Old task identifier was replayed; bytes suppressed')
            self.assertEqual(self.events(),events)

    def test_maintain_02_fresh_nonce_consent_and_replay(self):
        with self.session() as session:
            path,_=self.known_none(session);first=self.preview(session);second=self.preview(session)
            self.assertTrue(first['confirmation']!=second['confirmation'],'Maintenance nonce was reused')
            self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation=first['confirmation'],consent='1')
            for fields in ({'job':'a'*32,'confirmation':second['confirmation']},
                           {'job':'a'*32,'confirmation':second['confirmation'],'consent':'0'}):
                self.refused_maintenance('maintain_commit',session,**fields)
            self.assertTrue((path/'raw').exists())
            self.commit(session,second['confirmation'])
            self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation=second['confirmation'],consent='1')
            self.refused_maintenance('maintain_preview',session,job='a'*32)

    def test_maintain_03_detail_and_grant_binding_before_consuming_nonce(self):
        with self.session() as session:
            path,_=self.known_none(session);preview=self.preview(session)
            for file in (path/'raw',STORE/'ddns-authority'):
                original=file.read_bytes()
                try:
                    file.write_bytes(original+b'changed-fixture')
                    self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation=preview['confirmation'],consent='1')
                finally:file.write_bytes(original)
            self.refused_maintenance('maintain_commit',session,job='b'*32,confirmation=preview['confirmation'],consent='1')
            self.commit(session,preview['confirmation'])

    def test_maintain_04_pending_and_unknown_never_become_maintainable(self):
        with self.session() as session:
            self.authorize(session);events=self.events()
            with self.hold():
                self.accepted_held(session)
                self.refused_maintenance('maintain_preview',session,job='a'*32)
                self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation='b'*32,consent='1')
            row=self.settled(session)
            self.assertTrue(row['state']=='interrupted' and row['last_effect']=='unknown')
            self.refused_maintenance('maintain_preview',session,job='a'*32)
            self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation='b'*32,consent='1')
            self.assertEqual(self.events(),events+b'job-launch\n')
            self.assertFalse((jobs.JOBS/('a'*32)/'maintained').exists())

    def test_maintain_05_post_csrf_and_exact_fields_before_backend(self):
        with self.session() as session,self.session() as other:
            sid,token=session;before=self.snapshot()
            calls=(STATE/'entry-calls').read_bytes() if (STATE/'entry-calls').exists() else b''
            for action in ('maintain_preview','maintain_commit'):
                status,_,_=self.cgi(luci.BASE+'/ddns_native/'+action,cookie=sid)
                self.assertEqual(status,405)
                for fields in ({},{'token':'wrong-fixture'},{'token':other[1]},{'token':[token,'wrong-fixture']}):
                    status,_,_=self.cgi(luci.BASE+'/ddns_native/'+action,cookie=sid,verb='POST',fields=fields)
                    self.assertEqual(status,403)
            for action,fields in [('maintain_preview',{'job':'../bad'}),
                ('maintain_preview',{'job':'a'*32,'rule':'ddns_0'}),
                ('maintain_commit',{'job':'a'*32,'confirmation':'short','consent':'1'}),
                ('maintain_commit',{'job':'a'*32,'confirmation':'b'*32,'consent':'0'}),
                ('maintain_commit',{'job':'a'*32,'confirmation':'b'*32,'consent':'1','command':'cleanup'})]:
                self.refused_maintenance(action,session,**fields)
            after=(STATE/'entry-calls').read_bytes() if (STATE/'entry-calls').exists() else b''
            self.assertEqual(calls,after);self.assertTrue(before==self.snapshot(),'Invalid maintenance changed state')

    def test_maintain_06_busy_locks_and_closed_gate_preserve_preview(self):
        with self.session() as session:
            path,_=self.known_none(session);preview=self.preview(session)
            for file in (RUN/'frontend.lock',STORE/'.supervisor.lock',RUN/'ddns-ui-jobs.lock',path/'lock'):
                with file.open('rb') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation=preview['confirmation'],consent='1')
            helper=read.GUEST_PROTO/'homegate-ddns-job.sh';original=helper.read_bytes()
            try:
                self.assertEqual(original.count(b'ddns_ui_maintenance_enabled=true'),1)
                helper.write_bytes(original.replace(b'ddns_ui_maintenance_enabled=true',b'ddns_ui_maintenance_enabled=false'))
                self.refused_maintenance('maintain_preview',session,job='a'*32)
                self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation=preview['confirmation'],consent='1')
            finally:helper.write_bytes(original)
            self.commit(session,preview['confirmation'])

    def test_maintain_07_staged_confirmation_requires_fresh_preview_and_consent(self):
        with self.session() as session:
            path,_=self.known_none(session);first=self.preview(session)
            (path/'maintenance').rename(path/'maintenance.next')
            self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation=first['confirmation'],consent='1')
            before={n:(path/n).read_bytes() for n in ('meta','result','raw')}
            second=self.preview(session)
            self.assertTrue(first['confirmation']!=second['confirmation'],'Staged consent was revived')
            self.assertFalse((path/'maintenance.next').exists())
            self.assertTrue(all((path/n).read_bytes()==b for n,b in before.items()),'Preview recovery changed task evidence')
            self.refused_maintenance('maintain_commit',session,job='a'*32,confirmation=first['confirmation'],consent='1')
            self.commit(session,second['confirmation'])

    def test_maintain_08_corrupt_or_linked_stage_is_preserved(self):
        with self.session() as session:
            path,_=self.known_none(session);self.preview(session)
            stage=path/'maintenance.next';(path/'maintenance').rename(stage);original=stage.read_bytes()
            try:
                stage.write_bytes(original+b'x')
                self.refused_maintenance('maintain_preview',session,job='a'*32)
            finally:stage.write_bytes(original)
            outside=RUN/'saved-maintenance-stage';stage.rename(outside);stage.symlink_to(outside)
            try:
                self.refused_maintenance('maintain_preview',session,job='a'*32)
                self.assertTrue(outside.read_bytes()==original,'Linked preview target changed; bytes suppressed')
            finally:stage.unlink();outside.rename(stage)
            fresh=self.preview(session);self.commit(session,fresh['confirmation'])


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
        names=[n for n in sorted(Maintenance.__dict__) if n.startswith('test_maintain_') and n.split('_')[2] in GROUPS[args.group]]
        if len(names)!=len(GROUPS[args.group]):raise ValueError('Incomplete maintenance group')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Maintenance(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER] if p.is_file()}
    if (read.PROTO/'homegate-ddns-job.sh').read_bytes().count(b'ddns_ui_maintenance_enabled=false')!=1:
        raise ValueError('Original maintenance gate must remain closed')
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
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original project changed during maintenance checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
