#!/usr/bin/env python3
"""Real LuCI submissions and retained Shell jobs, without provider dispatch."""
import argparse
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from project import ROOT

spec=importlib.util.spec_from_file_location('job_authority_base',ROOT/'scripts/luci-ddns-authority-regressions.py')
grant=importlib.util.module_from_spec(spec);spec.loader.exec_module(grant)
read,luci,rpc=grant.read,grant.luci,grant.rpc
STORE,RUN,STATE=read.STORE,read.RUN,read.STATE
JOBS=RUN/'ddns-ui-jobs'
GROUPS={'dispatch':('01','02','03'),'guards':('04','05','06','07')}


def setup_state(state):
    grant.setup_state(state)
    setup_launch_control(state)


def setup_launch_control(state):
    os.mkfifo(state/'launch-gate',0o600)
    (state/'launch-mode').write_text('fail')
    launcher=state/'tools/setsid'
    launcher.write_text(r'''#!/usr/bin/python3
import os,sys
from pathlib import Path
if len(sys.argv)!=5 or sys.argv[1]!='ash' or sys.argv[2]!='/teststate/project/core/prototype/homegate-ddns-job.sh' or sys.argv[3]!='work':
    os.execv('/usr/bin/setsid',['setsid',*sys.argv[1:]])
with open('/teststate/launch-events','ab') as stream:stream.write(b'job-launch\n')
if Path('/teststate/launch-mode').read_text()!='hold':os._exit(1)
fd=os.open('/teststate/launch-gate',os.O_RDWR)
Path('/teststate/launch-entered').write_bytes(b'held')
command=os.read(fd,1);os.close(fd)
if command!=b'r':os._exit(1)
os.execv('/usr/bin/setsid',['setsid',*sys.argv[1:]])
''')
    launcher.chmod(0o755)


class Jobs(grant.Authority):
    def setUp(self):
        super().setUp()
        self.held=False
        (STATE/'launch-mode').write_text('fail')
        (STATE/'launch-entered').unlink(missing_ok=True)

    def release(self,run=False):
        if self.held:
            fd=os.open(STATE/'launch-gate',os.O_RDWR)
            try:
                os.write(fd,b'r' if run else b'f')
            finally:
                os.close(fd)
            self.held=False

    def tearDown(self):
        self.cleanup_jobs()
        super().tearDown()

    def cleanup_jobs(self):
        self.release()
        # A fixture must never remove records while its own child owns the lock.
        if JOBS.exists():
            self.wait_for(lambda:all(not j['pending'] for j in self.command('homegate-ddns-job.sh','list')['jobs']))
            if JOBS.parent!=RUN or JOBS.is_symlink():raise RuntimeError('Unexpected fixture job directory')
            shutil.rmtree(JOBS)
            (RUN/'ddns-ui-jobs.lock').unlink()

    def events(self):
        path=STATE/'launch-events'
        return path.read_bytes() if path.exists() else b''

    def authorize(self,session):
        preview=self.post('preview',session,selection='ddns_0')
        self.post('commit',session,confirmation=preview['confirmation'],consent='1')

    def request_job(self,action,session,*,expected=200,**fields):
        sid,token=session
        status,_,body=self.cgi(luci.BASE+'/ddns_native/'+action,cookie=sid,verb='POST' if action=='submit' else 'GET',
                               fields={'token':token,**fields} if action=='submit' else fields)
        self.assertEqual(status,expected,'Job HTTP status changed; body suppressed')
        for value in (b'SECRET_SENTINEL',b'PRIVATE_ACCOUNT',b'FIXTURE_ID',b'example.test',
                      b'/teststate',b'credentials',sid.encode(),token.encode()):
            self.assertTrue(value not in body,'Private value escaped; body suppressed')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')),[])
        if expected!=200:
            self.gate_response(action,status,body)
            return None
        result=json.loads(body)
        self.assertEqual(set(result),{'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertTrue(result['api_version']==1 and result['prototype'] is True and result['ok'] is True and
                        result['phase']=='ddns-ui' and result['operation']==action and result['write_ready'] is False and
                        result['effect']==('unknown' if action=='submit' else 'none'),'Invalid task envelope; body suppressed')
        return result['report']

    def submit(self,session,job='a'*32,rule='ddns_0',expected=200):
        return self.request_job('submit',session,expected=expected,job=job,rule=rule,consent='1')

    def jobs(self,session):
        report=self.request_job('jobs',session)
        self.assertEqual(set(report),{'api_version','prototype','ok','phase','jobs','effect','write_ready'})
        self.assertTrue(report['phase']=='ddns-jobs' and report['effect']=='none' and report['write_ready'] is False)
        return report['jobs']

    def settled(self,session,job='a'*32):
        end=time.monotonic()+10
        while time.monotonic()<end:
            rows=self.jobs(session)
            row=next((j for j in rows if j['job']==job),None)
            if row and not row['pending']:
                return row
            time.sleep(0.05)
        raise AssertionError('Private worker did not settle within bound; state suppressed')

    @contextmanager
    def hold(self):
        (STATE/'launch-entered').unlink(missing_ok=True)
        (STATE/'launch-mode').write_text('hold')
        self.held=True
        try:
            yield
        finally:
            self.release()
            (STATE/'launch-mode').write_text('fail')

    def accepted_held(self,session):
        row=self.submit(session)
        self.assertTrue(row['pending'] and row['state']=='pending' and row['last_effect']=='unknown' and row['result'] is False)
        self.wait_for(lambda:(STATE/'launch-entered').exists())
        self.held=True
        self.assertFalse((JOBS/('a'*32)/'start').exists())
        return row

    def changed_result(self,session):
        original=(STORE/'ddns-authority').read_bytes()
        try:
            with self.hold():
                self.accepted_held(session)
                # Controlled source drift, not a fabricated worker response.
                (STORE/'ddns-authority').write_bytes(original+b'\n')
                self.release(run=True)
                row=self.settled(session)
        finally:
            (STORE/'ddns-authority').write_bytes(original)
        self.assertTrue(row['state']=='finished' and row['reason']=='changed' and row['last_effect']=='none')
        self.assertEqual(row['result'],{'rule':'ddns_0','provider':'aliyun','status':'blocked','effect':'none',
                                        'error_kind':'temporary','retryable':False,'retry_in':0})
        self.assertTrue((JOBS/('a'*32)/'start').is_file())
        self.assertFalse((JOBS/('a'*32)/'raw').exists())
        return row

    def test_job_01_pending_duplicate_and_busy_business_observation(self):
        with self.session() as session:
            self.authorize(session);before_events=self.events()
            with self.hold():
                self.accepted_held(session)
                before=self.snapshot()
                self.assertTrue(self.submit(session)['pending'])
                self.assertTrue(self.jobs(session)[0]['pending'])
                self.submit(session,job='b'*32,expected=503)
                self.submit(session,rule='ddns_1',expected=503)
                self.read('status',session[0],expected=503)
                self.assertTrue(before==self.snapshot(),'Pending observation/replay changed records; bytes suppressed')
                self.assertEqual(self.events(),before_events+b'job-launch\n')
            row=self.settled(session)
            self.assertTrue(row['state']=='interrupted' and row['last_effect']=='unknown' and row['result'] is False)

    def test_job_02_failed_spawn_retains_unknown_and_never_relaunches(self):
        with self.session() as session:
            self.authorize(session);self.submit(session);row=self.settled(session)
            self.assertTrue(row['state']=='interrupted' and row['reason']=='interrupted' and row['last_effect']=='unknown')
            before=self.snapshot();events=self.events()
            self.assertEqual(self.submit(session),row)
            self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'Interrupted evidence changed; bytes suppressed')
            self.assertEqual(self.events(),events)

    def test_job_03_real_worker_publishes_known_no_dispatch_after_source_change(self):
        with self.session() as session:
            self.authorize(session);row=self.changed_result(session)
            before=self.snapshot();events=self.events()
            self.assertEqual(self.submit(session),row)
            self.assertEqual(self.jobs(session),[row])
            self.assertTrue(before==self.snapshot(),'Completed evidence changed; bytes suppressed')
            self.assertEqual(self.events(),events)
            self.assertFalse((RUN/'ddns-state').exists())

    def test_job_04_post_csrf_exact_consent_and_input_guards(self):
        with self.session() as session,self.session() as other:
            sid,token=session;before=self.snapshot()
            calls=(STATE/'entry-calls').read_bytes() if (STATE/'entry-calls').exists() else b''
            status,_,_=self.cgi(luci.BASE+'/ddns_native/submit',cookie=sid)
            self.assertEqual(status,405)
            for fields in ({},{'token':'wrong-fixture'},{'token':other[1]},{'token':[token,'wrong-fixture']}):
                status,_,_=self.cgi(luci.BASE+'/ddns_native/submit',cookie=sid,verb='POST',fields=fields)
                self.assertEqual(status,403)
            for fields in ({'job':'a'*32,'rule':'ddns_0'},
                           {'job':'a'*32,'rule':'ddns_0','consent':'0'},
                           {'job':'../bad','rule':'ddns_0','consent':'1'},
                           {'job':'a'*32,'rule':'ddns_0;bad','consent':'1'},
                           {'job':'a'*32,'rule':'ddns_0','consent':'1','command':'sync'}):
                self.request_job('submit',session,expected=503,**fields)
            after=(STATE/'entry-calls').read_bytes() if (STATE/'entry-calls').exists() else b''
            self.assertEqual(calls,after);self.assertFalse(JOBS.exists())
            self.assertTrue(before==self.snapshot(),'Rejected request changed private state; bytes suppressed')

    def test_job_05_corrupt_or_linked_real_result_is_preserved(self):
        with self.session() as session:
            self.authorize(session);self.changed_result(session)
            path=JOBS/('a'*32)/'result';original=path.read_bytes()
            try:
                path.write_bytes(original+b'x');before=self.snapshot()
                self.request_job('jobs',session,expected=503)
                self.assertTrue(before==self.snapshot(),'Corrupt result was changed; bytes suppressed')
            finally:
                path.write_bytes(original)
            outside=RUN/'saved-job-result';path.rename(outside);path.symlink_to(outside)
            try:
                before=self.snapshot();self.request_job('jobs',session,expected=503)
                self.assertTrue(before==self.snapshot(),'Linked result was changed; bytes suppressed')
                self.assertTrue(outside.read_bytes()==original,'Link target changed; bytes suppressed')
            finally:
                path.unlink();outside.rename(path)

    def test_job_06_closed_job_gate_preserves_retained_evidence(self):
        with self.session() as session:
            self.authorize(session);self.submit(session);row=self.settled(session)
            path=read.GUEST_PROTO/'homegate-ddns-job.sh';original=path.read_bytes()
            self.assertEqual(original.count(b'ddns_ui_jobs_enabled=true'),1)
            try:
                path.write_bytes(original.replace(b'ddns_ui_jobs_enabled=true',b'ddns_ui_jobs_enabled=false'))
                before=self.snapshot();self.submit(session,expected=503)
                self.request_job('jobs',session,expected=503)
                self.assertTrue(before==self.snapshot(),'Closed gate changed job evidence; bytes suppressed')
            finally:
                path.write_bytes(original)
            self.assertEqual(self.jobs(session),[row])

    def test_job_07_catalog_busy_and_read_refresh_do_not_allocate_or_retry(self):
        with self.session() as session:
            before=self.snapshot();self.assertEqual(self.jobs(session),[])
            self.assertTrue(before==self.snapshot(),'Empty job read allocated state; bytes suppressed')
            self.authorize(session);self.submit(session);self.settled(session)
            before=self.snapshot();events=self.events()
            with (RUN/'ddns-ui-jobs.lock').open('rb') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.request_job('jobs',session,expected=503)
                self.submit(session,expected=503)
            self.assertEqual(self.events(),events)
            self.assertTrue(before==self.snapshot(),'Busy catalog changed records; bytes suppressed')


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
        names=[n for n in sorted(Jobs.__dict__) if n.startswith('test_job_') and n.split('_')[2] in GROUPS[args.group]]
        if len(names)!=len(GROUPS[args.group]):raise ValueError('Incomplete task group')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Jobs(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER] if p.is_file()}
    if (read.PROTO/'homegate-ddns-job.sh').read_bytes().count(b'ddns_ui_jobs_enabled=false')!=1:
        raise ValueError('Original task gate must remain closed')
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
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original project changed during job checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
