#!/usr/bin/env python3
"""Real confirmed provider jobs -> fresh Lua consent -> original receipt archive."""
import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from project import ROOT

spec=importlib.util.spec_from_file_location('confirmed_archive_provider',ROOT/'scripts/luci-ddns-provider-jobs-regressions.py')
provider=importlib.util.module_from_spec(spec);spec.loader.exec_module(provider)
read,luci,rpc=provider.read,provider.luci,provider.rpc
STORE,RUN,STATE=provider.STORE,provider.RUN,provider.STATE
CASES=('01','02','03','04','05','06')


def setup_state(state):
    provider.setup_state(state)
    enable_archive(state)


def enable_archive(state,provider_name='cloudflare'):
    if provider_name not in ('cloudflare','aliyun','dnspod','huaweicloud'):raise ValueError('Unsupported archive fixture provider')
    reconcile=('dns_reconcile_enabled',) if provider_name=='cloudflare' else ('dns_reconcile_enabled',provider_name+'_reconcile_enabled')
    flags={'homegate-ddns-job.sh':('ddns_ui_maintenance_enabled',),
           'homegate-cloudflare-read.sh':('ddns_closeout_enabled',*reconcile),
           'homegate-dns-recovery.sh':('ddns_closeout_enabled',)}
    for name,names in flags.items():
        path=state/'project/core/prototype'/name;body=path.read_bytes()
        for flag in names:
            original=(flag+'=false').encode()
            if body.count(original)!=1:raise ValueError('Expected one closed archive gate')
            body=body.replace(original,(flag+'=true').encode())
        path.write_bytes(body)
    (state/'publication-mode').write_text('pass')
    sync=state/'tools/fsync';sync.unlink()
    sync.write_text(r'''#!/usr/bin/python3
import os,sys
from pathlib import Path
target='/var/run/homegate/ddns-ui-jobs/'+'a'*32+'/maintained.next'
if Path('/teststate/publication-mode').read_text()=='fail' and target in sys.argv[1:]:sys.exit(1)
os.execv('/usr/sbin/busybox',['busybox','fsync',*sys.argv[1:]])
''')
    sync.chmod(0o755)


class Archive(provider.ProviderJobs):
    ARCHIVE_RULE='ddns_1'

    def confirmed(self,session):
        row=self.run_job(session);self.assert_origin(row,'created')
        return provider.jobs.JOBS/('a'*32),row

    def maintain(self,action,session,*,expected=200,**fields):
        sid,token=session
        status,_,body=self.cgi(luci.BASE+'/ddns_native/'+action,cookie=sid,verb='POST',fields={'token':token,**fields})
        self.assertEqual(status,expected,'Archive HTTP status changed; body suppressed')
        for value in (b'SECRET_SENTINEL',b'PRIVATE_ACCOUNT',b'FIXTURE_ID',b'example.test',
                      b'2001:db8',b'/teststate',b'credentials',sid.encode(),token.encode()):
            self.assertTrue(value not in body,'Private value escaped; body suppressed')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')),[])
        if expected!=200:
            self.gate_response(action,status,body)
            return None
        result=json.loads(body)
        self.assertEqual(set(result),{'api_version','prototype','ok','phase','operation','effect','write_ready','report'})
        self.assertTrue(result['api_version']==1 and result['prototype'] is True and result['ok'] is True and
                        result['phase']=='ddns-ui' and result['operation']==action and result['effect']=='none' and
                        result['write_ready'] is False,'Invalid archive envelope; body suppressed')
        report=result['report'];keys={'api_version','prototype','ok','phase','job','rule','operation','effect','write_ready'}
        keys |= {'confirmation','expires_in'} if action=='maintain_preview' else {'completed'}
        self.assertEqual(set(report),keys)
        self.assertTrue(report['api_version']==1 and report['prototype'] is True and report['ok'] is True and
                        report['phase']=='ddns-maintenance' and report['job']==fields['job'] and report['rule']==self.ARCHIVE_RULE and
                        report['operation']=='archive' and report['effect']=='none' and report['write_ready'] is False,
                        'Unexpected archive source scope; body suppressed')
        if action=='maintain_preview':
            self.assertTrue(len(report['confirmation'])==32 and report['expires_in']==300,'Invalid archive confirmation')
        else:self.assertTrue(report['completed'] is True)
        return report

    def preview(self,session,**kwargs):return self.maintain('maintain_preview',session,job='a'*32,**kwargs)
    def commit(self,session,nonce,**kwargs):return self.maintain('maintain_commit',session,job='a'*32,confirmation=nonce,consent='1',**kwargs)

    def refused(self,action,session,**fields):
        before=self.snapshot();self.maintain(action,session,expected=503,**fields)
        self.assertTrue(before==self.snapshot(),'Rejected archive changed original evidence; private bytes suppressed')

    @staticmethod
    def tree(path):
        return {p.relative_to(path).as_posix():p.read_bytes() for p in path.rglob('*') if p.is_file()}

    def archived(self,session,path,row,original):
        self.assertFalse((STORE/'dns-operation').exists())
        archive=STORE/'dns-settled';self.assertTrue(archive.is_dir())
        contents=self.tree(archive)
        self.assertTrue(all(contents.get(n)==b for n,b in original.items()),'Archive did not retain the original receipt; bytes suppressed')
        self.assertTrue((path/'meta').is_file() and (path/'result').is_file() and (path/'proof').is_file() and (path/'raw').is_file())
        current=self.jobs(session)[0]
        self.assertTrue(current['reason']=='archived' and current['last_effect']=='confirmed' and current['result']==row['result'])
        return current

    def test_archive_01_explicit_archive_retains_original_receipt_and_task(self):
        with self.session() as session:
            path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation');requests=list(self.requests)
            before=self.snapshot();preview=self.preview(session);after=self.snapshot()
            self.assertTrue(all(after.get(n)==v for n,v in before.items()),'Preview changed original receipt or task')
            retained={n:(path/n).read_bytes() for n in ('meta','result','proof','raw','lock')}
            self.commit(session,preview['confirmation']);current=self.archived(session,path,row,original)
            self.assertTrue(all((path/n).read_bytes()==v for n,v in retained.items()),'Archive changed retained task files')
            before=self.snapshot();self.assertEqual(self.submit(session),current)
            self.refused('maintain_commit',session,job='a'*32,confirmation=preview['confirmation'],consent='1')
            self.assertTrue(before==self.snapshot(),'Archived task was replayed')
            self.assertEqual(self.requests,requests)

    def test_archive_02_nonce_and_original_source_binding(self):
        with self.session() as session:
            path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation')
            first=self.preview(session);second=self.preview(session)
            self.assertTrue(first['confirmation']!=second['confirmation'],'Archive confirmation was reused')
            self.refused('maintain_commit',session,job='a'*32,confirmation=first['confirmation'],consent='1')
            self.refused('maintain_commit',session,job='a'*32,confirmation=second['confirmation'],consent='0')
            self.refused('maintain_commit',session,job='a'*32,confirmation=second['confirmation'])
            journal=STORE/'dns-operation';slot=(journal/'current').read_text().strip()
            for file in (path/'proof',path/'raw',journal/'terminal',journal/('slot-'+slot)/'manifest'):
                saved=file.read_bytes()
                try:
                    file.write_bytes(saved+b'changed-fixture')
                    self.refused('maintain_commit',session,job='a'*32,confirmation=second['confirmation'],consent='1')
                finally:file.write_bytes(saved)
            self.commit(session,second['confirmation']);self.archived(session,path,row,original)

    def test_archive_03_all_locks_and_closed_maintenance_gate_preserve_source(self):
        with self.session() as session:
            path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation');preview=self.preview(session)
            for file in (RUN/'frontend.lock',STORE/'.supervisor.lock',RUN/'ddns-ui-jobs.lock',path/'lock'):
                with file.open('rb') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.refused('maintain_commit',session,job='a'*32,confirmation=preview['confirmation'],consent='1')
            helper=read.GUEST_PROTO/'homegate-ddns-job.sh';saved=helper.read_bytes()
            try:
                self.assertEqual(saved.count(b'ddns_ui_maintenance_enabled=true'),1)
                helper.write_bytes(saved.replace(b'ddns_ui_maintenance_enabled=true',b'ddns_ui_maintenance_enabled=false'))
                self.refused('maintain_commit',session,job='a'*32,confirmation=preview['confirmation'],consent='1')
            finally:helper.write_bytes(saved)
            self.commit(session,preview['confirmation']);self.archived(session,path,row,original)

    def test_archive_04_collector_refusal_consumes_old_consent_but_keeps_receipt(self):
        with self.session() as session:
            path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation');preview=self.preview(session)
            helper=read.GUEST_PROTO/'homegate-cloudflare-read.sh';saved=helper.read_bytes();requests=list(self.requests)
            try:
                self.assertEqual(saved.count(b'ddns_closeout_enabled=true'),1)
                helper.write_bytes(saved.replace(b'ddns_closeout_enabled=true',b'ddns_closeout_enabled=false'))
                self.commit(session,preview['confirmation'],expected=503)
            finally:helper.write_bytes(saved)
            self.assertTrue(self.tree(STORE/'dns-operation')==original,'Failed collector changed original receipt')
            self.assertFalse((STORE/'dns-settled').exists());self.assertFalse((path/'maintained').exists())
            self.assertTrue((path/'maintenance-used').is_file() and not (path/'maintenance').exists())
            self.refused('maintain_commit',session,job='a'*32,confirmation=preview['confirmation'],consent='1')
            fresh=self.preview(session);self.assertTrue(fresh['confirmation']!=preview['confirmation'])
            self.commit(session,fresh['confirmation']);self.archived(session,path,row,original)
            self.assertEqual(self.requests,requests)

    def test_archive_05_archive_before_final_marker_requires_fresh_consent(self):
        with self.session() as session:
            path,row=self.confirmed(session);original=self.tree(STORE/'dns-operation');preview=self.preview(session);requests=list(self.requests)
            try:
                (STATE/'publication-mode').write_text('fail')
                self.commit(session,preview['confirmation'],expected=503)
            finally:(STATE/'publication-mode').write_text('pass')
            self.assertFalse((STORE/'dns-operation').exists());self.assertTrue((STORE/'dns-settled').is_dir())
            self.assertFalse((path/'maintained').exists());self.assertTrue((path/'maintained.next').is_file())
            self.assertTrue(self.jobs(session)[0]['reason']!='archived','Unpublished marker claimed completion')
            archived_before=self.tree(STORE/'dns-settled')
            self.refused('maintain_commit',session,job='a'*32,confirmation=preview['confirmation'],consent='1')
            fresh=self.preview(session);self.assertTrue(fresh['confirmation']!=preview['confirmation'])
            self.commit(session,fresh['confirmation']);self.archived(session,path,row,original)
            self.assertTrue(self.tree(STORE/'dns-settled')==archived_before,'Recovery rewrote original archive')
            self.assertEqual(self.requests,requests)

    def test_archive_06_unknown_attempt_cannot_be_collected(self):
        type(self).fail_after_mutation=True
        with self.session() as session:
            row=self.run_job(session);self.assertTrue(row['last_effect']=='unknown')
            requests=list(self.requests);before=self.snapshot()
            self.refused('maintain_preview',session,job='a'*32)
            self.refused('maintain_commit',session,job='a'*32,confirmation='b'*32,consent='1')
            self.assertTrue(before==self.snapshot(),'Unknown attempt evidence changed')
            self.assertTrue((STORE/'dns-operation').is_dir());self.assertFalse((STORE/'dns-settled').exists())
            self.assertEqual(self.requests,requests)


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
        names=[n for n in sorted(Archive.__dict__) if n.startswith('test_archive_') and n.split('_')[2]==args.case]
        if len(names)!=1:raise ValueError('Expected one original-receipt archive scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Archive(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    curl=subprocess.run([str(provider.CURL),'--version'],capture_output=True,check=True)
    if not curl.stdout.startswith(b'curl 7.83.1 '):raise ValueError('Use pinned curl7.83.1')
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER] if p.is_file()}
    result=0
    for case in ((args.case,) if args.case else CASES):
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
            extra_mounts=lambda state:((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),(state/'libexec','/usr/libexec'),
                (state/'tools','/usr/sbin'),(state/'curl-transport','/usr/bin/curl')),
            extra_rw_mounts=lambda state:((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
            state_setup=setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--case',case))
        if result:break
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original source changed during archive checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
