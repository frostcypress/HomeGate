#!/usr/bin/env python3
"""Candidate CLI and admission exclusion against existing real TLS fixtures."""
import argparse,json,os,re,subprocess,time,unittest
from pathlib import Path
from project import ROOT
from 核心目录CLI回归 import Static as CatalogStatic, Runtime as CatalogRuntime
from 核心账户CLI回归 import suite as status_suite
from 核心区域CLI回归 import suite as zones_suite
from 核心网络CLI回归 import suite as network_suite
from 核心配置校验回归 import suite as configuration_suite
from 核心健康CLI回归 import suite as health_suite
from 核心恢复CLI回归 import suite as recovery_suite
from DDNS恢复生产回归 import suite as ddns_recovery_suite
from DDNS恢复收尾回归 import suite as ddns_repair_suite
from DDNS有界调度回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase
from DDNS计划回归 import fixture_uid
from 生命周期准备回归 import Runtime as PrepareBase
PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_changed_shell_and_lua_grammar(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh','homegate-ddns-schedule.sh','homegate-lifecycle-prepare.sh']:
            b=(PROTO/name).read_bytes();self.assertNotIn(b'\r',b);self.assertFalse(parser.parse(b).root_node.has_error,name)
        LuaRuntime().compile((PROTO/'homegate-ddns-cli.lua').read_bytes())
    def test_closed_gate_fixed_commands_and_no_production_replacement(self):
        b=(PROTO/'homegate-cli.sh').read_text();self.assertEqual(b.count('native_cli_enabled=false'),1)
        for text in ['eval ','kill ','curl ','daemon)','--confirm-closeouts']:self.assertNotIn(text,b)
        self.assertIn('exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-',b)
        self.assertIn('[ "$(id -u)" = 0 ]',b);self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_lifecycle_holds_admission_lock_before_business_and_bootstrap(self):
        b=(PROTO/'homegate-lifecycle-prepare.sh').read_text()
        self.assertLess(b.index('schedule_file ||'),b.index('exec 9>>'))
        self.assertLess(b.index('flock -n 9'),b.index('exec 6>>'))
        self.assertLess(b.index('Schedule control requires explicit stop and reap'),b.index('ash "$dir/homegate-store'))
        self.assertIn('Schedule lock identity changed',b)
    def test_quiescence_is_gate_independent_and_has_no_cleanup(self):
        b=(PROTO/'homegate-ddns-schedule.sh').read_text();q=b.split('if [ "$action" = quiescent ]; then',1)[1].split('if [ "$action" = status ]',1)[0]
        for text in ['mkdir ','rm ','rmdir ','kill ','locks ||']:self.assertNotIn(text,q)
        self.assertIn('point_in_time":true',q);self.assertIn('writer-check',q)

class CLIMixin:
    def setUp(self):
        super().setUp();self.candidate=self.engine.parent/'homegate-cli.sh'
        b=self.candidate.read_text().replace('native_cli_enabled=false','native_cli_enabled=true')
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store)}
        b=re.sub('|'.join(re.escape(k) for k in mapping),lambda m:mapping[m[0]],b)
        self.candidate.write_text(fixture_uid(b.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
        self.prepare=self.engine.parent/'homegate-lifecycle-prepare.sh'
        var=self.base/'cli-var';var.mkdir(mode=0o700);alias=var/'run';alias.symlink_to(self.native.lockdir.parent,target_is_directory=True)
        tmp=self.base/'cli-tmp';tmp.mkdir(mode=0o700)
        b=self.prepare.read_text().replace('runtime_prepare_enabled=false','runtime_prepare_enabled=true')
        for key,value in [('var_root=/var',var),('tmp_root=/tmp',tmp),('run_alias=/var/run',alias),('linux_run=/run',self.native.lockdir.parent)]:b=b.replace(key,key.split('=',1)[0]+'='+str(value))
        b=b.replace('runtime="$runtime_base/homegate"','runtime='+str(self.native.lockdir))
        self.prepare.write_text(fixture_uid(b.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
    def candidate_call(self,*args,expected=0,read_only=True,env=None):
        n=len(self.calls);p=subprocess.run([self.busybox,'ash',str(self.candidate),*args],env=env or self.env,capture_output=True,timeout=45)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertLess(len(p.stdout),65536)
        if read_only:self.assertEqual(len(self.calls),n)
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'pppoe-wan',os.fsencode(self.store),os.fsencode(self.base)]:self.assertNotIn(marker,p.stdout)
        self.assertEqual(self.config_bytes(),self.baseline_config);return json.loads(p.stdout)
    def test_cli_full_status_and_batch_noop_share_one_sample(self):
        self.seed();out=self.candidate_call('ddns-status');self.assertEqual([r['rule'] for r in out['rules']],['ddns_a','ddns_b','ddns_c']);self.assertFalse(self.state_dir.exists());self.assertFalse(self.netlog.exists())
        out=self.candidate_call('ddns-sync',read_only=False);self.assertEqual([r['status'] for r in out['rules']],['unchanged','unchanged']);self.assertEqual(self.mutations(),[])
        out=self.candidate_call('ddns-status','ddns_b');self.assertEqual([r['status'] for r in out['rules']],['waiting']);self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes'])
    def test_cli_selected_sync_preserves_original_receipt_and_other_rule(self):
        out=self.candidate_call('ddns-sync','ddns_b',read_only=False);self.assertEqual((out['rule'],out['effect']),('ddns_b','confirmed'));self.assertEqual(len(self.mutations()),1)
        before=self.files(self.journal);out=self.candidate_call('ddns-status');self.assertEqual([r['status'] for r in out['rules']],['blocked','blocked','blocked'])
        self.candidate_call('ddns-sync',expected=4);self.assertEqual(self.files(self.journal),before);self.assertFalse((self.store/'dns-batch-results').exists())

class CF(CLIMixin,CFBase):pass
class Ali(CLIMixin,AliBase):pass
class DNP(CLIMixin,DNPBase):pass
class HW(CLIMixin,HWBase):pass

class Boundaries(CF):
    def test_stop_gate_closed_quiesce_then_explicit_reap_and_prepare(self):
        self.seed();p=self.start();self.wait_for(p);self.candidate_call('schedule-quiescent',expected=4);self.candidate_call('lifecycle-prepare',expected=4)
        self.candidate.write_text(self.candidate.read_text().replace('native_cli_enabled=true','native_cli_enabled=false'))
        self.schedule.write_text(self.schedule.read_text().replace('ddns_schedule_enabled=true','ddns_schedule_enabled=false'))
        self.candidate_call('schedule-stop','--confirm');self.finish(p);before=self.files(self.schedule_dir)
        self.assertTrue(self.candidate_call('schedule-quiescent')['quiescent']);self.assertEqual(self.files(self.schedule_dir),before)
        self.candidate.write_text(self.candidate.read_text().replace('native_cli_enabled=false','native_cli_enabled=true'))
        self.candidate_call('lifecycle-prepare',expected=4);self.candidate_call('schedule-reap','--confirm');self.candidate_call('lifecycle-prepare')
    def test_admitted_batch_stop_is_not_quiescent(self):
        self.seed();entered,release=self.gated_http();p=self.start();self.assertTrue(entered.wait(30));self.candidate_call('schedule-stop','--confirm');self.candidate_call('schedule-quiescent',expected=4);self.candidate_call('lifecycle-prepare',expected=4)
        self.assertIsNone(p.poll());release.set();self.finish(p);self.assertTrue(self.candidate_call('schedule-quiescent')['point_in_time'])
    def test_confirmed_receipt_stays_barrier_after_owner_finishes(self):
        self.finish(self.start(),4);before=self.files(self.journal);self.candidate_call('schedule-quiescent',expected=4);self.candidate_call('lifecycle-prepare',expected=4);self.assertEqual(self.files(self.journal),before)
    def test_unknown_control_is_not_quiescent_or_prepared(self):
        self.seed();p=self.start();self.wait_for(p);self.control_call('stop');self.finish(p)
        extra=self.schedule_dir/'unknown';extra.write_bytes(b'KEEP');extra.chmod(0o600);self.candidate_call('schedule-quiescent',expected=7);self.candidate_call('lifecycle-resume',expected=4);self.assertEqual(extra.read_bytes(),b'KEEP')
    def test_no_session_quiescent_is_read_only_and_common_locks_block(self):
        import fcntl
        before=self.files(self.native.lockdir);self.assertTrue(self.candidate_call('schedule-quiescent')['quiescent']);self.assertEqual(self.files(self.native.lockdir),before)
        for path in [self.native.lock,self.store/'.supervisor.lock']:
            with path.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.candidate_call('schedule-quiescent',expected=4)
        work=self.native.lockdir/'.ddns-plan-999999999';work.mkdir(mode=0o700);self.candidate_call('schedule-quiescent',expected=4);self.candidate_call('lifecycle-prepare',expected=4);self.assertTrue(work.exists())
    def test_revoked_grant_still_allows_read_only_status(self):
        self.revoke_fixture();out=self.candidate_call('ddns-status');self.assertEqual([r['status'] for r in out['rules']],['unauthorized','unauthorized','unauthorized']);self.candidate_call('ddns-sync',expected=7);self.assertEqual(self.calls,[])
    def test_cli_input_gate_environment_and_corrupt_cache_never_publish_partial(self):
        for args in [(),('daemon',),('ddns-status',''),('ddns-status','../bad'),('schedule-stop',),('schedule-run','--confirm','extra')]:self.candidate_call(*args,expected=2)
        # Existing rule identifiers permit hyphens, including this spelling.
        # It is an absent rule (7), never forwarded as closeout permission.
        self.candidate_call('ddns-sync','--confirm-closeouts',expected=7);self.assertFalse((self.store/'dns-batch-results').exists())
        self.candidate.write_text(self.candidate.read_text().replace('native_cli_enabled=true','native_cli_enabled=false'));self.candidate_call('ddns-sync',expected=2,env={**self.env,'native_cli_enabled':'true'});self.candidate.write_text(self.candidate.read_text().replace('native_cli_enabled=false','native_cli_enabled=true'))
        self.candidate_call('ddns-status','missing',expected=7);self.state_dir.mkdir(mode=0o700);bad=self.state_dir/'ddns_b';bad.write_bytes(b'SECRET_SENTINEL');bad.chmod(0o600);out=self.candidate_call('ddns-status',expected=7);self.assertNotIn('rules',out)
    def test_lifecycle_held_admission_lock_refuses_without_changing_store(self):
        import fcntl
        self.candidate_call('lifecycle-prepare');lock=self.native.lockdir/'ddns-schedule.lock';inode=lock.stat().st_ino
        with lock.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.candidate_call('lifecycle-prepare',expected=4);self.candidate_call('schedule-run','--confirm',expected=4)
        self.assertEqual(lock.stat().st_ino,inode)
    def test_cli_schedule_run_exec_owner_is_recognized(self):
        self.seed();p=subprocess.Popen([self.busybox,'ash',str(self.candidate),'schedule-run','--confirm'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.jobs.append(p);self.wait_for(p)
        self.assertTrue(self.candidate_call('schedule-status')['running']);self.candidate_call('schedule-stop','--confirm');self.finish(p)
    def test_quiescent_replaced_admission_lock_is_not_readiness(self):
        self.candidate_call('lifecycle-prepare');lock=self.native.lockdir/'ddns-schedule.lock'
        self.fault('flock',"if sys.argv[1:]==['-n','9']:\n from pathlib import Path\n p=Path("+repr(str(lock))+");p.unlink();p.touch(mode=0o600)")
        self.candidate_call('schedule-quiescent',expected=4);self.assertFalse(self.schedule_dir.exists())
    def test_status_replaced_business_lock_refuses_before_reading_rows(self):
        self.fault('flock',"if sys.argv[1:]==['-n','6']:\n from pathlib import Path\n p=Path("+repr(str(self.native.lock))+");p.unlink();p.touch(mode=0o600)")
        out=self.candidate_call('ddns-status',expected=4);self.assertNotIn('rules',out);self.assertFalse(self.netlog.exists())

class Cold(PrepareBase):
    def test_unreaped_control_blocks_cold_prepare_without_deleting(self):
        self.native.lockdir.mkdir(mode=0o700);work=self.native.lockdir/'ddns-schedule';work.mkdir(mode=0o700);f=work/'lease.next';f.write_bytes(b'KEEP');f.chmod(0o600)
        self.run_prepare(expected=4);self.assertEqual(f.read_bytes(),b'KEEP');self.assertFalse(self.store.exists())
    def test_schedule_lock_symlink_hardlink_and_content_preserved(self):
        self.native.lockdir.mkdir(mode=0o700);lock=self.native.lockdir/'ddns-schedule.lock';outside=self.base/'foreign';outside.write_bytes(b'KEEP');outside.chmod(0o600)
        lock.symlink_to(outside);self.run_prepare(expected=7);self.assertEqual(outside.read_bytes(),b'KEEP');lock.unlink()
        os.link(outside,lock);self.run_prepare(expected=7);lock.unlink();lock.write_bytes(b'KEEP');lock.chmod(0o600);self.run_prepare(expected=7);self.assertEqual(lock.read_bytes(),b'KEEP')
    def test_schedule_lock_replacement_at_flock_refuses(self):
        lock=self.native.lockdir/'ddns-schedule.lock';self.fault('flock',"if sys.argv[1:]==['-n','9']:\n from pathlib import Path\n p=Path("+repr(str(lock))+");p.unlink();p.touch(mode=0o600)")
        self.run_prepare(expected=7);self.assertFalse(self.store.exists())
    def test_prepare_keeps_admission_lock_through_bootstrap(self):
        script=self.engine.parent/'homegate-store-bootstrap-prototype.sh';b=script.read_text();script.write_text(b.replace('set -u','set -u\nflock -n '+str(self.native.lockdir/'ddns-schedule.lock')+' '+self.busybox+' true && exit 99',1))
        self.run_prepare();self.assertTrue(self.store.exists())

PARTITIONS=('lifecycle','dns','network-config','health-recovery','ddns-recovery')


def build_suite(runtime,partition=None):
    if partition is not None and (not runtime or partition not in PARTITIONS):
        raise ValueError('Runtime partition required')
    suite=unittest.TestSuite()
    def selected(name):return partition is None or partition==name
    if selected('lifecycle'):
        for cls in ([CF,Ali,DNP,HW,Boundaries,Cold,CatalogRuntime] if runtime else [Static,CatalogStatic]):
            members=CLIMixin.__dict__ if cls in [CF,Ali,DNP,HW] else cls.__dict__
            suite.addTests(cls(n) for n,v in members.items() if n.startswith('test_') and callable(v))
    for name,builders in [
        ('dns',[status_suite,zones_suite]),
        ('network-config',[network_suite,configuration_suite]),
        ('health-recovery',[health_suite,recovery_suite]),
        ('ddns-recovery',[ddns_recovery_suite,ddns_repair_suite]),
    ]:
        if selected(name):
            for builder in builders:suite.addTests(builder(runtime))
    return suite


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true')
    p.add_argument('--partition',choices=PARTITIONS);p.add_argument('--list-tests',action='store_true');a=p.parse_args()
    if a.partition and not a.runtime:p.error('Partition selection requires --runtime')
    suite=build_suite(a.runtime,a.partition)
    if a.list_tests:
        print(json.dumps([test.id() for test in suite]));raise SystemExit(0)
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
