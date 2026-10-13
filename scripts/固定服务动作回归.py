#!/usr/bin/env python3
"""Fixed init actions in copied persistent namespaces; no target service changes."""
import argparse, json, os, re, shutil, signal, subprocess, sys, time, unittest
from pathlib import Path
from project import ROOT
from 持久初始化回归 import Runtime as BootstrapRuntime
from 服务采样回归 import Runtime as ObserverRuntime

PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_shell_grammar_and_closed_gates(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-config-prototype.sh','homegate-service-observer-watchdog.sh']:
            body=(PROTO/name).read_bytes(); self.assertNotIn(b'\r',body)
            self.assertFalse(parser.parse(body).root_node.has_error,name)
            self.assertEqual(body.count(b'service_actions_enabled=false'),1)
            self.assertNotIn(b'service_actions_enabled=true',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_fixed_actions_and_lock_inheritance(self):
        s=(PROTO/'homegate-service-observer-watchdog.sh').read_text()
        for action in ['start','stop']: self.assertIn('/etc/init.d/homegate '+action+' 3>&- 6>&- 7>&-',s)
        self.assertIn('/sbin/uci -q show homegate',s)
        self.assertIn('flock -n "$fd"',s); self.assertIn('deadline=$((now + 5))',s)
        self.assertNotRegex(s,r'/etc/init.d/homegate (enable|disable|restart|reload)\b')
        self.assertNotIn('eval ',s)

    def test_observation_precedes_terminal_record(self):
        s=(PROTO/'homegate-config-prototype.sh').read_text().split('service_transition() {',1)[1].split('command=${1:-}',1)[0]
        self.assertLess(s.index('projection_observe_finish'),s.index('journal_write applied'))
        self.assertLess(s.index('journal_write applied'),s.index('journal_close'))
        self.assertIn('"business_applied":false',s)

class Runtime(BootstrapRuntime):
    @classmethod
    def setUpClass(cls):
        BootstrapRuntime.setUpClass.__func__(cls)
        ObserverRuntime.setUpClass.__func__(cls)

    def setUp(self):
        super().setUp(); self.boot(); self.commit_body(self.business)
        self.config=self.etc/'config'; self.config.mkdir(mode=0o700)
        self.source=self.config/'homegate'; self.original=b'\n'.join(line for line in self.business.split(b'\n') if not line.startswith(b'#')).replace(b"option enabled '0'",b"option enabled '1'",1)
        self.source.write_bytes(self.original); self.source.chmod(0o600)
        self.actions=self.base/'actions'; self.actions.touch(mode=0o600)
        self.flags=self.base/'flags.json'; self.flags.write_text('{}'); self.flags.chmod(0o600)
        self.pidfile=self.base/'daemon.pid'; self.enabled=self.base/'enabled'; self.enabled.write_text('1')
        self.marker=self.base/'package-state'
        self.init=self.base/'init'; self.common=self.base/'rc.common'; self.ubus=self.base/'ubus'; self.uci=self.base/'uci'
        self.executable=self.base/'homegate'; shutil.copy2(self.daemon,self.executable); self.executable.chmod(0o700)
        self.common.write_text('#!/bin/sh\nexit 0\n'); self.common.chmod(0o700)
        initcode="""import json,os,signal,subprocess,sys,time
from pathlib import Path
base=Path(BASE); flags=json.loads((base/'flags.json').read_text()); action=sys.argv[1]
assert len(sys.argv)==2 and action in ['enabled','start','stop']
if action=='enabled': sys.exit(0 if (base/'enabled').read_text()=='1' else 1)
with (base/'actions').open('a') as f: f.write(json.dumps({'action':action,'group':os.getpgrp(),'env':{k:os.environ.get(k) for k in ['HOMEGATE_PACKAGE_UPGRADE_STATE','PROCD_DEBUG','INIT_TRACE']}})+'\\n')
if flags.get(action+'_hang'):
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 while True: time.sleep(0.1)
if action=='stop' and not flags.get('stop_noop') and (base/'daemon.pid').exists():
 pid=int((base/'daemon.pid').read_text())
 try: os.kill(pid,signal.SIGTERM)
 except ProcessLookupError: pass
 for i in range(200):
  try: dead=(Path('/proc')/str(pid)/'stat').read_text().split(') ')[1][0] in ['Z','X']
  except FileNotFoundError: dead=True
  if dead: break
  time.sleep(0.005)
 (base/'daemon.pid').unlink()
if action=='start' and not flags.get('start_noop') and "option enabled '1'" in (base/'etc/config/homegate').read_text():
 p=subprocess.Popen([str(base/'homegate'),'daemon'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
 (base/'daemon.pid').write_text(str(p.pid)); time.sleep(0.03)
sys.exit(flags.get(action+'_exit',0))
""".replace('BASE',repr(str(self.base)))
        self.init.write_text('#!'+sys.executable+'\n'+initcode); self.init.chmod(0o700)
        querycode="""import json,sys
from pathlib import Path
base=Path(BASE)
assert sys.argv[1:]==['-t','2','-S','call','service','list','{"name":"homegate","verbose":true}']
doc={}
if (base/'daemon.pid').exists():
 pid=int((base/'daemon.pid').read_text())
 try: running=(Path('/proc')/str(pid)/'stat').read_text().split(') ')[1][0] not in ['Z','X']
 except FileNotFoundError: running=False
 if running: doc={'homegate':{'instances':{'instance1':{'running':True,'pid':pid,'command':[str(base/'homegate'),'daemon']}}}}
sys.stdout.write(json.dumps(doc))
""".replace('BASE',repr(str(self.base)))
        self.ubus.write_text('#!'+sys.executable+'\n'+querycode); self.ubus.chmod(0o700)
        (self.base/'uci-save').mkdir(mode=0o700)
        ucicode="""import json,os,sys
from pathlib import Path
base=Path(BASE); assert sys.argv[1:]==['-q','show','homegate']
count=base/'prechecks'; n=int(count.read_text())+1 if count.exists() else 1; count.write_text(str(n))
flags=json.loads((base/'flags.json').read_text())
if flags.get('precheck_fail') or flags.get('precheck_fail_after',999)<n: sys.exit(1)
os.execv(UCI,[UCI,'-c',str(base/'etc/config'),'-P',str(base/'uci-save'),'-q','show','homegate'])
""".replace('BASE',repr(str(self.base))).replace('UCI',repr(str(ROOT/'build/uci-parser/uci')))
        self.uci.write_text('#!'+sys.executable+'\n'+ucicode); self.uci.chmod(0o700)
        mapping={'/etc/init.d/homegate':str(self.init),'/etc/rc.common':str(self.common),'/sbin/ubus':str(self.ubus),
                 '/sbin/uci':str(self.uci),'/usr/bin/homegate':str(self.executable),'/tmp/.homegate-package-upgrade-state':str(self.marker)}
        for name in ['homegate-config-prototype.sh','homegate-service-observer-watchdog.sh','homegate-service-observer.lua']:
            file=self.engine.parent/name; body=file.read_text()
            more={**mapping,str(self.etc/'init.d/homegate'):str(self.init),str(self.etc/'rc.common'):str(self.common)} if name=='homegate-config-prototype.sh' else {**mapping,'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
            body=re.sub('|'.join(re.escape(k) for k in sorted(more,key=len,reverse=True)),lambda m:more[m[0]],body)
            body=body.replace('service_actions_enabled=false','service_actions_enabled=true').replace('production_writes_enabled=false','production_writes_enabled=true')
            body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+str(os.getuid())+' ]').replace('= 0:600:1','= '+str(os.getuid())+':600:1')
            if name.endswith('.lua'): body=body.replace("local json= require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json= require('luci.jsonc')")
            file.write_text(body)
        self.processes=[]; self.created=[]
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))

    def tearDown(self):
        for p in self.processes:
            if p.poll() is None: p.kill()
            try:p.communicate(timeout=5)
            except subprocess.TimeoutExpired:pass
        if self.pidfile.exists(): self.created.append(int(self.pidfile.read_text()))
        for pid in set(self.created):
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
        # Groups came only from this fixture's fixed init action entries.
        for entry in self.log():
            try:os.killpg(entry['group'],signal.SIGKILL)
            except ProcessLookupError:pass
        super().tearDown()

    def log(self): return [json.loads(x) for x in self.actions.read_text().splitlines()]
    def flag(self,**kw): self.flags.write_text(json.dumps(kw))
    def running(self):
        if not self.pidfile.exists(): return False
        pid=int(self.pidfile.read_text())
        try:return Path('/proc/'+str(pid)+'/stat').read_text().split(') ')[1][0] not in ['Z','X']
        except FileNotFoundError:return False
    def start_daemon(self):
        p=subprocess.Popen([str(self.executable),'daemon']); self.processes.append(p); self.created.append(p.pid)
        self.pidfile.write_text(str(p.pid)); time.sleep(0.03); self.assertTrue(self.running())
    def begin(self,boot=1,running=0):
        self.enabled.write_text(str(boot))
        if running:self.start_daemon()
        result=self.cli('commit-apply-projection',self.plan['confirmation']); self.handle=result['apply_handle']; self.target=result['revision']; return result
    def apply(self,expected=0):return self.cli('service-apply',self.handle,expected=expected)
    def recover(self,expected=0):return self.cli('service-recover',expected=expected)
    def pending(self):
        self.assertTrue(self.cli('status')['application_pending']); self.writer(7)
    def closed(self,revision):
        s=self.cli('status');self.assertEqual(s['revision'],revision);self.assertFalse(s['application_pending']);self.assertFalse(s['persistent_fence_pending']);self.writer()

    def test_apply_stops_each_running_state_and_preserves_boot_intent(self):
        for boot,running in [(0,0),(0,1),(1,0),(1,1)]:
            self.begin(boot,running); report=self.apply();self.assertFalse(report['business_applied']);self.closed(self.target)
            self.assertFalse(self.running());self.assertEqual(self.enabled.read_text(),str(boot))
            self.assertEqual(self.source.read_bytes(),(self.store/f'gen-{self.target}/public.conf').read_bytes())
            self.assertNotIn('start',[x['action'] for x in self.log()])
            self.original=self.source.read_bytes();self.plan=self.preview(self.business)

    def test_failed_publication_restores_four_original_states_and_exact_source(self):
        for boot,running in [(0,0),(0,1),(1,0),(1,1)]:
            self.begin(boot,running); self.flag(precheck_fail_after=1); self.apply(7);self.pending()
            self.flag(); self.recover();self.closed(2)
            self.assertEqual(self.source.read_bytes(),self.original);self.assertEqual(self.running(),bool(running));self.assertEqual(self.enabled.read_text(),str(boot))
            if self.running():
                subprocess.run([str(self.init),'stop'],check=True);self.created.extend([p.pid for p in self.processes])
            (self.base/'prechecks').unlink(missing_ok=True); self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))

    def test_zero_exit_stop_without_observed_stop_never_publishes(self):
        self.begin(running=1); self.flag(stop_noop=True);self.apply(7);self.pending();self.assertEqual(self.source.read_bytes(),self.original)
        self.flag();self.recover();self.closed(2);self.assertTrue(self.running())

    def test_nonzero_stop_after_stopping_keeps_recovery_barrier(self):
        self.begin(running=1);self.flag(stop_exit=9);self.apply(7);self.pending();self.assertFalse(self.running());self.assertEqual(self.source.read_bytes(),self.original)
        self.flag();self.recover();self.closed(2);self.assertTrue(self.running())

    def test_precheck_failure_cannot_stop_or_publish(self):
        self.begin(running=1);self.flag(precheck_fail=True);self.apply(7);self.assertEqual(self.log(),[]);self.assertTrue(self.running());self.pending();self.assertEqual(self.source.read_bytes(),self.original)

    def test_zero_exit_start_without_running_refuses_recovery_ack(self):
        self.begin(running=1);self.flag(precheck_fail_after=1);self.apply(7);self.flag(start_noop=True);self.recover(7);self.pending();self.assertEqual(self.source.read_bytes(),self.original)
        self.flag();self.recover();self.closed(2);self.assertTrue(self.running())

    def test_nonzero_start_never_acknowledges_even_if_daemon_started(self):
        self.begin(running=1);self.flag(precheck_fail_after=1);self.apply(7);self.flag(start_exit=9);self.recover(7);self.pending()
        self.flag();self.recover();self.closed(2);self.assertTrue(self.running())

    def test_foreign_source_refuses_before_any_action(self):
        self.begin(running=1);self.source.write_bytes(b'PRIVATE_SENTINEL foreign source');self.apply(7);self.assertEqual(self.log(),[]);self.assertTrue(self.running());self.pending()

    def test_changed_boot_intent_refuses_before_stop(self):
        self.begin(running=1);self.enabled.write_text('0');self.apply(7);self.assertEqual(self.log(),[]);self.assertTrue(self.running());self.pending()

    def test_different_boot_refuses_both_apply_and_restore(self):
        self.begin(running=1);self.boot_id.write_text('00000000-0000-0000-0000-000000000000\n');self.apply(7);self.recover(7);self.assertEqual(self.log(),[]);self.assertTrue(self.running())

    def test_arguments_wrong_handle_and_old_journal_formats_cannot_control_service(self):
        self.begin();self.cli('service-apply','0'*32,expected=5)
        self.cli('service-apply',self.handle,'start',expected=2);self.cli('service-recover','1','0',expected=2);self.assertEqual(self.log(),[])

    def test_receipt_only_and_unprojected_intent_journals_refuse_service_actions(self):
        report=self.cli('commit-apply',self.plan['confirmation']);self.handle=report['apply_handle'];self.apply(5);self.assertEqual(self.log(),[])
        self.cli('apply-finish',self.handle,'failure');self.cli('restore-finish',self.handle,'success')
        self.plan=self.preview(self.business);report=self.cli('commit-apply-observed',self.plan['confirmation']);self.handle=report['apply_handle'];self.apply(5);self.assertEqual(self.log(),[])

    def test_private_source_and_credentials_restored_without_output_reflection(self):
        self.secret(b'PRIVATE_SENTINEL');self.original=self.original.replace(b"config dns_account 'dns_a'\n",b"config dns_account 'dns_a'\n\toption secret 'PRIVATE_SENTINEL'\n");self.source.write_bytes(self.original)
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"));self.begin(running=1);self.flag(precheck_fail_after=1);self.apply(7);self.flag();self.recover();self.closed(3)
        self.assertEqual(self.source.read_bytes(),self.original);self.assertEqual((self.store/'gen-3/credentials/cloudflare.dns_a.secret').read_bytes(),b'PRIVATE_SENTINEL')

    def test_missing_or_unsafe_dependency_preserves_service_and_configuration(self):
        self.begin(running=1);self.executable.chmod(0o777);self.apply(7);self.assertEqual(self.log(),[]);self.assertEqual(self.source.read_bytes(),self.original)
        self.executable.chmod(0o700);self.common.unlink();self.apply(7);self.assertEqual(self.log(),[])

    def test_active_package_marker_cannot_start_or_stop(self):
        self.begin(running=1);self.marker.write_text('was_running=0\n');self.apply(4);self.assertEqual(self.log(),[]);self.assertTrue(self.running());self.assertTrue(self.marker.exists())

    def test_shared_writer_contention_and_borrowed_fd(self):
        import fcntl
        self.begin()
        with self.native.lock.open('rb') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);self.apply(4);self.assertEqual(self.log(),[])
        wrapper=self.base/'borrow.sh';wrapper.write_text('exec 6>>'+str(self.native.lock)+'\nflock -n 6 || exit 4\nexec '+self.busybox+' ash '+str(self.engine)+' --persistent service-apply '+self.handle+'\n')
        result=subprocess.run([self.busybox,'ash',str(wrapper)],env=self.env,capture_output=True,timeout=15);self.assertEqual(result.returncode,0,(result.stdout,result.stderr));self.closed(3)

    def test_closed_source_gates_cannot_be_enabled_by_environment(self):
        self.begin();s=self.engine.read_text().replace('service_actions_enabled=true','service_actions_enabled=false');self.engine.write_text(s)
        self.cli('service-apply',self.handle,env={**self.env,'service_actions_enabled':'true'},expected=2);self.assertEqual(self.log(),[])

    def test_action_environment_cleared_and_secret_never_returned(self):
        self.begin(running=1);self.cli('service-apply',self.handle,env={**self.env,'INIT_TRACE':'PRIVATE_SENTINEL','PROCD_DEBUG':'PRIVATE_SENTINEL','HOMEGATE_PACKAGE_UPGRADE_STATE':str(self.marker)})
        self.assertEqual(self.log()[0]['env'],{'HOMEGATE_PACKAGE_UPGRADE_STATE':None,'PROCD_DEBUG':None,'INIT_TRACE':None});self.closed(3)

    def test_caller_sigkill_retains_action_lock_until_independent_deadline(self):
        self.begin(running=1);self.flag(stop_hang=True)
        watchdog=self.engine.parent/'homegate-service-observer-watchdog.sh';watchdog.write_text(watchdog.read_text().replace('deadline=$((now + 5))','deadline=$((now + 2))'))
        p=subprocess.Popen([self.busybox,'ash',str(self.engine),'--persistent','service-apply',self.handle],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        deadline=time.monotonic()+5
        while not self.log():
            self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.02)
        p.kill();p.communicate(timeout=2);self.recover(4);self.writer(4)
        time.sleep(3.4);self.flag();self.recover();self.closed(2);self.assertTrue(self.running())

    def test_terminal_journal_cleanup_rechecks_actual_service(self):
        self.begin();self.fault('rm','sys.exit(1) if sys.argv[1:]==["-f",'+repr(str(self.store/'application'))+'] else None')
        self.apply(7);self.restore_tool('rm');self.assertEqual((self.store/'application').read_text().splitlines()[4],'applied')
        self.recover();self.closed(3);self.assertFalse(self.running())

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,value in cls.__dict__.items() if name.startswith('test_') and callable(value))
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
