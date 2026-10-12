#!/usr/bin/env python3
"""Real Linux locks/proc/sessions with explicit init/ubus fixture endpoints.
Builds unchanged official LuCI jsonc. Does not contact the target router.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import unittest
from project import ROOT
from 配置事务原型回归 import SCRIPT
from 完整配置事务回归 import Runtime as FullRuntime

DIRECTORY=SCRIPT.parent

class Static(unittest.TestCase):
    def test_fixed_commands_and_native_shell_grammar(self):
        import tree_sitter
        import tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for file in [SCRIPT,DIRECTORY/'homegate-service-observer-watchdog.sh']:
            body=file.read_bytes(); self.assertNotIn(b'\r',body)
            self.assertFalse(parser.parse(body).root_node.has_error,file.name)
        lua=(DIRECTORY/'homegate-service-observer.lua').read_text()
        self.assertNotIn('os.getenv',lua)
        self.assertIn("require('luci.jsonc')",lua)
        self.assertNotIn('pidof',lua)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_lua51_source_compiles(self):
        from lupa.lua51 import LuaRuntime
        LuaRuntime().compile((DIRECTORY/'homegate-service-observer.lua').read_text())

class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FullRuntime.setUpClass.__func__(cls)
        if not (ROOT/'build/service-observer/luci/jsonc.so').is_file():
            raise RuntimeError('Requires real pinned official LuCI jsonc binding')
        cls.daemon=ROOT/'build/service-observer/homegate-fixture'
        source=cls.daemon.with_suffix('.c'); source.write_text('#include <unistd.h>\nint main(void) { for (;;) pause(); }\n')
        subprocess.run(['gcc','-O2',str(source),'-o',str(cls.daemon)],check=True,timeout=30)

    cli=FullRuntime.cli
    export=FullRuntime.export
    commit_body=FullRuntime.commit_body
    preview=FullRuntime.preview

    def raw(self,*args,payload=None,expected=0,env=None):
        result=subprocess.run([self.busybox,'ash',str(getattr(self,'engine',SCRIPT)),'--public-uci',*args],
                              input=payload,capture_output=True,env=env or self.env,timeout=12)
        self.assertEqual(result.returncode,expected,(args,result.stdout,result.stderr))
        self.assertEqual(result.stderr,b''); self.assertLess(len(result.stdout),300000)
        self.assertNotIn(b'PRIVATE_SENTINEL',result.stdout)
        return result.stdout

    def setUp(self):
        FullRuntime.setUp(self)
        fixture=self.base/'fixture/project/core/prototype'
        shutil.copytree(DIRECTORY,fixture)
        backup=fixture.parent.parent/'luci/lua/luasrc/model/homegate'; backup.mkdir(parents=True)
        shutil.copy2(ROOT/'project/luci/lua/luasrc/model/homegate/backup.lua',backup/'backup.lua')
        self.engine=fixture/'homegate-config-prototype.sh'
        self.init=self.base/'homegate-init'; self.common=self.base/'rc.common'; self.ubus=self.base/'ubus'
        self.common.write_text('#!/bin/sh\nexit 0\n'); self.common.chmod(0o700)
        self.executable=self.base/'homegate'; shutil.copy2(self.daemon,self.executable)
        for name in ['homegate-service-observer.lua','homegate-service-observer-watchdog.sh']:
            file=fixture/name; body=file.read_text()
            for before,after in [('/etc/init.d/homegate',str(self.init)),('/etc/rc.common',str(self.common)),
                                 ('/sbin/ubus',str(self.ubus)),('/usr/bin/homegate',str(self.executable))]:
                self.assertIn(before,body) if before in ['/etc/init.d/homegate'] else None
                body=body.replace(before,after)
            if name.endswith('.sh'):
                self.assertIn('[ "$(id -u)" = 0 ]',body)
                body=body.replace('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+str(os.getuid())+' ]')
            file.write_text(body)
        self.env['LUA_CPATH']=str(ROOT/'build/service-observer/?.so')+';;'
        self.processes=[]; self.groups=[]
        self.enable(1); self.query({})
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))

    def tearDown(self):
        for p in self.processes:
            if p.poll() is None: p.kill()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: pass
            if p.stdout: p.stdout.close()
            if p.stderr: p.stderr.close()
        for group in self.groups:
            try: os.killpg(group,signal.SIGKILL)
            except ProcessLookupError: pass
        FullRuntime.tearDown(self)

    def enable(self,value,code=None):
        calls=str(self.base/'init-calls')
        self.init.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> '+calls+'\n[ "$#" -eq 1 ] && [ "$1" = enabled ] || exit 99\n'+
                             (code if code is not None else 'exit '+str(0 if value else 1))+'\n')
        self.init.chmod(0o700)

    def query(self,doc,status=0,code=''):
        body=doc if isinstance(doc,str) else json.dumps(doc)
        expected=['-t','2','-S','call','service','list','{"name":"homegate","verbose":true}']
        self.ubus.write_text('#!'+sys.executable+'\nimport os,sys,time,signal,json\nassert sys.argv[1:]=='+repr(expected)+'\n'+code+
                             '\nsys.stdout.write('+repr(body)+'); sys.stdout.flush(); sys.exit('+str(status)+')\n')
        self.ubus.chmod(0o700)

    def daemon_start(self):
        p=subprocess.Popen([str(self.executable),'daemon']); self.processes.append(p); return p

    def doc(self,pid=None,running=True):
        instance={'running':running,'command':[str(self.executable),'daemon']}
        if pid is not None: instance['pid']=pid
        return {'homegate':{'instances':{'instance1':instance}}}

    def observe(self,expected=0):
        return self.cli('commit-apply-observed',self.plan['confirmation'],expected=expected)

    def unchanged(self):
        self.assertEqual((self.store/'current').read_bytes(),b'2\n')
        self.assertFalse((self.store/'application').exists()); self.assertFalse((self.store/'gen-3').exists())
        self.assertTrue((self.store/'pending').exists())

    def test_four_independent_states_sample_real_processes_and_bind_journal(self):
        for enabled,running in [(0,0),(0,1),(1,0),(1,1)]:
            self.enable(enabled); p=self.daemon_start() if running else None
            self.query(self.doc(p.pid if p else None,running=bool(running)))
            report=self.observe(); rows=(self.store/'application').read_text().splitlines()
            self.assertEqual(rows[7:9],[str(enabled),str(running)])
            self.assertEqual(rows[9],Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            self.cli('apply-finish-intent',report['apply_handle'],str(enabled),'0')
            # Observation ACK arguments here remain a separate protocol fixture;
            # this sampler itself never stops or starts the fixture daemon.
            if p: self.assertIsNone(p.poll()); p.terminate(); p.wait(timeout=5)
            self.plan=self.preview(self.business)
        self.assertEqual(set((self.base/'init-calls').read_text().splitlines()),{'enabled'})

    def test_known_empty_service_forms_are_stopped(self):
        for doc in [{},{'homegate':{}},{'homegate':{'autostart':False}}]:
            self.query(doc); result=self.observe()
            self.assertEqual((self.store/'application').read_text().splitlines()[8],'0')
            self.cli('apply-finish-intent',result['apply_handle'],'1','0')
            self.plan=self.preview(self.business)

    def test_running_pid_wrong_command_and_untracked_daemon_fail_closed(self):
        self.query(self.doc(os.getpid())); self.observe(7); self.unchanged()
        p=self.daemon_start(); self.query({}); self.observe(7); self.unchanged()
        self.query(self.doc(p.pid)); doc=self.doc(p.pid); doc['homegate']['instances']['instance1']['command'][1]='other'
        self.query(doc); self.observe(7); self.unchanged()

    def test_dead_pid_or_multiple_instances_are_unknown(self):
        p=self.daemon_start(); pid=p.pid; p.terminate(); p.wait(timeout=5)
        self.query(self.doc(pid)); self.observe(7); self.unchanged()
        doc=self.doc(running=False); doc['homegate']['instances']['second']=doc['homegate']['instances']['instance1']
        self.query(doc); self.observe(7); self.unchanged()

    def test_malformed_types_arrays_trailing_documents_and_size_are_rejected(self):
        bad=['[]','{}{}','{"homegate":[]}','{"homegate":{"instances":[]}}','{"other":{}}','{"homegate":null}',
             '{','X'*65537, json.dumps(self.doc(running=False)).replace('false','0'),
             json.dumps(self.doc(2)).replace('"pid": 2','"pid": 2.5')]
        for body in bad:
            self.query(body); self.observe(7); self.unchanged()

    def test_ubus_error_and_init_unknown_do_not_default_to_zero(self):
        for status in [1,2,127]:
            self.query({},status=status); self.observe(7); self.unchanged()
        self.query({}); self.enable(0,code='exit 2'); self.observe(7); self.unchanged()
        self.ubus.unlink(); self.observe(7); self.unchanged()

    def test_boot_enable_change_between_samples_is_rejected(self):
        marker=self.base/'enabled-once'
        self.enable(0,code='if [ -e '+str(marker)+' ]; then exit 0; fi\n: > '+str(marker)+'\nexit 1')
        self.observe(7); self.unchanged()

    def test_restarted_daemon_identity_between_samples_is_rejected(self):
        p=self.daemon_start(); doc=self.doc(p.pid)
        marker=self.base/'ubus-once'
        self.query(doc,code='marker='+repr(str(marker))+'\nif os.path.exists(marker):\n    os.kill('+str(p.pid)+',signal.SIGTERM)\n    time.sleep(0.1)\nelse:\n    open(marker,"w").close()')
        self.observe(7); self.unchanged()

    def test_configuration_lock_is_held_through_sampling(self):
        marker=self.base/'sampling'
        self.query({},code='open('+repr(str(marker))+',"w").close(); time.sleep(0.5)')
        p=subprocess.Popen([self.busybox,'ash',str(self.engine),'--public-uci','commit-apply-observed',self.plan['confirmation']],
                           env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE); self.processes.append(p)
        end=time.monotonic()+3
        while not marker.exists():
            if time.monotonic()>end: self.fail('Sampler did not begin')
            time.sleep(0.02)
        self.cli('cancel',expected=4); self.cli('status',expected=4)
        out,err=p.communicate(timeout=10); self.assertEqual(p.returncode,0,(out,err)); self.assertEqual(err,b'')

    def test_hanging_query_is_bounded_and_its_session_is_quiet(self):
        marker=self.base/'session'
        self.query({},code='open('+repr(str(marker))+',"w").write(str(os.getsid(0))); signal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True: time.sleep(0.1)')
        started=time.monotonic(); self.observe(7)
        self.assertLess(time.monotonic()-started,9)
        group=int(marker.read_text()); self.groups.append(group)
        self.assert_quiet(group); self.unchanged()

    def assert_quiet(self,group):
        end=time.monotonic()+2
        while True:
            result=subprocess.check_output([self.lua,str(DIRECTORY/'worker-process.lua'),'group',str(group),'0'],env=self.env)
            if result==b'0\n': return
            if time.monotonic()>end: self.fail('Observer descendants remain live')
            time.sleep(0.05)

    def test_caller_sigkill_does_not_disable_independent_deadline(self):
        marker=self.base/'session'
        self.query({},code='open('+repr(str(marker))+',"w").write(str(os.getsid(0))); signal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True: time.sleep(0.1)')
        p=subprocess.Popen([self.busybox,'ash',str(self.engine),'--public-uci','commit-apply-observed',self.plan['confirmation']],
                           env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE); self.processes.append(p)
        end=time.monotonic()+3
        while not marker.exists():
            if time.monotonic()>end: self.fail('Sampler did not begin')
            time.sleep(0.02)
        group=int(marker.read_text()); self.groups.append(group)
        p.kill(); p.communicate(timeout=10); self.assertEqual(p.returncode,-9)
        time.sleep(6.2); self.assert_quiet(group); self.unchanged()

    def test_extra_arguments_cannot_supply_state_or_command(self):
        for args in [(self.plan['confirmation'],'1','0'),(self.plan['confirmation'],'/bin/sh'),('0'*32,)]:
            self.cli('commit-apply-observed',*args,expected=5 if len(args)==1 else 2)
        self.unchanged(); self.assertFalse((self.base/'init-calls').exists())

    def test_json_environment_secrets_never_appear_in_output_or_journal(self):
        p=self.daemon_start(); doc=self.doc(p.pid)
        doc['homegate']['instances']['instance1']['env']={'API_TOKEN':'PRIVATE_SENTINEL'}
        self.query(doc); report=self.observe()
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(report))
        self.assertNotIn(b'PRIVATE_SENTINEL',(self.store/'application').read_bytes())
        self.assertFalse(list(self.store.glob('.work.*')))

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--runtime',action='store_true'); p.add_argument('--static',action='store_true')
    a=p.parse_args(); result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if a.runtime else Static))
    raise SystemExit(not result.wasSuccessful())
