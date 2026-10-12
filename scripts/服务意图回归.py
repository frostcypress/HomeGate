#!/usr/bin/env python3
"""Real Linux journal/locks/process faults; service observations are fixtures.
Does not query procd or start/stop the router's actual HomeGate service.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from project import ROOT
from 配置事务原型回归 import SCRIPT
from 完整配置事务回归 import Runtime as FullRuntime
from 私有配置读取回归 import Runtime as PrivateRuntime

class Runtime(unittest.TestCase):
    setUpClass=classmethod(FullRuntime.setUpClass.__func__)
    setUp=FullRuntime.setUp
    tearDown=FullRuntime.tearDown
    raw=FullRuntime.raw
    cli=FullRuntime.cli
    export=FullRuntime.export
    commit_body=FullRuntime.commit_body
    secret=FullRuntime.secret
    secret_path=FullRuntime.secret_path
    fault=FullRuntime.fault
    restore_tool=FullRuntime.restore_tool
    preview=FullRuntime.preview
    snapshot=PrivateRuntime.snapshot
    decode=PrivateRuntime.decode

    def begin(self,boot=1,running=1):
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))
        result=self.cli('commit-apply-intent',self.plan['confirmation'],str(boot),str(running))
        self.handle=result['apply_handle']
        self.assertFalse(result['business_applied'])
        return result

    def context(self): return self.cli('service-intent-read',self.handle)
    def journal(self): return (self.store/'application').read_bytes()
    def phase(self): return self.cli('status')['application_phase']
    def acknowledge(self,boot,running,restore=False,expected=0):
        return self.cli('restore-finish-intent' if restore else 'apply-finish-intent',self.handle,str(boot),str(running),expected=expected)

    def test_four_independent_boot_run_states_are_bound_without_import_activation(self):
        for boot,running in [(0,0),(0,1),(1,0),(1,1)]:
            result=self.begin(boot,running); rows=self.journal().decode().splitlines()
            self.assertEqual(len(rows),10); self.assertEqual(rows[0],'HGAPPLICATION2')
            self.assertEqual(rows[7:9],[str(boot),str(running)])
            self.assertEqual(rows[9],Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            state=self.context()
            self.assertEqual((state['boot_enabled'],state['baseline_running'],state['expected_running']),(boot,running,0))
            self.assertTrue(state['same_boot']); self.assertEqual(state['revision'],result['revision'])
            status=self.cli('status'); self.assertTrue(status['service_intent_bound'])
            for private in ['boot_enabled','baseline_running','expected_running','same_boot',self.handle]:
                self.assertNotIn(private,json.dumps(status)); self.assertNotIn(private,self.export().decode())
            self.acknowledge(boot,0)
            self.assertFalse(self.cli('status')['service_intent_bound'])

    def test_legacy_ack_and_receipt_worker_cannot_close_service_intent(self):
        self.begin(); before=self.journal()
        self.cli('apply-finish',self.handle,'success',expected=5)
        for command in ['apply-authorize','apply-snapshot-read','restore-authorize']:
            self.cli(command,self.handle,expected=5)
        result=subprocess.run([self.busybox,'ash',str(SCRIPT.parent/'homegate-worker-supervisor.sh'),'run-apply',self.handle],
                              env=self.env,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,5,(result.stdout,result.stderr)); self.assertEqual(result.stderr,b'')
        self.assertFalse((self.store/'worker').exists()); self.assertFalse((self.store/'runtime').exists())
        self.assertEqual(self.journal(),before)

    def test_wrong_application_observations_preserve_pointer_and_barrier(self):
        self.begin(1,0); before=self.journal(); current=(self.store/'current').read_bytes()
        for boot,running in [(0,0),(1,1),(0,1)]:
            self.acknowledge(boot,running,expected=7)
            self.assertEqual(self.journal(),before); self.assertEqual((self.store/'current').read_bytes(),current)
        self.cli('preview',payload=self.business,expected=4)
        self.acknowledge(1,0); self.assertEqual(self.phase(),'none')

    def test_failure_restores_both_original_intents_for_all_four_combinations(self):
        for boot,running in [(0,0),(0,1),(1,0),(1,1)]:
            self.begin(boot,running); base=int(self.journal().splitlines()[1])
            result=self.cli('apply-finish',self.handle,'failure')
            self.assertFalse(result['business_restored']); self.assertEqual(result['revision'],base)
            state=self.context()
            self.assertEqual((state['boot_enabled'],state['expected_running'],state['phase']),(boot,running,'restoring'))
            before=self.journal()
            self.acknowledge(boot,1-running,restore=True,expected=7)
            self.acknowledge(1-boot,running,restore=True,expected=7)
            self.cli('restore-finish',self.handle,'success',expected=5)
            self.assertEqual(self.journal(),before)
            self.acknowledge(boot,running,restore=True); self.assertEqual(self.phase(),'none')

    def test_service_snapshot_delivers_same_generation_binary_credentials_privately(self):
        value=b'PRIVATE_SENTINEL\x00\xff\n'; self.secret(value); self.begin(0,1)
        report,frame=self.snapshot('apply-service-snapshot-read',self.handle)
        self.assertEqual(report['revision'],4)
        self.assertEqual(self.decode(frame)[b'credentials'][b'cloudflare.dns_a.secret'],value)
        self.snapshot('apply-snapshot-read',self.handle,expected=5)
        self.cli('apply-finish',self.handle,'failure')
        report,frame=self.snapshot('restore-service-snapshot-read',self.handle)
        self.assertEqual(report['revision'],3)
        self.assertEqual(self.decode(frame)[b'credentials'][b'cloudflare.dns_a.secret'],value)
        self.snapshot('apply-service-snapshot-read',self.handle,expected=5)
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(self.context()))
        self.assertNotIn(b'PRIVATE_SENTINEL',self.journal())

    def test_invalid_intent_arguments_fail_before_mutation(self):
        plan=self.preview(); current=(self.store/'current').read_bytes()
        for flags in [('01','0'),('0','true'),('2','0'),('-1','1'),('1;false','0'),('','1')]:
            self.cli('commit-apply-intent',plan['confirmation'],*flags,expected=2)
        for args in [(plan['confirmation'],),(plan['confirmation'],'0'),(plan['confirmation'],'0','1','/bin/sh')]:
            self.cli('commit-apply-intent',*args,expected=2)
        self.assertEqual((self.store/'current').read_bytes(),current)
        self.assertFalse((self.store/'application').exists()); self.assertFalse((self.store/'gen-3').exists())
        self.begin()
        self.cli('service-intent-read','0'*32,expected=5)
        self.cli('apply-finish-intent','0'*32,'1','0',expected=5)
        for command in ['apply-finish-intent','restore-finish-intent']:
            self.cli(command,self.handle,'yes','0',expected=2)
            self.cli(command,self.handle,'1','0','extra',expected=2)

    def test_legacy_journal_cannot_be_upgraded_by_observation_ack(self):
        plan=self.preview(); started=self.cli('commit-apply',plan['confirmation']); self.handle=started['apply_handle']
        self.assertEqual(self.journal().splitlines()[0],b'HGAPPLICATION1')
        self.cli('service-intent-read',self.handle,expected=5)
        self.snapshot('apply-service-snapshot-read',self.handle,expected=5)
        self.acknowledge(0,0,expected=5)
        self.cli('apply-finish',self.handle,'failure')
        self.acknowledge(0,0,restore=True,expected=5)
        self.cli('restore-finish',self.handle,'success')

    def test_tampered_flags_boot_framing_and_links_fail_closed(self):
        self.begin(1,1); original=self.journal(); journal=self.store/'application'
        rows=original.splitlines()
        variants=[original[:-1],original+b'\n',original+b'0\n']
        for index,value in [(7,b'0'),(8,b'0'),(7,b'01'),(9,b'0'*36),(0,b'HGAPPLICATION1')]:
            changed=list(rows); changed[index]=value; variants.append(b'\n'.join(changed)+b'\n')
        for body in variants:
            journal.write_bytes(body); self.cli('recover-application',expected=1)
            self.assertEqual((self.store/'current').read_bytes(),b'3\n')
        target=self.base/'target'; target.write_bytes(original); target.chmod(0o600)
        journal.unlink(); journal.symlink_to(target); self.cli('status',expected=1)
        journal.unlink(); os.link(target,journal); self.cli('status',expected=1)
        journal.unlink(); journal.write_bytes(original); journal.chmod(0o600)
        self.cli('recover-application'); self.acknowledge(1,1,restore=True)

    def test_copying_whole_store_cannot_rebind_service_baseline(self):
        self.begin(0,1); other=self.base/'other'; shutil.copytree(self.store,other)
        self.cli('recover-application',env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(other)},expected=1)
        self.assertEqual(self.context()['baseline_running'],1)

    def test_prepared_directory_sync_failure_retains_original_service_baseline(self):
        plan=self.preview()
        self.fault('fsync','if sys.argv[-1]=='+repr(str(self.store))+': sys.exit(1)')
        self.cli('commit-apply-intent',plan['confirmation'],'0','1',expected=7)
        self.assertEqual(self.phase(),'prepared'); self.assertEqual((self.store/'current').read_bytes(),b'2\n')
        self.assertTrue((self.store/'gen-3/manifest').exists())
        self.handle=self.journal().splitlines()[3].decode(); self.cli('service-intent-read',self.handle,expected=5)
        self.restore_tool('fsync'); self.cli('recover-application')
        self.assertEqual(self.context()['expected_running'],1); self.acknowledge(0,1,restore=True)

    def test_service_intent_file_sync_failure_does_not_publish_or_activate(self):
        plan=self.preview()
        self.fault('fsync','from pathlib import Path\nif sys.argv[-1].split("/")[-1].startswith(".work.") and Path(sys.argv[-1]).read_bytes().startswith(b"HGAPPLICATION2"):\n    sys.exit(1)')
        self.cli('commit-apply-intent',plan['confirmation'],'1','1',expected=7)
        self.assertFalse((self.store/'application').exists()); self.assertFalse((self.store/'gen-3').exists())
        self.assertEqual((self.store/'current').read_bytes(),b'2\n')
        self.restore_tool('fsync'); started=self.cli('commit-apply-intent',plan['confirmation'],'1','1')
        self.handle=started['apply_handle']; self.acknowledge(1,0)

    def test_sigkill_after_publish_recovers_bound_original_intent(self):
        plan=self.preview()
        self.fault('mv','import subprocess\nif sys.argv[-1].endswith("/current"):\n    subprocess.run(['+repr(self.busybox)+',"mv",*sys.argv[1:]],check=True); os.kill(os.getppid(),signal.SIGKILL); sys.exit(0)')
        result=subprocess.run([self.busybox,'ash',str(SCRIPT),'--public-uci','commit-apply-intent',plan['confirmation'],'1','0'],
                              env=self.env,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,-9,(result.stdout,result.stderr)); self.assertEqual(result.stdout,b''); self.assertEqual(result.stderr,b'')
        self.restore_tool('mv'); self.assertEqual(self.phase(),'prepared')
        self.handle=self.journal().splitlines()[3].decode(); self.cli('recover-application')
        self.assertEqual(self.context()['expected_running'],0); self.acknowledge(1,0,restore=True)
        self.assertEqual(self.export(),self.business)

    def test_verified_application_cleanup_failure_does_not_restore_old_intent(self):
        self.begin(1,1); self.fault('rm','if sys.argv[-1].endswith("/application"): sys.exit(1)')
        self.acknowledge(1,0,expected=7); self.assertEqual(self.phase(),'applied')
        self.cli('service-intent-read',self.handle,expected=5)
        self.restore_tool('rm'); result=self.cli('recover-application')
        self.assertFalse(result['application_pending']); self.assertEqual(result['revision'],3)
        self.assertIn(b"option https_port '8443'",self.export())

    def test_verified_restoration_cleanup_failure_only_retries_closure(self):
        self.begin(0,1); self.cli('apply-finish',self.handle,'failure')
        self.fault('rm','if sys.argv[-1].endswith("/application"): sys.exit(1)')
        self.acknowledge(0,1,restore=True,expected=7); self.assertEqual(self.phase(),'restored')
        self.restore_tool('rm'); self.cli('recover-application'); self.assertEqual(self.phase(),'none')
        self.assertEqual(self.export(),self.business)

    def test_concurrent_observation_ack_has_one_winner_and_rejects_replay(self):
        self.begin(0,1)
        def complete():
            return subprocess.run([self.busybox,'ash',str(SCRIPT),'--public-uci','apply-finish-intent',self.handle,'0','0'],
                                  env=self.env,capture_output=True,timeout=10)
        with ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(lambda _:complete(),range(4)))
        self.assertEqual(sum(r.returncode==0 for r in results),1)
        self.assertTrue(all(r.returncode in (0,4,5) and r.stderr==b'' for r in results))
        self.acknowledge(0,0,expected=5); self.cli('commit-apply-intent',self.plan['confirmation'],'0','1',expected=5)

    def test_capacity_full_and_changed_boot_keep_recovery_explicit(self):
        self.begin(1,1); (self.store/'gen-32').mkdir(mode=0o700)
        rows=self.journal().decode().splitlines(); rows[9]='00000000-0000-0000-0000-000000000000'
        # Privileged fixture emulates an intact log originating on an older
        # boot, recomputing the documented bindings. Not a production hook.
        for index,revision in [(5,rows[1]),(6,rows[2])]:
            manifest=(self.store/('gen-'+revision)/'manifest').read_text().rstrip('\n')
            framed='\n'.join(['HGAPPLICATION2',str(self.store),rows[9],rows[7],rows[8],manifest])+'\n'
            rows[index]=hashlib.sha256(framed.encode()).hexdigest()
        (self.store/'application').write_text('\n'.join(rows)+'\n')
        self.assertFalse(self.context()['same_boot'])
        self.acknowledge(1,0,expected=7)
        self.cli('recover-application'); self.assertEqual(self.context()['expected_running'],1)
        self.acknowledge(1,1,restore=True,expected=7)
        self.assertTrue(self.cli('status')['application_pending']); self.assertEqual(self.cli('status')['revision'],2)
        self.cli('preview',payload=self.business,expected=4)

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--runtime',action='store_true',required=True); parser.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Runtime))
    raise SystemExit(not result.wasSuccessful())
