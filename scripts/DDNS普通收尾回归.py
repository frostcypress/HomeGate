#!/usr/bin/env python3
"""Explicit ordinary-source receipt maintenance; no cloud writes during closeout."""
import argparse,json,os,re,shutil,subprocess,unittest
from pathlib import Path
from project import ROOT
from DDNS普通运行回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase
from DDNS执行回归 import SyncMixin
from DDNS计划回归 import fixture_uid
PROTO=ROOT/'project/core/prototype'
HELPERS=['homegate-cloudflare-read.sh','homegate-dns-recovery.sh','homegate-dns-orphan.sh','homegate-dns-retention.sh']

class Static(unittest.TestCase):
    def test_gates_grammar_and_no_production_install(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in HELPERS:
            body=(PROTO/name).read_bytes();self.assertEqual(body.count(b'ddns_closeout_enabled=false'),1)
            self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error,name)
        LuaRuntime().compile((PROTO/'homegate-ddns-sync.lua').read_bytes())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_runtime_aliases_have_fixed_actions_and_original_confirmation(self):
        body=(PROTO/'homegate-cloudflare-read.sh').read_text()
        for action in ['collect-orphan','collect-receipt','retire-archive']:
            self.assertIn('--runtime-'+action+'-internal',body)
        self.assertIn('runtime_closeout=true',body);self.assertIn('runtime-ddns-recovery-snapshot-read',body)
        self.assertNotIn('--runtime-repair',body)
    def test_guard_checks_stay_independent_of_new_gate(self):
        body=(PROTO/'homegate-dns-retention.sh').read_text().split('if [ "$action" = check ]; then',1)[1].split('\nfi',1)[0]
        self.assertNotIn('ddns_closeout_enabled',body)
        body=(PROTO/'homegate-dns-recovery.sh').read_text().split('    archive-check)\n',1)[1].split('    collect)\n',1)[0]
        self.assertNotIn('ddns_closeout_enabled',body)
    def test_helpers_keep_fixed_member_operations(self):
        for name in ['homegate-dns-orphan.sh','homegate-dns-retention.sh']:
            body=(PROTO/name).read_text()
            for forbidden in ['rm -r','curl','wget','eval ','kill ']:self.assertNotIn(forbidden,body)

class CloseMixin:
    def setUp(self):
        super().setUp()
        prefix={'cloudflare':'dns','aliyun':'aliyun','dnspod':'dnspod','huaweicloud':'huaweicloud'}[self.provider]
        mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        for name in HELPERS:
            p=self.engine.parent/name;body=p.read_text().replace('ddns_closeout_enabled=false','ddns_closeout_enabled=true')
            for suffix in ['orphan_collection_enabled','retention_enabled']:body=body.replace(prefix+'_'+suffix+'=false',prefix+'_'+suffix+'=true')
            # The inherited ordinary fixture has already mapped coordinator and
            # recovery paths. Replacing their /etc suffix again corrupts them.
            if name in ['homegate-dns-orphan.sh','homegate-dns-retention.sh']:
                body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
            p.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
        self.journal=self.store/'dns-operation';self.archive=self.store/'dns-settled';self.ledger=self.store/'dns-collection'
    def original_job(self):
        base=self.journal if self.journal.exists() else self.archive
        return (base/('slot-'+(base/'current').read_text().strip())/'manifest').read_text().splitlines()[6]
    def maintenance(self,action,expected=0,job=None,account='dns_a',provider=None,args=None,env=None):
        n=len(self.calls)
        command=args if args is not None else ['--runtime-'+action+'-internal',provider or self.provider,account,job or self.original_job(),'--confirm']
        p=subprocess.run([self.busybox,'ash',str(self.reader),*command],env=env or self.env,capture_output=True,timeout=18)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertEqual(len(self.calls),n)
        out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',b'pppoe-wan']:self.assertNotIn(marker,p.stdout)
        if expected==0:self.assertFalse(out['write_ready'])
        return out
    def confirmed(self):
        self.grant();self.sync_call();self.oldjob=self.original_job();return self.oldjob
    def archive_confirmed(self):
        self.confirmed();before=self.files(self.journal);self.maintenance('collect-receipt')
        self.assertFalse(self.journal.exists());self.assertEqual(before,self.files(self.archive));self.cli('writer-check')
        return self.oldjob
    def stranded_provider(self):
        self.grant();self.fault('rm','sys.exit(1) if any("/.dns-check-" in a and a.endswith("/input") for a in sys.argv[1:]) else None')
        self.sync_call(7);self.restore_tool('rm');self.oldjob=self.original_job()
        self.work=self.native.lockdir/('.dns-check-'+self.oldjob)
        self.assertTrue(self.work.is_dir());self.assertTrue((self.journal/'terminal').is_file())
        # Simulate loss of just the outer RAM directory, never persistent proof.
        outer=self.native.lockdir/('.ddns-plan-'+self.oldjob)
        assert outer.parent.resolve()==self.native.lockdir.resolve() and outer.resolve().is_relative_to(self.native.base.resolve())
        shutil.rmtree(outer)
        return self.oldjob
    def test_confirmed_archive_repeat_retire_and_next_explicit_update(self):
        old=self.archive_confirmed();before=self.files(self.archive);self.maintenance('collect-receipt',job=old);self.assertEqual(before,self.files(self.archive))
        self.maintenance('retire-archive',job=old);self.assertFalse(self.archive.exists());self.assertFalse(self.ledger.exists());self.cli('writer-check')
        self.maintenance('retire-archive',job=old)
        self.settings['addresses']=self.settings['addresses'].replace('2001:db8::2','2001:db8::3');self.control.write_text(json.dumps(self.settings))
        self.sync_call();new=self.original_job();self.assertNotEqual(old,new);before=self.files(self.journal)
        self.maintenance('retire-archive',job=old);self.assertEqual(before,self.files(self.journal));self.cli('writer-check',expected=4)
        self.maintenance('collect-receipt',job=new);self.assertEqual(len(self.mutations()),2)
    def test_provider_orphan_partial_collection_preserves_receipt_and_resumes(self):
        self.stranded_provider();before=self.files(self.journal)
        self.fault('rm','sys.exit(1) if any("/.dns-check-" in a and a.endswith("/input") for a in sys.argv[1:]) else None')
        self.maintenance('collect-orphan',7);self.restore_tool('rm');self.assertTrue((self.journal/'orphan-plan').exists())
        self.maintenance('collect-orphan');self.assertFalse(self.work.exists());self.assertEqual(before,self.files(self.journal));self.cli('writer-check',expected=4)
        self.maintenance('collect-receipt');self.cli('writer-check');self.assertEqual(len(self.mutations()),1)
    def test_unknown_with_only_desired_observation_cannot_archive(self):
        self.grant();SyncMixin.test_unknown_mutation_is_durable_and_not_retried(self);self.oldjob=self.original_job();self.recover_read()
        # Simulated loss of all volatile work cannot fabricate a terminal.
        for p in list(self.native.lockdir.glob('.ddns-plan-*'))+list(self.native.lockdir.glob('.dns-check-*')):
            assert p.parent.resolve()==self.native.lockdir.resolve() and p.resolve().is_relative_to(self.native.base.resolve());shutil.rmtree(p)
        before=self.files(self.journal)
        for action in ['collect-orphan','collect-receipt','retire-archive']:self.maintenance(action,7)
        self.assertEqual(before,self.files(self.journal));self.cli('writer-check',expected=4);self.assertEqual(len(self.mutations()),1)
    def test_source_change_refuses_closeout_and_preserves_original_evidence(self):
        self.confirmed();before=self.files(self.journal);self.source.write_bytes(self.source.read_bytes()+b'\n')
        for action in ['collect-orphan','collect-receipt','retire-archive']:self.maintenance(action,7)
        self.assertEqual(before,self.files(self.journal));self.cli('writer-check',expected=4)
    def test_archive_rename_failure_resumes_without_repeating_cloud_write(self):
        self.confirmed();self.fault('mv','sys.exit(1) if any(a.endswith("/dns-operation") for a in sys.argv[1:]) else None')
        self.maintenance('collect-receipt',7);self.restore_tool('mv');self.assertTrue(self.journal.exists());self.cli('writer-check',expected=4)
        self.maintenance('collect-receipt');self.cli('writer-check');self.assertEqual(len(self.mutations()),1)

class CF(CloseMixin,CFBase):provider='cloudflare'
class Ali(CloseMixin,AliBase):provider='aliyun'
class DNP(CloseMixin,DNPBase):provider='dnspod'
class HW(CloseMixin,HWBase):provider='huaweicloud'

class Boundaries(CF):
    def test_outer_unresolved_work_prevents_every_maintenance_action(self):
        self.grant();self.pending_success();before=self.files(self.outer);durable=self.files(self.journal)
        for action in ['collect-orphan','collect-receipt','retire-archive']:self.maintenance(action,4)
        self.assertEqual(before,self.files(self.outer));self.assertEqual(durable,self.files(self.journal))
        self.collect();self.maintenance('collect-receipt');self.cli('writer-check')
    def test_revoked_write_authority_still_allows_confirmed_closeout(self):
        self.confirmed();self.revoke_fixture();self.maintenance('collect-receipt');self.cli('writer-check')
        self.baseline_config=self.config_bytes();self.sync_call(7);self.assertEqual(len(self.mutations()),1)
    def test_closed_entry_gate_and_grammar_never_enable_by_environment(self):
        self.confirmed();old=self.oldjob
        for args in [['--runtime-collect-receipt-internal',self.provider,'dns_a',old],['--runtime-collect-receipt-internal','other','dns_a',old,'--confirm'],['--runtime-collect-receipt-internal',self.provider,'dns_a','../bad','--confirm']]:self.maintenance('collect-receipt',2,args=args)
        raw=self.reader.read_text();self.reader.write_text(raw.replace('ddns_closeout_enabled=true','ddns_closeout_enabled=false'))
        self.maintenance('collect-receipt',2,env={**self.env,'ddns_closeout_enabled':'true'});self.assertTrue(self.journal.exists())
    def test_helper_gates_cannot_be_bypassed_by_legacy_alias(self):
        self.confirmed();before=self.files(self.journal);helper=self.engine.parent/'homegate-dns-recovery.sh'
        helper.write_text(helper.read_text().replace('ddns_closeout_enabled=true','ddns_closeout_enabled=false'))
        self.maintenance('collect-receipt',7);self.maintenance('collect-receipt',7,args=['dns_a','--collect-receipt',self.oldjob,'--confirm'])
        self.assertEqual(before,self.files(self.journal));self.cli('writer-check',expected=4)
    def test_wrong_account_and_job_leave_receipt_unchanged(self):
        self.confirmed();before=self.files(self.journal);self.maintenance('collect-receipt',7,account='other');self.maintenance('collect-receipt',7,job='999999999')
        self.assertEqual(before,self.files(self.journal))
    def test_terminal_corruption_never_authorizes_archive(self):
        self.confirmed();p=self.journal/'terminal';p.write_bytes(p.read_bytes()+b' ');before=self.files(self.journal)
        self.maintenance('collect-receipt',7);self.assertEqual(before,self.files(self.journal));self.cli('writer-check',expected=4)
    def test_common_locks_prevent_maintenance(self):
        import fcntl
        self.confirmed()
        for p in [self.native.lock,self.store/'.supervisor.lock']:
            with p.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.maintenance('collect-receipt',4)
    def test_retirement_partial_delete_keeps_guard_even_with_gate_closed(self):
        old=self.archive_confirmed();self.fault('rm','sys.exit(1) if any("/dns-retiring/" in a and a.endswith("/context") for a in sys.argv[1:]) else None')
        self.maintenance('retire-archive',7,job=old);self.restore_tool('rm');self.cli('writer-check',expected=4)
        helper=self.engine.parent/'homegate-dns-retention.sh';raw=helper.read_text();helper.write_text(raw.replace('ddns_closeout_enabled=true','ddns_closeout_enabled=false'));self.cli('writer-check',expected=4)
        helper.write_text(raw);self.maintenance('retire-archive',job=old);self.cli('writer-check')
    def test_after_archive_move_sync_failure_requires_explicit_resume(self):
        self.confirmed();self.fault('fsync','from pathlib import Path\nsys.exit(1) if sys.argv[1:]==['+repr(str(self.store))+'] and Path('+repr(str(self.archive))+').exists() else None')
        self.maintenance('collect-receipt',7);self.restore_tool('fsync');self.assertFalse(self.journal.exists());self.cli('writer-check',expected=4)
        self.maintenance('collect-receipt',job=self.oldjob);self.cli('writer-check');self.assertEqual(len(self.mutations()),1)

Runtime=CF
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();suite=unittest.TestSuite()
    for cls in ([CF,Ali,DNP,HW,Boundaries] if a.runtime else [Static]):
        methods=Boundaries.__dict__ if cls is Boundaries else CloseMixin.__dict__ if a.runtime else Static.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching cases')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
