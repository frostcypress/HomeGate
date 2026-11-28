#!/usr/bin/env python3
"""Explicit, source-bound closeout of the producer's metadata transaction."""
import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import unittest
from project import ROOT
from DDNS计划回归 import fixture_uid
from DDNS恢复生产回归 import Runtime as Production, Static as ModelFixture

PROTO=ROOT/'project/core/prototype'


class Static(ModelFixture):
    def test_new_shell_grammar_closed_gates_and_fixed_metadata_scope(self):
        import tree_sitter,tree_sitter_bash
        p=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-ddns-recovery-control.sh','homegate-ddns-recovery.sh','homegate-cli.sh']:
            raw=(PROTO/name).read_bytes();self.assertNotIn(b'\r',raw)
            self.assertFalse(p.parse(raw).root_node.has_error,name)
        for name in ['homegate-ddns-recovery-control.sh','homegate-ddns-recovery.sh']:
            body=(PROTO/name).read_text();self.assertIn('ddns_recovery_repair_enabled=false',body)
            for forbidden in ['curl ', 'ddns-state.sh', '$run/recovery.json', '"$dir/homegate-dns-']:
                self.assertNotIn(forbidden,body)
        self.assertIn('recovery-summary-finish', (PROTO/'homegate-cli.sh').read_text())

    def test_marker_binds_exact_candidate_and_rejects_legacy_unknown_and_noncanonical(self):
        raw=self.model.pending('1.3.0-r129','1','a'*64,'b'*64,'11111111-1111-1111-1111-111111111111','c'*64,'d'*64,'e'*32,self.codec.json)
        doc=json.loads(raw);table=self.lua.table_from(doc,recursive=True)
        self.assertEqual(self.model.pending_decode(raw,table,self.codec.json)['candidate_sha256'],'d'*64)
        for bad in [raw+'\n',raw.replace('PENDING2','PENDING1'),json.dumps(doc)+'\n','HGDDNSRECOVERYPENDING1\n']:
            try: obj=self.lua.table_from(json.loads(bad),recursive=True)
            except ValueError:obj=None
            self.assertIsNone(self.model.pending_decode(bad,obj,self.codec.json))
        table['extra']=True;self.assertIsNone(self.model.pending_decode(self.codec.json(table)+'\n',table,self.codec.json))

    def test_marker_current_requires_version_revision_identity_generation_boot_and_inputs(self):
        raw=self.model.pending('1.3.0-r129','1','a'*64,'b'*64,'11111111-1111-1111-1111-111111111111','c'*64,'d'*64,'e'*32,self.codec.json)
        doc=self.lua.table_from(json.loads(raw),recursive=True)
        binding=self.lua.table_from(dict(identity='a'*64,generation='b'*64))
        proof=self.model.proof('c'*64+':11111111-1111-1111-1111-111111111111')
        self.assertTrue(self.model.fresh(doc,'1.3.0-r129','1',binding,proof))
        self.assertFalse(self.model.fresh(doc,'1.3.0-r128','1',binding,proof))
        self.assertFalse(self.model.fresh(doc,'1.3.0-r129','2',binding,proof))
        binding['generation']='f'*64;self.assertFalse(self.model.fresh(doc,'1.3.0-r129','1',binding,proof))

    def test_confirmation_frame_includes_stamps_and_no_persisted_preview(self):
        body=(PROTO/'homegate-ddns-recovery.sh').read_text()
        self.assertIn("%d:%i:%u:%a:%h:%s",body);self.assertIn('HGDDNSREPAIR1',body)
        self.assertIn('[ "$confirmation" = "$token" ]',body)
        self.assertIn('context_same && [ "$(capture_files)" = "$frame" ]',body)
        self.assertIn('business_recovered',body);self.assertNotIn('preview.json',body)


class Runtime(Production):
    def setUp(self):
        super().setUp()
        self.pending=self.native.lockdir/'.ddns-recovery-pending'
        self.stage_path=self.native.lockdir/'.ddns-recovery-next'
        self.producer.write_text(self.producer.read_text().replace('ddns_recovery_repair_enabled=false','ddns_recovery_repair_enabled=true'))
        self.repair_control=self.engine.parent/'homegate-ddns-recovery-control.sh'
        b=self.repair_control.read_text().replace('ddns_recovery_read_enabled=false','ddns_recovery_read_enabled=true').replace('ddns_recovery_repair_enabled=false','ddns_recovery_repair_enabled=true')
        b=b.replace('/var/run/homegate',str(self.native.lockdir)).replace('/etc/homegate/transactions',str(self.store))
        self.repair_control.write_text(fixture_uid(b.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))

    def repair_call(self,*args,expected=0,env=None):
        calls=len(self.calls)
        p=subprocess.run([self.busybox,'ash',str(self.candidate),*args],env=env or self.env,capture_output=True,timeout=20)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),p.stdout)
        self.assertEqual(len(self.calls),calls)
        for bad in [b'SECRET_SENTINEL',b'example.test',b'ddns_a',b'identity',b'input_digest',b'candidate_sha256']:
            self.assertNotIn(bad,p.stdout)
        doc=json.loads(p.stdout);self.assertFalse(doc['write_ready'])
        if 'business_recovered' in doc:self.assertFalse(doc['business_recovered'])
        return doc

    def check_summary(self):return self.repair_call('recovery-summary-check')
    def finish_summary(self,token,expected=0):return self.repair_call('recovery-summary-finish',token,'--confirm',expected=expected)
    def interrupted(self,published=False):
        self.grant();self.seed();self.managed();self.tick(1300)
        suffix='/ddns-recovery.json' if published else '/.ddns-recovery-next'
        self.fault('fsync','sys.exit(1) if any(a.endswith('+repr(suffix)+') for a in sys.argv[1:]) else None')
        self.managed(7);self.restore_tool('fsync')
        self.assertTrue(self.pending.exists());self.assertEqual(self.stage_path.exists(),not published)

    def test_clean_read_only_check_creates_nothing_and_cannot_finish(self):
        before=self.files(self.native.lockdir);store=self.files(self.store)
        out=self.check_summary();self.assertEqual(out['stage'],'clean');self.assertFalse(out['repair_required'])
        self.assertNotIn('confirmation',out);self.finish_summary('0'*64,4)
        self.assertEqual(self.files(self.native.lockdir),before);self.assertEqual(self.files(self.store),store)

    def test_staged_real_interruption_finishes_metadata_only_and_replay_refuses(self):
        self.interrupted();global_before=self.global_record();cache=self.files(self.state_dir);store=self.files(self.store)
        before=self.files(self.native.lockdir);check=self.check_summary();self.assertEqual(check['stage'],'staged')
        self.assertTrue(check['finish_ready']);self.assertEqual(self.files(self.native.lockdir),before)
        self.assertEqual(check,self.check_summary());candidate=self.stage_path.read_bytes()
        out=self.finish_summary(check['confirmation']);self.assertTrue(out['metadata_changed'])
        self.assertEqual(self.record_path.read_bytes(),candidate);self.assertFalse(self.pending.exists());self.assertFalse(self.stage_path.exists())
        self.assertEqual(self.files(self.state_dir),cache);self.assertEqual(self.files(self.store),store)
        self.assertEqual(self.global_path.read_bytes(),global_before);self.assertEqual(self.stored()['summary']['unknown'],1)
        self.finish_summary(check['confirmation'],4);self.assertEqual(self.check_summary()['stage'],'clean')
        calls=len(self.calls);self.managed(4);self.assertEqual(len(self.calls),calls)

    def test_already_published_finish_preserves_target_inode_and_bytes(self):
        self.interrupted(True);before=self.record_path.read_bytes();inode=self.record_path.stat().st_ino
        out=self.check_summary();self.assertEqual(out['stage'],'published');self.finish_summary(out['confirmation'])
        self.assertEqual(self.record_path.read_bytes(),before);self.assertEqual(self.record_path.stat().st_ino,inode)

    def test_after_rename_failure_retains_marker_and_requires_new_phase_confirmation(self):
        self.interrupted();token=self.check_summary()['confirmation']
        self.fault('fsync','sys.exit(1) if any(a.endswith("/ddns-recovery.json") for a in sys.argv[1:]) else None')
        self.finish_summary(token,7);self.restore_tool('fsync')
        self.assertTrue(self.pending.exists());self.assertFalse(self.stage_path.exists())
        out=self.check_summary();self.assertEqual(out['stage'],'published');self.assertNotEqual(token,out['confirmation'])
        self.finish_summary(token,4);self.finish_summary(out['confirmation'])

    def test_source_boot_clock_cache_and_version_changes_refuse_stale_confirmation(self):
        self.interrupted();token=self.check_summary()['confirmation'];artifacts=(self.pending.read_bytes(),self.stage_path.read_bytes())
        for target,changed in [(self.source,self.source.read_bytes()+b'\n'),(self.boot_id,b'11111111-1111-1111-1111-111111111111\n'),
                               (self.clock,b'999\n'),(self.state_file,self.state_file.read_bytes()+b'\n')]:
            old=target.read_bytes();target.write_bytes(changed)
            out=self.repair_call('recovery-summary-check',expected=7 if target==self.source else 0)
            if target!=self.source:self.assertFalse(out['finish_ready'])
            self.finish_summary(token,4 if target!=self.source else 7)
            target.write_bytes(old)
            self.assertEqual((self.pending.read_bytes(),self.stage_path.read_bytes()),artifacts)
        marker=json.loads(self.pending.read_bytes());marker['version']='1.3.0-r128'
        self.pending.write_text(json.dumps(marker,sort_keys=True,separators=(',',':'))+'\n')
        self.assertFalse(self.check_summary()['finish_ready']);self.finish_summary(token,4)

    def test_same_bytes_new_inode_invalidate_confirmation(self):
        self.interrupted();token=self.check_summary()['confirmation'];original=self.pending.read_bytes()
        replacement=self.native.lockdir/'replacement';replacement.write_bytes(original);replacement.chmod(0o600)
        os.replace(replacement,self.pending)
        newer=self.check_summary()['confirmation'];self.assertNotEqual(newer,token);self.finish_summary(token,4)
        self.finish_summary(newer)

    def test_legacy_marker_missing_marker_and_partial_stage_preserved(self):
        self.interrupted();original=self.pending.read_bytes()
        self.pending.write_bytes(b'HGDDNSRECOVERYPENDING1\nSECRET_SENTINEL\n')
        for mutate in [lambda:None,lambda:self.pending.unlink(),lambda:self.pending.write_bytes(original)]:
            mutate()
            if self.pending.exists() and self.pending.read_bytes()==original:self.stage_path.write_bytes(b'PARTIAL')
            before=self.files(self.native.lockdir);out=self.check_summary();self.assertFalse(out['finish_ready'])
            self.assertNotIn('confirmation',out);self.finish_summary('0'*64,4);self.assertEqual(self.files(self.native.lockdir),before)

    def test_foreign_linked_or_unsafe_target_never_overwritten(self):
        self.interrupted();self.record_path.write_bytes(b'SECRET_SENTINEL');self.record_path.chmod(0o600)
        outside=self.base/'foreign-target';outside.write_bytes(b'KEEP');outside.chmod(0o600)
        for kind in ['foreign','symlink','hardlink','mode']:
            if kind!='foreign':
                self.record_path.unlink()
                if kind=='symlink':self.record_path.symlink_to(outside)
                elif kind=='hardlink':os.link(outside,self.record_path)
                else:self.record_path.write_bytes(b'KEEP');self.record_path.chmod(0o644)
            before=self.files(self.native.lockdir);self.assertFalse(self.check_summary()['finish_ready'])
            self.finish_summary('0'*64,4);self.assertEqual(self.files(self.native.lockdir),before);self.assertEqual(outside.read_bytes(),b'KEEP')

    def test_shared_locks_arguments_closed_gates_and_internal_descriptors(self):
        for lock in [self.native.lock,self.store/'.supervisor.lock']:
            with lock.open('rb') as f:
                fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.repair_call('recovery-summary-check',expected=4)
        for args in [('recovery-summary-check','extra'),('recovery-summary-finish','0'*64),('recovery-summary-finish','../path','--confirm'),
                     ('recovery-summary-finish','A'*64,'--confirm'),('recovery-summary-finish','0'*64,'--confirm','extra')]:
            self.repair_call(*args,expected=2)
        p=subprocess.run([self.busybox,'ash',str(self.producer),'repair-check-internal'],env=self.env,capture_output=True,timeout=10)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(4,b'',b''))
        self.repair_control.write_text(self.repair_control.read_text().replace('ddns_recovery_repair_enabled=true','ddns_recovery_repair_enabled=false'))
        self.repair_call('recovery-summary-finish','0'*64,'--confirm',expected=2,env={**self.env,'ddns_recovery_repair_enabled':'true'})
        self.assertFalse(self.pending.exists());self.assertEqual(self.calls,[])

    def test_unknown_dns_business_receipt_and_global_record_survive_closeout(self):
        self.grant()
        def hook(*args):
            if args[0]!='GET':self.seed();return 500,{'success':False,'errors':[]}
        self.hook=hook;self.managed(1);self.hook=None
        self.assertEqual(self.stored()['summary']['unknown'],1);global_before=self.global_record()
        self.fault('fsync','sys.exit(1) if any(a.endswith("/.ddns-recovery-next") for a in sys.argv[1:]) else None')
        self.publish(7);self.restore_tool('fsync')
        cache=self.files(self.state_dir);store=self.files(self.store)
        out=self.check_summary();self.assertTrue(out['finish_ready']);self.finish_summary(out['confirmation'])
        self.assertEqual(self.files(self.state_dir),cache);self.assertEqual(self.files(self.store),store)
        self.assertEqual(self.global_path.read_bytes(),global_before)
        row=next(r for r in self.observe_recovery_cli()['modules'] if r['module']=='ddns')
        self.assertEqual(row['error_kind'],'reconciliation_required');calls=len(self.calls);self.managed(4);self.assertEqual(len(self.calls),calls)

    def test_final_directory_sync_failure_retains_or_restores_marker(self):
        self.interrupted(True);token=self.check_summary()['confirmation'];marker=self.pending.read_bytes()
        self.fault('fsync','sys.exit(1) if len(sys.argv)==2 and sys.argv[1]=='+repr(str(self.native.lockdir))+' else None')
        self.finish_summary(token,7);self.restore_tool('fsync')
        self.assertEqual(self.pending.read_bytes(),marker)
        out=self.check_summary();self.assertEqual(out['stage'],'published');self.finish_summary(out['confirmation'])


def suite(runtime):
    cls=Runtime if runtime else Static
    return unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    r=unittest.TextTestRunner(verbosity=2,failfast=True).run(suite(a.runtime));raise SystemExit(not r.wasSuccessful())
