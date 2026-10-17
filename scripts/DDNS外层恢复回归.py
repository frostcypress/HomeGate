#!/usr/bin/env python3
"""Confirmed outer-work collection in private Linux copies, no real DNS calls."""
import argparse,hashlib,json,os,re,subprocess,unittest
from pathlib import Path
from project import ROOT
from DDNS执行回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase,SyncMixin
PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_three_closed_gates_and_grammar(self):
        import tree_sitter,tree_sitter_bash
        p=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-ddns-work.sh','homegate-ddns-read.sh','homegate-cloudflare-read.sh']:
            b=(PROTO/n).read_bytes();self.assertEqual(b.count(b'ddns_work_enabled=false'),1);self.assertNotIn(b'\r',b);self.assertFalse(p.parse(b).root_node.has_error,n)
        from lupa.lua51 import LuaRuntime
        LuaRuntime().compile((PROTO/'homegate-ddns-sync.lua').read_bytes())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_full_validation_precedes_fixed_member_removal(self):
        s=(PROTO/'homegate-ddns-work.sh').read_text()
        self.assertLess(s.index('preflight remaining && quiet'),s.index('rm -f "$work/$name"'));self.assertIn('source_check && terminal_check',s)
        for forbidden in ['rm -r','kill ','curl','wget','eval ','rm -f "$store','rm -f "$journal']:self.assertNotIn(forbidden,s)
    def test_origin_is_published_before_dispatch_and_job_is_preserved(self):
        s=(PROTO/'homegate-ddns-read.sh').read_text();self.assertLess(s.index('homegate-ddns-work.sh" "$bind"'),s.index('effect=unknown;result=0'))
        c=(PROTO/'homegate-cloudflare-read.sh').read_text();self.assertIn('job=$ddns_job',c);self.assertIn('[ "$2" = "$ddns_job" ]',c);self.assertLess(c.index('homegate-ddns-work.sh" "$work_check"'),c.index('job=$$'))
    def test_recovery_rebinds_request_and_original_provider_context(self):
        s=(PROTO/'homegate-ddns-sync.lua').read_text();self.assertIn('recovery.restore(snapshot,entry.account',s);self.assertIn('codec.json(context.request)~=codec.json(entry.request)',s)
        s=(PROTO/'homegate-ddns-work.sh').read_text();self.assertIn('HGDDNSWORK1',s);self.assertIn('HGDDNSCOLLECT1',s);self.assertIn('orphan-check',s);self.assertIn('migration-source-recovery-snapshot-read',s)

class WorkMixin:
    def setUp(self):
        super().setUp();self.helper=self.engine.parent/'homegate-ddns-work.sh'
        p=self.engine.parent/'homegate-dns-recovery.sh';s=p.read_text();gate={'cloudflare':'dns','aliyun':'aliyun','dnspod':'dnspod','huaweicloud':'huaweicloud'}[self.provider]+'_orphan_collection_enabled';p.write_text(s.replace(gate+'=false',gate+'=true'))
    def files(self,p):return {q.relative_to(p).as_posix():(q.stat().st_mode&0o777,q.stat().st_ino,q.read_bytes() if q.is_file() else None) for q in p.rglob('*')}
    def locate(self):
        dirs=list(self.native.lockdir.glob('.ddns-plan-*'));self.assertEqual(len(dirs),1);self.outer=dirs[0];self.oldjob=self.outer.name.rsplit('-',1)[1];self.collection=self.native.lockdir/('.ddns-collect-'+self.oldjob);self.journal=self.store/'dns-operation'
    def pending_success(self):
        self.fault('rm','sys.exit(1) if any("/.ddns-plan-" in a and a.endswith("/input") for a in sys.argv[1:]) else None')
        self.sync_call(7);self.restore_tool('rm');self.locate();self.assertEqual(json.loads((self.outer/'provider').read_bytes())['effect'],'confirmed')
        slot=self.journal/('slot-'+(self.journal/'current').read_text().strip());self.assertEqual((slot/'manifest').read_text().splitlines()[6],self.oldjob)
        self.original_journal=self.files(self.journal);self.http_before=len(self.calls)
    def collect(self,expected=0,args=None,env=None):
        before=len(self.calls);p=subprocess.run([self.busybox,'ash',str(self.entry),*(args if args is not None else ['--collect-work',self.oldjob,'--confirm'])],env=env or self.env,capture_output=True,timeout=12)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertEqual(len(self.calls),before)
        if p.stdout:
            out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
            for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',b'pppoe-wan']:self.assertNotIn(marker,p.stdout)
        else:out=None
        return out
    def test_confirmed_collection_preserves_dns_and_is_idempotent(self):
        self.pending_success();out=self.collect();self.assertTrue(out['outer_collected']);self.assertFalse(out['write_ready']);self.assertFalse(self.outer.exists());self.assertTrue(self.collection.is_file());self.assertEqual(self.files(self.journal),self.original_journal);self.collect();self.cli('writer-check',expected=4)
    def test_unknown_is_never_collected_or_retried(self):
        SyncMixin.test_unknown_mutation_is_durable_and_not_retried(self);self.locate();before=self.files(self.outer);j=self.files(self.journal);self.collect(7);self.assertEqual(self.files(self.outer),before);self.assertEqual(self.files(self.journal),j);self.assertFalse(self.collection.exists())
    def test_partial_collection_resumes_only_from_valid_plan(self):
        self.pending_success();self.fault('rm','sys.exit(1) if any("/.ddns-plan-" in a and a.endswith("/input") for a in sys.argv[1:]) else None');self.collect(7);self.restore_tool('rm');self.assertFalse((self.outer/'provider').exists());self.assertTrue(self.collection.exists());self.collect();self.assertFalse(self.outer.exists());self.assertEqual(self.files(self.journal),self.original_journal)
    def test_extra_member_refuses_before_any_delete(self):
        self.pending_success();p=self.outer/'unexpected';p.write_bytes(b'KEEP');p.chmod(0o600);before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before);p.unlink();self.collect();self.assertEqual(self.files(self.journal),self.original_journal)

class CF(WorkMixin,CFBase):pass
class Ali(WorkMixin,AliBase):pass
class DNP(WorkMixin,DNPBase):pass
class HW(WorkMixin,HWBase):pass

class Boundaries(CF):
    def test_prior_collection_path_blocks_new_job_before_dispatch(self):
        p=self.ip;s=p.read_text();s+='\nfor d in Path('+repr(str(self.native.lockdir))+').glob(".ddns-plan-*"):\n q=d.parent/(".ddns-collect-"+d.name.rsplit("-",1)[1]);q.write_bytes(b"OLD");q.chmod(0o600)\n';p.write_text(s);self.sync_call(7);self.assertEqual(self.calls,[]);self.assertFalse((self.store/'dns-operation').exists())
    def test_confirmation_grammar_and_gate_cannot_be_bypassed(self):
        self.pending_success();before=self.files(self.outer)
        for args in [['--collect-work',self.oldjob],['--collect-work',self.oldjob,'no'],['--collect-work','../x','--confirm'],['--collect-work','01','--confirm'],['--collect-work',self.oldjob,'--confirm','extra']]:self.collect(2,args)
        self.helper.write_text(self.helper.read_text().replace('ddns_work_enabled=true','ddns_work_enabled=false'));self.collect(2,env={**self.env,'ddns_work_enabled':'true'});self.assertEqual(self.files(self.outer),before)
    def test_missing_origin_from_old_draft_is_retained(self):
        self.pending_success();(self.outer/'binding').unlink();before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before)
    def test_boot_change_and_source_change_are_refused(self):
        self.pending_success();before=self.files(self.outer);boot=self.boot_id.read_bytes();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.collect(7);self.boot_id.write_bytes(boot);self.source.write_bytes(self.source.read_bytes().replace(b'SECRET_SENTINEL',b'CHANGED'));self.collect(7);self.assertEqual(self.files(self.outer),before)
    def test_modified_binding_and_frozen_members_refused(self):
        self.pending_success()
        for name in ['binding','plan','intent','result','input']:
            p=self.outer/name;old=p.read_bytes();p.write_bytes(old+b'X');before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before);p.write_bytes(old)
    def test_unknown_publication_does_not_authorize_collection(self):
        self.pending_success();p=self.outer/'provider';d=json.loads(p.read_bytes());d.update(ok=False,effect='unknown',result='failed',error_kind='temporary',affected=0,reconciliation_required=True);p.write_text(json.dumps(d,separators=(',',':'))+'\n');before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before)
    def test_missing_or_corrupt_terminal_is_retained(self):
        self.pending_success();p=self.journal/'terminal';old=p.read_bytes();p.write_bytes(old+b'X');before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before);p.write_bytes(old);p.unlink();self.collect(7);self.assertEqual(self.files(self.outer),before)
    def test_links_permissions_oversize_and_missing_members_refuse(self):
        self.pending_success();p=self.outer/'public';saved=self.base/'saved-public';p.rename(saved)
        try:
            p.symlink_to(saved);self.collect(7);p.unlink();os.link(saved,p);self.collect(7);p.unlink();p.write_bytes(b'x'*65537);p.chmod(0o600);self.collect(7);p.unlink();self.collect(7)
        finally:
            if p.exists() or p.is_symlink():p.unlink()
            saved.rename(p)
        p.chmod(0o644);self.collect(7);p.chmod(0o600);self.collect()
    def test_directory_inode_change_refuses(self):
        self.pending_success();old=self.outer.with_name(self.outer.name+'-saved');self.outer.rename(old);self.outer.mkdir(mode=0o700)
        for p in old.iterdir():q=self.outer/p.name;q.write_bytes(p.read_bytes());q.chmod(0o600)
        before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before)
    def test_live_or_reused_pid_is_never_signalled(self):
        self.pending_success();p=self.engine.parent/'worker-process.lua';s=p.read_text();p.write_text("if arg[1]=='info' and arg[2]=='"+self.oldjob+"' then io.write('R:1:1:1:999:0\\n');return end\n"+s);before=self.files(self.outer);self.collect(4);self.assertEqual(self.files(self.outer),before)
    def test_complete_unpublished_plan_resumes_after_fsync_failure(self):
        self.pending_success();self.fault('fsync','sys.exit(1) if any("/.ddns-collect-" in a and a.endswith(".next") for a in sys.argv[1:]) else None');before=self.files(self.outer);self.collect(7);self.restore_tool('fsync');self.assertEqual(self.files(self.outer),before);self.assertTrue(Path(str(self.collection)+'.next').exists());self.collect();self.assertFalse(self.outer.exists())
    def test_plan_rename_and_post_publish_sync_failure_resume(self):
        self.pending_success();self.fault('mv','sys.exit(1) if any("/.ddns-collect-" in a for a in sys.argv[1:]) else None');self.collect(7);self.restore_tool('mv');self.collect();self.assertFalse(self.outer.exists())
    def test_remaining_hash_and_source_rechecked_after_partial_delete(self):
        self.pending_success();self.fault('rm','sys.exit(1) if any("/.ddns-plan-" in a and a.endswith("/input") for a in sys.argv[1:]) else None');self.collect(7);self.restore_tool('rm');p=self.outer/'input';old=p.read_bytes();p.write_bytes(old+b'X');before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before);p.write_bytes(old);self.source.write_bytes(self.source.read_bytes().replace(b'SECRET_SENTINEL',b'CHANGED'));before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before)
    def test_tampered_plan_and_terminal_binding_stop_resume(self):
        self.pending_success();self.fault('rm','sys.exit(1) if any("/.ddns-plan-" in a and a.endswith("/input") for a in sys.argv[1:]) else None');self.collect(7);self.restore_tool('rm');old=self.collection.read_bytes();self.collection.write_bytes(old+b'X');before=self.files(self.outer);self.collect(7);self.assertEqual(self.files(self.outer),before);self.collection.write_bytes(old);p=self.journal/'terminal-meta';p.write_bytes(p.read_bytes()+b'X');self.collect(7);self.assertEqual(self.files(self.outer),before)

Runtime=CF
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();suite=unittest.TestSuite()
    for cls in ([CF,Ali,DNP,HW,Boundaries] if a.runtime else [Static]):
        methods=Boundaries.__dict__ if cls is Boundaries else WorkMixin.__dict__ if a.runtime else Static.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v))
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
