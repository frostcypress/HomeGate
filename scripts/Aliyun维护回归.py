#!/usr/bin/env python3
"""Confirmed AliDNS archive retirement and interrupted terminal/work recovery."""
import argparse,hashlib,json,os,re,subprocess,unittest
from Aliyun终态回归 import Static as TerminalStatic,Runtime as TerminalRuntime,PROTO,record

GATES=('aliyun_retention_enabled','aliyun_terminal_repair_enabled','aliyun_orphan_collection_enabled')
class Static(TerminalStatic):
    def test_closed_maintenance_gates_and_shared_shell_grammar(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-aliyun-read.sh','homegate-cloudflare-read.sh','homegate-dns-recovery.sh','homegate-dns-retention.sh','homegate-dns-orphan.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error,name)
        for name in ['homegate-aliyun-read.sh','homegate-cloudflare-read.sh']:
            for gate in GATES:self.assertEqual((PROTO/name).read_text().count(gate+'=false'),1)
        for name in ['aliyun-checkpoint.lua','aliyun-reconcile-plan.lua']:self.lua.compile((PROTO/name).read_bytes())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_orphan_requires_exact_frozen_request_verified_stage_and_id(self):
        c=self.context();w=self.context();w[b'stage']=b'verify-AddDomainRecord';w[b'last_id']=b'5000'
        self.assertTrue(self.recovery.orphan(c,w,c[b'request'],self.codec.json))
        for key,value in [(b'stage',b'AddDomainRecord'),(b'last_id',b'bad'),(b'url',b'https://bad.invalid'),(b'account',b'other')]:
            v=self.lua.table_from(dict(w.items()));v[key]=value;self.assertFalse(self.recovery.orphan(c,v,c[b'request'],self.codec.json),key)
        self.assertFalse(self.recovery.orphan(c,w,self.lua.table_from({}),self.codec.json))
        c[b'stage']=b'UpdateDomainRecord';c[b'first_id']=b'1';w=self.lua.table_from(dict(c.items()));w[b'stage']=b'verify-UpdateDomainRecord';w[b'last_id']=b'2'
        self.assertFalse(self.recovery.orphan(c,w,c[b'request'],self.codec.json));w[b'last_id']=b'1';self.assertTrue(self.recovery.orphan(c,w,c[b'request'],self.codec.json))
    def test_maintenance_has_no_remote_call_or_recursive_deletion(self):
        for name in ['homegate-dns-retention.sh','homegate-dns-orphan.sh']:
            body=(PROTO/name).read_text()
            for forbidden in ['rm -r','curl','eval ','kill ']:self.assertNotIn(forbidden,body)
        body=(PROTO/'homegate-dns-orphan.sh').read_text();self.assertIn('HGALIOrphan1',body);self.assertIn('sign-input sign-output',body)
        self.assertLess(body.index('preflight remaining && quiet'),body.index('rm -f "$work/$name"'))

class Runtime(TerminalRuntime):
    def contents(self):
        return {k:v for k,v in super().contents().items() if k not in ('dns-retirement','.dns-retirement-next','dns-retired','dns-retiring') and not k.startswith('dns-retiring/')}
    def setUp(self):
        super().setUp();self.retention=self.engine.parent/'homegate-dns-retention.sh';self.collector=self.engine.parent/'homegate-dns-orphan.sh'
        for name in ['homegate-aliyun-read.sh','homegate-cloudflare-read.sh','homegate-dns-recovery.sh','homegate-dns-retention.sh','homegate-dns-orphan.sh']:
            p=self.engine.parent/name;s=p.read_text()
            for gate in GATES:s=s.replace(gate+'=false',gate+'=true')
            if p in (self.retention,self.collector):
                mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
                s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
                s=s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
            p.write_text(s)
        self.retiring=self.store/'dns-retiring';self.retire_plan=self.store/'dns-retirement';self.completed=self.store/'dns-retired'
    def maintenance(self,action,expected=0,job=None,account='dns_a',confirmed=True):
        calls=len(self.calls);args=[account,action,job or self.oldjob]+(['--confirm'] if confirmed else [])
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),*args],env=self.env,capture_output=True,timeout=20)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertEqual(len(self.calls),calls)
        for value in [b'SECRET_SENTINEL',b'OLD_ID',b'example.test',b'2001:db8::2']:self.assertNotIn(value,p.stdout)
        doc=json.loads(p.stdout);self.assertEqual(doc['ok'],expected==0)
        if expected==0:self.assertFalse(doc['write_ready'])
        return doc
    def tree(self,p):return {f.relative_to(p).as_posix():f.read_bytes() for f in p.rglob('*') if f.is_file()}
    def archived(self):self.finish();self.collect();return self.oldjob
    def prepared(self,hybrid=False):
        name='mv' if hybrid else 'fsync';suffix='/.terminal-meta' if hybrid else '/.terminal'
        self.fault(name,'if any(v.endswith('+repr(suffix)+') for v in sys.argv[1:]):sys.exit(1)');self.finish(expected=7);self.restore_tool(name)
        self.work=self.native.lockdir/('.dns-check-'+self.oldjob)
    def orphan_ready(self,q=None):
        self.fault('rm','if any(v.endswith("/input") for v in sys.argv[1:]):sys.exit(1)');self.finish(q,expected=7);self.restore_tool('rm')
        self.work=self.native.lockdir/('.dns-check-'+self.oldjob);self.assertEqual(len(list(self.work.iterdir())),9);self.terminal()
    def reject_orphan(self,expected=7):
        before=self.tree(self.journal);work=self.tree(self.work);self.maintenance('--collect-orphan',expected);self.assertEqual(before,self.tree(self.journal));self.assertEqual(work,self.tree(self.work));self.writer(4)
    def test_archive_retirement_frees_capacity_and_is_idempotent(self):
        old=self.archived();self.maintenance('--retire-archive');self.assertFalse(self.archive.exists());self.assertFalse(self.ledger.exists());self.writer()
        self.assertEqual(self.completed.read_text().splitlines()[0],'HGALIRetire1');self.maintenance('--retire-archive');self.writer()
        self.finish(self.payload(value='2001:db8::3'));self.assertNotEqual(old,self.oldjob);self.collect();self.maintenance('--retire-archive');self.writer()
    def test_retirement_preserves_active_next_receipt(self):
        old=self.archived();self.finish(self.payload(value='2001:db8::3'));before=self.journal_bytes();self.maintenance('--retire-archive',job=old)
        self.assertEqual(before,self.journal_bytes());self.writer(4);self.collect();self.writer()
    def test_wrong_archive_confirmation_or_identity_preserves_evidence(self):
        self.archived();before=self.archived_bytes();self.maintenance('--retire-archive',2,confirmed=False);self.maintenance('--retire-archive',7,account='other');self.maintenance('--retire-archive',7,job='999999999');self.assertEqual(before,self.archived_bytes());self.writer()
    def test_corrupt_and_linked_archive_is_not_retired(self):
        self.archived();p=self.archive/'terminal';raw=p.read_bytes();p.write_bytes(raw+b' ');self.maintenance('--retire-archive',7);self.assertFalse(self.retire_plan.exists());p.write_bytes(raw)
        outside=self.base/'outside-terminal';os.link(p,outside);self.maintenance('--retire-archive',7);self.assertEqual(outside.read_bytes(),raw);self.writer(4)
    def test_retirement_rename_failure_resumes_only_after_confirmation(self):
        self.archived();self.fault('mv','if any(v.endswith("/dns-settled") for v in sys.argv[1:]):sys.exit(1)');self.maintenance('--retire-archive',7);self.assertTrue(self.retire_plan.exists());self.writer(4)
        self.restore_tool('mv');self.maintenance('--retire-archive',2,confirmed=False);self.maintenance('--retire-archive');self.writer()
    def test_partial_retirement_revalidates_remaining_hashes(self):
        self.archived();self.fault('rm','if any(v.endswith("/dns-retiring/current") for v in sys.argv[1:]):sys.exit(1)');self.maintenance('--retire-archive',7);self.writer(4);self.assertTrue(self.retiring.exists())
        self.restore_tool('rm');self.maintenance('--retire-archive');self.writer()
    def test_retirement_scratch_keeps_gate_independent_writer_fence(self):
        self.archived();before=self.archived_bytes();self.fault('fsync','if any(v.endswith("/.dns-retirement-next") for v in sys.argv[1:]):sys.exit(1)');self.maintenance('--retire-archive',7);self.assertEqual(before,self.archived_bytes())
        self.retention.write_text(self.retention.read_text().replace('aliyun_retention_enabled=true','aliyun_retention_enabled=false'));self.writer(4)
    def test_prepared_terminal_repair_keeps_original_proof_and_work(self):
        self.prepared();raw=(self.journal/'.terminal').read_bytes();meta=(self.journal/'.terminal-meta').read_bytes();work=self.tree(self.work)
        self.maintenance('--repair-terminal');self.assertEqual(raw,(self.journal/'terminal').read_bytes());self.assertEqual(meta,(self.journal/'terminal-meta').read_bytes());self.assertEqual(work,self.tree(self.work));self.writer(4)
        self.maintenance('--repair-terminal');self.maintenance('--collect-orphan');self.collect();self.writer()
    def test_half_published_terminal_repair(self):
        self.prepared(True);self.maintenance('--repair-terminal');self.terminal();self.maintenance('--collect-orphan');self.collect();self.writer()
    def test_missing_or_corrupt_prepared_pair_cannot_be_inferred(self):
        self.prepared();p=self.journal/'.terminal-meta';raw=p.read_bytes();p.write_bytes(raw+b' ');before=self.journal_bytes();self.maintenance('--repair-terminal',7);self.assertEqual(before,self.journal_bytes())
        p.unlink();before=self.journal_bytes();self.maintenance('--repair-terminal',7);self.assertEqual(before,self.journal_bytes());self.writer(4)
    def test_unknown_observation_cannot_authorize_repair_or_orphan_cleanup(self):
        self.pending();self.maintenance('--repair-terminal',7);self.work=self.old;self.reject_orphan();self.assertFalse((self.journal/'terminal').exists())
    def test_nine_file_orphan_collection_keeps_original_terminal_until_separate_archive(self):
        self.orphan_ready();before=self.journal_bytes();self.collect(4);self.maintenance('--collect-orphan');self.assertFalse(self.work.exists());self.assertEqual(before,self.journal_bytes());self.writer(4);self.collect();self.writer()
    def test_confirmed_multi_delete_and_txt_orphans(self):
        self.add(record(1,value='2001:db8::2'),record(2,value='2001:db8::2'));self.orphan_ready(self.payload(operation='delete'));self.assertEqual(self.terminal()['affected'],2)
        self.maintenance('--collect-orphan');self.collect();self.maintenance('--retire-archive');self.orphan_ready(self.txt());self.maintenance('--collect-orphan');self.collect();self.writer()
    def test_orphan_request_context_and_success_must_match_frozen_proof(self):
        self.orphan_ready()
        for name,key,value in [('input','value','2001:db8::3'),('context','last_id','bad'),('zones','affected',2)]:
            p=self.work/name;raw=p.read_bytes();doc=json.loads(raw);doc[key]=value;p.write_bytes(self.encoded(doc));self.reject_orphan();p.write_bytes(raw)
    def test_missing_extra_and_linked_orphan_members_are_preserved(self):
        self.orphan_ready();p=self.work/'sign-output';outside=self.base/'sign-out';p.rename(outside);self.reject_orphan();p.symlink_to(outside);self.reject_orphan();p.unlink();outside.rename(p)
        extra=self.work/'unexpected';extra.write_bytes(b'keep');extra.chmod(0o600);self.reject_orphan()
    def test_oversized_signing_file_rejected_before_cleanup(self):
        self.orphan_ready();(self.work/'sign-input').write_bytes(b'x'*131073);self.reject_orphan()
    def test_orphan_plan_contains_only_hashes_and_can_resume_partial_cleanup(self):
        self.orphan_ready();self.fault('rm','if any(v.endswith("/sign-output") for v in sys.argv[1:]):sys.exit(1)');self.maintenance('--collect-orphan',7)
        plan=self.journal/'orphan-plan';raw=plan.read_bytes();self.assertEqual(len(raw.splitlines()),19);self.assertTrue(raw.startswith(b'HGALIOrphan1\n'));self.assertFalse((self.work/'input').exists());self.writer(4)
        for value in [b'SECRET_SENTINEL',b'OLD_ID',b'example.test',b'2001:db8::2']:self.assertNotIn(value,raw)
        self.restore_tool('rm');self.maintenance('--collect-orphan');self.assertFalse(self.work.exists());self.collect();self.writer()
    def test_orphan_plan_sync_failure_preserves_all_work_and_resumes(self):
        self.orphan_ready();before=self.tree(self.work);self.fault('fsync','if any(v.endswith("/.orphan-plan") for v in sys.argv[1:]):sys.exit(1)');self.maintenance('--collect-orphan',7);self.assertEqual(before,self.tree(self.work));self.writer(4)
        self.restore_tool('fsync');self.maintenance('--collect-orphan');self.collect();self.writer()
    def test_remaining_sign_hash_tampering_prevents_further_cleanup(self):
        self.orphan_ready();self.fault('rm','if any("/.dns-check-" in v for v in sys.argv[1:]):sys.exit(1)');self.maintenance('--collect-orphan',7);self.restore_tool('rm')
        p=self.work/'sign-output';p.write_bytes(b'changed');self.reject_orphan();self.assertTrue((self.work/'request').exists())
    def test_reused_pid_and_changed_boot_are_not_collected(self):
        self.orphan_ready();p=self.engine.parent/'worker-process.lua';raw=p.read_text();p.write_text('if arg[1]=="info" and arg[2]=="'+self.oldjob+'" then io.write("S:1:2:3:4:0\\n");return end\n'+raw);self.reject_orphan();p.write_text(raw)
        self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.reject_orphan()
    def test_orphan_confirmation_and_all_closed_gates_ignore_environment(self):
        self.orphan_ready();self.maintenance('--collect-orphan',2,confirmed=False);self.env['aliyun_orphan_collection_enabled']='true'
        for p,expected in [(self.ali_entry,2),(self.reader,2),(self.recovery_helper,7),(self.collector,7)]:
            raw=p.read_text();p.write_text(raw.replace('aliyun_orphan_collection_enabled=true','aliyun_orphan_collection_enabled=false'));self.reject_orphan(expected);p.write_text(raw)
    def test_closed_retire_and_repair_gates_preserve_evidence(self):
        self.prepared();raw=self.ali_entry.read_text();self.env['aliyun_terminal_repair_enabled']='true';self.ali_entry.write_text(raw.replace('aliyun_terminal_repair_enabled=true','aliyun_terminal_repair_enabled=false'));self.maintenance('--repair-terminal',2);self.ali_entry.write_text(raw)
        self.maintenance('--repair-terminal');self.maintenance('--collect-orphan');self.collect();self.env['aliyun_retention_enabled']='true';self.retention.write_text(self.retention.read_text().replace('aliyun_retention_enabled=true','aliyun_retention_enabled=false'));before=self.archived_bytes();self.maintenance('--retire-archive',7);self.assertEqual(before,self.archived_bytes());self.writer()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
