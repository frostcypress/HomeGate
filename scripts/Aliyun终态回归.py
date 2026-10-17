#!/usr/bin/env python3
"""AliDNS terminal proof and explicitly confirmed archive; loopback fixtures."""
import argparse,hashlib,json,os,re,shutil,subprocess,unittest
from pathlib import Path
from Aliyun恢复回归 import Static as RecoveryStatic,Runtime as RecoveryRuntime,PROTO,record

class Static(RecoveryStatic):
    def public_receipt(self,**extra):
        data={b'account':b'dns_a',b'configuration_revision':3,b'provider':b'aliyun',b'ok':True,b'effect':b'confirmed',b'error_kind':b'',b'provider_code':b'',b'retryable':False,b'reconciliation_required':False,b'result':b'created',b'affected':1}
        data.update({k.encode():v for k,v in extra.items()});return self.lua.table_from(data)
    def test_terminal_requires_original_success_and_identity(self):
        c=self.context();self.assertTrue(self.recovery.terminal(c,self.public_receipt(),self.codec.json))
        for key,value in [('provider',b'cloudflare'),('account',b'other'),('configuration_revision',2),('effect',b'unknown'),('retryable',True),('reconciliation_required',True),('result',b'updated'),('affected',2),('ok',False)]:
            self.assertFalse(self.recovery.terminal(c,self.public_receipt(**{key:value}),self.codec.json),key)
    def test_final_delete_count_requires_last_matching_target(self):
        c=self.context();c[b'operation']=b'delete';c[b'request'][b'operation']=b'delete';c[b'stage']=b'DeleteDomainRecord';c[b'records']=self.lua.table_from([self.stored(1),self.stored(2)]);c[b'position']=2;c[b'target_id']=b'2';c[b'affected']=1
        self.assertTrue(self.recovery.terminal(c,self.public_receipt(result=b'deleted',affected=2),self.codec.json))
        self.assertFalse(self.recovery.terminal(c,self.public_receipt(result=b'deleted',affected=1),self.codec.json))
        c[b'position']=1;c[b'target_id']=b'1';c[b'affected']=0
        self.assertFalse(self.recovery.terminal(c,self.public_receipt(result=b'deleted',affected=1),self.codec.json))
    def test_closed_gates_shell_lua_and_alias_formats(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-aliyun-read.sh','homegate-cloudflare-read.sh','homegate-dns-recovery.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error,name);self.assertEqual(body.count(b'aliyun_settlement_enabled=false'),1)
        for name in ['aliyun-checkpoint.lua','aliyun-reconcile-plan.lua']:self.lua.compile((PROTO/name).read_bytes())
        body=(PROTO/'homegate-dns-recovery.sh').read_text();self.assertIn('HGALITerminal1',body);self.assertIn('HGALICollection1',body)
        collect=body.split('    collect)\n',1)[1];self.assertLess(collect.index('ledger_write collecting'),collect.index('mv "$journal" "$archive"'));self.assertLess(collect.index('mv "$journal" "$archive"'),collect.index('ledger_write settled'))
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class Runtime(RecoveryRuntime):
    def contents(self):
        return {k:v for k,v in super().contents().items() if not k.startswith('dns-settled/') and k not in ('dns-settled','dns-collection','.dns-collection-next')}
    def setUp(self):
        super().setUp();self.archive=self.store/'dns-settled';self.ledger=self.store/'dns-collection';self.recovery_helper=self.engine.parent/'homegate-dns-recovery.sh'
        for name in ['homegate-aliyun-read.sh','homegate-cloudflare-read.sh','homegate-dns-recovery.sh']:
            p=self.engine.parent/name;s=p.read_text().replace('aliyun_settlement_enabled=false','aliyun_settlement_enabled=true')
            if name=='homegate-dns-recovery.sh':
                mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
                s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
                s=s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
            p.write_text(s)
    def finish(self,q=None,expected=0):
        out=self.records(q,expected);self.oldjob=self.job()
        return out
    def job(self):
        base=self.journal if self.journal.exists() else self.archive;slot=base/('slot-'+(base/'current').read_text().strip());return (slot/'manifest').read_text().splitlines()[6]
    def terminal(self):
        raw=(self.journal/'terminal').read_bytes();meta=(self.journal/'terminal-meta').read_bytes();lines=meta.splitlines();self.assertEqual(len(lines),11)
        self.assertEqual(lines[0],b'HGALITerminal1');self.assertEqual(lines[8],hashlib.sha256((self.journal/('slot-'+(self.journal/'current').read_text().strip())/'manifest').read_bytes()).hexdigest().encode())
        self.assertEqual(lines[9],hashlib.sha256(raw).hexdigest().encode());self.assertEqual(lines[10],hashlib.sha256(b'\n'.join(lines[:10])+b'\n').hexdigest().encode())
        return json.loads(raw)
    def collect(self,expected=0,account='dns_a',job=None,confirmed=True):
        calls=len(self.calls);args=[account,'--collect-receipt',job or self.oldjob]+(['--confirm'] if confirmed else [])
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),*args],env=self.env,capture_output=True,timeout=15)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr));self.assertEqual(p.stderr,b'');self.assertEqual(len(self.calls),calls)
        for secret in [b'SECRET_SENTINEL',b'OLD_ID',b'example.test',b'2001:db8::2']:self.assertNotIn(secret,p.stdout)
        out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0);return out
    def lose_volatile(self):
        old=self.native.lockdir/('.dns-check-'+self.oldjob)
        if old.exists():
            self.assertEqual(old.parent.resolve(),self.native.lockdir.resolve());self.assertTrue(old.resolve().is_relative_to(self.native.base.resolve()));shutil.rmtree(old)
    def archived_bytes(self):return {p.relative_to(self.archive).as_posix():p.read_bytes() for p in self.archive.rglob('*') if p.is_file()}
    def test_success_terminal_and_confirmed_archive_preserve_original_bytes(self):
        self.finish();self.assertEqual(self.terminal()['result'],'created');before=self.journal_bytes();self.blocked()
        out=self.collect();self.assertTrue(out['write_ready']);self.assertFalse(self.journal.exists());self.assertEqual(self.archived_bytes(),before);self.assertEqual(self.ledger.read_text().splitlines()[0],'HGALICollection1');self.writer()
        self.collect();self.assertEqual(self.archived_bytes(),before);self.writer()
    def test_update_and_delete_terminal_results_match_checkpoints(self):
        self.add(record(1),record(2,rr='other'));self.finish();self.assertEqual(self.terminal()['result'],'updated');self.collect();self.writer()
    def test_multi_delete_terminal_has_full_confirmed_count(self):
        self.add(*(record(i,value='2001:db8::2') for i in [1,2,3]));self.finish(self.payload(operation='delete'));self.assertEqual(self.terminal()['affected'],3);self.collect();self.writer()
    def test_unknown_observation_cannot_authorize_archive(self):
        self.pending();self.assertEqual(self.reconcile(durable=True)['observation'],'desired-present');self.assertFalse((self.journal/'terminal').exists());self.lose_volatile();self.collect(7);self.blocked()
    def test_confirmed_terminal_can_be_observed_without_collection(self):
        self.finish();self.saved_journal=self.journal_bytes();self.saved={};self.old=self.native.lockdir/('.dns-check-'+self.oldjob);self.before=len(self.mutations())
        self.assertEqual(self.reconcile(durable=True)['observation'],'desired-present');self.blocked()
    def test_simulated_boot_change_does_not_invalidate_confirmed_archive(self):
        self.finish();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.collect();self.writer()
    def test_wrong_account_job_or_missing_confirmation_is_refused(self):
        self.finish();before=self.journal_bytes();self.collect(7,account='other');self.collect(7,job=str(int(self.oldjob)+1));self.collect(2,confirmed=False);self.assertEqual(self.journal_bytes(),before);self.blocked()
    def test_source_change_blocks_collection(self):
        self.finish();self.source.write_bytes(self.source.read_bytes().replace(b'OLD_ID',b'CHANGED'));self.collect(7);self.blocked()
    def test_terminal_corruption_blocks_archive(self):
        self.finish();p=self.journal/'terminal';p.write_bytes(p.read_bytes().replace(b'"affected":1',b'"affected":2'));self.collect(7);self.blocked()
    def test_terminal_fsync_failure_never_returns_success(self):
        self.fault('fsync','if any(v.endswith("/.terminal") for v in sys.argv[1:]):sys.exit(1)');self.finish(expected=7)
        self.assertTrue((self.journal/'.terminal').is_file());self.assertFalse((self.journal/'terminal').exists());self.lose_volatile();self.collect(7);self.blocked();self.assertEqual(len(self.mutations()),1)
    def test_terminal_second_rename_failure_stays_blocked(self):
        self.fault('mv','if any(v.endswith("/.terminal-meta") for v in sys.argv[1:]):sys.exit(1)');self.finish(expected=7)
        self.assertTrue((self.journal/'terminal').exists());self.assertTrue((self.journal/'.terminal-meta').exists());self.lose_volatile();self.collect(7);self.blocked()
    def test_archive_rename_failure_can_resume_only_after_confirmation(self):
        self.finish();self.fault('mv','if sys.argv[1:]==['+repr(str(self.journal))+','+repr(str(self.archive))+']:sys.exit(1)');self.collect(7);self.blocked();self.assertIn('collecting',self.ledger.read_text())
        self.restore_tool('mv');self.collect();self.writer()
    def test_archive_parent_sync_failure_keeps_writes_fenced_until_resync(self):
        self.finish();self.fault('fsync','from pathlib import Path\nif sys.argv[1:]==['+repr(str(self.store))+'] and Path('+repr(str(self.archive))+').exists():sys.exit(1)')
        self.collect(7);self.writer(4);self.assertTrue(self.archive.exists());self.restore_tool('fsync');self.collect();self.writer()
    def test_archive_guard_revalidates_hashes_with_feature_gate_closed(self):
        self.finish();self.collect();self.recovery_helper.write_text(self.recovery_helper.read_text().replace('aliyun_settlement_enabled=true','aliyun_settlement_enabled=false'));self.writer()
        slot=self.archive/('slot-'+(self.archive/'current').read_text().strip());p=slot/'context';p.write_bytes(p.read_bytes()+b' ');self.writer(4)
    def test_archive_remains_bound_after_configuration_revision_changes(self):
        self.finish();self.collect();before=self.archived_bytes();self.cli('credential-put','aliyun','dns_a','secret',payload=b'NEXT_SECRET');self.writer();self.assertEqual(self.archived_bytes(),before)
    def test_archive_capacity_one_never_overwrites_prior_evidence(self):
        self.finish();self.collect();before=self.archived_bytes();self.db.clear();self.finish();self.collect(7);self.assertEqual(self.archived_bytes(),before);self.blocked()
    def test_closed_collection_gate_ignores_environment_override(self):
        self.finish();self.ali_entry.write_text(self.ali_entry.read_text().replace('aliyun_settlement_enabled=true','aliyun_settlement_enabled=false'))
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),'dns_a','--collect-receipt',self.oldjob,'--confirm'],env={**self.env,'aliyun_settlement_enabled':'true'},capture_output=True,timeout=5)
        self.assertEqual(p.returncode,2);self.assertEqual(p.stderr,b'');self.assertTrue(self.journal.exists());self.blocked()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if r.wasSuccessful() else 1)
