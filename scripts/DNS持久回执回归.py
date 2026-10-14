#!/usr/bin/env python3
"""Durable DNS checkpoints and writer fences; private Linux loopback fixtures."""
import argparse,hashlib,json,os,re,shutil,subprocess,unittest
from pathlib import Path
from Cloudflare核对回归 import Runtime as ReconcileRuntime
from Cloudflare记录回归 import Static as RecordStatic,PROTO,rec

class Static(RecordStatic):
    def setUp(self):
        super().setUp();self.receipt=self.lua.execute((PROTO/'cloudflare-receipt.lua').read_bytes())
    def test_allowlist_excludes_credentials_and_transport_state(self):
        q=self.ddns();c=self.bind(q);c[b'request']=self.lua.table_from(q,recursive=True);c[b'attempted']=True;c[b'stage']=b'create'
        c[b'token']=b'PRIVATE_SENTINEL';c[b'url']=b'https://bad.invalid';c[b'headers']=b'PRIVATE_SENTINEL'
        out=self.receipt.export(c);body=self.codec.json(out);self.assertNotIn(b'PRIVATE_SENTINEL',body);self.assertNotIn(b'url',body)
        self.assertEqual(out[b'request'][b'value'],b'2001:db8::2');self.assertTrue(out[b'attempted'])
    def test_no_checkpoint_for_reads_or_reconciliation(self):
        for stage,attempted,reconciliation in [(b'zones',False,None),(b'records',True,None),(b'create',False,None),(b'create',True,True)]:
            c=self.bind(self.ddns());c[b'request']=self.lua.table_from(self.ddns());c[b'stage']=stage;c[b'attempted']=attempted;c[b'reconciliation']=reconciliation
            self.assertIsNone(self.receipt.export(c))
    def test_closed_receipt_gates_and_checked_publish_order(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-dns-receipt.sh','homegate-cloudflare-read.sh','homegate-cloudflare-worker.sh','homegate-service-observer-watchdog.sh']:
            body=(PROTO/n).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error);self.assertEqual(body.count(b'dns_receipt_enabled=false'),1)
        s=(PROTO/'homegate-dns-receipt.sh').read_text();self.assertLess(s.index('fsync "$stage/context"'),s.index('mv "$stage" "$inactive"'))
        self.assertLess(s.index('fsync "$journal/.next"'),s.index('mv -f "$journal/.next" "$journal/current"'))
        w=(PROTO/'homegate-cloudflare-worker.sh').read_text();loop=w.split('while [ "$step"',1)[1];self.assertLess(loop.index('homegate-dns-receipt.sh'),loop.index('ready=$(fetch'))
        self.assertIn('9>&- 6>&- 7>&-',w);self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_presence_fences_writers_independent_of_recovery_gate(self):
        s=(PROTO/'homegate-config-prototype.sh').read_text();barrier=s.split('Presence alone fences',1)[1].split('    if [ "$persistent_mode"',1)[0]
        self.assertNotIn('enabled',barrier);self.assertIn('DNS operation requires explicit durable recovery',barrier)
        self.assertIn('dns_recovery_read_enabled=false',s);self.assertIn('"write_ready":false,"read_ready":true',s)

class Runtime(ReconcileRuntime):
    def setUp(self):
        super().setUp();self.journal=self.store/'dns-operation';self.helper=self.engine.parent/'homegate-dns-receipt.sh'
        for n in ['homegate-cloudflare-read.sh','homegate-cloudflare-worker.sh','homegate-service-observer-watchdog.sh','homegate-dns-receipt.sh']:
            p=self.engine.parent/n;s=p.read_text().replace('dns_receipt_enabled=false','dns_receipt_enabled=true')
            if n=='homegate-service-observer-watchdog.sh':s=s.replace('action=cloudflare-check; budget=4','action=cloudflare-check; budget=8')
            if n=='homegate-dns-receipt.sh':
                mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
                s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
                s=s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
            p.write_text(s)
        self.engine.write_text(self.engine.read_text().replace('dns_recovery_read_enabled=false','dns_recovery_read_enabled=true'))
    def preserved(self):
        self.assertEqual({p.relative_to(self.store).as_posix():p.read_bytes() for p in self.store.rglob('*') if p.is_file() and self.journal not in p.parents},self.baseline)
    def active(self):
        pointer=(self.journal/'current').read_bytes();self.assertIn(pointer,[b'1\n',b'2\n']);slot=self.journal/('slot-'+pointer.decode().strip())
        raw=(slot/'context').read_bytes();meta=(slot/'manifest').read_bytes();lines=meta.splitlines();self.assertEqual(len(lines),10)
        self.assertEqual(lines[0:2],[b'HGCFJOURNAL1',b'homegate']);self.assertEqual(lines[2],hashlib.sha256(self.identity.read_bytes()).hexdigest().encode())
        self.assertEqual(lines[3]+b'\n',self.boot_id.read_bytes());self.assertEqual(lines[4],(self.store/'current').read_bytes().strip());self.assertEqual(lines[5],b'dns_a')
        self.assertEqual(lines[7],hashlib.sha256((self.store/('gen-'+lines[4].decode())/'manifest').read_bytes()).hexdigest().encode())
        self.assertEqual(lines[8],hashlib.sha256(raw).hexdigest().encode());self.assertEqual(lines[9],hashlib.sha256(b'\n'.join(lines[:9])+b'\n').hexdigest().encode())
        for p in [self.journal,*self.journal.rglob('*')]:
            self.assertFalse(p.is_symlink());self.assertEqual(p.stat().st_mode&0o777,0o700 if p.is_dir() else 0o600)
            if p.is_file():self.assertEqual(p.stat().st_nlink,1);self.assertNotIn(b'PRIVATE_SENTINEL',p.read_bytes())
        d=json.loads(raw);self.assertNotIn('token',d);return d,raw
    def blocked(self):
        self.writer(4);self.cli('writer-check',expected=4);self.cli('credential-delete','cloudflare','dns_a','secret',expected=4)
        self.cli('preview',payload=self.business,expected=4);self.cli('cancel',expected=4);self.records(expected=4);self.check(4)
    def no_http_mutation(self,code):
        self.fault('fsync',code);r=self.records(expected=7);self.assertEqual(self.mutations(),[]);self.assertEqual(r['effect'],'unknown');self.assertTrue(self.journal.exists());self.blocked();self.preserved()
    def test_checkpoint_is_durable_and_bound_before_first_http_mutation(self):
        def hook(method,*args):
            if method=='POST':self.assertEqual(self.active()[0]['stage'],'create')
        self.hook=hook;self.records();self.active();self.blocked();self.preserved()
    def test_unknown_mutation_can_be_observed_but_durable_barrier_is_retained(self):
        self.pending();before={p.relative_to(self.journal).as_posix():p.read_bytes() for p in self.journal.rglob('*') if p.is_file()}
        self.assertEqual(self.reconcile()['observation'],'desired-present');self.blocked();self.preserved()
        self.assertEqual(before,{p.relative_to(self.journal).as_posix():p.read_bytes() for p in self.journal.rglob('*') if p.is_file()})
    def test_volatile_loss_and_simulated_new_boot_do_not_remove_persistent_block(self):
        self.pending();before=(self.journal/'current').read_bytes()
        assert self.old.resolve().is_relative_to(self.base.resolve());shutil.rmtree(self.old)
        self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.blocked();self.assertEqual((self.journal/'current').read_bytes(),before)
    def test_context_file_fsync_failure_prevents_http_mutation(self):
        self.no_http_mutation('if any(v.endswith("/.prepare/context") for v in sys.argv[1:]):sys.exit(1)')
    def test_manifest_file_fsync_failure_prevents_http_mutation(self):
        self.no_http_mutation('if any(v.endswith("/.prepare/manifest") for v in sys.argv[1:]):sys.exit(1)')
    def test_stage_directory_fsync_failure_prevents_http_mutation(self):
        self.no_http_mutation('if any(v.endswith("/.prepare") for v in sys.argv[1:]):sys.exit(1)')
    def test_journal_parent_fsync_failure_before_checkpoint_prevents_mutation(self):
        self.no_http_mutation('if sys.argv[1:]==['+repr(str(self.store))+']:sys.exit(1)')
    def test_slot_directory_publication_failure_preserves_barrier(self):
        self.fault('mv','if any(v.endswith("/.prepare") for v in sys.argv[1:]):sys.exit(1)');self.records(expected=7)
        self.assertEqual(self.mutations(),[]);self.assertTrue((self.journal/'.prepare/context').is_file());self.blocked()
    def test_slot_parent_fsync_failure_prevents_http_mutation(self):
        self.no_http_mutation('from pathlib import Path\nif sys.argv[1:]==['+repr(str(self.journal))+'] and Path('+repr(str(self.journal/'slot-1'))+').exists():sys.exit(1)')
    def test_pointer_file_fsync_failure_prevents_http_mutation(self):
        self.no_http_mutation('if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)')
    def test_pointer_rename_failure_keeps_private_checkpoint_and_block(self):
        self.fault('mv','if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)');self.records(expected=7)
        self.assertEqual(self.mutations(),[]);self.assertTrue((self.journal/'slot-1/context').is_file());self.blocked()
    def test_final_directory_fsync_failure_never_sends_mutation(self):
        self.no_http_mutation('if sys.argv[1:]==['+repr(str(self.journal))+','+repr(str(self.store))+']:sys.exit(1)')
    def test_three_deletions_rotate_two_slots_and_keep_frozen_plan(self):
        self.add(*(rec(i,value='2001:db8::2') for i in [1,2,3]));self.records(self.payload(operation='delete'))
        d,_=self.active();self.assertEqual((d['position'],d['affected'],len(d['delete_ids'])),(3,2,3));self.assertEqual(self.db,{})
        self.assertEqual({p.name for p in self.journal.iterdir()},{'current','slot-1','slot-2'});self.assertEqual(len(self.mutations()),3);self.blocked()
    def test_failed_second_checkpoint_keeps_first_active_evidence(self):
        self.add(rec(1,value='2001:db8::2'),rec(2,value='2001:db8::2'));saved=[]
        def hook(method,*args):
            if method=='DELETE' and not saved:
                saved.append(self.active()[1]);self.fault('fsync','if any(v.endswith("/.prepare/context") for v in sys.argv[1:]):sys.exit(1)')
        self.hook=hook;self.records(self.payload(operation='delete'),expected=7)
        self.assertEqual(self.active()[1],saved[0]);self.assertEqual(len(self.mutations()),1);self.blocked()
    def test_store_identity_change_between_mutations_prevents_next_delete(self):
        self.add(rec(1,value='2001:db8::2'),rec(2,value='2001:db8::2'))
        def hook(method,*args):
            if method=='DELETE':self.write_identity(identity='b'*32)
        self.hook=hook;self.records(self.payload(operation='delete'),expected=7);self.assertEqual(len(self.mutations()),1);self.blocked()
    def test_interrupted_scratch_blocks_next_checkpoint_without_collection(self):
        self.add(rec(1,value='2001:db8::2'),rec(2,value='2001:db8::2'))
        def hook(method,*args):
            if method=='DELETE':(self.journal/'.prepare').mkdir(mode=0o700)
        self.hook=hook;self.records(self.payload(operation='delete'),expected=7);self.assertEqual(len(self.mutations()),1);self.blocked()
    def test_internal_checkpoint_requires_existing_work_and_loaned_locks(self):
        p=subprocess.run([self.busybox,'ash',str(self.helper),'checkpoint','dns_a','3','999999999'],env=self.env,capture_output=True,timeout=5)
        self.assertEqual(p.returncode,1);self.assertEqual(p.stdout+p.stderr,b'');self.assertFalse(self.journal.exists());self.assertEqual(self.calls,[])
    def test_malformed_or_symlink_receipt_still_blocks_native_and_config_writers(self):
        self.journal.symlink_to(self.base/'missing');self.blocked();self.assertTrue(self.journal.is_symlink());self.assertEqual(self.calls,[])
    def test_service_recovery_is_fenced_before_any_service_action(self):
        self.records();self.engine.write_text(self.engine.read_text().replace('service_actions_enabled=false','service_actions_enabled=true').replace('production_writes_enabled=false','production_writes_enabled=true'))
        self.cli('service-recover',expected=4);self.blocked()
    def test_receipt_helper_gate_cannot_be_enabled_by_environment(self):
        self.helper.write_text(self.helper.read_text().replace('dns_receipt_enabled=true','dns_receipt_enabled=false'));self.env['dns_receipt_enabled']='true'
        self.records(expected=7);self.assertFalse(self.journal.exists());self.assertEqual(self.mutations(),[])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
