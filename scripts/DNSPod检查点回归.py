#!/usr/bin/env python3
"""DNSPod adapter for shared checkpoint publication and crash-state contracts."""
import argparse,hashlib,json,os,re,subprocess,unittest
from DNSPod终态回归 import Static as TerminalStatic,Runtime as TerminalRuntime,PROTO,record
from DNS检查点修复回归 import Runtime as SharedRuntime

class Static(TerminalStatic):
    def test_closed_gates_and_shared_shell_grammar(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-dnspod-read.sh','homegate-cloudflare-read.sh','homegate-dns-checkpoint-repair.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error,name)
            self.assertEqual(body.count(b'dnspod_checkpoint_repair_enabled=false'),1)
        self.lua.compile((PROTO/'dnspod-checkpoint.lua').read_bytes());self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_fixed_alias_has_no_remote_call_deletion_or_volatile_inference(self):
        body=(PROTO/'homegate-dns-checkpoint-repair.sh').read_text()
        for forbidden in ['curl','rm ','rmdir','work/context','work/zones','eval ']:self.assertNotIn(forbidden,body)
        for required in ['HGDNPJOURNAL1','HGDNPCVALID1','migration-source-recovery-snapshot-read','dnspod-checkpoint.lua']:self.assertIn(required,body)
    def test_restored_delete_advance_rejects_changed_targets_and_prefix(self):
        before=self.context();before[b'operation']=b'delete';before[b'request'][b'operation']=b'delete';before[b'stage']=b'DeleteRecord'
        before[b'records']=self.lua.table_from([self.stored(1),self.stored(2),self.stored(3)]);before[b'position']=1;before[b'target_id']=b'1'
        after=self.lua.table_from(dict(before.items()));after[b'position']=3;after[b'target_id']=b'3';after[b'affected']=2
        self.assertIsNotNone(self.restore(before));self.assertIsNotNone(self.restore(after));self.assertTrue(self.recovery.advance(before,after,self.codec.json))
        after[b'affected']=1;self.assertIsNone(self.restore(after));after[b'affected']=2;after[b'target_id']=b'2';self.assertIsNone(self.restore(after))
    def test_restored_record_ids_reject_noncanonical_and_inexact_numbers(self):
        c=self.context();c[b'operation']=b'delete';c[b'request'][b'operation']=b'delete';c[b'stage']=b'DeleteRecord'
        c[b'records']=self.lua.table_from([self.stored(1)]);c[b'position']=1;c[b'target_id']=b'1'
        self.assertIsNotNone(self.restore(c))
        for value in [b'0',b'01',b'1e2',b'9007199254740992']:
            c[b'records'][1][b'id']=value;c[b'target_id']=value;self.assertIsNone(self.restore(c),value)

class Runtime(TerminalRuntime):
    def setUp(self):
        super().setUp();self.checkpoint=self.engine.parent/'homegate-dns-checkpoint-repair.sh'
        for p in [self.ali_entry,self.reader,self.checkpoint]:
            body=p.read_text().replace('dnspod_checkpoint_repair_enabled=false','dnspod_checkpoint_repair_enabled=true')
            if p==self.checkpoint:
                mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir)}
                body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
                body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
            p.write_text(body)
    def interrupted(self,where='prepared',second=False,third=False):
        failures={
            'prepared':('fsync','if any(v.endswith("/.prepare/context") for v in sys.argv[1:]):sys.exit(1)'),
            'slot':('fsync','if sys.argv[1:]==['+repr(str(self.journal))+']:sys.exit(1)'),
            'pointer':('fsync','if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)'),
            'rename':('mv','if any(v.endswith("/.next") for v in sys.argv[1:]):sys.exit(1)'),
            'final':('fsync','if sys.argv[1:]==['+repr(str(self.journal))+','+repr(str(self.store))+']:sys.exit(1)')}
        tool,code=failures[where]
        if second or third:
            self.add(*(record(i,value='2001:db8::2') for i in [1,2,3]));seen=[0]
            def hook(action,q):
                if action=='DeleteRecord':
                    seen[0]+=1
                    if seen[0]==(2 if third else 1):self.fault(tool,code)
            self.hook=hook;self.records(self.payload(operation='delete'),expected=1);self.hook=None
        else:self.fault(tool,code);self.records(expected=1)
        self.restore_tool(tool);work=list(self.native.lockdir.glob('.dns-check-*'));self.assertEqual(len(work),1)
        self.oldjob=work[0].name.removeprefix('.dns-check-');return self.oldjob
    def recovery_call(self,action='--collect-receipt',expected=0,account='dns_a',job=None,args=None):
        args=args if args is not None else [account,action,job or self.oldjob,'--confirm']
        p=subprocess.run([self.busybox,'ash',str(self.ali_entry),*args],env=self.env,capture_output=True,timeout=20)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));doc=json.loads(p.stdout);self.assertEqual(doc['ok'],expected==0)
        for value in [b'SECRET_SENTINEL',b'OLD_ID',b'example.test',b'2001:db8::2']:self.assertNotIn(value,p.stdout)
        return doc
    bytes_tree=staticmethod(lambda p:{f.relative_to(p).as_posix():f.read_bytes() for f in p.rglob('*') if f.is_file()})
    repair=SharedRuntime.repair
    resign=SharedRuntime.resign
    reject=SharedRuntime.reject
    def test_changed_frozen_delete_ids_cannot_advance(self):
        job=self.interrupted(second=True);slot=self.journal/'.prepare';p=slot/'context';d=json.loads(p.read_bytes());d['records'][0]['id']='999';p.write_bytes(self.encoded(d));self.resign(slot);self.reject(job)
    def test_all_three_closed_gates_ignore_environment_override(self):
        job=self.interrupted();self.env['dnspod_checkpoint_repair_enabled']='true'
        for p,code in [(self.ali_entry,2),(self.reader,2),(self.checkpoint,7)]:
            raw=p.read_text();p.write_text(raw.replace('dnspod_checkpoint_repair_enabled=true','dnspod_checkpoint_repair_enabled=false'));self.reject(job,code);p.write_text(raw)
    def test_source_change_and_other_provider_format_are_rejected(self):
        job=self.interrupted();raw=self.source.read_bytes();self.source.write_bytes(raw.replace(b'OLD_ID',b'CHANGED'));self.reject(job);self.source.write_bytes(raw)
        p=self.journal/'.prepare/manifest';lines=p.read_bytes().splitlines();lines[0]=b'HGCFJOURNAL1';lines[-1]=hashlib.sha256(b'\n'.join(lines[:-1])+b'\n').hexdigest().encode();p.write_bytes(b'\n'.join(lines)+b'\n');self.reject(job)
    def test_internal_dnspod_alias_requires_borrowed_locks(self):
        job=self.interrupted();before=self.bytes_tree(self.journal);p=subprocess.run([self.busybox,'ash',str(self.checkpoint),'--dnspod-internal','repair-checkpoint','dns_a','3',job],env=self.env,capture_output=True,timeout=5)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(1,b'',b''));self.assertEqual(before,self.bytes_tree(self.journal))
    def test_changed_frozen_line_weight_or_remark_cannot_advance(self):
        job=self.interrupted(second=True);slot=self.journal/'.prepare';p=slot/'context';raw=p.read_bytes()
        for key,value in [('line_id','90=0'),('weight',7),('remark','changed')]:
            d=json.loads(raw);d['records'][0][key]=value;p.write_bytes(self.encoded(d));self.resign(slot);self.reject(job)
        p.write_bytes(raw);self.resign(slot);self.repair(job)

# Run the same filesystem/publication contract under the DNSPod fixture. Provider
# record encoding, gates and fixed internal alias have their own cases above.
for name,value in SharedRuntime.__dict__.items():
    if name.startswith('test_') and name not in {'test_changed_frozen_delete_ids_cannot_advance','test_both_gates_cannot_be_overridden_by_environment','test_no_borrowed_locks_cannot_modify_the_journal'}:
        setattr(Runtime,name,value)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
