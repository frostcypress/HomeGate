#!/usr/bin/env python3
"""One shared sample, scoped existing workers, per-rule pacing and global fences."""
import argparse,copy,json,os,re,subprocess,unittest
from project import ROOT
from DDNS多规则授权回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase
from DDNS运行授权回归 import Static as BaseStatic
from DDNS计划回归 import fixture_uid
PROTO=ROOT/'project/core/prototype'

class Static(BaseStatic):
    def setUp(self):
        super().setUp();self.batch=self.lua.execute((PROTO/'ddns-batch.lua').read_bytes());self.sync=self.lua.execute((PROTO/'ddns-sync.lua').read_bytes())
    def example(self):
        s=self.frame_snapshot();sections=s[b'configuration'];n=len(sections)
        sections[n+1]=self.table({'kind':'ddns_rule','name':'ddns_b','values':{'account':'dns_a','zone':'example.test','host':'www.example.test','type':'AAAA','source':'auto','ttl':'600'}})
        intent,_=self.authority.intent(s,b'ddns_a,ddns_b',self.planner.id)
        plan=self.planner.build(s,b'',lambda:self.table({'address':'2001:db8::2','device':'pppoe-wan','source':'public-ip'}),self.records,intent)
        return s,intent,plan
    def slice(self,s,i,p,name=b'ddns_b'):return self.batch.slice(s,i,p,name,self.planner,self.authority,self.network,self.records,self.codec.json)
    def test_rebuild_full_plan_then_narrow_selected_rule_and_intent(self):
        s,i,p=self.example();before=self.codec.json(s);plan,intent=self.slice(s,i,p);self.assertEqual(len(plan[b'entries']),1);self.assertEqual(plan[b'selected'],b'ddns_b');self.assertEqual(dict(intent[b'switches'].items()),{b'ddns_a':b'0',b'ddns_b':b'1'});self.assertEqual(self.codec.json(s),before)
        self.assertIsNone(self.slice(s,i,p,b'missing'))
        p[b'entries'][2][b'request'][b'value']=b'2001:db8::9';self.assertIsNone(self.slice(s,i,p))
    def test_nonpublic_address_extra_fields_and_foreign_intent_are_rejected(self):
        for value in [b'fc00::1',b'::ffff:192.0.2.1',b'2001:::1']:
            s,i,p=self.example();p[b'entries'][1][b'request'][b'value']=value;self.assertIsNone(self.slice(s,i,p))
        s,i,p=self.example();p[b'extra']=b'SECRET_SENTINEL';self.assertIsNone(self.slice(s,i,p))
        s,i,p=self.example();i[b'switches'][b'ddns_b']=b'0';self.assertIsNone(self.slice(s,i,p))
    def test_rows_only_accept_canonical_bound_existing_receipts(self):
        raw=b'{"api_version":1,"prototype":true,"ok":true,"phase":"dns-provider","provider":"cloudflare","account":"a","configuration_revision":3,"check_scope":"record-operation","error_kind":"","retryable":false,"provider_code":"","result":"unchanged","effect":"none","affected":0,"reconciliation_required":false}\n'
        result,_=self.sync.result(raw,self.table(json.loads(raw)),b'cloudflare',b'a',b'3',b'ddns_a',b'0')
        row,effect=self.batch.row(result,self.table(json.loads(result)),b'3',b'ddns_a',b'0',self.planner,self.sync,lambda raw:self.table(json.loads(raw)))
        self.assertEqual(effect,b'none');self.assertEqual(json.loads(row)['status'],'unchanged')
        for key,value in [('extra','SECRET_SENTINEL'),('effect','confirmed'),('rule','other')]:
            doc=json.loads(result);doc[key]=value;bad=json.dumps(doc,separators=(',',':')).encode()+b'\n';self.assertIsNone(self.batch.row(bad,self.table(doc),b'3',b'ddns_a',b'0',self.planner,self.sync,lambda raw:self.table(json.loads(raw))))
    def test_gates_fixed_parent_descriptors_shell_lua_and_no_production_install(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-ddns-batch.sh','homegate-ddns-state.sh','homegate-ddns-read.sh']:
            body=(PROTO/name).read_bytes();self.assertEqual(body.count(b'ddns_batch_enabled=false'),1);self.assertFalse(parser.parse(body).root_node.has_error,name);self.assertNotIn(b'\r',body)
        for name in ['ddns-batch.lua','homegate-ddns-batch.lua']:self.lua.compile((PROTO/name).read_bytes())
        for name in ['homegate-ddns-state.sh','homegate-ddns-read.sh']:self.assertIn('= 0:600:0 ]',(PROTO/name).read_text())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class BatchMixin:
    def setUp(self):
        super().setUp();self.batch_helper=self.engine.parent/'homegate-ddns-batch.sh';self.state_helper=self.engine.parent/'homegate-ddns-state.sh';self.state_dir=self.native.lockdir/'ddns-state';self.clock=self.base/'batch-clock';self.clock.write_text('1000\n')
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        for helper in [self.batch_helper,self.state_helper]:
            body=helper.read_text().replace('ddns_batch_enabled=false','ddns_batch_enabled=true').replace('ddns_state_enabled=false','ddns_state_enabled=true')
            body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
            if helper==self.state_helper:body=body.replace('now=$(lua "$dir/worker-process.lua" now 2>/dev/null)','now=$(cat '+str(self.clock)+')')
            helper.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
        self.entry.write_text(fixture_uid(self.entry.read_text().replace('ddns_batch_enabled=false','ddns_batch_enabled=true')))
        self.baseline_config=self.config_bytes()
    def batch_call(self,expected=0,args=None,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.batch_helper),*(args if args is not None else ['sync','--confirm'])],env=env or self.env,capture_output=True,timeout=55)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0);self.assertFalse(out['write_ready'])
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',b'pppoe-wan',b'identity',b'generation',b'grant']:self.assertNotIn(marker,p.stdout)
        self.assertEqual(self.config_bytes(),self.baseline_config);return out
    def state_call(self,*args,expected=0):
        p=subprocess.run([self.busybox,'ash',str(self.state_helper),*args],env=self.env,capture_output=True,timeout=20);self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));return json.loads(p.stdout)
    def test_two_noops_share_sample_and_whole_batch_waits_without_sampling(self):
        self.seed();out=self.batch_call();self.assertEqual([r['status'] for r in out['rules']],['unchanged','unchanged']);self.assertTrue(out['sampled']);self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes'])
        before=len(self.calls);out=self.batch_call(4);self.assertFalse(out['sampled']);self.assertEqual([r['status'] for r in out['rules']],['waiting','waiting']);self.assertEqual(len(self.calls),before)
        self.clock.write_text('1300\n');self.batch_call();self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes']*2);self.assertEqual(self.mutations(),[])
    def test_confirmed_change_blocks_remaining_rule_until_explicit_closeout(self):
        out=self.batch_call(4);self.assertEqual([r['status'] for r in out['rules']],['created','blocked']);self.assertEqual(out['effect'],'confirmed');self.assertEqual(len(self.mutations()),1)
        before=self.files(self.journal);n=len(self.calls);sample=self.netlog.read_bytes();self.batch_call(4);self.assertEqual(len(self.calls),n);self.assertEqual(self.netlog.read_bytes(),sample);self.assertEqual(self.files(self.journal),before)
        self.maintenance('collect-receipt');self.maintenance('retire-archive');out=self.batch_call(4);self.assertEqual([r['status'] for r in out['rules']],['waiting','unchanged']);self.assertEqual(len(self.mutations()),1)
    def test_unknown_first_rule_preserves_evidence_and_never_retries_batch(self):
        def hook(*args):
            action=args[0];mutation=action not in ['GET'] if self.provider in ['cloudflare','huaweicloud'] else action==('AddDomainRecord' if self.provider=='aliyun' else 'CreateRecord')
            if mutation:self.seed();return 500,{'success':False,'errors':[],'Code':'InternalError','code':'busy','Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
        self.hook=hook;out=self.batch_call(1);self.hook=None;self.assertEqual(out['effect'],'unknown');self.assertEqual([r['status'] for r in out['rules']],['failed','blocked']);self.assertEqual(len(self.db),1)
        n=len(self.calls);before=self.files(self.journal);self.clock.write_text('999999999\n');self.batch_call(4);self.assertEqual(len(self.calls),n);self.assertEqual(before,self.files(self.journal));self.cli('writer-check',expected=4)

class CF(BatchMixin,CFBase):pass
class Ali(BatchMixin,AliBase):pass
class DNP(BatchMixin,DNPBase):pass
class HW(BatchMixin,HWBase):pass

class Boundaries(CF):
    def test_closed_gate_and_cli_cannot_be_enabled_by_environment(self):
        for args in [[],['sync'],['sync','bad'],['sync','--confirm','ddns_a'],['../bad','--confirm']]:self.batch_call(2,args)
        self.batch_helper.write_text(self.batch_helper.read_text().replace('ddns_batch_enabled=true','ddns_batch_enabled=false'));self.batch_call(2,env={**self.env,'ddns_batch_enabled':'true'});self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
    def test_internal_calls_without_real_parent_and_anonymous_descriptor_refuse(self):
        self.state_call('batch-sync-internal','ddns_a',str(os.getpid()),'--confirm',expected=7)
        p=subprocess.run([self.busybox,'ash',str(self.entry),'--runtime-batch-internal','ddns_a',str(os.getpid()),'--confirm'],env=self.env,capture_output=True,timeout=8);self.assertEqual((p.returncode,p.stderr),(7,b''));self.assertEqual(self.calls,[]);self.assertFalse(self.state_dir.exists())
    def test_common_locks_and_unrecognized_outer_work_preserve_barriers(self):
        import fcntl
        for path in [self.native.lock,self.store/'.supervisor.lock']:
            with path.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.batch_call(4)
        p=self.native.lockdir/'.ddns-plan-999999999';p.mkdir(mode=0o700);self.batch_call(4);self.assertTrue(p.exists());self.assertFalse(self.netlog.exists());self.assertEqual(self.calls,[])
    def test_corrupt_one_rule_cache_refuses_before_any_sample_or_http(self):
        self.state_dir.mkdir(mode=0o700);p=self.state_dir/'ddns_b';p.write_bytes(b'CORRUPT');p.chmod(0o600);self.batch_call(7);self.assertEqual(p.read_bytes(),b'CORRUPT');self.assertFalse(self.netlog.exists());self.assertEqual(self.calls,[])
    def test_network_failure_is_one_sample_and_independent_backoff(self):
        self.settings['addresses']='';self.control.write_text(json.dumps(self.settings));out=self.batch_call(1);self.assertEqual([r['status'] for r in out['rules']],['network_unavailable']*2);self.assertEqual(self.calls,[])
        sample=self.netlog.read_bytes();out=self.batch_call(4);self.assertFalse(out['sampled']);self.assertEqual([r['status'] for r in out['rules']],['retry_wait']*2);self.assertEqual(self.netlog.read_bytes(),sample)
        self.clock.write_text('1300\n');self.batch_call(1);self.assertEqual([json.loads((self.state_dir/n).read_bytes())['failures'] for n in ['ddns_a','ddns_b']],[2,2])
    def test_paused_rule_does_not_block_another_eligible_rule(self):
        self.hook=lambda *a:(401,{'success':False,'errors':[{'code':9109,'message':'SECRET_SENTINEL'}]});self.state_call('sync','ddns_a','--confirm',expected=1);self.hook=None;self.seed()
        before=(self.state_dir/'ddns_a').read_bytes();out=self.batch_call(4);self.assertEqual([r['status'] for r in out['rules']],['paused','unchanged']);self.assertEqual((self.state_dir/'ddns_a').read_bytes(),before);self.assertEqual(self.mutations(),[])
    def test_cache_publication_failure_stops_batch_and_never_clears_stage(self):
        self.seed();self.fault('fsync','sys.exit(1) if any(a.endswith("/.ddns_b.next") for a in sys.argv[1:]) else None');out=self.batch_call(7);self.restore_tool('fsync');self.assertEqual(out['effect'],'unknown');self.assertEqual([r['status'] for r in out['rules']],['unchanged']);self.assertTrue((self.state_dir/'.ddns_b.next').exists())
        n=len(self.calls);out=self.batch_call(4);self.assertFalse(out['sampled']);self.assertEqual(len(self.calls),n);self.assertTrue((self.state_dir/'.ddns_b.next').exists())
    def test_changed_source_after_sample_refuses_dispatch_and_keeps_outer_stage(self):
        self.ip.write_text(self.ip.read_text()+'\np=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes()+b"\\n")\n');self.batch_call(7);self.assertEqual(self.calls,[]);self.assertTrue(list(self.native.lockdir.glob('.ddns-plan-*')));self.assertFalse(self.journal.exists())

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();suite=unittest.TestSuite()
    for cls in ([CF,Ali,DNP,HW,Boundaries] if a.runtime else [Static]):
        methods=Boundaries.__dict__ if cls is Boundaries else BatchMixin.__dict__ if a.runtime else Static.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v))
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
