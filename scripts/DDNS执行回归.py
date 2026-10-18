#!/usr/bin/env python3
"""Single-rule DDNS through actual provider workers and disposable TLS databases."""
import argparse,copy,json,os,re,shutil,subprocess,sys,unittest
from pathlib import Path
from project import ROOT
from DDNS计划回归 import Static as PlanStatic,ADDR,ROUTE,fixture_uid
from DNS回执恢复回归 import Runtime as CFRuntime
from Aliyun终态回归 import Runtime as AliRuntime
from DNSPod终态回归 import Runtime as DNPRuntime
from 华为云终态回归 import Runtime as HWRuntime
from 生命周期准备回归 import configure_runtime_fixture
from 生命周期业务集成回归 import Runtime as LifecycleRuntime
from 旧配置迁移回归 import LEGACY
from Cloudflare记录回归 import rec
from Aliyun记录回归 import record as ali_record
from DNSPod记录回归 import record as dnp_record
from 华为云记录回归 import record as hw_record
PROTO=ROOT/'project/core/prototype'

class Static(PlanStatic):
    def setUp(self):
        super().setUp();self.sync=self.lua.execute((PROTO/'ddns-sync.lua').read_bytes())
    def bound(self):
        snapshot=self.parse(self.frame());intent=self.intent(snapshot)
        plan=self.planner.build(snapshot,b'ddns_a',lambda:self.table({'address':'2001:db8::2','device':'pppoe-wan','source':'public-ip'}),self.records,intent)
        return snapshot,intent,plan
    def test_rebinds_exact_rule_request_provider_and_source_intent(self):
        snapshot,intent,plan=self.bound();self.assertIsNotNone(self.sync.bind(snapshot,intent,plan,b'ddns_a',self.planner,self.network,self.records,self.codec.json))
        for field,value in [(b'account',b'other'),(b'provider',b'aliyun'),(b'rule',b'other'),(b'device',b'../bad'),(b'source',b'interface')]:
            old=plan[b'entries'][1][field];plan[b'entries'][1][field]=value;self.assertIsNone(self.sync.bind(snapshot,intent,plan,b'ddns_a',self.planner,self.network,self.records,self.codec.json));plan[b'entries'][1][field]=old
        intent[b'switches'][b'ddns_a']=b'0';self.assertIsNone(self.sync.bind(snapshot,intent,plan,b'ddns_a',self.planner,self.network,self.records,self.codec.json))
    def test_rejects_extra_fields_foreign_generation_and_nonpublic_address(self):
        snapshot,intent,plan=self.bound()
        for k,v in [(b'revision',2),(b'extra',True),(b'selected',b'other')]:
            old=plan[k];plan[k]=v;self.assertIsNone(self.sync.bind(snapshot,intent,plan,b'ddns_a',self.planner,self.network,self.records,self.codec.json));plan[k]=old
        for value in [b'::',b'fd00::1',b'fe80::1',b'::ffff:192.0.2.1']:
            plan[b'entries'][1][b'request'][b'value']=value;self.assertIsNone(self.sync.bind(snapshot,intent,plan,b'ddns_a',self.planner,self.network,self.records,self.codec.json))
    def receipt(self,provider='cloudflare',result='created',effect='confirmed',affected=1,kind='',retry=False):
        raw=('{'+'"api_version":1,"prototype":true,"ok":'+str(not kind).lower()+',"phase":"dns-provider","provider":"'+provider+'","account":"dns_a","configuration_revision":3,"check_scope":"record-operation","error_kind":"'+kind+'","retryable":'+str(retry).lower()+',"provider_code":"","result":"'+result+'","effect":"'+effect+'","affected":'+str(affected)+',"reconciliation_required":'+str(effect=='unknown').lower()+'}\n').encode();return raw,json.loads(raw)
    def test_four_provider_receipts_preserve_effect_and_no_sensitive_data(self):
        for provider in ['cloudflare','aliyun','dnspod','huaweicloud']:
            raw,d=self.receipt(provider);out,effect=self.sync.result(raw,self.table(d),provider.encode(),b'dns_a',b'3',b'ddns_a',b'0');self.assertEqual(effect,b'confirmed');self.assertEqual(json.loads(out)['phase'],'ddns-sync');self.assertFalse(json.loads(out)['write_ready'])
        raw,d=self.receipt(result='failed',effect='unknown',affected=0,kind='temporary');out,effect=self.sync.result(raw,self.table(d),b'cloudflare',b'dns_a',b'3',b'ddns_a',b'1');self.assertEqual(effect,b'unknown');self.assertTrue(json.loads(out)['reconciliation_required']);self.assertFalse(json.loads(out)['retryable'])
    def test_noncanonical_misbound_or_false_provider_success_is_rejected(self):
        raw,d=self.receipt()
        for key,value in [('account','other'),('configuration_revision',4),('provider','dnspod'),('affected',2),('result','deleted'),('effect','none'),('extra','SECRET_SENTINEL')]:
            bad=copy.deepcopy(d);bad[key]=value;b=json.dumps(bad,separators=(',',':')).encode()+b'\n';self.assertIsNone(self.sync.result(b,self.table(bad),b'cloudflare',b'dns_a',b'3',b'ddns_a',b'0'))
    def test_gates_fixed_modes_and_shell_lua_grammar(self):
        import tree_sitter,tree_sitter_bash
        p=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-ddns-read.sh','homegate-cloudflare-read.sh']:
            b=(PROTO/n).read_bytes();self.assertEqual(b.count(b'ddns_sync_enabled=false'),1);self.assertFalse(p.parse(b).root_node.has_error);self.assertNotIn(b'\r',b)
        for n in ['ddns-sync.lua','homegate-ddns-sync.lua']:self.lua.compile((PROTO/n).read_bytes());self.assertNotIn(b'os.execute',(PROTO/n).read_bytes())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class SyncMixin:
    run_prepare=LifecycleRuntime.run_prepare
    def migrated(self):
        self.source.write_bytes(self.source.read_bytes().replace(b"option source 'url'",b"option source 'auto'"))
        return LifecycleRuntime.migrated(self)
    def setUp(self):
        super().setUp()
        if self.provider=='cloudflare':
            assert self.store.resolve().is_relative_to(self.base.resolve()) and self.store!=self.base
            shutil.rmtree(self.store)
            configure_runtime_fixture(self,extra_files=[p for p in self.engine.parent.iterdir() if p.is_file() and p not in [self.engine,self.bootstrap]])
            self.engine.write_text(self.engine.read_text().replace('lifecycle_migration_enabled=false','lifecycle_migration_enabled=true'))
            d=self.etc/'config';d.mkdir(mode=0o700,exist_ok=True);self.source=d/'homegate';self.source.write_bytes(LEGACY.encode());self.source.chmod(0o600);self.migrated()
        self.entry=self.engine.parent/'homegate-ddns-read.sh';self.control=self.base/'ddns-net';self.netlog=self.base/'ddns-calls'
        self.settings={'addresses':ADDR,'routes':ROUTE,'wan6':json.dumps({'up':True,'l3_device':'eth4'})};self.control.write_text(json.dumps(self.settings))
        code='#!'+sys.executable+'\nimport json,sys\nfrom pathlib import Path\nk="wan6" if sys.argv[0].endswith("ubus-fixture") else "addresses" if "addr" in sys.argv else "routes"\nwith open('+repr(str(self.netlog))+',"a") as f:f.write(k+"\\n")\nprint(json.loads(Path('+repr(str(self.control))+').read_text())[k],end="")\n'
        self.ip=self.base/'ddns-ip-fixture';self.netubus=self.base/'ddns-ubus-fixture'
        for p in [self.ip,self.netubus]:p.write_text(code);p.chmod(0o700)
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/sbin/ip':str(self.ip),'/bin/ubus':str(self.netubus)}
        for n in ['homegate-ddns-read.sh','homegate-ddns-work.sh','homegate-ddns-plan-worker.sh','homegate-ddns-plan.lua','homegate-service-observer-watchdog.sh','homegate-config-prototype.sh','homegate-cloudflare-read.sh']:
            p=self.engine.parent/n;s=p.read_text().replace('ddns_plan_enabled=false','ddns_plan_enabled=true').replace('ddns_sync_enabled=false','ddns_sync_enabled=true').replace('ddns_work_enabled=false','ddns_work_enabled=true')
            if n in ['homegate-ddns-read.sh','homegate-ddns-work.sh','homegate-ddns-plan-worker.sh','homegate-ddns-plan.lua']:s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
            if n=='homegate-ddns-work.sh':s=s.replace('/proc/sys/kernel/random/boot_id',str(self.boot_id))
            s=s.replace('dns_migrated_read_enabled=false','dns_migrated_read_enabled=true').replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))
            p.write_text(fixture_uid(s))
        self.baseline_config=self.config_bytes()
    def config_bytes(self):return {p.relative_to(self.store).as_posix():p.read_bytes() for p in self.store.rglob('*') if p.is_file() and not any(x.startswith('dns-') or x.startswith('.dns-') for x in p.relative_to(self.store).parts)}
    def sync_call(self,expected=0,args=None):
        p=subprocess.run([self.busybox,'ash',str(self.entry),*(args if args is not None else ['--sync','ddns_a','--confirm'])],env=self.env,capture_output=True,timeout=18)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        for secret in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'OLD_ID',b'example.test',b'2001:db8',b'pppoe-wan']:self.assertNotIn(secret,p.stdout)
        self.assertEqual(self.config_bytes(),self.baseline_config);return out
    def seed(self,value='2001:db8::2'):
        r={'cloudflare':lambda:rec(1,value=value),'aliyun':lambda:ali_record(1,value=value),'dnspod':lambda:dnp_record(1,value=value),'huaweicloud':lambda:hw_record(1,values=[value])}[self.provider]();self.add(r)
    def test_actual_rule_create_persists_original_terminal_and_keeps_barrier(self):
        out=self.sync_call();self.assertEqual((out['provider'],out['result'],out['effect']),(self.provider,'created','confirmed'));j=self.store/'dns-operation';self.assertTrue((j/'terminal-meta').is_file());self.assertEqual(json.loads((j/'terminal').read_bytes())['result'],'created')
        slot=j/('slot-'+(j/'current').read_text().strip());q=json.loads((slot/'context').read_bytes());self.assertEqual(q['request'],{'operation':'upsert','kind':'ddns','resource':'ddns_a','value':'2001:db8::2'});self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes']);n=len(self.calls);self.sync_call(4);self.assertEqual(len(self.calls),n)
    def test_equal_address_does_not_mutate_or_create_checkpoint(self):
        self.seed();out=self.sync_call();self.assertEqual((out['result'],out['effect']),('unchanged','none'));self.assertFalse((self.store/'dns-operation').exists());self.assertEqual(self.mutations(),[]);self.assertFalse(list(self.native.lockdir.glob('.ddns-plan-*')))
    def test_changed_address_updates_selected_record(self):
        self.seed('2001:db8::1');out=self.sync_call();self.assertEqual((out['result'],out['effect']),('updated','confirmed'));self.assertEqual(len(self.mutations()),1)
    def test_unknown_mutation_is_durable_and_not_retried(self):
        # Fail after the actual mutation request reaches the simulated cloud.
        def hook(*args):
            method,path=args[:2]
            mutating=(method not in ['GET']) if self.provider in ['cloudflare','huaweicloud'] else (method=='CreateRecord' if self.provider=='dnspod' else False)
            if self.provider=='aliyun':mutating=method=='AddDomainRecord'
            if mutating:
                self.seed()
                return 500,{'success':False,'errors':[],'Code':'InternalError','code':'busy','Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
        self.hook=hook;out=self.sync_call(1);self.hook=None;self.assertEqual(len(self.db),1);self.assertEqual(out['effect'],'unknown');self.assertFalse(out['retryable']);self.assertTrue(out['reconciliation_required']);self.assertTrue((self.store/'dns-operation').exists());self.assertTrue(list(self.native.lockdir.glob('.ddns-plan-*')));n=len(self.calls);self.sync_call(4);self.assertEqual(len(self.calls),n)
    def test_confirmation_and_closed_dispatch_gate_prevent_http(self):
        for args in [['--sync','ddns_a'],['--sync','ddns_a','bad'],['--sync','','--confirm'],['--sync','../bad','--confirm'],['--sync','ddns_a','--confirm','2001:db8::9']]:self.sync_call(2,args)
        p=self.engine.parent/'homegate-cloudflare-read.sh';p.write_text(p.read_text().replace('ddns_sync_enabled=true','ddns_sync_enabled=false'));self.sync_call(2);self.assertEqual(self.calls,[])

class CF(SyncMixin,CFRuntime):provider='cloudflare'
class Ali(SyncMixin,AliRuntime):provider='aliyun'
class DNP(SyncMixin,DNPRuntime):provider='dnspod'
class HW(SyncMixin,HWRuntime):provider='huaweicloud'

class Boundaries(CF):
    def test_private_mode_and_foreign_owner_still_block_before_sampling(self):
        self.native.lockdir.chmod(0o755);self.sync_call(7);self.native.lockdir.chmod(0o700)
        self.native.lock.chmod(0o644);self.sync_call(7);self.native.lock.chmod(0o600)
        raw=self.entry.read_text();needle='= '+str(os.getuid())+':700 ]';self.assertIn(needle,raw)
        self.entry.write_text(raw.replace(needle,'= '+str(os.getuid()+1)+':700 ]'));self.sync_call(7)
        self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())

    def test_entry_gate_ignores_environment(self):
        self.entry.write_text(self.entry.read_text().replace('ddns_sync_enabled=true','ddns_sync_enabled=false'))
        p=subprocess.run([self.busybox,'ash',str(self.entry),'--sync','ddns_a','--confirm'],env={**self.env,'ddns_sync_enabled':'true'},capture_output=True,timeout=5);self.assertEqual((p.returncode,p.stderr),(2,b''));self.assertFalse(json.loads(p.stdout)['ok']);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
    def test_durable_and_settlement_flags_cannot_be_omitted(self):
        p=self.engine.parent/'homegate-cloudflare-read.sh';raw=p.read_text()
        for gate in ['dns_receipt_enabled','dns_settlement_enabled']:
            p.write_text(raw.replace(gate+'=true',gate+'=false'));self.sync_call(2);self.assertEqual(self.calls,[])
            for d in self.native.lockdir.glob('.ddns-plan-*'):
                assert d.resolve().is_relative_to(self.native.base.resolve()) and d.parent==self.native.lockdir
                shutil.rmtree(d)
    def test_changed_private_plan_cannot_be_dispatched(self):
        p=self.engine.parent/'homegate-ddns-plan.lua';s=p.read_text();needle='local private=codec.json(plan)';self.assertEqual(s.count(needle),1);p.write_text(s.replace(needle,"plan.entries[1].account='other'\n"+needle));self.sync_call(7);self.assertEqual(self.calls,[])
    def test_changed_source_between_plan_and_dispatch_stops_before_http(self):
        self.source.write_bytes(self.source.read_bytes().replace(b'SECRET_SENTINEL',b'NEW_TOKEN'))
        self.sync_call(1);self.assertEqual(self.calls,[])
    def test_fresh_source_change_after_sampling_stops_dispatch(self):
        p=self.ip;s=p.read_text();s+='\np=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes().replace(b"SECRET_SENTINEL",b"NEW_TOKEN"))\n';p.write_text(s)
        self.sync_call(7);self.assertEqual(self.calls,[])
    def test_disabled_rule_has_no_network_or_dns_effect(self):
        # Reset only this disposable store for a disabled original-source case.
        assert self.store.resolve().is_relative_to(self.base.resolve()) and self.store!=self.base
        shutil.rmtree(self.store);self.source.write_bytes(self.source.read_bytes().replace(b"config ddns_rule 'ddns_a'\n option enabled '1'",b"config ddns_rule 'ddns_a'\n option enabled '0'"));self.migrated();self.baseline_config=self.config_bytes();out=self.sync_call();self.assertEqual(out['rules'][0]['status'],'disabled');self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
    def test_network_unavailable_has_no_provider_call(self):
        self.settings['addresses']='';self.control.write_text(json.dumps(self.settings));out=self.sync_call(1);self.assertEqual(out['effect'],'none');self.assertEqual(self.calls,[])
    def test_main_and_supervisor_locks_prevent_sampling(self):
        import fcntl
        for p in [self.native.lock,self.store/'.supervisor.lock']:
            with p.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.sync_call(4)
        self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
    def test_missing_terminal_cannot_publish_confirmed_result(self):
        p=self.engine.parent/'homegate-cloudflare-read.sh';s=p.read_text();s=s.replace('case "$result" in 0|1) cat <&5 || fail;', 'rm -f "'+str(self.store/'dns-operation/terminal')+'"\ncase "$result" in 0|1) cat <&5 || fail;');p.write_text(s)
        out=self.sync_call(7);self.assertEqual(out['effect'],'unknown');self.assertTrue((self.store/'dns-operation').exists());self.assertTrue(list(self.native.lockdir.glob('.ddns-plan-*')))

Runtime=CF
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--provider',choices=['cloudflare','aliyun','dnspod','huaweicloud','boundaries']);p.add_argument('--case');a=p.parse_args()
    classes=([{'cloudflare':CF,'aliyun':Ali,'dnspod':DNP,'huaweicloud':HW,'boundaries':Boundaries}[a.provider]] if a.provider else [CF,Ali,DNP,HW,Boundaries]) if a.runtime else [Static]
    suite=unittest.TestSuite()
    for cls in classes:
        methods=Boundaries.__dict__ if cls is Boundaries else SyncMixin.__dict__ if a.runtime else Static.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
