#!/usr/bin/env python3
"""WAN/rule preflight against disposable command fixtures; no network mutations."""
import argparse,copy,json,os,re,shutil,subprocess,sys,time,unittest
from pathlib import Path
from project import ROOT
from 私有配置读取回归 import Codec
from 生命周期业务集成回归 import Runtime as LifecycleRuntime
from 旧配置迁移回归 import LEGACY
PROTO=ROOT/'project/core/prototype'
ADDR='12: pppoe-wan inet6 2001:db8::2/64 scope global dynamic\n13: br-lan inet6 2001:db8:1::1/64 scope global\n'
ROUTE='default via fe80::1 dev pppoe-wan metric 512\n'

def fixture_uid(body):
    """Adapt copied test scripts to their owner; production root checks stay intact."""
    uid=str(os.getuid())
    for before,after in [('= 0:700 ]','= '+uid+':700 ]'),
                         ('= 0:600:1 ]','= '+uid+':600:1 ]'),
                         ('= 0:600:0 ]','= '+uid+':600:0 ]'),
                         ('[ "$(id -u)" = 0 ]','[ "$(id -u)" = '+uid+' ]'),
                         ('[ "$owner" = 0 ]','[ "$owner" = '+uid+' ]')]:
        body=body.replace(before,after)
    return body

class Static(Codec):
    def setUp(self):
        super().setUp();self.records=self.lua.execute((PROTO/'cloudflare-record-plan.lua').read_bytes());self.network=self.lua.execute((PROTO/'wan6-plan.lua').read_bytes());self.planner=self.lua.execute((PROTO/'ddns-plan.lua').read_bytes())
    def table(self,o):
        if isinstance(o,dict):return self.lua.table_from({k.encode() if isinstance(k,str) else k:self.table(v) for k,v in o.items()})
        if isinstance(o,list):return self.lua.table_from([self.table(v) for v in o])
        return o.encode() if isinstance(o,str) else o
    def sample(self,addresses=ADDR,routes=ROUTE,wan=None,fail=None):
        calls=[];values={b'addresses':addresses.encode(),b'routes':routes.encode(),b'wan6':json.dumps(wan or {'up':True,'l3_device':'eth4'}).encode()}
        def run(k):calls.append(k);return values[k],k!=fail
        out=self.network.sample(run,lambda raw:self.table(json.loads(raw)),self.records)
        return (out[0] if isinstance(out,tuple) else out),calls
    def intent(self,snapshot):
        return self.table({'schema':'HGDDNSINTENT1','revision':snapshot[b'revision'],'switches':{s[b'name'].decode():'1' for _,s in snapshot[b'configuration'].items() if s[b'kind']==b'ddns_rule'}})
    def test_private_source_intent_preserves_import_disable_protection(self):
        raw=LEGACY.encode();switches=self.codec.private_ddns_switches(raw)
        self.assertEqual(dict(switches.items()),{b'ddns_a':b'1'})
        public=self.codec.canonical(raw)
        # Legacy-only fields are accepted only through the migration reader.
        self.assertIsInstance(public,tuple)
        normalized,_=self.codec.migration(raw)
        self.assertIn(b"option enabled '0'",normalized);self.assertNotIn(b"option enabled '1'",normalized)
        self.assertIsNone(self.codec.private_ddns_switches(normalized))
        self.assertNotIn(b'SECRET_SENTINEL',repr(dict(switches.items())).encode())
        for body in [raw.replace(b"config ddns_rule 'ddns_a'",b"config ddns_rule 'ddns_a'\n option enabled '1'"),raw.replace(b"option enabled '1'",b"option enabled 'bad'")]:
            result=self.codec.private_ddns_switches(body);self.assertTrue(result is None or isinstance(result,tuple) and result[0] is None)
    def test_public_ipv6_rejects_mapped_local_unusable_and_bad_forms(self):
        for s in ['::','::1','::ffff:192.0.2.1','fc00::1','fd12::1','fe80::1','febf::1','ff02::1','2001:::1','fe80::1%eth0']:
            self.assertIsNone(self.network.public_ipv6(s.encode(),self.records),s)
        self.assertEqual(self.network.public_ipv6(b'2001:0DB8::2',self.records),b'2001:0db8:0000:0000:0000:0000:0000:0002')
    def test_qwrt_route_owner_skips_ubus_eth_trap(self):
        v,calls=self.sample();self.assertEqual((v[b'device'],v[b'address']),(b'pppoe-wan',b'2001:db8::2'));self.assertEqual(calls,[b'addresses',b'routes'])
    def test_ubus_fallback_down_and_lan_only(self):
        v,_=self.sample('8: odd-wan inet6 2001:db8::3/64 scope global\n',ROUTE,{'up':True,'l3_device':'odd-wan'});self.assertEqual(v[b'device'],b'odd-wan')
        v,_=self.sample(routes='',wan={'up':False,'l3_device':'pppoe-wan'});self.assertIsNone(v)
        v,_=self.sample('8: br-lan inet6 2001:db8::3/64 scope global\n','');self.assertIsNone(v)
    def test_flags_equivalence_suffix_and_input_limits(self):
        raw='1: eth4@if9 inet6 2001:db8::2/64 scope global dynamic\n2: eth4 inet6 2001:0db8:0:0:0:0:0:2/64 scope global\n'
        for flag in ['tentative','dadfailed','deprecated']:raw+='3: eth4 inet6 2001:db8::9/64 scope global '+flag+'\n'
        rows=self.network.addresses(raw.encode(),self.records);self.assertEqual(len(rows),1);self.assertEqual(rows[1][b'device'],b'eth4')
        for raw in [b'x'*65537,b'x'*4097,b'\0']:self.assertIsNone(self.network.addresses(raw,self.records))
        self.assertIsNone(self.sample(fail=b'addresses')[0])
    def test_batch_configuration_binding_four_providers_and_one_sample(self):
        snapshot=self.parse(self.frame());sections=snapshot[b'configuration'];n=len(sections);calls=[]
        for i,provider in enumerate(['aliyun','dnspod','huaweicloud'],1):
            sections[n+2*i-1]=self.table({'kind':'dns_account','name':'dns_'+str(i),'values':{'provider':provider}})
            sections[n+2*i]=self.table({'kind':'ddns_rule','name':'ddns_'+str(i),'values':{'enabled':'1','account':'dns_'+str(i),'zone':'example.test','host':'www.example.test','type':'AAAA','source':'auto','ttl':'600'}})
        def sample():calls.append(1);return self.table({'address':'2001:db8::2','device':'pppoe-wan','source':'public-ip'})
        # Canonical private data is disabled; the independently source-bound intent is required.
        rule=next(s for _,s in sections.items() if s[b'kind']==b'ddns_rule');rule[b'values'][b'source']=b'auto'
        plan=self.planner.build(snapshot,b'',sample,self.records,self.intent(snapshot));self.assertEqual(len(calls),1);self.assertEqual(len(plan[b'entries']),4)
        for _,e in plan[b'entries'].items():self.assertEqual(e[b'request'][b'value'],b'2001:db8::2');self.assertEqual(e[b'request'][b'resource'],e[b'rule'])
    def test_disabled_and_unsupported_never_sample(self):
        snapshot=self.parse(self.frame());rule=next(s for _,s in snapshot[b'configuration'].items() if s[b'kind']==b'ddns_rule');calls=[]
        for field,value,status in [(b'enabled',b'0',b'disabled'),(b'source',b'url',b'unsupported'),(b'source',b'interface',b'unsupported'),(b'type',b'A',b'unsupported')]:
            old=rule[b'values'][field];rule[b'values'][field]=value
            intent=self.intent(snapshot)
            if field==b'enabled':intent[b'switches'][b'ddns_a']=b'0'
            plan=self.planner.build(snapshot,b'ddns_a',lambda:calls.append(1),self.records,intent);self.assertEqual(plan[b'entries'][1][b'status'],status);rule[b'values'][field]=old
        self.assertEqual(calls,[])
    def test_public_result_is_canonical_bound_and_address_free(self):
        entries=self.table([{'rule':'ddns_a','provider':'cloudflare','status':'ready','request':{'value':'PRIVATE_SENTINEL'}}]);raw,ok=self.planner.report(b'3',b'ddns_a',entries)
        self.assertTrue(ok);self.assertNotIn(b'PRIVATE_SENTINEL',raw);self.assertEqual(self.planner.validate(raw,self.table(json.loads(raw)),b'3',b'ddns_a',b'0'),raw)
        for key,value in [('effect','confirmed'),('configuration_revision',4),('extra','PRIVATE_SENTINEL')]:
            d=json.loads(raw);d[key]=value;bad=json.dumps(d,separators=(',',':')).encode()+b'\n';self.assertIsNone(self.planner.validate(bad,self.table(d),b'3',b'ddns_a',b'0'))
    def test_missing_stale_or_extra_intent_is_rejected_before_sample(self):
        snapshot=self.parse(self.frame());good={'schema':'HGDDNSINTENT1','revision':3,'switches':{'ddns_a':'1'}};bad=[None,{}, {**good,'revision':4},{**good,'switches':{}},{**good,'switches':{'ddns_a':'2'}},{**good,'switches':{'ddns_a':'1','other':'1'}},{**good,'extra':True}];calls=[]
        for intent in bad:
            out=self.planner.build(snapshot,b'',lambda:calls.append(1),self.records,self.table(intent));self.assertEqual(out,(None,b'invalid_configuration'))
        self.assertEqual(calls,[])
        raw,_=self.planner.report(b'3',b'',self.table([]),b'rule_failure');self.assertIsNone(self.planner.validate(raw,self.table(json.loads(raw)),b'3',b'',b'1'))
    def test_closed_gates_grammar_and_fixed_read_commands(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-ddns-read.sh','homegate-ddns-plan-worker.sh','homegate-service-observer-watchdog.sh']:
            b=(PROTO/n).read_bytes();self.assertFalse(parser.parse(b).root_node.has_error,n);self.assertNotIn(b'\r',b);self.assertEqual(b.count(b'ddns_plan_enabled=false'),1)
        for n in ['wan6-plan.lua','ddns-plan.lua','homegate-ddns-plan.lua']:self.lua.compile((PROTO/n).read_bytes())
        s=(PROTO/'homegate-ddns-plan.lua').read_text();self.assertIn('/sbin/ip -6 -o addr show scope global',s);self.assertIn('/bin/ubus call network.interface.wan6 status',s)
        for word in ['curl','wget','os.getenv','--records']:self.assertNotIn(word,s)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class Runtime(LifecycleRuntime):
    def setUp(self):
        super().setUp();self.business=LEGACY.encode().replace(b"option source 'url'",b"option source 'auto'");self.source.write_bytes(self.business);self.migrated();self.entry=self.engine.parent/'homegate-ddns-read.sh';self.worker=self.engine.parent/'homegate-ddns-plan-worker.sh';self.watchdog=self.engine.parent/'homegate-service-observer-watchdog.sh'
        self.control=self.base/'net-control';self.call_log=self.base/'net-calls';self.capture=self.base/'private-plan';self.settings={'addresses':{'raw':ADDR},'routes':{'raw':ROUTE},'wan6':{'raw':json.dumps({'up':True,'l3_device':'eth4'})}};self.save()
        code='#!'+sys.executable+'\nimport json,os,sys,time\nfrom pathlib import Path\nk="wan6" if sys.argv[0].endswith("ubus-fixture") else "addresses" if "addr" in sys.argv else "routes"\nd=json.loads(Path('+repr(str(self.control))+').read_text())[k]\nfds={}\nfor n in range(10):\n try:fds[str(n)]=os.readlink("/proc/self/fd/"+str(n))\n except OSError:pass\nwith open('+repr(str(self.call_log))+',"a") as f:f.write(json.dumps({"kind":k,"args":sys.argv[1:],"fds":fds,"env":dict(os.environ)})+"\\n")\ntime.sleep(d.get("delay",0));sys.stdout.write(d.get("raw",""));sys.stderr.write("PRIVATE_SENTINEL diagnostic");sys.exit(d.get("rc",0))\n'
        self.ip=self.base/'ip-fixture';self.ubus=self.base/'ubus-fixture'
        for p in [self.ip,self.ubus]:p.write_text(code);p.chmod(0o700)
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/sbin/ip':str(self.ip),'/bin/ubus':str(self.ubus)}
        for n in ['homegate-ddns-read.sh','homegate-ddns-plan-worker.sh','homegate-ddns-plan.lua','homegate-service-observer-watchdog.sh','cloudflare-codec.lua','homegate-config-prototype.sh']:
            p=self.engine.parent/n;s=p.read_text().replace('ddns_plan_enabled=false','ddns_plan_enabled=true')
            if n in ['homegate-ddns-read.sh','homegate-ddns-plan-worker.sh','homegate-ddns-plan.lua']:
                s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
            s=s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))
            s=fixture_uid(s)
            if n=='cloudflare-codec.lua':s=s.replace("local json=require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json=require('luci.jsonc')")
            p.write_text(s)
        self.fault('rm','from pathlib import Path\nfor a in sys.argv[1:]:\n if a.endswith("/plan"):Path('+repr(str(self.capture))+').write_bytes(Path(a).read_bytes())')
        self.before=self.contents()
    def save(self):self.control.write_text(json.dumps(self.settings))
    def net_calls(self):return [json.loads(x) for x in self.call_log.read_text().splitlines()] if self.call_log.exists() else []
    def read(self,rule=None,expected=0,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.entry),*([rule] if rule is not None else [])],env=env or self.env,capture_output=True,timeout=12)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0)
        for x in [b'PRIVATE_SENTINEL',b'SECRET_SENTINEL',b'2001:db8',b'example.test',b'pppoe-wan']:self.assertNotIn(x,p.stdout)
        self.assertEqual(self.contents(),self.before)
        if expected in [0,1]:self.assertFalse(list(self.native.lockdir.glob('.ddns-plan-*')))
        return out
    def change(self,body):
        # Independent source scenarios each start from a fresh disposable store.
        # Production correctly refuses a second migration over a used store.
        assert self.store.resolve().is_relative_to(self.base.resolve()) and self.store!=self.base
        shutil.rmtree(self.store);self.source.write_bytes(body);self.migrated();self.before=self.contents()
    def test_real_ash_snapshot_network_binding_and_no_store_change(self):
        out=self.read('ddns_a');self.assertEqual(out['rules'][0]['status'],'ready');c=json.loads(self.capture.read_bytes());e=c['entries'][0];self.assertEqual(e['request'],{'operation':'upsert','kind':'ddns','resource':'ddns_a','value':'2001:db8::2'});self.assertEqual(e['device'],'pppoe-wan');self.assertEqual([x['kind'] for x in self.net_calls()],['addresses','routes'])
    def test_disabled_rule_skips_network(self):
        self.change(self.business.replace(b"config ddns_rule 'ddns_a'\n option enabled '1'",b"config ddns_rule 'ddns_a'\n option enabled '0'"));self.assertEqual(self.read()['rules'][0]['status'],'disabled');self.assertEqual(self.net_calls(),[])
    def test_unknown_rule_and_bad_argument_never_sample(self):
        self.assertEqual(self.read('missing',1)['error_kind'],'not_found');self.read('../bad',2);self.read('',2);self.assertEqual(self.net_calls(),[])
    def test_unsupported_sources_and_ipv4_skip_network(self):
        for body in [self.business.replace(b"option source 'auto'",b"option source 'url'"),self.business.replace(b"option source 'auto'",b"option source 'interface'"),self.business.replace(b"config ddns_rule 'ddns_a'",b"config ddns_rule 'ddns_a'\n option type 'A'")]:
            self.change(body);self.assertEqual(self.read(expected=1)['rules'][0]['status'],'unsupported')
        self.assertEqual(self.net_calls(),[])
    def test_four_provider_batch_samples_once(self):
        body=self.business
        for i,provider in enumerate(['aliyun','dnspod','huaweicloud'],1):body+=("\nconfig dns_account 'dns_"+str(i)+"'\n option provider '"+provider+"'\nconfig ddns_rule 'ddns_"+str(i)+"'\n option enabled '1'\n option account 'dns_"+str(i)+"'\n option zone 'example.test'\n option host 'www.example.test'\n").encode()
        self.change(body);out=self.read();self.assertEqual({r['provider'] for r in out['rules']},{'cloudflare','aliyun','dnspod','huaweicloud'});self.assertEqual(len(self.net_calls()),2)
    def test_ubus_fallback_selects_actual_address_owner(self):
        self.settings['addresses']['raw']='8: odd-wan inet6 2001:db8::3/64 scope global\n';self.settings['wan6']['raw']=json.dumps({'up':True,'l3_device':'odd-wan'});self.save();self.read();self.assertEqual(json.loads(self.capture.read_bytes())['entries'][0]['device'],'odd-wan');self.assertEqual(len(self.net_calls()),3)
    def test_down_ubus_rejects_stale_wan_and_lan_only(self):
        self.settings['routes']['raw']='';self.settings['wan6']['raw']=json.dumps({'up':False,'l3_device':'pppoe-wan'});self.save();self.assertEqual(self.read(expected=1)['rules'][0]['status'],'network_unavailable')
        self.settings['addresses']['raw']='8: br-lan inet6 2001:db8::3/64 scope global\n';self.settings['wan6']['raw']=json.dumps({'up':True,'l3_device':'eth4'});self.save();self.read(expected=1)
    def test_wan_name_fallback_after_ubus_failure(self):
        self.settings['routes']['raw']='';self.settings['wan6']['rc']=1;self.save();self.read();self.assertEqual(json.loads(self.capture.read_bytes())['entries'][0]['device'],'pppoe-wan')
    def test_unusable_flags_and_local_addresses_are_not_planned(self):
        self.settings['addresses']['raw']='1: pppoe-wan inet6 2001:db8::2/64 scope global tentative\n2: pppoe-wan inet6 fd00::1/64 scope global\n';self.save();self.read(expected=1)
    def test_command_failure_and_oversized_output_are_bounded(self):
        self.settings['addresses']['rc']=1;self.save();self.read(expected=1);self.settings['addresses']={'raw':'x'*65537};self.save();self.read(expected=1)
    def test_mixed_rule_results_keep_good_plan_and_one_sample(self):
        self.change(self.business+b"\nconfig ddns_rule 'ddns_b'\n option enabled '1'\n option account 'dns_a'\n option zone 'example.test'\n option host 'other.example.test'\n option source 'url'\n");out=self.read(expected=1);self.assertEqual([r['status'] for r in out['rules']],['ready','unsupported']);self.assertEqual(len(self.net_calls()),2)
    def test_frontend_and_supervisor_locks_block_sampling(self):
        import fcntl
        for p in [self.native.lock,self.store/'.supervisor.lock']:
            with p.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.read(expected=4)
        self.assertEqual(self.net_calls(),[])
    def test_dns_barrier_and_orphan_directories_are_preserved(self):
        for p in [self.store/'dns-operation',self.native.lockdir/'.dns-check-999999',self.native.lockdir/'.ddns-plan-999999']:
            p.mkdir(mode=0o700);self.before=self.contents();self.read(expected=4);self.assertTrue(p.is_dir());p.rmdir();self.before=self.contents()
        self.assertEqual(self.net_calls(),[])
    def test_fresh_configuration_revision_and_no_caller_address_override(self):
        first=self.read()['configuration_revision'];self.assertEqual(first,self.cli('status')['revision']);self.source.write_bytes(self.business.replace(b"option host 'www'",b"option host 'other'"));self.read(expected=1);self.read('2001:db8::2',2);self.assertEqual(len(self.net_calls()),2)
    def test_four_gates_ignore_environment_and_forged_action_is_refused(self):
        for p,rc in [(self.entry,2),(self.worker,7),(self.watchdog,7),(self.engine,1)]:
            raw=p.read_text();p.write_text(raw.replace('ddns_plan_enabled=true','ddns_plan_enabled=false'));self.read(expected=rc,env={**self.env,'ddns_plan_enabled':'true'});p.write_text(raw)
            for q in self.native.lockdir.glob('.ddns-plan-*'):
                self.assertTrue(q.resolve().is_relative_to(self.native.base.resolve()));import shutil;shutil.rmtree(q)
        p=subprocess.run([self.busybox,'ash',str(self.watchdog),'--action','a'*32,'ddns-plan'],env=self.env,capture_output=True,timeout=5);self.assertEqual((p.returncode,p.stdout,p.stderr),(2,b'',b''));self.assertEqual(self.net_calls(),[])
    def test_worker_result_effect_tampering_is_not_published(self):
        p=self.engine.parent/'homegate-ddns-plan.lua';s=p.read_text();s=s.replace('if not public or #public>65536 then',"public=public:gsub('none','confirmed')\nif not public or #public>65536 then");p.write_text(s);self.read(expected=7);self.assertTrue(list(self.native.lockdir.glob('.ddns-plan-*')))
    def test_command_arguments_environment_and_descriptors_do_not_leak_private_frame(self):
        self.read();raw=self.call_log.read_bytes();self.assertNotIn(b'PRIVATE_SENTINEL',raw);self.assertNotIn(b'SECRET_SENTINEL',raw)
        for c in self.net_calls():
            for target in c['fds'].values():self.assertNotIn('frontend.lock',target);self.assertNotIn('.supervisor.lock',target);self.assertNotIn('/plan',target);self.assertNotIn('/result',target)
        self.assertEqual(self.net_calls()[0]['args'],['-6','-o','addr','show','scope','global'])
    def test_changed_source_is_rejected_before_sampling(self):
        self.source.write_bytes(self.business.replace(b'SECRET_SENTINEL',b'NEW_TOKEN'));self.assertEqual(self.read(expected=1)['error_kind'],'invalid_configuration');self.assertEqual(self.net_calls(),[])
    def test_unbound_projected_generation_is_rejected_before_sampling(self):
        self.secret(b'NEW_PRIVATE');self.before=self.contents();self.assertEqual(self.read(expected=1)['error_kind'],'invalid_configuration');self.assertEqual(self.net_calls(),[])
    def test_caller_loss_keeps_independent_deadline_and_orphan_fence(self):
        self.settings['addresses']['delay']=10;self.save();p=subprocess.Popen([self.busybox,'ash',str(self.entry)],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+4
            while not self.net_calls() and time.monotonic()<deadline:time.sleep(.05)
            self.assertTrue(self.net_calls());p.kill();p.communicate(timeout=3);self.read(expected=4);time.sleep(6);self.read(expected=4)
        finally:
            if p.poll() is None:p.kill();p.communicate(timeout=3)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v) and (not a.case or n==a.case))
    if not suite.countTestCases():p.error('No matching case')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
