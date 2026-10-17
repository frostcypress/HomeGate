#!/usr/bin/env python3
"""Bounded local pacing, no automatic retries or mutation-fence bypass."""
import argparse,copy,json,os,re,subprocess,unittest
from pathlib import Path
from project import ROOT
from DDNS普通运行回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase
from DDNS计划回归 import Static as PlanStatic
PROTO=ROOT/'project/core/prototype'

class Static(PlanStatic):
    def setUp(self):super().setUp();self.state=self.lua.execute((PROTO/'ddns-state.lua').read_bytes())
    def context(self):return self.table({'rule':'ddns_a','provider':'cloudflare','revision':4,'identity':'a'*64,'generation':'b'*64,'boot':'11111111-1111-1111-1111-111111111111','interval':60})
    def begin(self):return self.state.begin(self.context(),None,1000)
    def test_success_resets_failure_and_uses_interval(self):
        for result,effect in [('created','confirmed'),('updated','confirmed'),('unchanged','none')]:
            d=self.begin();d[b'failures']=8;s=self.state.finish(d,1001,result.encode(),b'',effect.encode(),False);self.assertTrue(self.state.valid(s));self.assertEqual((s[b'failures'],s[b'delay']),(0,60));self.assertEqual(self.state.decision(s,self.context(),1020,False,True,False),(b'waiting',41));self.assertEqual(self.state.decision(s,self.context(),1061,False,True,False),(b'ready',0))
    def test_exponential_backoff_is_capped_and_respects_long_interval(self):
        c=self.context();old=None;delays=[]
        for _ in range(12):
            old=self.state.finish(self.state.begin(c,old,1000),1000,b'failed',b'rate_limit',b'none',True);delays.append(old[b'delay'])
        self.assertEqual(delays,[60,120,240,480,960,1920,3600,3600,3600,3600,3600,3600]);self.assertEqual(old[b'failures'],8)
        c[b'interval']=7200;s=self.state.finish(self.state.begin(c,None,1000),1000,b'failed',b'temporary',b'none',True);self.assertEqual(s[b'delay'],7200)
    def test_unknown_and_inflight_never_become_eligible_by_time(self):
        d=self.begin()
        for now in [1000,999999999]:self.assertEqual(self.state.decision(d,self.context(),now,False,True,False),(b'reconciliation_required',0))
        s=self.state.finish(d,1001,b'failed',b'timeout',b'unknown',False);self.assertEqual(self.state.decision(s,self.context(),999999999,False,True,False),(b'reconciliation_required',0));self.assertIsNone(self.state.finish(d,1001,b'failed',b'timeout',b'unknown',True))
    def test_barrier_authority_stale_generation_and_clock_rules(self):
        c=self.context();d=self.state.finish(self.begin(),1001,b'unchanged',b'',b'none',False)
        self.assertEqual(self.state.decision(d,c,1002,True,True,False),(b'blocked',0));self.assertEqual(self.state.decision(d,c,1002,False,False,False),(b'unauthorized',0));self.assertEqual(self.state.decision(d,c,999,False,True,False),(b'clock_invalid',0))
        c[b'generation']=b'c'*64;self.assertEqual(self.state.decision(d,c,1002,False,True,False),(b'stale',0))
    def test_authentication_and_validation_failure_pause(self):
        for kind in ['authentication','invalid_request','invalid_configuration','unsupported']:
            s=self.state.finish(self.begin(),1001,b'failed',kind.encode(),b'none',False);self.assertEqual(self.state.decision(s,self.context(),999999999,False,True,False),(b'paused',0));self.assertIsNone(self.state.finish(self.begin(),1001,b'failed',kind.encode(),b'none',True))
    def test_extra_fields_invalid_numbers_and_fabricated_effect_are_rejected(self):
        d=self.begin()
        for k,v in [(b'extra',b'SECRET_SENTINEL'),(b'failures',9),(b'updated',-1),(b'delay',1),(b'last_effect',b'confirmed'),(b'interval',59)]:
            old=d[k];d[k]=v;self.assertFalse(self.state.valid(d));d[k]=old
    def test_public_status_omits_private_binding_and_never_grants_authority(self):
        d=self.state.finish(self.begin(),1001,b'updated',b'',b'confirmed',False);raw=self.state.report(d,self.context(),1002,True,False,False);out=json.loads(raw);self.assertEqual(out['effect'],'none');self.assertFalse(out['write_ready']);self.assertEqual(out['last_effect'],'confirmed')
        for value in [b'a'*64,b'b'*64,b'11111111-',b'account',b'address',b'example.test']:self.assertNotIn(value,raw)
    def test_shell_lua_grammar_closed_gate_and_fixed_reset(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        b=(PROTO/'homegate-ddns-state.sh').read_bytes();self.assertEqual(b.count(b'ddns_state_enabled=false'),1);self.assertFalse(parser.parse(b).root_node.has_error);self.assertNotIn(b'\r',b)
        for name in ['homegate-ddns-state.lua','ddns-state.lua']:self.lua.compile((PROTO/name).read_bytes())
        for word in ['rm -r','curl','wget','eval ','kill ','/etc/init.d']:self.assertNotIn(word,b.decode())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class StateMixin:
    def setUp(self):
        super().setUp();self.helper=self.engine.parent/'homegate-ddns-state.sh';self.state_dir=self.native.lockdir/'ddns-state';self.state_file=self.state_dir/'ddns_a';self.clock=self.base/'state-clock';self.clock.write_text('1000\n')
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        s=self.helper.read_text().replace('ddns_state_enabled=false','ddns_state_enabled=true');s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
        s=s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)).replace('now=$(lua "$dir/worker-process.lua" now 2>/dev/null)','now=$(cat '+str(self.clock)+')');self.helper.write_text(s)
    def state_call(self,*args,expected=0):
        p=subprocess.run([self.busybox,'ash',str(self.helper),*args],env=self.env,capture_output=True,timeout=20);self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));out=json.loads(p.stdout)
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',b'pppoe-wan']:self.assertNotIn(marker,p.stdout)
        return out
    def tick(self,value):self.clock.write_text(str(value)+'\n')
    def status(self):return self.state_call('status','ddns_a')
    def managed(self,expected=0):return self.state_call('sync','ddns_a','--confirm',expected=expected)
    def test_noop_cooldown_skips_sampling_and_becomes_due(self):
        self.grant();self.seed();out=self.managed();self.assertEqual(out['result'],'unchanged');before=len(self.calls);samples=self.netlog.read_bytes();self.assertEqual(self.status()['status'],'waiting');self.managed(4);self.assertEqual(len(self.calls),before);self.assertEqual(self.netlog.read_bytes(),samples);self.tick(1300);self.managed();self.assertEqual(self.mutations(),[])
    def test_confirmed_status_does_not_clear_durable_barrier(self):
        self.grant();self.managed();before=self.files(self.store/'dns-operation');n=len(self.calls);out=self.status();self.assertEqual(out['status'],'blocked');self.assertEqual(out['last_effect'],'confirmed');self.assertEqual(out['effect'],'none');self.managed(4);self.state_call('reset','ddns_a','--confirm',expected=4);self.assertEqual(len(self.calls),n);self.assertEqual(self.files(self.store/'dns-operation'),before)
    def test_unknown_status_and_elapsed_time_cannot_retry(self):
        self.grant()
        def hook(*args):
            action=args[0];mutation=action not in ['GET'] if self.provider in ['cloudflare','huaweicloud'] else action==('AddDomainRecord' if self.provider=='aliyun' else 'CreateRecord')
            if mutation:self.seed();return 500,{'success':False,'errors':[],'Code':'InternalError','code':'busy','Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
        self.hook=hook;out=self.managed(1);self.hook=None;self.assertEqual(out['effect'],'unknown');self.assertEqual(len(self.db),1);n=len(self.calls);self.tick(999999999);out=self.status();self.assertEqual(out['last_effect'],'unknown');self.managed(4);self.state_call('reset','ddns_a','--confirm',expected=4);self.assertEqual(len(self.calls),n)

class CF(StateMixin,CFBase):provider='cloudflare'
class Ali(StateMixin,AliBase):provider='aliyun'
class DNP(StateMixin,DNPBase):provider='dnspod'
class HW(StateMixin,HWBase):provider='huaweicloud'

class Boundaries(CF):
    def test_read_only_status_does_not_create_cache_or_sample(self):
        out=self.status();self.assertEqual(out['status'],'unauthorized');self.assertFalse(self.state_dir.exists());self.assertFalse(self.netlog.exists());self.grant();self.assertEqual(self.status()['status'],'ready');self.assertFalse(self.state_dir.exists());self.assertEqual(self.calls,[])
    def test_network_failure_backoff_increments_and_caps(self):
        self.grant();self.settings['addresses']='';self.control.write_text(json.dumps(self.settings));out=self.managed(1);self.assertEqual(out['phase'],'ddns-plan');self.assertEqual(self.status()['status'],'retry_wait');self.assertEqual(self.status()['retry_in'],300);self.managed(4);self.tick(1300);self.managed(1);self.assertEqual(self.status()['failures'],2);self.assertEqual(self.calls,[])
    def test_auth_failure_pauses_until_explicit_safe_reset(self):
        self.grant();self.hook=lambda *a:(401,{'success':False,'errors':[{'code':9109,'message':'SECRET_SENTINEL'}]});out=self.managed(1);self.hook=None;self.assertEqual(out['effect'],'none');self.assertEqual(self.status()['status'],'paused');self.tick(999999999);self.managed(4);self.state_call('reset','ddns_a','--confirm');self.assertEqual(self.status()['status'],'ready');self.assertFalse(self.state_file.exists())
    def test_authority_revocation_prevents_managed_dispatch(self):
        self.grant();self.seed();self.managed();self.auth('revoke','--confirm');self.assertEqual(self.status()['status'],'unauthorized');n=len(self.calls);self.tick(2000);self.managed(4);self.assertEqual(len(self.calls),n)
    def test_cache_publication_failure_prevents_dispatch_and_reset_is_explicit(self):
        self.grant();self.fault('fsync','sys.exit(1) if any(a.endswith("/.ddns_a.next") for a in sys.argv[1:]) else None');self.managed(7);self.restore_tool('fsync');self.assertTrue((self.state_dir/'.ddns_a.next').exists());self.assertEqual(self.calls,[]);self.assertEqual(self.status()['status'],'blocked');self.managed(4);self.state_call('reset','ddns_a','--confirm');self.assertEqual(self.status()['status'],'ready')
    def test_result_publication_failure_retains_inflight_and_original_evidence(self):
        self.grant();self.fault('mv','from pathlib import Path\nsys.exit(1) if any(a.endswith("/.ddns_a.next") for a in sys.argv[1:]) and Path('+repr(str(self.state_dir/'.ddns_a.result'))+').exists() else None');self.managed(7);self.restore_tool('mv');self.assertEqual(len(self.mutations()),1);before=self.files(self.store/'dns-operation');self.managed(4);self.state_call('reset','ddns_a','--confirm',expected=4);self.assertEqual(before,self.files(self.store/'dns-operation'))
    def test_unsafe_files_and_unknown_members_refuse_without_cleanup(self):
        self.grant();self.seed();self.managed();old=self.state_file.read_bytes();self.state_file.chmod(0o644);self.state_call('status','ddns_a',expected=7);self.state_file.chmod(0o600);self.state_file.write_bytes(old+b'X');self.state_call('status','ddns_a',expected=7);self.assertEqual(self.state_file.read_bytes(),old+b'X');self.state_call('reset','ddns_a','--confirm');p=self.state_dir/'.unknown';p.touch(mode=0o600);self.state_call('status','ddns_a',expected=7);self.assertTrue(p.exists())
    def test_common_locks_block_status_and_dispatch(self):
        import fcntl
        self.grant()
        for p in [self.native.lock,self.store/'.supervisor.lock']:
            with p.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.state_call('status','ddns_a',expected=4);self.managed(4)
        self.assertEqual(self.calls,[])
    def test_source_change_refuses_before_cache_or_network(self):
        self.grant();self.source.write_bytes(self.source.read_bytes()+b'\n');self.managed(7);self.assertFalse(self.state_dir.exists());self.assertEqual(self.calls,[])
    def test_clock_reversal_and_simulated_boot_staleness(self):
        self.grant();self.seed();self.managed();self.tick(999);self.assertEqual(self.status()['status'],'clock_invalid');self.managed(4);self.tick(1000);self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.assertEqual(self.status()['status'],'stale');self.managed();self.assertEqual(self.mutations(),[])
    def test_closed_gate_and_cli_do_not_enable_from_environment(self):
        self.grant()
        for a in [[],['sync','ddns_a'],['reset','ddns_a'],['status','../bad'],['status','ddns_a','extra']]:self.state_call(*a,expected=2)
        self.helper.write_text(self.helper.read_text().replace('ddns_state_enabled=true','ddns_state_enabled=false'));p=subprocess.run([self.busybox,'ash',str(self.helper),'sync','ddns_a','--confirm'],env={**self.env,'ddns_state_enabled':'true'},capture_output=True,timeout=5);self.assertEqual(p.returncode,2);self.assertEqual(self.calls,[])
    def test_state_operations_preserve_published_config_and_credentials(self):
        self.grant();self.seed();config_before=self.config_bytes();source_before=self.source.read_bytes();self.managed();self.status();self.tick(1300);self.managed();self.state_call('reset','ddns_a','--confirm');self.assertEqual(self.config_bytes(),config_before);self.assertEqual(self.source.read_bytes(),source_before)
    def test_reset_removed_rule_cache_requires_valid_source_but_not_grant(self):
        self.state_dir.mkdir(mode=0o700);p=self.state_dir/'removed_rule';p.write_bytes(b'OLD');p.chmod(0o600);self.state_call('reset','removed_rule','--confirm');self.assertFalse(p.exists());self.assertEqual(self.calls,[])
    def test_publication_reserves_space_for_two_stages(self):
        self.grant();self.state_dir.mkdir(mode=0o700)
        for n in range(190):p=self.state_dir/('rule_'+str(n));p.touch(mode=0o600)
        self.managed(7);self.assertFalse(self.state_file.exists());self.assertFalse(self.netlog.exists());self.assertEqual(self.calls,[])
    def test_capacity_overflow_refuses_before_sampling(self):
        self.grant();self.state_dir.mkdir(mode=0o700)
        for n in range(193):p=self.state_dir/('rule_'+str(n));p.touch(mode=0o600)
        self.managed(7);self.assertEqual(len(list(self.state_dir.iterdir())),193);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
    def test_post_rename_cache_sync_failure_cannot_dispatch(self):
        self.grant();self.fault('fsync','sys.exit(1) if any(a.endswith("/ddns-state/ddns_a") for a in sys.argv[1:]) else None');self.managed(7);self.restore_tool('fsync');self.assertEqual(self.status()['status'],'reconciliation_required');self.assertEqual(self.calls,[]);self.state_call('reset','ddns_a','--confirm');self.assertEqual(self.status()['status'],'ready')
    def test_forged_success_without_canonical_receipt_is_retained(self):
        self.grant();self.entry.write_text('#!/bin/sh\nprintf \'{"ok":true,"phase":"ddns-sync","SECRET_SENTINEL":true}\\n\'\n');self.managed(7);self.assertEqual(self.status()['status'],'blocked');self.assertEqual(self.calls,[]);self.assertTrue((self.state_dir/'.ddns_a.result').exists())
    def test_foreign_rule_cache_cannot_be_presented_as_current(self):
        self.grant();self.seed();self.managed();d=json.loads(self.state_file.read_bytes());d['rule']='other';self.state_file.write_bytes(self.state_file.read_bytes().replace(b'\"rule\":\"ddns_a\"',b'\"rule\":\"other\"'));self.state_call('status','ddns_a',expected=7);self.assertEqual(self.mutations(),[])
    def test_cache_capacity_and_links_are_bounded(self):
        self.grant();self.state_dir.mkdir(mode=0o700);outside=self.base/'outside-state';outside.write_bytes(b'KEEP');outside.chmod(0o600);self.state_file.symlink_to(outside);self.state_call('status','ddns_a',expected=7);self.assertEqual(outside.read_bytes(),b'KEEP');self.assertTrue(self.state_file.is_symlink())

Runtime=CF
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();suite=unittest.TestSuite()
    for cls in ([CF,Ali,DNP,HW,Boundaries] if a.runtime else [Static]):
        methods=Boundaries.__dict__ if cls is Boundaries else StateMixin.__dict__ if a.runtime else Static.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v))
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
