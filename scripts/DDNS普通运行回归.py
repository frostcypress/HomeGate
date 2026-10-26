#!/usr/bin/env python3
"""Normal projected sources and granted DDNS against disposable provider TLS fixtures."""
import argparse,hashlib,json,os,re,subprocess,sys,unittest
from pathlib import Path
from project import ROOT
from DDNS执行回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase,SyncMixin
from DDNS外层恢复回归 import WorkMixin
from DDNS计划回归 import fixture_uid
PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_runtime_gates_and_grammar(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-ddns-read.sh','homegate-ddns-work.sh','homegate-cloudflare-read.sh','homegate-dns-receipt.sh']:
            b=(PROTO/name).read_bytes();self.assertEqual(b.count(b'ddns_runtime_enabled=false'),1);self.assertFalse(parser.parse(b).root_node.has_error);self.assertNotIn(b'\r',b)
        for name in ['homegate-config-prototype.sh','homegate-ddns-authority.sh','homegate-dns-receipt.sh']:self.assertFalse(parser.parse((PROTO/name).read_bytes()).root_node.has_error)
        LuaRuntime().compile((PROTO/'homegate-ddns-sync.lua').read_bytes());self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())
    def test_recovery_source_is_read_only_and_limited_to_dns_fences(self):
        s=(PROTO/'homegate-config-prototype.sh').read_text();self.assertEqual(s.count('migration-source-recovery-snapshot-read|runtime-ddns-recovery-snapshot-read)'),4)  # Includes the independent batch-results recovery guard.
        self.assertIn('runtime-ddns-snapshot-read|runtime-ddns-recovery-snapshot-read)',s)
        s=(PROTO/'homegate-cloudflare-read.sh').read_text();self.assertIn('[ "$mode" = reconcile ] && [ "$persistent_reconcile" = true ]',s)
        self.assertIn('check-rule "$ddns_rule"',s);self.assertIn('check-runtime',s)
    def test_distinct_origin_and_rebuilt_private_intent(self):
        s=(PROTO/'homegate-ddns-work.sh').read_text();self.assertIn('HGDDNSWORK2',s);self.assertIn('source_command=runtime-ddns-recovery-snapshot-read',s)
        s=(PROTO/'homegate-ddns-sync.lua').read_text();self.assertIn("ddns-authority.lua",s);self.assertIn("codec.json(expected)..'\\n'~=intent_raw",s)

class NormalMixin:
    def setUp(self):
        super().setUp();self.auth_helper=self.engine.parent/'homegate-ddns-authority.sh';self.active=self.store/'ddns-authority'
        mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        for name in ['homegate-config-prototype.sh','homegate-ddns-read.sh','homegate-ddns-work.sh','homegate-cloudflare-read.sh','homegate-ddns-authority.sh','homegate-dns-receipt.sh']:
            p=self.engine.parent/name;s=p.read_text().replace('ddns_runtime_enabled=false','ddns_runtime_enabled=true').replace('ddns_authority_enabled=false','ddns_authority_enabled=true').replace('production_writes_enabled=false','production_writes_enabled=true').replace('service_observer_enabled=false','service_observer_enabled=true')
            if name=='homegate-ddns-authority.sh':s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s)
            p.write_text(fixture_uid(s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
        # Real fixed observer, with read-only disabled-service responses. No service action.
        init=self.base/'normal-init';common=self.base/'normal-common';ubus=self.base/'normal-ubus';self.initlog=self.base/'normal-init-log'
        init.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> '+str(self.initlog)+'\n[ "$#" -eq 1 ] && [ "$1" = enabled ] || exit 99\nexit 1\n');common.write_text('#!/bin/sh\nexit 0\n');ubus.write_text('#!/bin/sh\nprintf "{}"\n')
        for p in [init,common,ubus]:p.chmod(0o700)
        paths={'/etc/init.d/homegate':str(init),'/etc/rc.common':str(common),'/sbin/ubus':str(ubus)}
        for name in ['homegate-service-observer.lua','homegate-service-observer-watchdog.sh']:
            p=self.engine.parent/name;s=p.read_text();s=re.sub('|'.join(re.escape(k) for k in paths),lambda m:paths[m[0]],s)
            s=s.replace('service_observer_enabled=false','service_observer_enabled=true')
            if name.endswith('.lua'):s=s.replace("local json= require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json= require('luci.jsonc')")
            p.write_text(s)
        # Use actual preview, capture, projection and observed finish, not forged generation files.
        current=self.cli('status')['revision'];body=(self.store/f'gen-{current}/public.conf').read_bytes()
        preview=self.cli('preview',payload=body);tx=self.cli('commit-apply-projection',preview['confirmation']);self.handle=tx['apply_handle']
        self.cli('projection-publish',self.handle,'apply');self.cli('apply-finish-projection',self.handle)
        self.baseline_config=self.config_bytes()
    def auth(self,*args,expected=0):
        p=subprocess.run([self.busybox,'ash',str(self.auth_helper),*args],env=self.env,capture_output=True,timeout=12);self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));return json.loads(p.stdout)
    def grant(self):
        p=self.auth('preview','ddns_a');self.auth('commit',p['confirmation']);self.baseline_config=self.config_bytes()
    def sync_call(self,expected=0,args=None):return super().sync_call(expected,args if args is not None else ['--runtime-sync','ddns_a','--confirm'])
    def recover_read(self,expected=0,account='dns_a',job=None,provider=None):
        if job is None:
            slot=(self.store/'dns-operation/current').read_text().strip();job=(self.store/f'dns-operation/slot-{slot}/manifest').read_text().splitlines()[6]
        before=len(self.mutations());p=subprocess.run([self.busybox,'ash',str(self.reader),'--runtime-reconcile-internal',provider or self.provider,account,job,'--confirm'],env=self.env,capture_output=True,timeout=18)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertEqual(len(self.mutations()),before)
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8']:self.assertNotIn(marker,p.stdout)
        return json.loads(p.stdout)
    def revoke_fixture(self):
        # Simulate a previously committed revocation while DNS locks fence writers.
        f=self.active.read_bytes().splitlines();f[1]=b'disabled';f[-1]=hashlib.sha256(b'\n'.join(f[:-1])+b'\n').hexdigest().encode();self.active.write_bytes(b'\n'.join(f)+b'\n');self.baseline_config=self.config_bytes()
    def test_ordinary_granted_create_and_readonly_recovery(self):
        self.grant();out=self.sync_call();self.assertEqual(out['effect'],'confirmed');self.assertEqual(len(self.mutations()),1);before=self.files(self.store/'dns-operation');self.recover_read();self.assertEqual(before,self.files(self.store/'dns-operation'));self.cli('writer-check',expected=4)
    def test_ordinary_noop_does_not_create_checkpoint(self):
        self.grant();self.seed();out=self.sync_call();self.assertEqual(out['result'],'unchanged');self.assertEqual(self.mutations(),[]);self.assertFalse((self.store/'dns-operation').exists())
    def test_ordinary_update_retains_disabled_public_configuration(self):
        self.grant();self.seed('2001:db8::1');out=self.sync_call();self.assertEqual(out['result'],'updated');self.assertEqual(len(self.mutations()),1);self.assertNotIn(b"option enabled '1'",self.source.read_bytes());self.assertTrue(all(x=='enabled' for x in self.initlog.read_text().splitlines()))
    def test_unknown_is_readonly_reconciled_without_new_authority(self):
        self.grant();SyncMixin.test_unknown_mutation_is_durable_and_not_retried(self);self.revoke_fixture();before=self.files(self.store/'dns-operation');out=self.recover_read();self.assertEqual(out['effect'],'unknown');self.assertEqual(out['observation'],'desired-present');self.assertEqual(before,self.files(self.store/'dns-operation'));self.cli('writer-check',expected=4)
    def test_ordinary_confirmed_outer_collection_uses_runtime_source(self):
        self.grant();self.pending_success();self.assertEqual((self.outer/'binding').read_text().splitlines()[0],'HGDDNSWORK2');self.collect();self.assertFalse(self.outer.exists());self.assertEqual(self.files(self.journal),self.original_journal)
    def test_ungranted_source_does_not_use_migration_switches(self):
        self.sync_call(7);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())

class CF(NormalMixin,WorkMixin,CFBase):provider='cloudflare'
class Ali(NormalMixin,WorkMixin,AliBase):provider='aliyun'
class DNP(NormalMixin,WorkMixin,DNPBase):provider='dnspod'
class HW(NormalMixin,WorkMixin,HWBase):provider='huaweicloud'

class Boundaries(CF):
    def test_revoked_and_preview_only_authority_prevent_sampling(self):
        self.auth('preview','ddns_a');self.baseline_config=self.config_bytes();self.sync_call(7);self.grant();self.auth('revoke','--confirm');self.baseline_config=self.config_bytes();self.sync_call(7);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
    def test_rule_selection_cannot_substitute_authority(self):
        self.grant();self.sync_call(7,['--runtime-sync','missing','--confirm']);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
    def test_source_change_after_sampling_prevents_provider_dispatch(self):
        self.grant();p=self.ip;p.write_text(p.read_text()+'\np=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes()+b"\\n")\n');self.sync_call(7);self.assertEqual(self.calls,[])
    def test_authority_revoked_after_sampling_prevents_provider_dispatch(self):
        self.grant();p=self.ip;p.write_text(p.read_text()+'\np=Path('+repr(str(self.active))+');f=p.read_bytes().splitlines();f[1]=b"disabled";import hashlib;f[-1]=hashlib.sha256(b"\\n".join(f[:-1])+b"\\n").hexdigest().encode();p.write_bytes(b"\\n".join(f)+b"\\n")\n')
        self.baseline_config=None
        old=self.config_bytes;self.config_bytes=lambda:None
        self.sync_call(7);self.config_bytes=old;self.assertEqual(self.calls,[])
    def test_closed_gates_and_confirmation_cannot_be_bypassed(self):
        self.grant()
        for args in [['--runtime-sync','ddns_a'],['--runtime'],['--runtime-sync','ddns_a','--confirm','extra']]:self.sync_call(2,args)
        self.entry.write_text(self.entry.read_text().replace('ddns_runtime_enabled=true','ddns_runtime_enabled=false'))
        p=subprocess.run([self.busybox,'ash',str(self.entry),'--runtime-sync','ddns_a','--confirm'],env={**self.env,'ddns_runtime_enabled':'true'},capture_output=True,timeout=5);self.assertEqual((p.returncode,p.stdout,p.stderr),(2,b'',b''));self.assertEqual(self.calls,[])
    def test_readonly_recovery_denies_wrong_source_job_and_account(self):
        self.grant();self.sync_call();self.recover_read(7,account='other');self.recover_read(4,job='999999999');self.assertEqual(len(self.mutations()),1)
    def test_readonly_recovery_refuses_changed_ordinary_source_before_http(self):
        self.grant();self.sync_call();before=self.files(self.store/'dns-operation');n=len(self.calls);self.source.write_bytes(self.source.read_bytes()+b'\n');p=subprocess.run([self.busybox,'ash',str(self.reader),'--runtime-reconcile-internal',self.provider,'dns_a',(self.store/('dns-operation/slot-'+(self.store/'dns-operation/current').read_text().strip())/'manifest').read_text().splitlines()[6],'--confirm'],env=self.env,capture_output=True,timeout=18);self.assertNotEqual(p.returncode,0);self.assertEqual(p.stderr,b'');self.assertFalse(json.loads(p.stdout)['ok']);self.assertEqual(len(self.calls),n);self.assertEqual(before,self.files(self.store/'dns-operation'))
    def test_readonly_recovery_does_not_require_live_grant(self):
        self.grant();self.sync_call();self.revoke_fixture();self.recover_read();self.assertEqual(len(self.mutations()),1)
    def test_coordinator_rechecks_authority_after_work_binding(self):
        self.grant();p=self.engine.parent/'homegate-ddns-work.sh';s=p.read_text();needle='    printf \'%s\\n\' "$rule"';self.assertEqual(s.count(needle),1)
        hook=self.base/'revoke-hook';hook.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nimport hashlib\np=Path('+repr(str(self.active))+');f=p.read_bytes().splitlines();f[1]=b"disabled";f[-1]=hashlib.sha256(b"\\n".join(f[:-1])+b"\\n").hexdigest().encode();p.write_bytes(b"\\n".join(f)+b"\\n")\n');hook.chmod(0o700)
        p.write_text(s.replace(needle,'    '+str(hook)+'\n'+needle));old=self.config_bytes;self.config_bytes=lambda:{k:v for k,v in old().items() if k!='ddns-authority'};self.baseline_config=self.config_bytes();self.sync_call(7);self.assertEqual(self.calls,[]);self.assertFalse((self.store/'dns-operation').exists())
    def test_readonly_recovery_after_simulated_boot_and_lost_volatile_work(self):
        self.grant();SyncMixin.test_unknown_mutation_is_durable_and_not_retried(self);self.lose_volatile();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.active.unlink();self.recover_read();self.cli('writer-check',expected=4);self.assertEqual(len(self.mutations()),1)
    def test_wrong_origin_format_is_refused_before_provider_call(self):
        self.grant();p=self.engine.parent/'homegate-ddns-work.sh';s=p.read_text();s=s.replace('runtime=true;format=HGDDNSWORK2;action=${action%-runtime}', 'runtime=true;format=HGDDNSWORK1;action=${action%-runtime}');p.write_text(s);self.sync_call(7);self.assertEqual(self.calls,[]);self.assertFalse((self.store/'dns-operation').exists())
    def test_partial_runtime_outer_collection_resumes(self):
        self.grant();self.pending_success();self.fault('rm','sys.exit(1) if any("/.ddns-plan-" in a and a.endswith("/input") for a in sys.argv[1:]) else None');self.collect(7);self.restore_tool('rm');self.collect();self.assertFalse(self.outer.exists())

class InterfaceMixin:
    def migrated(self):
        raw=self.source.read_bytes()
        for source in [b"option source 'url'",b"option source 'auto'"]:
            raw=raw.replace(source,b"option source 'interface'\n option interface 'odd-uplink'")
        # The original fixture may rely on the implicit auto default.
        if b"option source 'interface'" not in raw:
            raw=raw.replace(b"config ddns_rule 'ddns_a'",b"config ddns_rule 'ddns_a'\n option source 'interface'\n option interface 'odd-uplink'")
        self.source.write_bytes(raw);return super().migrated()
    def setUp(self):
        super().setUp()
        self.settings['addresses']+='14: odd-uplink inet6 2001:db8:2::9/64 scope global dynamic\n'
        self.control.write_text(json.dumps(self.settings))
    def test_interface_preview_only_then_confirmed_create_keeps_original_receipt(self):
        self.auth('preview','ddns_a');self.baseline_config=self.config_bytes();self.sync_call(7);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
        self.grant();out=self.sync_call();self.assertEqual((out['provider'],out['result'],out['effect']),(self.provider,'created','confirmed'))
        journal=self.store/'dns-operation';slot=journal/('slot-'+(journal/'current').read_text().strip())
        self.assertEqual(json.loads((slot/'context').read_bytes())['request']['value'],'2001:db8:2::9')
        self.assertEqual(json.loads((journal/'terminal').read_bytes())['result'],'created');self.assertEqual(self.netlog.read_text().splitlines(),['addresses'])
        before=self.files(journal);n=len(self.calls);self.sync_call(4);self.assertEqual(len(self.calls),n);self.assertEqual(before,self.files(journal))
    def test_interface_noop_then_update_stays_scoped(self):
        self.grant();self.seed('2001:db8:2::9');out=self.sync_call();self.assertEqual((out['result'],out['effect']),('unchanged','none'));self.assertFalse((self.store/'dns-operation').exists());self.assertEqual(self.mutations(),[])
        self.db.clear();self.seed('2001:db8:2::1');out=self.sync_call();self.assertEqual((out['result'],out['effect']),('updated','confirmed'));self.assertEqual(len(self.mutations()),1)
        self.assertEqual(self.netlog.read_text().splitlines(),['addresses','addresses'])
    def test_interface_unknown_attempt_is_durable_and_never_retried(self):
        self.grant();SyncMixin.test_unknown_mutation_is_durable_and_not_retried(self)
    def test_interface_missing_stale_and_private_addresses_never_fall_back(self):
        self.grant()
        for extra in ['', '14: odd-uplink inet6 2001:db8:2::9/64 scope global deprecated\n','14: odd-uplink inet6 fd00::9/64 scope global\n']:
            self.settings['addresses']='12: pppoe-wan inet6 2001:db8::2/64 scope global\n'+extra;self.control.write_text(json.dumps(self.settings))
            out=self.sync_call(1);self.assertEqual(out['effect'],'none');self.assertEqual(self.calls,[]);self.assertFalse((self.store/'dns-operation').exists())
        self.assertEqual(self.netlog.read_text().splitlines(),['addresses']*3)

class InterfaceCF(InterfaceMixin,CF):pass
class InterfaceAli(InterfaceMixin,Ali):pass
class InterfaceDNP(InterfaceMixin,DNP):pass
class InterfaceHW(InterfaceMixin,HW):pass
class InterfaceBoundaries(InterfaceCF):
    def test_interface_plan_cannot_borrow_default_wan_device_and_address(self):
        self.grant();p=self.engine.parent/'homegate-ddns-plan.lua';s=p.read_text();needle='local private=codec.json(plan)';self.assertEqual(s.count(needle),1)
        p.write_text(s.replace(needle,"plan.entries[1].device='pppoe-wan';plan.entries[1].request.value='2001:db8::2'\n"+needle))
        self.sync_call(7);self.assertEqual(self.calls,[]);self.assertFalse((self.store/'dns-operation').exists())
    def test_interface_change_after_sampling_stops_before_provider(self):
        self.grant();p=self.ip;p.write_text(p.read_text()+'\np=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes().replace(b"odd-uplink",b"other-uplink"))\n')
        self.sync_call(7);self.assertEqual(self.calls,[])
    def test_interface_change_after_preview_cannot_confirm_old_authority(self):
        preview=self.auth('preview','ddns_a');self.source.write_bytes(self.source.read_bytes().replace(b'odd-uplink',b'other-uplink'))
        self.auth('commit',preview['confirmation'],expected=7);self.assertFalse(self.active.exists());self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())

Runtime=CF
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');p.add_argument('--case');p.add_argument('--interface-only',action='store_true');a=p.parse_args();suite=unittest.TestSuite()
    if a.interface_only and not a.runtime:p.error('--interface-only requires --runtime')
    interfaces=[InterfaceCF,InterfaceAli,InterfaceDNP,InterfaceHW,InterfaceBoundaries]
    for cls in ((interfaces if a.interface_only else [CF,Ali,DNP,HW,Boundaries]+interfaces) if a.runtime else [Static]):
        methods=InterfaceBoundaries.__dict__ if cls is InterfaceBoundaries else InterfaceMixin.__dict__ if cls in interfaces else Boundaries.__dict__ if cls is Boundaries else NormalMixin.__dict__ if a.runtime else Static.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v) and (not a.case or a.case==n))
    if not suite.countTestCases():p.error('No cases')
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
