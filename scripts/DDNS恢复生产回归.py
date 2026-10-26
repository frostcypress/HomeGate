#!/usr/bin/env python3
"""Real DDNS transitions publish an independent, fresh recovery contribution."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import unittest
from project import ROOT, identity
from DDNS计划回归 import fixture_uid
from DDNS状态退避回归 import CF as StateFixture

PROTO = ROOT / 'project/core/prototype'
STAMP = '2026-10-26T03:04:05Z'


class Static(unittest.TestCase):
    def setUp(self):
        from lupa.lua51 import LuaRuntime
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.codec = self.lua.execute((ROOT / 'project/luci/lua/luasrc/model/homegate/backup.lua').read_text())
        self.model = self.lua.execute((PROTO / 'ddns-recovery.lua').read_text())
        self.state = self.lua.execute((PROTO / 'ddns-state.lua').read_text())
        self.health = self.lua.execute((PROTO / 'runtime-health.lua').read_text())

    def test_grammar_closed_gates_three_hooks_and_no_global_recovery_overwrite(self):
        import tree_sitter, tree_sitter_bash
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['ddns-recovery-files.sh', 'homegate-ddns-recovery.sh', 'homegate-ddns-state.sh',
                     'homegate-recovery-read.sh', 'homegate-recovery-worker.sh', 'homegate-service-observer-watchdog.sh']:
            body = (PROTO / name).read_bytes()
            self.assertNotIn(b'\r', body)
            self.assertFalse(parser.parse(body).root_node.has_error, name)
        for name in ['homegate-ddns-recovery.lua', 'homegate-recovery.lua', 'recovery-report.lua']:
            self.lua.compile((PROTO / name).read_bytes())
        helper = (PROTO / 'homegate-ddns-recovery.sh').read_text()
        self.assertIn('ddns_recovery_publish_enabled=false', helper)
        self.assertNotIn('$run/recovery.json', helper)
        self.assertNotIn('curl ', helper)
        self.assertEqual((PROTO / 'homegate-ddns-state.sh').read_text().count('publish_recovery || fail'), 3)
        self.assertNotIn('prototype/', (PROTO.parent / 'Makefile').read_text())

    def test_real_cache_states_project_without_fabricated_attempts_or_retry_queue(self):
        c = self.lua.table_from(dict(rule='rule', provider='cloudflare', revision=1, identity='a'*64,
                                     generation='b'*64, boot='11111111-1111-1111-1111-111111111111', interval=300))
        first = self.state.begin(c, None, 1000)
        cases = [(first, 'unknown'), (self.state.finish(first,1000,'unchanged','','none',False),'successful'),
                 (self.state.finish(first,1000,'failed','network_unavailable','none',True),'retry_wait'),
                 (self.state.finish(first,1000,'failed','authentication','none',False),'paused'),
                 (self.state.finish(first,1000,'failed','timeout','unknown',False),'unknown')]
        for state, field in cases:
            inp = dict(schema='HGDDNSRECOVERYINPUT1', version='1.3.0-r128', revision=1, identity='a'*64, generation='b'*64,
                       boot=c['boot'], cache_state='valid', rules=[dict(rule='rule',provider='cloudflare',interval=300,
                                                                       raw=self.codec.json(state)+'\n',clock_valid=True)])
            table = self.lua.table_from(inp, recursive=True)
            raw = self.codec.json(table)+'\n'
            parse = lambda text: self.lua.table_from(json.loads(text), recursive=True)
            record = self.model.build(raw,table,'c'*64,1000,STAMP,self.state,parse,self.codec.json)
            doc = json.loads(record)
            self.assertEqual(doc['summary'][field],1)
            decoded = self.model.decode(record,self.lua.table_from(doc,recursive=True),self.codec.json,self.health.timestamp)
            projected = self.model.project(self.model.public(decoded,None),STAMP,self.health.timestamp)
            if projected['row']:
                self.assertIsNone(projected['row']['attempt'])
                self.assertIsNone(projected['row']['max_attempts'])
                self.assertIsNone(projected['row']['next_retry_at'])

    def test_unsafe_missing_incomplete_and_stale_proofs_never_clear(self):
        for cache in ['unsafe','incomplete','absent']:
            s=self.lua.table_from(dict(total=1,successful=0,retry_wait=0,paused=0,unknown=0,unobserved=1))
            raw=self.model.make('1.3.0-r128',1,'a'*64,'b'*64,'11111111-1111-1111-1111-111111111111','c'*64,s,cache,STAMP,self.codec.json)
            doc=self.model.decode(raw,self.lua.table_from(json.loads(raw),recursive=True),self.codec.json,self.health.timestamp)
            self.assertTrue(self.model.project(self.model.public(doc,None),STAMP,self.health.timestamp)['row'])
            self.assertFalse(self.model.fresh(doc,'1.3.0-r128','1',self.lua.table_from(dict(identity='a'*64,generation='b'*64)),
                                            self.model.proof('d'*64+':11111111-1111-1111-1111-111111111111')))
        self.assertIsNone(self.model.proof('SECRET_SENTINEL'))

    def test_public_contribution_replaces_only_ddns_and_preserves_other_modules(self):
        recovery=self.lua.execute((PROTO/'recovery-report.lua').read_text())
        config=self.lua.table_from(dict(configured=True,enabled=False,error_kind=''))
        binding=recovery.binding('a'*64+':'+'b'*64+':clear:0')
        context=self.lua.table_from(dict(config=config,binding=binding,ddns_proof='unavailable'))
        row=dict(module='proxy',state='degraded',retryable=True,updated_at=STAMP)
        record=self.lua.table_from(dict(rows=[row],bound=True,reason=''),recursive=True)
        contribution=self.model.project(self.model.public(None,'state_unavailable'),STAMP,self.health.timestamp)
        raw=recovery.report('1.3.0-r128','1',context,record,STAMP,self.codec.json,contribution)
        out=json.loads(raw)
        self.assertEqual([r['module'] for r in out['modules']],['ddns','proxy'])
        self.assertFalse(out['ok'])
        self.assertFalse(out['complete_recovery_verified'])
        self.assertNotIn('identity',raw)


class Runtime(StateFixture):
    def setUp(self):
        super().setUp()
        self.producer=self.engine.parent/'homegate-ddns-recovery.sh'
        self.record_path=self.native.lockdir/'ddns-recovery.json'
        self.global_path=self.native.lockdir/'recovery.json'
        self.candidate=self.engine.parent/'homegate-cli.sh'
        for name in ['homegate-ddns-recovery.sh','homegate-recovery-read.sh','homegate-recovery-worker.sh',
                     'homegate-service-observer-watchdog.sh','homegate-cli.sh']:
            p=self.engine.parent/name;b=p.read_text()
            b=b.replace('ddns_recovery_publish_enabled=false','ddns_recovery_publish_enabled=true').replace('ddns_recovery_read_enabled=false','ddns_recovery_read_enabled=true')
            b=b.replace('recovery_status_enabled=false','recovery_status_enabled=true').replace('native_cli_enabled=false','native_cli_enabled=true')
            if name!='homegate-service-observer-watchdog.sh':
                b=b.replace('/var/run/homegate',str(self.native.lockdir)).replace('/etc/homegate/transactions',str(self.store))
            b=b.replace('/proc/sys/kernel/random/boot_id',str(self.boot_id))
            b=b.replace('0:600:1|0:644:1',str(os.getuid())+':600:1|'+str(os.getuid())+':644:1')
            b=b.replace('sample_now=$(lua "$dir/worker-process.lua" now)','sample_now=$(cat '+str(self.clock)+')')
            b=b.replace('now=$(lua "$dir/worker-process.lua" now)','now=$(cat '+str(self.clock)+')')
            p.write_text(fixture_uid(b.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
        self.helper.write_text(self.helper.read_text().replace('ddns_recovery_publish_enabled=false','ddns_recovery_publish_enabled=true'))
        for name in ['homegate-ddns-recovery.lua','homegate-recovery.lua']:
            p=self.engine.parent/name;b=p.read_text()
            b=b.replace("dir..'/../../../VERSION'",json.dumps(str(ROOT/'VERSION'))).replace("dir..'/../../../RELEASE'",json.dumps(str(ROOT/'RELEASE')))
            b=b.replace('/var/run/homegate/ddns-state',str(self.state_dir)).replace('/etc/config/homegate',str(self.source))
            p.write_text('package.cpath='+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+'\n'+b)
        self.engine.write_text(self.engine.read_text().replace('dns_recovery_read_enabled=false','dns_recovery_read_enabled=true'))

    def publish(self,expected=0):
        code='exec 6>>"$1" 7>>"$2"; flock -n 6 && flock -n 7 || exit 4; exec ash "$3" publish-internal'
        p=subprocess.run([self.busybox,'ash','-c',code,'fixture',str(self.native.lock),str(self.store/'.supervisor.lock'),str(self.producer)],
                         env=self.env,capture_output=True,timeout=15)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(expected,b'',b''))

    def observe_recovery_cli(self):
        calls=len(self.calls)
        p=subprocess.run([self.busybox,'ash',str(self.candidate),'recovery-status'],env=self.env,capture_output=True,timeout=15)
        self.assertEqual((p.returncode,p.stderr),(0,b''),p.stdout)
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',b'pppoe-wan']:
            self.assertNotIn(marker,p.stdout)
        self.assertEqual(len(self.calls),calls)
        out=json.loads(p.stdout)
        self.assertFalse(out['write_ready']);self.assertFalse(out['complete_recovery_verified'])
        return out

    def stored(self):
        raw=self.record_path.read_bytes()
        self.assertLess(len(raw),8192)
        for marker in [b'ddns_a',b'example.test',b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'2001:db8']:
            self.assertNotIn(marker,raw)
        self.assertEqual(self.record_path.stat().st_mode&0o777,0o600)
        return json.loads(raw)

    def global_record(self):
        rev=self.cli('status')['revision']
        out=dict(api_version=1,ok=False,version=identity()['normalized'],phase='recovery',degraded=True,
                 modules=[dict(module='proxy',state='degraded',retryable=True,updated_at=STAMP)],
                 source=dict(schema='HGRECOVERYSOURCE1',configuration_revision=rev,
                             identity=hashlib.sha256((self.store/'identity').read_bytes()).hexdigest(),
                             generation=hashlib.sha256((self.store/f'gen-{rev}/manifest').read_bytes()).hexdigest()))
        self.global_path.write_text(json.dumps(out)+'\n');self.global_path.chmod(0o644)
        return self.global_path.read_bytes()

    def test_actual_noop_publishes_current_ddns_success_without_clearing_global_unknown(self):
        self.grant();self.seed();before=self.config_bytes();source=self.source.read_bytes()
        self.managed()
        self.assertEqual(self.stored()['summary']['successful'],1)
        out=self.observe_recovery_cli();self.assertTrue(out['ddns_observation']['valid'])
        self.assertEqual(out['ddns_observation']['summary']['successful'],1)
        self.assertFalse(out['ok']);self.assertIn('recovery',[r['module'] for r in out['modules']])
        self.assertEqual(self.config_bytes(),before);self.assertEqual(self.source.read_bytes(),source)

    def test_inflight_contribution_exists_before_actual_provider_request(self):
        self.grant();self.seed();seen=[]
        def observe(*args):
            seen.append(self.stored()['summary']['unknown'])
            return None
        self.hook=observe;self.managed();self.hook=None
        self.assertTrue(seen);self.assertTrue(all(v==1 for v in seen))
        self.assertEqual(self.stored()['summary']['successful'],1)

    def test_network_failure_is_degraded_pacing_not_a_fabricated_retry_queue(self):
        self.grant();self.settings['addresses']='';self.control.write_text(json.dumps(self.settings))
        self.managed(1)
        self.assertEqual(self.stored()['summary']['retry_wait'],1)
        row=next(r for r in self.observe_recovery_cli()['modules'] if r['module']=='ddns')
        self.assertEqual(row['state'],'degraded');self.assertTrue(row['retryable'])
        for field in ['attempt','max_attempts','next_retry_at']:self.assertNotIn(field,row)

    def test_auth_pause_is_published_and_does_not_start_extra_requests(self):
        self.grant();self.hook=lambda *args:(401,{'success':False,'errors':[{'code':9109,'message':'SECRET_SENTINEL'}]})
        self.managed(1);self.hook=None
        self.assertEqual(self.stored()['summary']['paused'],1)
        self.assertEqual(next(r for r in self.observe_recovery_cli()['modules'] if r['module']=='ddns')['state'],'requires_user_action')

    def test_unknown_mutation_remains_reconciliation_required_and_cannot_retry(self):
        self.grant()
        def hook(*args):
            if args[0]!='GET':
                self.seed();return 500,{'success':False,'errors':[]}
        self.hook=hook;out=self.managed(1);self.hook=None
        self.assertEqual(out['effect'],'unknown');self.assertEqual(self.stored()['summary']['unknown'],1)
        self.assertEqual(next(r for r in self.observe_recovery_cli()['modules'] if r['module']=='ddns')['error_kind'],'reconciliation_required')
        calls=len(self.calls);self.tick(999999999);self.managed(4);self.assertEqual(len(self.calls),calls)

    def test_reset_forgets_history_but_does_not_report_missing_history_as_success(self):
        self.grant();self.seed();self.managed();before=self.record_path.read_bytes()
        with self.record_path.open('rb') as held:
            self.state_call('reset','ddns_a','--confirm')
            self.assertEqual(held.read(),before)
        self.assertEqual(self.stored()['summary']['unobserved'],1)
        self.assertEqual(next(r for r in self.observe_recovery_cli()['modules'] if r['module']=='ddns')['error_kind'],'state_unavailable')

    def test_stale_cache_boot_and_clock_change_invalidate_previous_clear_contribution(self):
        self.grant();self.seed();self.managed();self.assertTrue(self.observe_recovery_cli()['ddns_observation']['valid'])
        self.tick(999);self.assertFalse(self.observe_recovery_cli()['ddns_observation']['valid']);self.tick(1000)
        oldboot=self.boot_id.read_bytes();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n')
        self.assertFalse(self.observe_recovery_cli()['ddns_observation']['valid']);self.boot_id.write_bytes(oldboot)
        doc=json.loads(self.state_file.read_bytes());doc['generation']='a'*64
        self.state_file.write_text(json.dumps(doc,sort_keys=True,separators=(',',':'))+'\n')
        self.assertFalse(self.observe_recovery_cli()['ddns_observation']['valid'])
        self.publish();self.assertEqual(self.stored()['summary']['unobserved'],1)

    def test_failed_stage_sync_retains_old_record_and_pending_marker_before_dns(self):
        self.grant();self.seed();self.managed();old=self.record_path.read_bytes();calls=len(self.calls);self.tick(1300)
        self.fault('fsync','sys.exit(1) if any(a.endswith("/.ddns-recovery-next") for a in sys.argv[1:]) else None')
        self.managed(7);self.restore_tool('fsync')
        self.assertEqual(self.record_path.read_bytes(),old);self.assertEqual(len(self.calls),calls)
        self.assertTrue((self.native.lockdir/'.ddns-recovery-pending').exists())
        self.assertEqual(self.observe_recovery_cli()['ddns_observation']['reason'],'publication_pending')
        self.publish(4)

    def test_foreign_target_and_links_are_not_overwritten_by_internal_publication(self):
        self.record_path.write_text('SECRET_SENTINEL');self.record_path.chmod(0o600);self.publish(4)
        self.assertEqual(self.record_path.read_text(),'SECRET_SENTINEL');self.record_path.unlink()
        outside=self.base/'foreign-ddns-recovery';outside.write_text('KEEP');outside.chmod(0o600)
        self.record_path.symlink_to(outside);self.publish(4);self.assertEqual(outside.read_text(),'KEEP')
        self.assertEqual(self.calls,[])

    def test_incomplete_and_unsafe_cache_are_published_as_unknown_not_cleaned(self):
        self.grant();self.seed();self.managed()
        stage=self.state_dir/'.ddns_a.next';stage.write_text('SECRET_SENTINEL');stage.chmod(0o600)
        self.publish();self.assertEqual(self.stored()['cache_state'],'incomplete')
        self.assertEqual(next(r for r in self.observe_recovery_cli()['modules'] if r['module']=='ddns')['error_kind'],'state_unavailable')
        self.assertEqual(stage.read_text(),'SECRET_SENTINEL')
        stage.unlink();old=self.state_file.read_bytes();self.state_file.unlink()
        outside=self.base/'foreign-cache';outside.write_text('SECRET_SENTINEL');outside.chmod(0o600);self.state_file.symlink_to(outside)
        self.publish();self.assertEqual(self.stored()['cache_state'],'unsafe');self.assertTrue(self.state_file.is_symlink())
        self.assertEqual(outside.read_text(),'SECRET_SENTINEL')

    def test_other_modules_and_global_record_are_preserved_across_real_transitions(self):
        self.grant();self.seed();global_before=self.global_record();self.managed()
        self.assertEqual(self.global_path.read_bytes(),global_before)
        out=self.observe_recovery_cli();self.assertEqual([r['module'] for r in out['modules']],['proxy'])
        self.state_call('reset','ddns_a','--confirm')
        self.assertEqual(self.global_path.read_bytes(),global_before)
        self.assertEqual([r['module'] for r in self.observe_recovery_cli()['modules']],['ddns','proxy'])

    def test_source_change_during_publication_refuses_commit_and_leaves_inspection_evidence(self):
        self.grant();self.seed();self.managed();old=self.record_path.read_bytes();source=self.source.read_bytes()
        self.fault('fsync','\nif any(a.endswith("/.ddns-recovery-next") for a in sys.argv[1:]):\n from pathlib import Path\n p=Path('+repr(str(self.source))+');p.write_bytes(p.read_bytes()+b"\\n")')
        self.publish(7);self.restore_tool('fsync')
        self.assertEqual(self.record_path.read_bytes(),old)
        self.assertTrue((self.native.lockdir/'.ddns-recovery-pending').exists())
        self.source.write_bytes(source)

    def test_environment_cannot_open_disabled_producer_and_internal_call_needs_borrowed_locks(self):
        p=subprocess.run([self.busybox,'ash',str(self.producer),'publish-internal'],env=self.env,capture_output=True,timeout=5)
        self.assertEqual(p.returncode,4)
        self.producer.write_text(self.producer.read_text().replace('ddns_recovery_publish_enabled=true','ddns_recovery_publish_enabled=false'))
        p=subprocess.run([self.busybox,'ash',str(self.producer),'publish-internal'],env={**self.env,'ddns_recovery_publish_enabled':'true'},capture_output=True,timeout=5)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(2,b'',b''))
        self.assertFalse(self.record_path.exists());self.assertEqual(self.calls,[])


def suite(runtime):
    cls=Runtime if runtime else Static
    return unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    r=unittest.TextTestRunner(verbosity=2,failfast=True).run(suite(a.runtime));raise SystemExit(not r.wasSuccessful())
