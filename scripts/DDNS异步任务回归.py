#!/usr/bin/env python3
"""Retained single-rule jobs against the existing isolated four-provider TLS fixtures."""
import argparse,copy,fcntl,hashlib,json,os,re,subprocess,time,unittest
from pathlib import Path
from project import ROOT
from lupa.lua51 import LuaRuntime
from DDNS原生授权UI回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase
from DDNS计划回归 import fixture_uid
PROTO=ROOT/'project/core/prototype'
class Static(unittest.TestCase):
 def test_closed_gate_fixed_limits_grammar_and_no_replay_or_collection(self):
  import tree_sitter,tree_sitter_bash
  b=(PROTO/'homegate-ddns-job.sh').read_bytes();parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()));self.assertFalse(parser.parse(b).root_node.has_error)
  self.assertIn(b'ddns_ui_jobs_enabled=false',b);self.assertIn(b'[ "$count" -lt 8 ]',b);self.assertIn(b'current_now+300',b)
  for text in [b'kill ',b'curl',b'eval ',b'--confirm-closeouts',b'homegate-cli.sh']:self.assertNotIn(text,b)
  self.assertNotIn(b'rm -r',b)
  for n in ['ddns-job.lua','homegate-ddns-job.lua','ddns-ui-policy.lua','homegate-ddns-ui.lua']:LuaRuntime().compile((PROTO/n).read_bytes())
 def specimen(self):return {'api_version':1,'prototype':True,'ok':True,'phase':'ddns-job','job':'a'*32,'rule':'ddns_a','configuration_revision':3,'pending':False,'state':'interrupted','result':False,'last_effect':'unknown','reason':'interrupted','effect':'none','write_ready':False}
 def test_retained_history_schema_is_bounded_sorted_and_still_strict(self):
  lua=LuaRuntime(unpack_returned_tuples=True);policy=lua.execute((PROTO/'ddns-job.lua').read_bytes());table=lambda d:lua.table_from(d,recursive=True)
  d={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-jobs','jobs':[{**self.specimen(),'job':format(n,'032x')} for n in range(1,33)],'effect':'none','write_ready':False};self.assertTrue(policy.response('jobs','',table(d)))
  for jobs in [d['jobs']+[self.specimen()],list(reversed(d['jobs'])),[d['jobs'][0]]*2,[{**d['jobs'][0],'secret':'SECRET_SENTINEL'}]]:self.assertFalse(policy.response('jobs','',table({**d,'jobs':jobs})))
 def test_public_job_schema_rejects_secret_fields_success_on_unknown_and_foreign_scope(self):
  lua=LuaRuntime(unpack_returned_tuples=True);p=lua.execute((PROTO/'ddns-job.lua').read_bytes());d=self.specimen();table=lambda x:lua.table_from(x,recursive=True)
  self.assertTrue(p.response('submit','a'*32+':ddns_a',table(d)))
  for k,v in [('secret','SECRET_SENTINEL'),('last_effect','none'),('pending',True),('job','b'*32),('result',{'status':'created'})]:self.assertFalse(p.response('submit','a'*32+':ddns_a',table({**d,k:v})))
  self.assertFalse(p.row(table({'rule':'a','provider':'cloudflare','status':'created','effect':'unknown','error_kind':'','retryable':False,'retry_in':0}),'a'))
 def test_submit_consent_exact_ticket_and_read_acl(self):
  lua=LuaRuntime(unpack_returned_tuples=True);p=lua.execute((PROTO/'ddns-ui-policy.lua').read_bytes());select=lua.execute((PROTO/'ddns-authority.lua').read_bytes()).selection;id=lua.execute((PROTO/'ddns-plan.lua').read_bytes()).id
  d={'action':'submit','job':'a'*32,'rule':'ddns_a','consent':'1'};table=lambda x:lua.table_from(x,recursive=True)
  self.assertEqual(p.request(table(d),select,id),('submit','a'*32+':ddns_a'))
  for k,v in [('consent','0'),('job','../bad'),('rule','a,b'),('extra','x')]:self.assertIsNone(p.request(table({**d,k:v}),select,id))
  acl=json.loads((ROOT/'project/luci/prototype/js/ddns-acl.json').read_text())['luci-app-homegate-ddns'];self.assertEqual(set(acl['read']['ubus']['homegate_ddns']),{'status','jobs'});self.assertEqual(set(acl['write']['ubus']['homegate_ddns']),{'preview','commit','revoke','submit','maintain_preview','maintain_commit'})
 def test_quiescence_is_gate_independent_and_lifecycle_holds_business_lock(self):
  s=(PROTO/'homegate-lifecycle-prepare.sh').read_text();self.assertLess(s.index('flock -n 6'),s.index('homegate-ddns-job.sh'));self.assertLess(s.index('homegate-ddns-job.sh'),s.index('ash "$dir/homegate-store-bootstrap'))
  self.assertIn('check-quiescent',(PROTO/'homegate-ddns-schedule.sh').read_text());self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

class JobMixin:
 def setUp(self):
  super().setUp();self.original_source=self.source.read_bytes();self.job_helper=self.engine.parent/'homegate-ddns-job.sh';self.job_dir=self.native.lockdir/'ddns-ui-jobs'
  mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
  b=self.job_helper.read_text().replace('ddns_ui_jobs_enabled=false','ddns_ui_jobs_enabled=true');b=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],b).replace('current_now=$(lua "$dir/worker-process.lua" now)','current_now=$(cat '+str(self.clock)+')')
  self.job_helper.write_text(fixture_uid(b.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
 def job_call(self,*args,expected=0):
  p=subprocess.run([self.busybox,'ash',str(self.job_helper),*args],env=self.env,capture_output=True,timeout=12)
  self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertLess(len(p.stdout),65536)
  for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',os.fsencode(self.base),b'example.test',b'2001:db8']:self.assertNotIn(marker,p.stdout)
  return json.loads(p.stdout)
 def launch(self,n=1,rule='ddns_a',expected=0):return self.job_call('submit',format(n,'032x'),rule,'--confirm',expected=expected)
 def wait_job(self,n=1):
  until=time.monotonic()+35
  while time.monotonic()<until:
   out=self.job_call('list');j=next(v for v in out['jobs'] if v['job']==format(n,'032x'))
   if not j['pending']:return j
   time.sleep(.15)
  self.fail('fixed single job did not finish')
 def test_single_mutation_retained_deduplicated_and_durable_fence_untouched(self):
  self.launch();j=self.wait_job();self.assertEqual((j['state'],j['result']['status'],j['last_effect']),('finished','created','confirmed'));self.assertEqual(len(self.mutations()),1)
  old=self.files(self.journal);self.launch();self.assertEqual(len(self.mutations()),1);self.launch(2,expected=4);self.assertEqual(self.files(self.journal),old);self.assertFalse(self.archive.exists());self.assertEqual(self.source.read_bytes(),self.original_source)
 def test_noop_job_read_is_passive_and_rule_ticket_cannot_be_reused(self):
  self.seed();self.launch();j=self.wait_job();self.assertEqual(j['result']['status'],'unchanged');n=len(self.calls);net=self.netlog.read_bytes();before=self.files(self.job_dir)
  self.job_call('list');self.launch();self.launch(rule='ddns_b',expected=4);self.assertEqual(len(self.calls),n);self.assertEqual(self.netlog.read_bytes(),net);self.assertEqual(self.files(self.job_dir),before)
class CF(JobMixin,CFBase):pass
class Ali(JobMixin,AliBase):pass
class DNP(JobMixin,DNPBase):pass
class HW(JobMixin,HWBase):pass
class Boundaries(CF):
 def test_pending_observation_does_not_race_mutable_result_stage(self):
  self.seed();self.launch();self.wait_job();path=self.job_dir/format(1,'032x');stage=path/'result.next';probe=self.base/'mutable-stage-inspected';before=self.files(self.job_dir);calls=len(self.calls)
  # Represent a publisher's lock after all actual TLS work has finished. The
  # command fault must not change an in-flight provider worker's tool set.
  with (path/'lock').open('rb') as held:
   fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);stage.touch(mode=0o600)
   self.fault('stat','from pathlib import Path\nif sys.argv[-1:]==['+repr(str(stage))+']:\n Path('+repr(str(stage))+').unlink(missing_ok=True);Path('+repr(str(probe))+').touch();sys.exit(1)')
   try:
    out=self.job_call('list');self.assertTrue(out['jobs'][0]['pending']);self.assertEqual(out['jobs'][0]['last_effect'],'unknown');self.assertFalse(probe.exists());self.assertTrue(stage.exists())
   finally:self.restore_tool('stat');stage.unlink(missing_ok=True)
  self.assertEqual(self.wait_job()['result']['status'],'unchanged');self.assertEqual(self.files(self.job_dir),before);self.assertEqual(len(self.calls),calls)
 def test_empty_read_does_not_create_and_gate_does_not_accept_environment(self):
  self.assertEqual(self.job_call('list')['jobs'],[]);self.assertFalse(self.job_dir.exists());self.job_helper.write_text(self.job_helper.read_text().replace('ddns_ui_jobs_enabled=true','ddns_ui_jobs_enabled=false'));self.launch(expected=2);self.assertEqual(self.job_call('check-quiescent')['jobs'],[]);self.assertEqual(self.calls,[])
 def test_missing_consent_bad_job_and_foreign_commands_are_pre_io(self):
  for args in [('submit','a'*32,'ddns_a'),('submit','a'*32,'a;bad','--confirm'),('submit','../bad','ddns_a','--confirm'),('work','a'*32),('remove',)]:self.job_call(*args,expected=2 if args[0]!='work' else 7)
  self.assertEqual(self.calls,[]);self.assertFalse(self.job_dir.exists())
 def test_pending_duplicate_returns_immediately_and_refuses_new_job(self):
  self.seed();entered,release=self.gated_http();self.launch();self.assertTrue(entered.wait(15));n=len(self.calls);self.assertTrue(self.launch()['pending']);self.launch(2,expected=4);self.assertEqual(len(self.calls),n);self.job_call('check-quiescent',expected=4);self.candidate_call('lifecycle-prepare',expected=4);release.set();self.assertEqual(self.wait_job()['result']['status'],'unchanged')
 def test_unknown_retains_original_evidence_and_never_retries(self):
  def hook(*args):
   if args[0]!='GET':self.seed();return 500,{'success':False,'errors':[]}
  self.hook=hook;self.launch();j=self.wait_job();self.assertEqual(j['last_effect'],'unknown');old=self.files(self.journal);n=len(self.calls);self.launch();self.launch(2,expected=4);self.job_call('check-quiescent',expected=4);self.assertEqual(len(self.calls),n);self.assertEqual(self.files(self.journal),old)
 def test_failed_spawn_is_interrupted_and_lifecycle_refuses_without_cleanup(self):
  self.fault('setsid','sys.exit(1)');self.launch();j=self.wait_job();self.assertEqual((j['state'],j['last_effect']),('interrupted','unknown'));old=self.files(self.job_dir);self.launch();self.launch(2,expected=4);self.candidate_call('lifecycle-prepare',expected=4);self.job_helper.write_text(self.job_helper.read_text().replace('ddns_ui_jobs_enabled=true','ddns_ui_jobs_enabled=false'));self.job_call('check-quiescent',expected=4);self.assertEqual(self.files(self.job_dir),old);self.assertEqual(self.calls,[])
 def test_corrupt_private_result_symlink_and_foreign_members_are_preserved(self):
  self.seed();self.launch();self.wait_job();p=self.job_dir/format(1,'032x')/'result';original=p.read_bytes();p.write_bytes(original+b'x');self.job_call('list',expected=7);self.assertEqual(p.read_bytes(),original+b'x');p.write_bytes(original);outside=self.base/'outside-job';p.rename(outside);p.symlink_to(outside);self.job_call('list',expected=7);self.assertEqual(outside.read_bytes(),original);p.unlink();outside.rename(p);extra=p.parent/'extra';extra.write_bytes(b'KEEP');extra.chmod(0o600);self.job_call('list',expected=7);self.assertEqual(extra.read_bytes(),b'KEEP')
 def test_eight_retained_jobs_bound_and_read_only_quiescence(self):
  self.seed()
  for n in range(1,9):self.clock.write_text(str(1000+300*(n-1))+'\n');self.launch(n);self.assertEqual(self.wait_job(n)['result']['status'],'unchanged')
  old=self.files(self.job_dir);self.clock.write_text('5000\n');self.launch(9,expected=4);self.launch(1);self.job_call('check-quiescent');self.assertEqual(self.files(self.job_dir),old);self.assertEqual(self.mutations(),[])
 def test_expired_admission_returns_known_no_dispatch_and_keeps_record(self):
  self.fault('setsid','from pathlib import Path\nPath('+repr(str(self.clock))+').write_text("1301\\n")');self.launch();j=self.wait_job();self.assertEqual((j['reason'],j['last_effect']),('changed','none'));self.assertEqual(self.calls,[]);self.assertEqual(j['result']['status'],'blocked')
 def test_job_result_publication_failure_retains_unknown_and_original_receipt(self):
  self.fault('fsync','sys.exit(1) if any(a.endswith("/result.next") for a in sys.argv[1:]) else None');self.launch();j=self.wait_job();self.assertEqual((j['state'],j['last_effect']),('interrupted','unknown'));self.assertEqual(len(self.mutations()),1);old=self.files(self.journal);self.launch(2,expected=4);self.job_call('check-quiescent',expected=4);self.assertEqual(self.files(self.journal),old);self.assertTrue((self.job_dir/format(1,'032x')/'result.next').exists())
 def test_ui_submission_outer_effect_is_unknown_and_poll_is_read_only(self):
  self.seed();self.request.write_text(json.dumps({'action':'submit','job':'a'*32,'rule':'ddns_a','consent':'1'}));p=subprocess.run([self.busybox,'ash',str(self.ui_helper),str(self.request)],env=self.env,capture_output=True,timeout=12);self.assertEqual((p.returncode,p.stderr),(0,b''),p.stdout);d=json.loads(p.stdout);self.assertEqual((d['effect'],d['operation']),('unknown','submit'));self.wait_job(int('a'*32,16));n=len(self.calls);self.ask({'action':'jobs'});self.assertEqual(len(self.calls),n)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();suite=unittest.TestSuite()
 for c in ([CF,Ali,DNP,HW,Boundaries] if a.runtime else [Static]):
  members=JobMixin.__dict__ if c in [CF,Ali,DNP,HW] else c.__dict__;suite.addTests(c(n) for n,v in members.items() if n.startswith('test_') and callable(v))
 r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
