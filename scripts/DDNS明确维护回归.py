#!/usr/bin/env python3
"""Fresh, source-bound job maintenance; no HTTP, retry or receipt retirement."""
import argparse,copy,fcntl,hashlib,json,shutil,subprocess,unittest
from project import ROOT
from DDNS异步任务回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase,Static as JobStatic
from lupa.lua51 import LuaRuntime
PROTO=ROOT/'project/core/prototype'
class Static(unittest.TestCase):
 def test_new_gate_and_exact_nonce_consent_contract(self):
  lua=LuaRuntime(unpack_returned_tuples=True);p=lua.execute((PROTO/'ddns-ui-policy.lua').read_bytes());select=lua.execute((PROTO/'ddns-authority.lua').read_bytes()).selection;id=lua.execute((PROTO/'ddns-plan.lua').read_bytes()).id;table=lambda d:lua.table_from(d,recursive=True)
  d={'action':'maintain_commit','job':'a'*32,'confirmation':'b'*32,'consent':'1'};self.assertEqual(p.request(table(d),select,id),('maintain_commit','a'*32+':'+'b'*32))
  for k,v in [('job','../x'),('confirmation','short'),('consent','0'),('extra','PRIVATE_SENTINEL')]:self.assertIsNone(p.request(table({**d,k:v}),select,id))
  b=(PROTO/'homegate-ddns-job.sh').read_text();self.assertIn('ddns_ui_maintenance_enabled=false',b);self.assertNotIn('--runtime-retire-archive',b);self.assertNotIn('rm -r',b)
 def test_maintenance_public_schema_never_accepts_unknown_or_secret(self):
  lua=LuaRuntime(unpack_returned_tuples=True);p=lua.execute((PROTO/'ddns-job.lua').read_bytes());table=lambda d:lua.table_from(d,recursive=True)
  d={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-maintenance','job':'a'*32,'rule':'ddns_a','operation':'archive','confirmation':'b'*32,'expires_in':300,'effect':'none','write_ready':False};self.assertTrue(p.response('maintain_preview','a'*32,table(d)))
  for k,v in [('job','c'*32),('secret','PRIVATE_SENTINEL'),('operation','retry'),('expires_in',301),('write_ready',True)]:self.assertFalse(p.response('maintain_preview','a'*32,table({**d,k:v})))
 def test_changed_shell_and_lua_syntax_and_production_gates(self):
  import tree_sitter,tree_sitter_bash
  parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()));self.assertFalse(parser.parse((PROTO/'homegate-ddns-job.sh').read_bytes()).root_node.has_error)
  for n in ['homegate-ddns-job.lua','ddns-job.lua','ddns-ui-policy.lua']:LuaRuntime().compile((PROTO/n).read_bytes())
  for n in ['core','luci']:self.assertNotIn('prototype/',(ROOT/'project'/n/'Makefile').read_text())
class MaintainMixin:
 def setUp(self):
  super().setUp();self.job_helper.write_text(self.job_helper.read_text().replace('ddns_ui_maintenance_enabled=false','ddns_ui_maintenance_enabled=true'))
 def maintain(self,action='preview',nonce=None,expected=0,n=1):
  count=len(self.calls);args=['maintain-'+action,format(n,'032x')]+([nonce,'--confirm'] if action=='commit' else [])
  d=self.job_call(*args,expected=expected);self.assertEqual(len(self.calls),count);return d
 def clone_retained_fixture(self,n):
  # Capacity boundary data only: one real completed job, copied with a new
  # canonical meta identity and matching maintenance digest. Not network runs.
  source=self.job_dir/format(1,'032x');target=self.job_dir/format(n,'032x');shutil.copytree(source,target)
  def write_frame(path,tag,data):
   body=tag+b'\n'+data+b'\n';path.write_bytes(body+hashlib.sha256(body).hexdigest().encode()+b'\n')
  fields=(target/'meta').read_bytes().splitlines()[1].split(b':');fields[0]=format(n,'032x').encode();write_frame(target/'meta',b'HGDDNSUIJOB1',b':'.join(fields))
  if (target/'maintained').exists():
   fields=(target/'maintained').read_bytes().splitlines()[1].split(b':');fields[0]=hashlib.sha256((target/'meta').read_bytes()).hexdigest().encode();write_frame(target/'maintained',b'HGDDNSUIMAINTAINED1',b':'.join(fields))
  return target
 def test_explicit_maintenance_releases_one_slot_without_replaying_retained_id(self):
  self.seed();self.launch();self.wait_job()
  for n in range(2,9):self.clone_retained_fixture(n)
  before=self.files(self.job_dir);calls=len(self.calls);self.launch(9,expected=4);self.assertEqual(self.files(self.job_dir),before);p=self.maintain();self.launch(9,expected=4);self.assertEqual(len(self.calls),calls)
  self.maintain('commit',p['confirmation']);old=self.files(self.job_dir/format(1,'032x'));self.launch();self.launch(rule='ddns_b',expected=4);self.assertEqual(len(self.calls),calls)
  self.clock.write_text('1300\n');self.launch(9);self.assertEqual(self.wait_job(9)['result']['status'],'unchanged');out=self.job_call('list');self.assertEqual(len(out['jobs']),9);self.assertEqual(out['jobs'][0]['reason'],'compacted');self.assertEqual(self.files(self.job_dir/format(1,'032x')),old);self.assertEqual(self.mutations(),[])
 def interrupted_preview(self,existing=False,tool='mv'):
  previous=self.maintain() if existing else None
  self.fault(tool,'sys.exit(1) if any(a.endswith("/maintenance.next") for a in sys.argv[1:]) else None');self.maintain(expected=7);self.restore_tool(tool)
  path=self.job_dir/format(1,'032x');self.assertTrue((path/'maintenance.next').is_file());nonce=(path/'maintenance.next').read_bytes().splitlines()[1].split(b':')[7].decode()
  return path,previous,nonce
 def test_confirmed_receipt_requires_new_consent_archives_original_and_keeps_proof(self):
  self.launch();j=self.wait_job();self.assertEqual(j['last_effect'],'confirmed');before=self.files(self.journal);p=self.maintain();self.assertEqual(p['operation'],'archive');self.assertEqual(self.files(self.journal),before);self.assertFalse(self.archive.exists())
  self.maintain('commit','0'*32,5);self.maintain('commit',p['confirmation']);self.assertFalse(self.journal.exists());self.assertTrue(self.archive.exists());self.assertEqual(self.wait_job()['reason'],'archived');self.assertEqual(len(self.mutations()),1)
  self.maintain('commit',p['confirmation'],4);self.launch();self.assertEqual(len(self.mutations()),1);self.assertTrue((self.job_dir/format(1,'032x')/'proof').exists());self.assertTrue(self.archive.exists())
 def test_known_none_compacts_only_raw_and_preserves_identifier_budget(self):
  self.seed();self.launch();self.wait_job();path=self.job_dir/format(1,'032x');self.assertTrue((path/'raw').exists());meta=(path/'meta').read_bytes();p=self.maintain();self.assertEqual(p['operation'],'compact');self.maintain('commit',p['confirmation']);self.assertFalse((path/'raw').exists());self.assertEqual((path/'meta').read_bytes(),meta);self.assertEqual(self.wait_job()['reason'],'compacted');self.launch();self.assertEqual(self.mutations(),[])
 def test_interrupted_preview_requires_fresh_nonce_and_explicit_archive(self):
  self.launch();self.wait_job();before=self.files(self.journal);path,old,staged=self.interrupted_preview(existing=True);evidence=self.files(self.job_dir)
  self.maintain('commit',old['confirmation'],5);self.maintain('commit',staged,5);self.job_call('list');self.assertEqual(self.files(self.job_dir),evidence)
  self.clock.write_text('1301\n');fresh=self.maintain();self.assertNotIn(fresh['confirmation'],[old['confirmation'],staged]);self.assertFalse((path/'maintenance.next').exists());self.assertEqual(self.files(self.journal),before);self.assertFalse(self.archive.exists())
  self.maintain('commit',old['confirmation'],5);self.maintain('commit',staged,5);self.maintain('commit',fresh['confirmation']);self.assertEqual(self.wait_job()['reason'],'archived');self.assertEqual(len(self.mutations()),1)
class CF(MaintainMixin,CFBase):pass
class Ali(MaintainMixin,AliBase):pass
class DNP(MaintainMixin,DNPBase):pass
class HW(MaintainMixin,HWBase):pass
class Boundaries(CF):
 def test_confirmed_archive_releases_slot_but_keeps_original_receipt_and_ticket(self):
  self.launch();self.wait_job()
  for n in range(2,9):self.clone_retained_fixture(n)
  self.launch(9,expected=4);p=self.maintain();self.maintain('commit',p['confirmation']);archive=self.files(self.archive);old=self.files(self.job_dir/format(1,'032x'));calls=len(self.calls);self.launch();self.assertEqual(len(self.calls),calls)
  self.clock.write_text('1300\n');self.launch(9);self.assertEqual(self.wait_job(9)['result']['status'],'unchanged');self.assertEqual(self.files(self.archive),archive);self.assertEqual(self.files(self.job_dir/format(1,'032x')),old);self.assertEqual(len(self.mutations()),1)
 def test_total_identifier_budget_preserves_dedup_and_refuses_overflow(self):
  self.seed();self.launch();self.wait_job();p=self.maintain();self.maintain('commit',p['confirmation'])
  for n in range(2,33):self.clone_retained_fixture(n)
  before=self.files(self.job_dir);calls=len(self.calls);out=self.job_call('list');self.assertEqual(len(out['jobs']),32);lua=LuaRuntime(unpack_returned_tuples=True);policy=lua.execute((PROTO/'ddns-job.lua').read_bytes());self.assertTrue(policy.response('jobs','',lua.table_from(out,recursive=True)))
  self.launch();self.launch(rule='ddns_b',expected=4);self.launch(33,expected=4);self.job_call('check-quiescent');self.assertEqual(self.files(self.job_dir),before);self.assertEqual(len(self.calls),calls)
  self.clone_retained_fixture(33);before=self.files(self.job_dir);self.job_call('list',expected=7);self.launch(34,expected=7);self.assertEqual(self.files(self.job_dir),before);self.assertEqual(len(self.calls),calls)
 def test_incomplete_final_publication_never_releases_eighth_slot(self):
  self.seed();self.launch();self.wait_job()
  for n in range(2,9):self.clone_retained_fixture(n)
  p=self.maintain();self.fault('mv','sys.exit(1) if any(a.endswith("/maintained.next") for a in sys.argv[1:]) else None');self.maintain('commit',p['confirmation'],7);self.restore_tool('mv');before=self.files(self.job_dir);calls=len(self.calls);self.launch(9,expected=4);self.assertEqual(self.files(self.job_dir),before);self.assertEqual(len(self.calls),calls)
  p=self.maintain();self.maintain('commit',p['confirmation']);self.clock.write_text('1300\n');self.launch(9);self.assertEqual(self.wait_job(9)['result']['status'],'unchanged')
 def test_invalid_or_staged_final_marker_never_grants_capacity(self):
  self.seed();self.launch();self.wait_job()
  for n in range(2,9):self.clone_retained_fixture(n)
  p=self.maintain();self.maintain('commit',p['confirmation']);path=self.job_dir/format(1,'032x');marker=path/'maintained';original=marker.read_bytes();calls=len(self.calls)
  body=b'HGDDNSUIMAINTAINED1\n'+b'0'*64+b':'+hashlib.sha256((path/'result').read_bytes()).hexdigest().encode()+b':compact\n'
  for data in [original+b'x',body+hashlib.sha256(body).hexdigest().encode()+b'\n']:
   marker.write_bytes(data);before=self.files(self.job_dir);self.launch(9,expected=7);self.assertEqual(self.files(self.job_dir),before)
  marker.write_bytes(original);outside=self.base/'outside-maintained';marker.rename(outside);marker.symlink_to(outside);self.launch(9,expected=7);self.assertEqual(outside.read_bytes(),original);marker.unlink();outside.rename(marker)
  for name in ['maintained.next','maintenance','maintenance.next']:
   stage=path/name;stage.write_bytes(original);stage.chmod(0o600);before=self.files(self.job_dir);self.launch(9,expected=7);self.assertEqual(self.files(self.job_dir),before);stage.unlink()
  self.assertEqual(len(self.calls),calls)
 def test_retained_history_cannot_mask_live_or_interrupted_work(self):
  self.seed();self.launch();self.wait_job();p=self.maintain();self.maintain('commit',p['confirmation'])
  for n in range(2,10):self.clone_retained_fixture(n)
  before=self.files(self.job_dir);calls=len(self.calls)
  with (self.job_dir/format(1,'032x')/'lock').open('rb') as held:
   fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertTrue(self.launch()['pending']);self.launch(10,expected=4);self.job_call('check-quiescent',expected=4);self.assertEqual(self.files(self.job_dir),before)
  self.launch(10,expected=4);self.assertEqual(self.files(self.job_dir),before);self.clock.write_text('1300\n');self.fault('setsid','sys.exit(1)');self.launch(10);self.assertEqual(self.wait_job(10)['state'],'interrupted');before=self.files(self.job_dir);self.launch(11,expected=4);self.job_call('check-quiescent',expected=4);self.maintain(n=10,expected=4);self.assertEqual(self.files(self.job_dir),before);self.assertEqual(len(self.calls),calls)
 def test_known_none_stage_retirement_failure_preserves_data_then_compacts(self):
  self.seed();self.launch();self.wait_job();path,_,staged=self.interrupted_preview(tool='fsync');before=self.files(self.job_dir)
  self.fault('mv','sys.exit(1) if any(a.endswith("/maintenance-used") for a in sys.argv[1:]) else None');self.maintain(expected=7);self.assertEqual(self.files(self.job_dir),before);self.restore_tool('mv')
  fresh=self.maintain();self.maintain('commit',staged,5);self.maintain('commit',fresh['confirmation']);self.assertEqual(self.wait_job()['reason'],'compacted');self.assertFalse((path/'raw').exists());self.launch();self.assertEqual(self.mutations(),[])
 def test_corrupt_or_foreign_staged_frames_remain_untouched(self):
  self.seed();self.launch();self.wait_job();path,_,_=self.interrupted_preview();stage=path/'maintenance.next';original=stage.read_bytes()
  fields=original.splitlines()[1].split(b':')
  specimens=[original+b'x',original[:-12]]
  for index,value in [(0,b'f'*32),(1,b'f'*64),(2,b'f'*64),(3,b'none'),(4,b'f'*64),(5,b'archive'),(6,b'22222222-2222-2222-2222-222222222222'),(7,b'short'),(8,b'01000'),(8,b'1001'),(9,b'1301')]:
   changed=fields[:];changed[index]=value;body=b'HGDDNSUIMAINTENANCE1\n'+b':'.join(changed)+b'\n';specimens.append(body+hashlib.sha256(body).hexdigest().encode()+b'\n')
  for start,finish in [(b'1001',b'1301'),(b'999',b'1299'),(b'999999999',b'1000000299')]:
   changed=fields[:];changed[8:10]=[start,finish];body=b'HGDDNSUIMAINTENANCE1\n'+b':'.join(changed)+b'\n';specimens.append(body+hashlib.sha256(body).hexdigest().encode()+b'\n')
  for suffix in [b':',b'::',b' ']:
   body=b'HGDDNSUIMAINTENANCE1\n'+b':'.join(fields)+suffix+b'\n';specimens.append(body+hashlib.sha256(body).hexdigest().encode()+b'\n')
  for raw in specimens:
   stage.write_bytes(raw);before=self.files(self.job_dir);self.maintain(expected=7);self.assertEqual(self.files(self.job_dir),before)
  stage.write_bytes(original);fresh=self.maintain();self.maintain('commit',fresh['confirmation']);self.assertEqual(self.wait_job()['reason'],'compacted')
 def test_linked_preview_stage_preserves_external_file(self):
  self.seed();self.launch();self.wait_job();path,_,_=self.interrupted_preview();stage=path/'maintenance.next';outside=self.base/'outside-maintenance-stage';stage.rename(outside);stage.symlink_to(outside);before=outside.read_bytes()
  self.maintain(expected=7);self.assertTrue(stage.is_symlink());self.assertEqual(outside.read_bytes(),before);stage.unlink();outside.rename(stage);fresh=self.maintain();self.maintain('commit',fresh['confirmation'])
 def test_new_preview_publication_failure_never_revives_retired_nonces(self):
  self.seed();self.launch();self.wait_job();path,old,staged=self.interrupted_preview(existing=True)
  self.fault('fsync','sys.exit(1) if any(a.endswith("/maintenance.next") for a in sys.argv[1:]) else None');self.maintain(expected=7);self.restore_tool('fsync');self.assertFalse((path/'maintenance').exists());self.assertTrue((path/'maintenance.next').exists());self.assertTrue((path/'raw').exists())
  self.maintain('commit',old['confirmation'],5);self.maintain('commit',staged,5);fresh=self.maintain();self.maintain('commit',fresh['confirmation']);self.assertEqual(self.wait_job()['reason'],'compacted')
 def test_corrupt_published_preview_blocks_stage_recovery_without_overwrite(self):
  self.seed();self.launch();self.wait_job();path,_,_=self.interrupted_preview(existing=True);active=path/'maintenance';active.write_bytes(active.read_bytes()+b'x');before=self.files(self.job_dir);self.maintain(expected=7);self.assertEqual(self.files(self.job_dir),before)
 def test_retirement_sync_failure_keeps_stage_and_requires_new_consent(self):
  self.seed();self.launch();self.wait_job();path,old,staged=self.interrupted_preview(existing=True)
  self.fault('fsync','sys.exit(1) if any(a.endswith("/maintenance-used") for a in sys.argv[1:]) else None');self.maintain(expected=7);self.restore_tool('fsync');self.assertFalse((path/'maintenance').exists());self.assertTrue((path/'maintenance.next').exists());self.maintain('commit',old['confirmation'],5);self.maintain('commit',staged,5)
  fresh=self.maintain();self.maintain('commit',fresh['confirmation']);self.assertEqual(self.wait_job()['reason'],'compacted')
 def test_changed_source_refuses_valid_stage_recovery_without_cleanup(self):
  self.seed();self.launch();self.wait_job();path,_,_=self.interrupted_preview();self.source.write_bytes(self.source.read_bytes()+b'\n');before=self.files(self.job_dir);self.maintain(expected=7);self.assertEqual(self.files(self.job_dir),before);self.assertTrue((path/'raw').exists())
 def test_superseded_expired_and_changed_source_previews_do_not_consume_proofs(self):
  self.launch();self.wait_job();a=self.maintain();b=self.maintain();before=self.files(self.journal);self.maintain('commit',a['confirmation'],5);self.clock.write_text('1301\n');self.maintain('commit',b['confirmation'],5);self.clock.write_text('1000\n');self.source.write_bytes(self.source.read_bytes()+b'\n');self.maintain('commit',b['confirmation'],7);self.assertEqual(self.files(self.journal),before);self.assertEqual(len(self.mutations()),1)
 def test_interrupted_work_never_allows_maintenance(self):
  self.fault('setsid','sys.exit(1)');self.launch();self.assertEqual(self.wait_job()['state'],'interrupted');before=self.files(self.job_dir);self.maintain(expected=4);self.assertEqual(before,self.files(self.job_dir));self.assertEqual(self.calls,[])
 def test_proof_corruption_is_preserved_and_cannot_target_another_receipt(self):
  self.launch();self.wait_job();path=self.job_dir/format(1,'032x')/'proof';before=self.files(self.journal);path.write_bytes(path.read_bytes()+b'x');self.maintain(expected=7);self.assertTrue(path.read_bytes().endswith(b'x'));self.assertEqual(self.files(self.journal),before)
 def test_partial_archive_publication_needs_fresh_preview_and_does_not_retry_dns(self):
  self.launch();self.wait_job();p=self.maintain();self.fault('mv','sys.exit(1) if any(a.endswith("/maintained.next") for a in sys.argv[1:]) else None');self.maintain('commit',p['confirmation'],7);self.assertTrue(self.archive.exists());self.assertFalse(self.journal.exists());self.restore_tool('mv');self.maintain('commit',p['confirmation'],5);q=self.maintain();self.maintain('commit',q['confirmation']);self.assertEqual(self.wait_job()['reason'],'archived');self.assertEqual(len(self.mutations()),1)
 def test_gate_closed_does_not_consume_preview_and_read_still_works(self):
  self.seed();self.launch();self.wait_job();p=self.maintain();before=self.files(self.job_dir);self.job_helper.write_text(self.job_helper.read_text().replace('ddns_ui_maintenance_enabled=true','ddns_ui_maintenance_enabled=false'));self.maintain('commit',p['confirmation'],2);self.job_call('list');self.assertEqual(before,self.files(self.job_dir))
 def test_unknown_receipt_cannot_be_previewed_or_maintained(self):
  def hook(*args):
   if args[0]!='GET':self.seed();return 500,{'success':False,'errors':[]}
  self.hook=hook;self.launch();self.assertEqual(self.wait_job()['last_effect'],'unknown');before=self.files(self.journal);self.maintain(expected=4);self.maintain('commit','a'*32,4);self.assertEqual(self.files(self.journal),before)
 def test_live_job_refuses_maintenance_without_waiting_or_cleanup(self):
  self.seed();entered,release=self.gated_http();self.launch();self.assertTrue(entered.wait(15))
  try:self.maintain(expected=4)
  finally:release.set()
  self.assertEqual(self.wait_job()['result']['status'],'unchanged')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();suite=unittest.TestSuite()
 for c in ([CF,Ali,DNP,HW,Boundaries] if a.runtime else [Static]):
  members=MaintainMixin.__dict__ if c in [CF,Ali,DNP,HW] else c.__dict__;suite.addTests(c(n) for n,v in members.items() if n.startswith('test_') and callable(v))
 r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
