#!/usr/bin/env python3
"""Fresh, source-bound job maintenance; no HTTP, retry or receipt retirement."""
import argparse,copy,json,subprocess,unittest
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
 def test_confirmed_receipt_requires_new_consent_archives_original_and_keeps_proof(self):
  self.launch();j=self.wait_job();self.assertEqual(j['last_effect'],'confirmed');before=self.files(self.journal);p=self.maintain();self.assertEqual(p['operation'],'archive');self.assertEqual(self.files(self.journal),before);self.assertFalse(self.archive.exists())
  self.maintain('commit','0'*32,5);self.maintain('commit',p['confirmation']);self.assertFalse(self.journal.exists());self.assertTrue(self.archive.exists());self.assertEqual(self.wait_job()['reason'],'archived');self.assertEqual(len(self.mutations()),1)
  self.maintain('commit',p['confirmation'],4);self.launch();self.assertEqual(len(self.mutations()),1);self.assertTrue((self.job_dir/format(1,'032x')/'proof').exists());self.assertTrue(self.archive.exists())
 def test_known_none_compacts_only_raw_and_preserves_identifier_budget(self):
  self.seed();self.launch();self.wait_job();path=self.job_dir/format(1,'032x');self.assertTrue((path/'raw').exists());meta=(path/'meta').read_bytes();p=self.maintain();self.assertEqual(p['operation'],'compact');self.maintain('commit',p['confirmation']);self.assertFalse((path/'raw').exists());self.assertEqual((path/'meta').read_bytes(),meta);self.assertEqual(self.wait_job()['reason'],'compacted');self.launch();self.assertEqual(self.mutations(),[])
class CF(MaintainMixin,CFBase):pass
class Ali(MaintainMixin,AliBase):pass
class DNP(MaintainMixin,DNPBase):pass
class HW(MaintainMixin,HWBase):pass
class Boundaries(CF):
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
