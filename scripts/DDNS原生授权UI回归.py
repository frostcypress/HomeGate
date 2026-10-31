#!/usr/bin/env python3
"""Permission-only native UI against real existing Linux protocols; no new HTTP."""
import argparse,copy,json,os,re,subprocess,unittest
from pathlib import Path
from project import ROOT
from lupa.lua51 import LuaRuntime
from DDNS生命周期CLI回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase
from DDNS计划回归 import fixture_uid
PROTO=ROOT/'project/core/prototype';UI=ROOT/'project/luci/prototype'

class Static(unittest.TestCase):
 def test_shell_lua_and_candidate_installation_boundary(self):
  import tree_sitter,tree_sitter_bash
  parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()));body=(PROTO/'homegate-ddns-ui.sh').read_bytes();self.assertFalse(parser.parse(body).root_node.has_error)
  for p in [PROTO/'ddns-ui-policy.lua',PROTO/'homegate-ddns-ui.lua',UI/'lua/model/ddns.lua',UI/'lua/controller/ddns.lua']:LuaRuntime().compile(p.read_bytes())
  self.assertIn(b'ddns_ui_enabled=false',body);self.assertNotIn(b'ddns-sync',body);self.assertNotIn(b'schedule-run',body);self.assertNotIn(b'--confirm-closeouts',body)
  for p in [ROOT/'project/core/Makefile',ROOT/'project/luci/Makefile']:self.assertNotIn('prototype/',p.read_text())
 def test_lua_post_and_rpc_acl_are_separate_from_read(self):
  acl=json.loads((UI/'js/ddns-acl.json').read_text());v=acl['luci-app-homegate-ddns'];self.assertEqual(v['read']['ubus'],{'homegate_ddns':['status','jobs']});self.assertEqual(set(v['write']['ubus']['homegate_ddns']),{'preview','commit','revoke','submit','maintain_preview','maintain_commit'})
  c=(UI/'lua/controller/ddns.lua').read_text();self.assertIn('native_ddns_page_enabled=false',c)
  for action in ['preview','commit','revoke']:self.assertIn("post('"+action+"')",c)
  self.assertIn("h.getenv('REQUEST_METHOD')~='POST'",(UI/'lua/model/ddns.lua').read_text())
  rpc=(UI/'js/homegate-ddns.uc').read_text();self.assertIn('native_ddns_rpc_enabled = false',rpc);self.assertNotIn('web-submit',rpc)
 def test_request_contract_has_no_consent_bypass_or_foreign_fields(self):
  lua=LuaRuntime(unpack_returned_tuples=True);p=lua.execute((PROTO/'ddns-ui-policy.lua').read_bytes());select=lua.execute((PROTO/'ddns-authority.lua').read_bytes()).selection;id=lua.execute((PROTO/'ddns-plan.lua').read_bytes()).id
  table=lambda d:lua.table_from(d,recursive=True)
  self.assertEqual(p.request(table({'action':'preview','selection':'b,a'}),select,id),('preview','a,b'))
  for d in [{'action':'sync'},{'action':'commit','confirmation':'a'*32},{'action':'commit','confirmation':'a'*32,'consent':'0'},{'action':'status','selection':'a'},{'action':'preview','selection':'a,a'},{'action':'revoke','consent':'1','command':'SECRET_SENTINEL'}]:self.assertIsNone(p.request(table(d),select,id))
 def test_status_schema_and_preview_scope_reject_foreign_response(self):
  lua=LuaRuntime(unpack_returned_tuples=True);policy=lua.execute((PROTO/'ddns-ui-policy.lua').read_bytes());select=lua.execute((PROTO/'ddns-authority.lua').read_bytes()).selection;id=lua.execute((PROTO/'ddns-plan.lua').read_bytes()).id;codec=lua.execute((ROOT/'project/luci/lua/luasrc/model/homegate/backup.lua').read_bytes());schedule=lua.execute((PROTO/'ddns-schedule.lua').read_bytes())
  d={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-authority','confirmation':'a'*32,'configuration_revision':3,'rule':'a','provider':'cloudflare','expires_in':300,'authorized':False,'service_started':False}
  check=lambda x:policy.response('preview','a',lua.table_from(x,recursive=True),None,select,id,codec.json,schedule)
  self.assertTrue(check(d))
  for k,v in [('rule','b'),('secret','PRIVATE_SENTINEL'),('authorized',True),('expires_in',301),('service_started',True)]:self.assertFalse(check({**d,k:v}))
 def test_status_observations_are_validated_before_batch_projection(self):
  lua=LuaRuntime(unpack_returned_tuples=True);policy=lua.execute((PROTO/'ddns-ui-policy.lua').read_bytes());select=lua.execute((PROTO/'ddns-authority.lua').read_bytes()).selection;id=lua.execute((PROTO/'ddns-plan.lua').read_bytes()).id;codec=lua.execute((ROOT/'project/luci/lua/luasrc/model/homegate/backup.lua').read_bytes());schedule=lua.execute((PROTO/'ddns-schedule.lua').read_bytes())
  d={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-status','configuration_revision':1,'effect':'none','write_ready':False,'rules':[{'rule':'a','provider':'cloudflare','status':'ready','effect':'none','error_kind':'','retryable':False,'retry_in':0}]}
  def check(value,raw=None):
   if raw is None:raw=json.dumps(value,separators=(',',':'))+'\n'
   return policy.response('status','',lua.table_from(value,recursive=True),raw,select,id,codec.json,schedule)
  self.assertTrue(check(d));d['rules'][0].update(last_result='updated',last_effect='confirmed');self.assertTrue(check(d));d['rules'][0]['event_at']='2026-10-31T01:02:03Z';self.assertTrue(check(d))
  for k,v in [('last_result','FOREIGN'),('last_effect','write'),('last_effect',False),('event_at','2026-02-30T01:02:03Z'),('event_at','2026-13-01T01:02:03Z'),('event_at','2026-10-31T24:02:03Z'),('event_at','PRIVATE_SENTINEL'),('event_at',42),('effect','confirmed'),('secret','PRIVATE_SENTINEL'),('retry_in',-1),('retryable','false')]:
   bad=copy.deepcopy(d);bad['rules'][0][k]=v;self.assertFalse(check(bad),k)
  for k in ['last_result','last_effect']:
   bad=copy.deepcopy(d);del bad['rules'][0][k];self.assertFalse(check(bad))
  self.assertFalse(check(d,json.dumps(d)+'\n'));self.assertFalse(check({**d,'secret':'PRIVATE_SENTINEL'}))

class UIMixin:
 def setUp(self):
  super().setUp();self.ui_tmp=self.base/'ui-tmp';self.ui_tmp.mkdir(mode=0o700);self.request_dir=self.ui_tmp/('homegate-ddns-ui-'+'a'*32);self.request_dir.mkdir(mode=0o700);self.request=self.request_dir/'request';self.request.touch(mode=0o600)
  self.ui_helper=self.engine.parent/'homegate-ddns-ui.sh';b=self.ui_helper.read_text().replace('ddns_ui_enabled=false','ddns_ui_enabled=true').replace('/tmp',str(self.ui_tmp));self.ui_helper.write_text(fixture_uid(b.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
 def ask(self,d=None,expected=0,raw=None,args=None,env=None):
  if raw is not None:self.request.write_bytes(raw)
  elif d is not None:self.request.write_text(json.dumps(d,separators=(',',':'),sort_keys=True)+'\n',encoding='utf-8')
  n=len(self.calls);before={k:v for k,v in self.config_bytes().items() if 'ddns-authority' not in k}
  p=subprocess.run([self.busybox,'ash',str(self.ui_helper),*(args if args is not None else [str(self.request)])],env=env or self.env,capture_output=True,timeout=45)
  self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertLess(len(p.stdout),65536);self.assertEqual(len(self.calls),n);self.assertEqual(before,{k:v for k,v in self.config_bytes().items() if 'ddns-authority' not in k})
  for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',os.fsencode(self.base)]:self.assertNotIn(marker,p.stdout)
  out=json.loads(p.stdout);self.assertEqual(out['ok'],expected==0);self.assertEqual(out['effect'],'none');self.assertFalse(out['write_ready']);return out.get('report',out)
 def test_preview_commit_and_revoke_never_start_services_or_http(self):
  before=self.source.read_bytes();p=self.ask({'action':'preview','selection':'ddns_b'});self.assertFalse(p['authorized']);self.assertEqual(p['rule'],'ddns_b')
  self.ask({'action':'commit','confirmation':p['confirmation'],'consent':'1'});self.auth('check-rule','ddns_b');self.auth('check-rule','ddns_a',expected=7)
  status=self.ask({'action':'status'});self.assertEqual([r['status'] for r in status['rules']],['unauthorized','ready','unauthorized']);self.assertFalse(self.state_dir.exists())
  self.ask({'action':'revoke','consent':'1'});self.assertTrue(all(r['status']=='unauthorized' for r in self.ask({'action':'status'})['rules']));self.assertEqual(self.source.read_bytes(),before);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists());self.assertTrue(all(x=='enabled' for x in self.initlog.read_text().splitlines()))
 def test_multi_preview_requires_matching_explicit_confirmation(self):
  self.revoke_fixture();p=self.ask({'action':'preview','selection':'ddns_c,ddns_b'});self.assertEqual(p['rules'],['ddns_b','ddns_c']);self.auth('check-rule','ddns_b',expected=7)
  self.ask({'action':'commit','confirmation':'0'*32,'consent':'1'},expected=5);self.auth('check-rule','ddns_b',expected=7)
  self.ask({'action':'commit','confirmation':p['confirmation'],'consent':'1'});self.auth('check-rule','ddns_c');self.auth('check-rule','ddns_a',expected=7);self.assertEqual(self.calls,[])

class CF(UIMixin,CFBase):pass
class Ali(UIMixin,AliBase):pass
class DNP(UIMixin,DNPBase):pass
class HW(UIMixin,HWBase):pass
class Boundaries(CF):
 def test_unknown_fields_duplicates_nul_and_injection_rejected_before_authority(self):
  old=self.active.read_bytes()
  for raw in [b'{"action":"status","action":"preview"}',b'{"action":"status"} {}',b'{"action":"status","x":"PRIVATE_SENTINEL"}',b'{"action":"preview","selection":"a;touch bad"}',b'{"action":"preview","selection":"a\\u0000b"}',b'[]',b'x'*4097]:self.ask(raw=raw,expected=2 if len(raw)<=4096 else 7)
  self.assertEqual(self.active.read_bytes(),old);self.assertFalse((self.store/'ddns-authority-pending').exists())
 def test_missing_consent_cannot_commit_or_revoke(self):
  p=self.ask({'action':'preview','selection':'ddns_a'});before=self.active.read_bytes()
  for d in [{'action':'commit','confirmation':p['confirmation']},{'action':'revoke'},{'action':'revoke','consent':'yes'}]:self.ask(d,expected=2)
  self.assertEqual(self.active.read_bytes(),before)
 def test_changed_source_cannot_commit_old_preview(self):
  p=self.ask({'action':'preview','selection':'ddns_a'});old=self.active.read_bytes();self.source.write_bytes(self.source.read_bytes()+b'\n');self.ask({'action':'commit','confirmation':p['confirmation'],'consent':'1'},expected=7);self.assertEqual(self.active.read_bytes(),old)
 def test_superseded_preview_is_not_replayed(self):
  first=self.ask({'action':'preview','selection':'ddns_a'});second=self.ask({'action':'preview','selection':'ddns_b'});self.ask({'action':'commit','confirmation':first['confirmation'],'consent':'1'},expected=5);self.ask({'action':'commit','confirmation':second['confirmation'],'consent':'1'});self.auth('check-rule','ddns_a',expected=7)
 def test_request_permissions_links_and_short_path_are_not_repaired(self):
  self.request.write_bytes(b'{"action":"status"}\n');self.request.chmod(0o644);self.ask(expected=7);self.request.chmod(0o600)
  outside=self.base/'outside';outside.write_bytes(b'KEEP');outside.chmod(0o600);self.request.unlink();self.request.symlink_to(outside);self.ask(expected=7);self.request.unlink();os.link(outside,self.request);self.ask(expected=7);self.assertEqual(outside.read_bytes(),b'KEEP');self.ask(args=['../request'],expected=2)
 def test_closed_gate_environment_cannot_enable_or_read_request(self):
  self.ui_helper.write_text(self.ui_helper.read_text().replace('ddns_ui_enabled=true','ddns_ui_enabled=false'));self.ask(args=['/not-a-request'],expected=2,env={**self.env,'ddns_ui_enabled':'true','LUA_INIT':"error('SECRET_SENTINEL')"});self.assertEqual(self.calls,[])
 def test_common_lock_refuses_preview_without_changing_grant(self):
  import fcntl
  old=self.active.read_bytes()
  for path in [self.native.lock,self.store/'.supervisor.lock']:
   with path.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.ask({'action':'preview','selection':'ddns_a'},expected=4)
  self.assertEqual(self.active.read_bytes(),old)
 def test_forged_backend_status_never_releases_secret_fields(self):
  self.candidate.write_text("#!/bin/sh\nprintf '%s\\n' '{\"api_version\":1,\"prototype\":true,\"ok\":true,\"phase\":\"ddns-status\",\"configuration_revision\":3,\"effect\":\"none\",\"write_ready\":false,\"rules\":[],\"secret\":\"SECRET_SENTINEL\"}'\n")
  self.ask({'action':'status'},expected=7)
 def test_durable_receipt_blocks_permission_changes_and_is_preserved(self):
  self.candidate_call('ddns-sync','ddns_a',read_only=False);old=self.files(self.journal)
  self.ask({'action':'preview','selection':'ddns_b'},expected=4);self.ask({'action':'revoke','consent':'1'},expected=4);self.assertEqual(self.files(self.journal),old);self.assertFalse(self.archive.exists())

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();suite=unittest.TestSuite()
 for cls in ([CF,Ali,DNP,HW,Boundaries] if a.runtime else [Static]):
  members=UIMixin.__dict__ if cls in [CF,Ali,DNP,HW] else cls.__dict__
  suite.addTests(cls(n) for n,v in members.items() if n.startswith('test_') and callable(v))
 r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
