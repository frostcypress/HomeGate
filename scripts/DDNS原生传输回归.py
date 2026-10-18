#!/usr/bin/env python3
"""Lua native transport: real policy and codec, explicit HTTP/nixio boundaries."""
import copy,json,unittest
from pathlib import Path
from lupa.lua51 import LuaRuntime
from project import ROOT
MODEL=ROOT/'project/luci/prototype/lua/model/ddns.lua'
PROTO=ROOT/'project/core/prototype'
class Transport(unittest.TestCase):
 def setUp(self):
  self.lua=LuaRuntime(unpack_returned_tuples=True)
  self.lua.globals().decode=lambda s:self.lua.table_from(json.loads(s),recursive=True)
  codec=self.lua.execute((ROOT/'project/luci/lua/luasrc/model/homegate/backup.lua').read_bytes());self.lua.globals().backup_codec=codec
  self.report={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-authority','configuration_revision':3,'rule':'ddns_a','provider':'cloudflare','confirmation':'a'*32,'expires_in':300,'authorized':False,'service_started':False}
  self.result={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-ui','operation':'preview','effect':'none','write_ready':False,'report':self.report}
  self.lua.execute('''captured={}; method='POST'; csrf='csrf'; short=false; broken=false
package.preload['luci.http']=function()return {getenv=function(k)return method end}end
package.preload['luci.dispatcher']=function()return {context={authtoken=csrf}}end
package.preload['luci.model.homegate.backup']=function()return backup_codec end
package.preload['luci.jsonc']=function()return {parse=decode}end
package.preload['nixio.util']=function()return {}end
package.preload['nixio.fs']=function()return {mkdir=function(p,m)captured.dir=p;assert(m==448);return true end,unlink=function(p)captured.unlink=p end,rmdir=function(p)captured.rmdir=p end}end
package.preload['nixio']=function()return {open_flags=function(...)return 1 end,open=function(p,f,m)captured.path=p;assert(m==384);return {writeall=function(self,s)captured.private=s;if broken then error('SECRET_SENTINEL')end;return short and 0 or #s end,close=function()captured.closed=(captured.closed or 0)+1;return true end}end}end
package.preload['luci.sys']=function()return {exec=function(c)captured.command=c;return response end}end
io.open=function(p,m)assert(p=='/proc/sys/kernel/random/uuid');return {read=function()return '12345678-1234-1234-1234-123456789abc\\n'end,close=function()return true end}end
''')
  # Execute the actual pure modules; filesystem/sys.exec are the boundaries.
  # Lua 5.1 does not interpret JSON-style Unicode escapes in Windows paths.
  self.lua.globals().fixture_load=lambda p:self.lua.compile((PROTO/Path(p).name).read_bytes())
  self.lua.execute('loadfile=fixture_load')
  b=MODEL.read_text(encoding='utf-8').replace('native_ddns_ui_enabled=false','native_ddns_ui_enabled=true').replace("local root='/usr/libexec/homegate'","local root='/fixture'")
  self.enabled=b;self.model=self.lua.execute(b)
 def call(self,action='preview',form=None):
  self.lua.globals().response=json.dumps(self.result,separators=(',',':'))
  result=self.model.call(action,self.lua.table_from({'selection':'ddns_a','token':'csrf'} if form is None else form,recursive=True));return json.loads(self.lua.globals().backup_codec.json(result))
 def test_disabled_gate_precedes_http_and_private_io(self):
  self.model=self.lua.execute(self.enabled.replace('native_ddns_ui_enabled=true','native_ddns_ui_enabled=false'));self.assertFalse(self.call()['ok']);self.assertIsNone(self.lua.globals().captured.path)
 def test_post_csrf_and_consent_cannot_be_self_reported(self):
  for form in [{'selection':'ddns_a'},{'selection':'ddns_a','token':'bad'},{'selection':'ddns_a','token':'csrf','authorized':'true'}]:self.assertFalse(self.call(form=form)['ok']);self.assertIsNone(self.lua.globals().captured.path)
  self.lua.globals().method='GET';self.assertFalse(self.call()['ok']);self.assertIsNone(self.lua.globals().captured.path)
 def test_preview_uses_private_body_and_only_generated_path_in_command(self):
  self.assertTrue(self.call()['ok']);c=self.lua.globals().captured;self.assertIn('ddns_a',c.private);self.assertNotIn('ddns_a',c.command);self.assertNotIn('csrf',c.private);self.assertIn('/tmp/homegate-ddns-ui-12345678123412341234123456789abc/request',c.command);self.assertEqual(c.unlink,c.path);self.assertEqual(c.rmdir,c.dir)
 def test_short_write_and_exception_close_and_clean(self):
  for flag in ['short','broken']:
   self.setUp();self.lua.globals()[flag]=True;out=self.call();self.assertFalse(out['ok']);c=self.lua.globals().captured;self.assertEqual(c.closed,1);self.assertEqual(c.unlink,c.path);self.assertEqual(c.rmdir,c.dir);self.assertNotIn('SECRET_SENTINEL',json.dumps(out));self.assertIsNone(c.command)
 def test_response_operation_scope_and_secret_fields_are_rejected(self):
  for where,key,value in [('outer','operation','commit'),('outer','secret','SECRET_SENTINEL'),('report','rule','ddns_b'),('report','secret','SECRET_SENTINEL'),('report','service_started',True)]:
   self.setUp();target=self.result if where=='outer' else self.result['report'];target[key]=value;out=self.call();self.assertFalse(out['ok']);self.assertNotIn('SECRET_SENTINEL',json.dumps(out));self.assertIsNone(out.get('report'))
 def test_read_only_status_uses_no_csrf_but_validates_all_rows(self):
  self.lua.globals().method='GET';self.result['operation']='status';self.result['report']={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-status','configuration_revision':3,'effect':'none','write_ready':False,'rules':[{'rule':'ddns_a','provider':'cloudflare','status':'unauthorized','effect':'none','error_kind':'','retryable':False,'retry_in':0}]}
  self.assertTrue(self.call('status',{})['ok']);self.result['report']['rules'][0]['secret']='SECRET_SENTINEL';self.assertFalse(self.call('status',{})['ok'])
  self.result['report']['rules']={'secret':'SECRET_SENTINEL'};self.assertFalse(self.call('status',{})['ok'])
 def test_commit_and_revoke_require_explicit_consent(self):
  self.assertFalse(self.call('commit',{'token':'csrf','confirmation':'a'*32})['ok']);self.assertIsNone(self.lua.globals().captured.path)
  self.assertFalse(self.call('revoke',{'token':'csrf','consent':'0'})['ok']);self.assertIsNone(self.lua.globals().captured.path)
 def job(self):
  return {'api_version':1,'prototype':True,'ok':True,'phase':'ddns-job','job':'a'*32,'rule':'ddns_a','configuration_revision':3,'pending':True,'state':'pending','result':False,'last_effect':'unknown','reason':'accepted','effect':'none','write_ready':False}
 def test_job_submit_csrf_consent_and_conservative_outer_effect(self):
  self.result.update(operation='submit',effect='unknown',report=self.job());form={'job':'a'*32,'rule':'ddns_a','consent':'1','token':'csrf'};self.assertTrue(self.call('submit',form)['ok']);self.assertEqual(self.call('submit',form)['effect'],'unknown')
  for k,v in [('token','bad'),('consent','0'),('job','bad'),('extra','secret')]:
   out=self.call('submit',{**form,k:v});self.assertFalse(out['ok']);self.assertEqual(out['effect'],'unknown')
 def test_jobs_read_does_not_require_csrf_and_rejects_wrong_scope_or_secret(self):
  self.lua.globals().method='GET';self.result.update(operation='jobs',report={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-jobs','jobs':[self.job()],'effect':'none','write_ready':False});self.assertTrue(self.call('jobs',{})['ok']);self.result['report']['jobs'][0]['secret']='SECRET_SENTINEL';out=self.call('jobs',{});self.assertFalse(out['ok']);self.assertNotIn('SECRET_SENTINEL',json.dumps(out))
 def test_submit_lost_or_wrong_response_never_claims_no_effect(self):
  self.result.update(operation='submit',effect='none',report=self.job());form={'job':'a'*32,'rule':'ddns_a','consent':'1','token':'csrf'};out=self.call('submit',form);self.assertFalse(out['ok']);self.assertEqual(out['effect'],'unknown');self.result['effect']='unknown';self.result['report']['rule']='other';self.assertFalse(self.call('submit',form)['ok'])
 def test_maintenance_requires_csrf_fresh_nonce_and_exact_receipt_scope(self):
  self.result.update(operation='maintain_preview',effect='none',report={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-maintenance','job':'a'*32,'rule':'ddns_a','operation':'archive','confirmation':'b'*32,'expires_in':300,'effect':'none','write_ready':False});form={'job':'a'*32,'token':'csrf'};self.assertTrue(self.call('maintain_preview',form)['ok']);self.assertFalse(self.call('maintain_preview',{'job':'a'*32})['ok']);self.result['report']['job']='c'*32;self.assertFalse(self.call('maintain_preview',form)['ok']);self.result['report'].update(job='a'*32);self.result['operation']='maintain_commit';del self.result['report']['confirmation'];del self.result['report']['expires_in'];self.result['report']['completed']=True;self.assertFalse(self.call('maintain_commit',{'job':'a'*32,'confirmation':'b'*32,'token':'csrf'})['ok']);self.assertTrue(self.call('maintain_commit',{'job':'a'*32,'confirmation':'b'*32,'consent':'1','token':'csrf'})['ok'])
if __name__=='__main__':unittest.main(verbosity=2)
