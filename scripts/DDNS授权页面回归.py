#!/usr/bin/env python3
"""Real browser DOM/XHR/RPC adapter checks; metadata HTTP is an explicit fixture."""
import html,json,os,unittest
from pathlib import Path
from urllib.parse import parse_qs
from playwright.sync_api import sync_playwright
from project import ROOT
UI=ROOT/'project/luci/prototype';OUT=ROOT/'docs/验证/r76-页面截图'
class Browser(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.pw=sync_playwright().start();edge=Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe');executable=os.environ.get('HOMEGATE_BROWSER') or (str(edge) if edge.exists() else None)
  cls.browser=cls.pw.chromium.launch(**({'executable_path':executable} if executable else {}),headless=True);OUT.mkdir(exist_ok=True)
 @classmethod
 def tearDownClass(cls):cls.browser.close();cls.pw.stop()
 def open(self,variant):
  if hasattr(self,'context'):self.context.close()
  self.variant=variant;self.context=self.browser.new_context();self.page=self.context.new_page();self.page.set_default_timeout(5000);self.calls=[];self.active=[];self.nonce=None;self.hold=False;self.held=None;self.bad=False;self.fail_commit=False;self.forged=False;self.retained=[];self.fail_submit=False;self.finish_jobs=False
  self.rows=['ddns_a','ddns_b'];self.context.route('http://homegate.test/**',self.serve)
  self.page.goto('http://homegate.test/page');self.page.get_by_role('status').filter(has_text='状态已读取').wait_for();self.page.add_style_tag(content=(ROOT/'scripts/fixtures'/('legacy-bootstrap/cascade.css' if variant=='lua' else 'luci/bootstrap.css')).read_text(encoding='utf-8'))
 def tearDown(self):
  if hasattr(self,'context'):self.context.close();del self.context
 def wrapper(self,action,r):return {'api_version':1,'prototype':True,'ok':True,'phase':'ddns-ui','operation':action,'effect':'unknown' if action=='submit' else 'none','write_ready':False,'report':r}
 def response(self,action,form):
  if action=='jobs':
   return self.wrapper(action,{'api_version':1,'prototype':True,'ok':True,'phase':'ddns-jobs','jobs':self.retained,'effect':'none','write_ready':False})
  if action=='submit':
   assert form['consent']=='1';j=self.job(form['job'],form['rule']);self.retained=[j];return self.wrapper(action,j)
  if action=='maintain_preview':
   j=next(j for j in self.retained if j['job']==form['job']);self.maintenance={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-maintenance','job':j['job'],'rule':j['rule'],'operation':'archive' if j['last_effect']=='confirmed' else 'compact','confirmation':'b'*32,'expires_in':300,'effect':'none','write_ready':False};return self.wrapper(action,self.maintenance)
  if action=='maintain_commit':
   assert form['consent']=='1' and form['confirmation']==self.maintenance['confirmation'];j=next(j for j in self.retained if j['job']==form['job']);j['reason']='archived' if self.maintenance['operation']=='archive' else 'compacted';r={k:v for k,v in self.maintenance.items() if k not in ['confirmation','expires_in']};r['completed']=True;return self.wrapper(action,r)
  if action=='status':
   return self.wrapper(action,{'api_version':1,'prototype':True,'ok':True,'phase':'ddns-status','configuration_revision':3,'effect':'none','write_ready':False,'rules':[{'rule':v,'provider':'cloudflare','status':'ready' if v in self.active else 'unauthorized','effect':'none','error_kind':'','retryable':False,'retry_in':0} for v in self.rows]})
  if action=='preview':
   self.selection=sorted(form['selection'].split(','));self.nonce=format(len(self.calls),'032x');r={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-authority','configuration_revision':3,'provider':'cloudflare','expires_in':300,'authorized':False,'service_started':False,'confirmation':self.nonce}
   selected=['other'] if self.forged else self.selection
   r['rules' if len(selected)>1 else 'rule']=selected if len(selected)>1 else selected[0];return self.wrapper(action,r)
  if action=='commit':
   assert form['consent']=='1' and form['confirmation']==self.nonce;self.active=list(self.selection);r={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-authority','configuration_revision':3,'provider':'cloudflare','authorized':True,'service_started':False};r['rules' if len(self.active)>1 else 'rule']=self.active if len(self.active)>1 else self.active[0];return self.wrapper(action,r)
  assert action=='revoke' and form['consent']=='1';self.active=[];return self.wrapper(action,{'api_version':1,'prototype':True,'ok':True,'phase':'ddns-authority','authorized':False,'revoked':True,'service_started':False})
 def serve(self,route):
  req=route.request;path=req.url.split('homegate.test',1)[1]
  if path=='/luci-static/resources/homegate/ddns-ui.js':route.fulfill(body=(UI/'js/ddns-ui.js').read_text(encoding='utf-8'),content_type='application/javascript; charset=utf-8');return
  if path=='/page':
   if self.variant=='lua':
    body=(UI/'lua/view/ddns.htm').read_text(encoding='utf-8').replace('<%+header%>','<!doctype html><html><head><meta charset="utf-8"></head><body>').replace('<%+footer%>','</body></html>').replace('<%=pcdata(token)%>','fixture-csrf').replace("<%=url('admin/services/homegate/ddns_native')%>",'/cgi-bin/luci/admin/services/homegate/ddns_native').replace('<%=resource%>','/luci-static/resources')
   else:
    module=json.dumps((UI/'js/ddns-view.js').read_text(encoding='utf-8'));body='''<!doctype html><html><head><meta charset="utf-8"></head><body><script>
var view={extend:x=>x},L={resource:p=>'/luci-static/resources/'+p},E=(t,a)=>{var e=document.createElement(t);Object.keys(a||{}).forEach(k=>e.setAttribute(k,a[k]));return e;};
var rpc={declare:d=>function(){var f={};Array.from(arguments).forEach((v,i)=>f[d.params[i]]=v);return fetch('/rpc/'+d.method,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(f)}).then(r=>{if(!r.ok)throw Error('rpc');return r.json();});}};
var m=new Function('view','rpc','L','E',MODULE)(view,rpc,L,E);Promise.resolve(m.load()).then(()=>document.body.appendChild(m.render()));
</script></body></html>'''.replace('MODULE',module)
   route.fulfill(body=body,content_type='text/html; charset=utf-8');return
  if path.startswith('/rpc/'):
   action=path.rsplit('/',1)[1];form=json.loads(req.post_data or '{}');assert req.method=='POST'
  else:
   action=path.rsplit('/',1)[1];form={k:v[0] for k,v in parse_qs(req.post_data or '').items()}
   assert req.method==('GET' if action in ['status','jobs'] else 'POST')
   if action not in ['status','jobs']:assert form.pop('token')=='fixture-csrf'
  assert action in ['status','preview','commit','revoke','jobs','submit','maintain_preview','maintain_commit'];self.calls.append((action,form))
  result=self.response(action,form)
  if action=='preview' and self.hold:self.held=(route,result);return
  if action=='submit' and self.fail_submit:route.abort();return
  if action=='commit' and self.fail_commit:route.abort();return
  route.fulfill(body='not-json' if self.bad else json.dumps(result),content_type='application/json')
 def choose(self,name='ddns_a'):self.page.get_by_role('checkbox',name='选择 '+name,exact=True).check()
 def preview(self):self.choose();self.page.get_by_role('button',name='预览授权',exact=True).click();self.page.get_by_text('预览尚未授权。请核对规则后确认。').wait_for()
 def variants(self):return ['lua','js']
 def test_initial_load_is_only_status_and_confirmation_disabled(self):
  for variant in self.variants():
   with self.subTest(variant=variant):self.open(variant);self.assertEqual(sorted(a for a,f in self.calls),['jobs','status']);self.assertTrue(self.page.get_by_role('button',name='确认授权',exact=True,include_hidden=True).is_disabled());self.assertEqual(self.page.evaluate('localStorage.length'),0)
 def test_preview_explicit_consent_and_duplicate_click_only_one_commit(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.preview();button=self.page.get_by_role('button',name='确认授权',exact=True,include_hidden=True);self.assertTrue(button.is_disabled());self.assertEqual(self.active,[]);self.page.locator('#hg-ddns-consent').check();button.evaluate('(b)=>{b.click();b.click();}');self.page.get_by_text('授权已保存，未启动服务。请刷新状态。').wait_for();self.assertEqual([a for a,f in self.calls].count('commit'),1);self.assertEqual(self.active,['ddns_a']);self.assertNotIn(self.nonce,self.page.url)
 def test_selection_change_invalidates_preview_and_consent(self):
  for variant in self.variants():
   with self.subTest(variant=variant):self.open(variant);self.preview();self.page.locator('#hg-ddns-consent').check();self.choose('ddns_b');self.assertFalse(self.page.locator('#hg-ddns-consent').is_visible());self.assertTrue(self.page.get_by_role('button',name='确认授权',exact=True,include_hidden=True).is_disabled());self.assertNotIn('commit',[a for a,f in self.calls])
 def test_late_preview_response_cannot_reenable_changed_selection(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.choose();self.hold=True;self.page.get_by_role('button',name='预览授权',exact=True).click();self.page.wait_for_timeout(100);self.assertIsNotNone(self.held);self.choose('ddns_b');route,result=self.held;route.fulfill(body=json.dumps(result),content_type='application/json');self.page.wait_for_timeout(100);self.assertFalse(self.page.locator('#hg-ddns-consent').is_visible());self.assertTrue(self.page.get_by_role('button',name='确认授权',exact=True,include_hidden=True).is_disabled())
 def test_close_preview_never_commits_or_persists_nonce(self):
  for variant in self.variants():
   with self.subTest(variant=variant):self.open(variant);self.preview();self.page.get_by_role('button',name='关闭预览',exact=True).click();self.assertNotIn('commit',[a for a,f in self.calls]);self.assertEqual(self.page.evaluate('localStorage.length+sessionStorage.length'),0);self.assertFalse(self.page.locator('#hg-ddns-consent').is_visible())
 def test_uncertain_commit_does_not_automatically_retry(self):
  for variant in self.variants():
   with self.subTest(variant=variant):self.open(variant);self.preview();self.fail_commit=True;self.page.locator('#hg-ddns-consent').check();self.page.get_by_role('button',name='确认授权',exact=True,include_hidden=True).click();self.page.get_by_text('请求未确认，请先刷新状态。请勿自动重复提交。').wait_for();self.page.wait_for_timeout(150);self.assertEqual([a for a,f in self.calls].count('commit'),1);self.assertTrue(self.page.get_by_role('button',name='确认授权',exact=True,include_hidden=True).is_disabled())
 def test_revoke_cancel_is_not_a_write_then_accept_is_explicit(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.page.once('dialog',lambda d:d.dismiss());self.page.get_by_role('button',name='撤销当前授权',exact=True).click();self.assertNotIn('revoke',[a for a,f in self.calls]);self.page.once('dialog',lambda d:d.accept());self.page.get_by_role('button',name='撤销当前授权',exact=True).click();self.page.get_by_text('已撤销授权，请刷新状态。').wait_for();self.assertEqual([a for a,f in self.calls].count('revoke'),1)
 def test_forged_preview_scope_cannot_enable_confirmation(self):
  for variant in self.variants():
   with self.subTest(variant=variant):self.open(variant);self.forged=True;self.choose();self.page.get_by_role('button',name='预览授权',exact=True).click();self.page.get_by_text('请求未确认，请先刷新状态。请勿自动重复提交。').wait_for();self.assertTrue(self.page.get_by_role('button',name='确认授权',exact=True,include_hidden=True).is_disabled())
 def test_untrusted_rule_markup_is_never_inserted_as_html(self):
  for variant in self.variants():
   with self.subTest(variant=variant):self.open(variant);self.rows=['<img src=x onerror="window.injected=1">'];self.page.get_by_role('button',name='刷新状态',exact=True).click();self.page.get_by_text('请求未确认，请先刷新状态。请勿自动重复提交。').wait_for();self.assertEqual(self.page.locator('img').count(),0);self.assertFalse(self.page.evaluate('!!window.injected'))
 def test_native_bootstrap_geometry_and_screenshots(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant)
    for width in [360,768,1280]:
     self.page.set_viewport_size({'width':width,'height':800});self.assertLessEqual(self.page.evaluate('document.documentElement.scrollWidth'),width+1);self.page.screenshot(path=str(OUT/(variant+'-'+str(width)+'.png')),full_page=True)
 def job(self,ticket='a'*32,rule='ddns_a',state='pending',effect='unknown'):
  row={'rule':rule,'provider':'cloudflare','status':'updated' if effect=='confirmed' else 'failed' if effect=='unknown' else 'unchanged','effect':effect,'error_kind':'temporary' if effect=='unknown' else '', 'retryable':False,'retry_in':0}
  return {'api_version':1,'prototype':True,'ok':True,'phase':'ddns-job','job':ticket,'rule':rule,'configuration_revision':3,'pending':state=='pending','state':state,'result':row if state=='finished' else False,'last_effect':effect,'reason':'completed' if state=='finished' else 'accepted' if state=='pending' else 'interrupted','effect':'none','write_ready':False}
 def test_single_submission_cancel_and_double_click_only_one_post(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.choose();button=self.page.get_by_role('button',name='同步所选规则一次');self.page.once('dialog',lambda d:d.dismiss());button.click();self.assertNotIn('submit',[a for a,f in self.calls]);self.page.once('dialog',lambda d:d.accept());button.evaluate('(b)=>{b.click();b.click();}');self.page.get_by_text('任务尚未完成，正在读取结果。').wait_for();self.assertEqual([a for a,f in self.calls].count('submit'),1);self.assertTrue(button.is_disabled());self.assertEqual(self.page.evaluate('localStorage.length+sessionStorage.length'),0)
 def test_selection_requires_one_rule_and_no_automatic_submission(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);button=self.page.get_by_role('button',name='同步所选规则一次');self.assertTrue(button.is_disabled());self.choose();self.assertTrue(button.is_enabled());self.choose('ddns_b');self.assertTrue(button.is_disabled());self.assertNotIn('submit',[a for a,f in self.calls])
 def test_uncertain_submission_uses_read_only_poll_and_recovers_after_reload(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.choose();self.fail_submit=True;self.page.once('dialog',lambda d:d.accept());self.page.get_by_role('button',name='同步所选规则一次').click();self.page.get_by_text('任务尚未完成，正在读取结果。').wait_for();self.retained[0]=self.job(self.retained[0]['job'],state='finished',effect='unknown');self.page.get_by_text('ddns_a · 结果未知，保留证据，请核实',exact=False).wait_for();self.assertEqual([a for a,f in self.calls].count('submit'),1);self.page.reload();self.page.get_by_text('ddns_a · 结果未知，保留证据，请核实',exact=False).wait_for();self.choose();self.assertTrue(self.page.get_by_role('button',name='同步所选规则一次').is_disabled());self.assertEqual([a for a,f in self.calls].count('submit'),1)
 def test_confirmed_result_requires_explicit_original_closeout(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.retained=[self.job(state='finished',effect='confirmed')];self.page.get_by_role('button',name='刷新状态',exact=True).click();self.page.get_by_text('ddns_a · 已更新；需明确收尾',exact=False).wait_for();self.assertEqual(set(a for a,f in self.calls),{'status','jobs'})
 def test_interrupted_and_full_retention_block_submission(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.retained=[self.job(state='interrupted')];self.page.get_by_role('button',name='刷新状态',exact=True).click();self.page.get_by_text('ddns_a · 任务中断，结果未知',exact=False).wait_for();self.choose();self.assertTrue(self.page.get_by_role('button',name='同步所选规则一次').is_disabled());self.retained=[self.job(format(i,'032x'),state='finished',effect='none') for i in range(1,9)];self.page.get_by_role('button',name='刷新状态',exact=True).click();self.page.get_by_text('已保留 8 份任务；需要后续明确维护。').wait_for();self.assertTrue(self.page.get_by_role('button',name='同步所选规则一次').is_disabled())
 def test_job_malformed_success_is_rejected_without_retry(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.retained=[self.job(state='finished',effect='unknown')];self.retained[0]['result']['status']='created';self.page.get_by_role('button',name='刷新状态',exact=True).click();self.page.get_by_text('任务读取未确认，请刷新读取；不要重复提交。').wait_for();self.choose();self.assertTrue(self.page.get_by_role('button',name='同步所选规则一次').is_disabled());self.assertNotIn('submit',[a for a,f in self.calls])
 def test_pending_poll_has_fixed_budget_and_never_submits(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.page.evaluate('window.originalTimeout=window.setTimeout;window.setTimeout=function(f,ms){return window.originalTimeout(f,ms===1000?0:ms)}');self.retained=[self.job()];self.page.get_by_role('button',name='刷新状态',exact=True).click();self.page.get_by_text('轮询已暂停；任务未被重发，请手动刷新读取。').wait_for(timeout=20000);n=sum(a=='jobs' for a,f in self.calls);self.page.wait_for_timeout(200);self.assertEqual(sum(a=='jobs' for a,f in self.calls),n);self.assertEqual(n,182);self.assertNotIn('submit',[a for a,f in self.calls])
 def test_maintenance_requires_preview_new_consent_and_one_commit(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.retained=[self.job(state='finished',effect='confirmed')];self.page.get_by_role('button',name='刷新状态',exact=True).click();button=self.page.get_by_role('button',name='预览维护 ddns_a',exact=True);button.wait_for();button.click();self.page.get_by_text('维护预览尚未执行，请核对后勾选确认。').wait_for();commit=self.page.get_by_role('button',name='确认此次维护',exact=True);self.assertTrue(commit.is_disabled());self.assertNotIn('maintain_commit',[a for a,f in self.calls]);self.page.locator('#hg-ddns-maintain-consent').check();commit.evaluate('(b)=>{b.click();b.click();}');self.page.get_by_text('ddns_a · 回执已归档，保留原摘要',exact=False).wait_for();self.assertEqual(sum(a=='maintain_commit' for a,f in self.calls),1);self.assertNotIn('submit',[a for a,f in self.calls]);self.assertEqual(self.page.evaluate('localStorage.length+sessionStorage.length'),0)
 def test_unknown_and_interrupted_have_no_maintenance_and_refresh_invalidates_preview(self):
  for variant in self.variants():
   with self.subTest(variant=variant):
    self.open(variant);self.retained=[self.job(state='finished',effect='unknown')];self.page.get_by_role('button',name='刷新状态',exact=True).click();self.page.get_by_text('ddns_a · 结果未知，保留证据，请核实',exact=False).wait_for();self.assertEqual(self.page.get_by_role('button',name='预览维护 ddns_a').count(),0);self.retained=[self.job(state='finished',effect='none')];self.page.get_by_role('button',name='刷新状态',exact=True).click();self.page.get_by_role('button',name='预览维护 ddns_a',exact=True).click();self.page.get_by_text('维护预览尚未执行，请核对后勾选确认。').wait_for();self.page.locator('#hg-ddns-maintain-consent').check();self.page.get_by_role('button',name='刷新状态',exact=True).click();self.assertFalse(self.page.locator('#hg-ddns-maintain-consent').is_visible());self.assertNotIn('maintain_commit',[a for a,f in self.calls])
if __name__=='__main__':unittest.main(verbosity=2)
