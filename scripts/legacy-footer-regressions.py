#!/usr/bin/env python3
"""Legacy input controls inherit official theme rules and preserve submit modes."""
from pathlib import Path
import json,os,re,hashlib
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/legacy-footer-regressions';OUT.mkdir(parents=True,exist_ok=True)
fixture=ROOT/'scripts/fixtures/legacy-bootstrap'
origin=json.loads((fixture/'origin.json').read_text(encoding='utf-8'))
for name,meta in origin['files'].items():
 assert hashlib.sha256((fixture/name).read_bytes()).hexdigest()==meta['sha256']
theme=(fixture/'cascade.css').read_text(encoding='utf-8')
official=(fixture/'footer.htm').read_text(encoding='utf-8')
assert '<input class="cbi-button cbi-button-save" type="submit"' in official
reference='''<div class="cbi-page-actions" id="reference"><input class="cbi-button cbi-button-apply" type="button" value="Save & Apply" /> <input class="cbi-button cbi-button-save" type="submit" value="Save" /> <input class="cbi-button cbi-button-reset" type="button" value="Reset" /></div>'''
styles=['width','height','padding','margin','color','backgroundImage','borderRadius','border','display','float','textAlign','fontSize']
results=[];submissions=[]
with sync_playwright() as pw:
 exe=os.environ.get('HOMEGATE_BROWSER');browser=pw.chromium.launch(**({'executable_path':exe} if exe else {}),headless=True)
 context=browser.new_context();context.route('http://homegate.test/**',lambda r:r.fulfill(body='<html></html>'))
 for name in ('basic','public','wol','maintenance'):
  markup=(ROOT/'build/native-ui-regressions'/(name+'.html')).read_text(encoding='utf-8')
  assert markup.count('name="mode" value="apply"')==1
  for width in (390,1400):
   page=context.new_page();page.set_viewport_size({'width':width,'height':900});page.goto('http://homegate.test/')
   clean=re.sub(r'<script\b.*?</script>','',markup,flags=re.S)
   page.set_content('<style>'+theme+'</style>'+clean+reference)
   page.locator('.cbi-page-actions').first.evaluate("e=>e.id='actual'")
   controls=page.locator('#actual > input')
   assert controls.count()==3 and page.locator('#actual > button').count()==0
   assert controls.evaluate_all("bs=>bs.every(b=>b.getAttribute('value')===b.value)")
   take="id=>[...document.querySelectorAll('#'+id+' > input')].map(b=>Object.fromEntries("+json.dumps(styles)+".map(p=>[p,getComputedStyle(b)[p]])))"
   assert page.evaluate(take,'actual')==page.evaluate(take,'reference'),(name,width)
   # A bounded synthetic selector stress fixture proves input-only theme rules
   # are honored. It is not represented as the user's actual QWRT stylesheet.
   page.add_style_tag(content='@media(max-width:600px){.cbi-page-actions{display:flex;padding:0}.cbi-page-actions>input{flex:1;width:0;margin:0;border-radius:0}}')
   assert page.evaluate(take,'actual')==page.evaluate(take,'reference')
   if width==390:
    widths=controls.evaluate_all('bs=>bs.map(b=>b.getBoundingClientRect().width)')
    assert max(widths)-min(widths)<1,widths
   results.append([name,width]);page.close()
  page=context.new_page();page.goto('http://homegate.test/')
  page.set_content('<script>window.homegateXHR=window.XHR={get:(u,f,cb)=>cb({status:200,responseText:"{}"},{})};</script>'+markup)
  page.wait_for_timeout(100)
  page.evaluate("n=>{window.captured=[];document.getElementById('homegate-'+n+'-form').addEventListener('submit',e=>{e.preventDefault();captured.push(Object.fromEntries(new FormData(e.target)));});}",name)
  for action in ('save','apply'):
   page.locator('.cbi-page-actions > .cbi-button-'+action).click()
   assert page.evaluate('captured.at(-1).mode')==action,(name,action)
   assert page.evaluate("captured.at(-1).token==='rpc'")
   submissions.append([name,action])
  if name=='basic':
   page.evaluate('captured=[]');page.locator('[name=ddns_interval]').fill('0')
   page.locator('.cbi-page-actions > .cbi-button-apply').click()
   assert page.evaluate('captured.length')==0
   page.locator('[name=ddns_interval]').fill('300');page.locator('[name=ddns_interval]').press('Enter')
   assert page.evaluate('captured.at(-1).mode')=='apply'
  page.evaluate('captured=[]');page.locator('.cbi-page-actions > .cbi-button-reset').click()
  assert page.url.endswith('/'+name)
  page.close()
 browser.close()
(OUT/'results.json').write_text(json.dumps({'official_legacy_theme_parity':results,'real_form_submissions':submissions,'invalid_number_blocked':True,'enter_default_apply':True,'reset_navigation':True,'fixture_commit':origin['commit'],'scope':'Official upstream CSS and input-selector stress; actual QWRT stylesheet/device acceptance pending'},indent=2))
print('PASS legacy footer: 8 official-style cases, input-only mobile selectors, 8 submits, token/mode, invalid input, Enter and reset')
