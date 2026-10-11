#!/usr/bin/env python3
"""Run generated modules through the pinned official LuCI 25.12 loader."""
from pathlib import Path
import hashlib,json,os
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
out=ROOT/'build/official-footer-regressions';out.mkdir(parents=True,exist_ok=True)
fixtures=ROOT/'scripts/fixtures/luci';resources=ROOT/'project/luci/js/htdocs/luci-static/resources'
origin=json.loads((fixtures/'origin.json').read_text(encoding='utf-8-sig'))
for name,meta in origin['files'].items():assert hashlib.sha256((fixtures/name).read_bytes()).hexdigest()==meta['sha256']
assert "'/usr/lib/lua/luci/i18n'" in (fixtures/'dispatcher.uc').read_text(encoding='utf-8')
with sync_playwright() as pw:
 edge=Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
 executable=os.environ.get('HOMEGATE_BROWSER') or (str(edge) if edge.exists() else None)
 browser=pw.chromium.launch(**({'executable_path':executable} if executable else {}),headless=True)
 context=browser.new_context()
 def serve(route):
  path=route.request.url.split('http://homegate.test/',1)[1].split('?')[0]
  if path.startswith('resources/'):
   relative=path[len('resources/'):]
   if relative=='rpc.js':body="""'use strict'; 'require baseclass'; return baseclass.extend({declare: function(def){return function(...args){window.hgCalls=window.hgCalls||[];hgCalls.push([def.object,def.method,...args]);if(def.object!=='homegate')return Promise.resolve({});if(def.method==='write')return Promise.resolve({ok:true,job:'a'.repeat(32)});if(def.method==='poll')return Promise.resolve({ok:true,result:{ok:true}});return Promise.resolve({ok:true,data:{main:{},wol_selected_interface:'br-lan',wol_interfaces:[{name:'br-lan',kind:'bridge'}]},body:'{}'});};}});"""
   elif relative in ('ui.js','validation.js','uci.js','fs.js'):body=(fixtures/relative).read_text(encoding='utf-8')
   elif relative=='form.js':body="'use strict'; 'require baseclass'; return baseclass.extend({});"
   elif relative=='bad.js':body="'use strict'; return {render:function(){}};"
   else:body=(resources/relative).read_text(encoding='utf-8')
   route.fulfill(status=200,body=body,content_type='application/javascript')
  else:route.fulfill(status=200,body='<html lang="en"><body><div id="view"></div></body></html>',content_type='text/html')
 context.route('http://homegate.test/**',serve);page=context.new_page();page.goto('http://homegate.test/')
 errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 page.add_script_tag(content=(fixtures/'cbi.js').read_text(encoding='utf-8'))
 page.add_script_tag(content=(fixtures/'luci.js').read_text(encoding='utf-8'))
 page.evaluate("LuCI.prototype.probeRPCBaseURL=()=>Promise.resolve('/ubus/');window.L=new LuCI({base_url:'/resources',resource_version:'test',scriptname:'/cgi-bin/luci',pathinfo:'',nodespec:{satisfied:true,readonly:false}});window._=v=>v;")
 result=page.evaluate("""async()=>{
   const names=['common','transport','overview','basic','public','wol','maintenance'];const loaded=[];
   for(const n of names){const mod=await L.require('homegate.'+n);if(n==='transport'){if(typeof mod.load!=='function'||typeof mod.install!=='function')throw Error(n);await mod.load('basic');}else{if(typeof mod.render!=='function')throw Error(n);const html=mod.render({main:{},packages:{},services:[],hosts:[],dns_accounts:[],certificates:[],access_regions:[],wol_interfaces:[],wol_clients:[],dns_provider_catalog:[],acme_ca_catalog:[],default_renew_days:'30'});if(typeof html!=='string'||!html.length)throw Error(n);}loaded.push(n);}
   let caught=false;try{await L.require('bad');}catch(e){caught=e.message.includes('factory yields invalid constructor');}if(!caught)throw Error('negative control failed');
   return loaded;
 }""")
 assert result==['common','transport','overview','basic','public','wol','maintenance'],result
 page.evaluate("async()=>{L.dom=await L.require('dom');window.E=(...args)=>L.dom.create(...args);}")
 page.add_style_tag(content=(fixtures/'bootstrap.css').read_text(encoding='utf-8'))
 assert page.evaluate("async()=>{const v=await L.require('view.homegate.overview');const node=v.render(await v.load());document.getElementById('view').replaceChildren(node);return node.querySelectorAll('form,.cbi-page-actions').length===0 && node.textContent.includes('Overview');}")
 theme_cases=[];action_cases=[]
 for name in ('basic','public','wol','maintenance'):
  assert page.evaluate("async n=>{const v=await L.require('view.homegate.'+n);const data=await v.load();const node=v.render(data);const vp=document.getElementById('view');vp.replaceChildren(node);vp.appendChild(v.addFooter());return vp.querySelectorAll('.cbi-page-actions').length===1 && !!vp.querySelector('.cbi-dropdown');}",name)
  page.wait_for_timeout(100)
  for lang in ('en','zh-CN'):
   page.evaluate("lang=>{document.documentElement.lang=lang;window._=s=>lang==='zh-CN'?({'Save & Apply':'保存并应用','Apply unchecked':'不检查应用','Save':'保存','Reset':'复位'}[s]||s):s;}",lang)
   for width in (390,1400):
    page.set_viewport_size({'width':width,'height':900})
    page.evaluate("async n=>{const v=await L.require('view.homegate.'+n);document.querySelector('.cbi-page-actions').remove();document.getElementById('view').appendChild(v.addFooter());document.querySelector('.homegate-native style').id='hg-style';}",name)
    take="()=>[document.querySelector('.cbi-page-actions'),...document.querySelectorAll('.cbi-page-actions > *')].map(e=>Object.fromEntries(['height','width','padding','margin','color','backgroundColor','borderRadius','display'].map(k=>[k,getComputedStyle(e)[k]])))"
    before=page.evaluate(take);page.evaluate("document.getElementById('hg-style').disabled=true");assert before==page.evaluate(take),(name,lang,width);page.evaluate("document.getElementById('hg-style').disabled=false")
    assert page.locator('.cbi-dropdown > span.open').count()==1
    gap=page.evaluate("()=>document.querySelector('.cbi-page-actions').getBoundingClientRect().top-document.querySelector('.hg-wrap').lastElementChild.getBoundingClientRect().bottom");assert gap>=17.9,(name,width,gap)
    theme_cases.append([name,lang,width])
  # Real official save control invokes the async HomeGate adapter exactly once.
  page.evaluate('window.hgCalls=[]')
  page.locator('.cbi-page-actions > .cbi-button-save').click();page.wait_for_timeout(650)
  writes=page.evaluate("hgCalls.filter(x=>x[1]==='write')");assert len(writes)==1 and writes[0][2]==name+'_apply' and writes[0][3]['mode']=='save',writes
  page.evaluate('window.hgCalls=[]')
  page.locator('.cbi-dropdown > span.open').click()
  assert page.locator('.cbi-dropdown[open]').count()==1
  page.locator('.cbi-dropdown li[data-value="1"][tabindex]').click()
  assert page.evaluate("hgCalls.filter(x=>x[1]==='write').length") == 0
  page.locator('.cbi-dropdown').click(position={'x':12,'y':12});page.wait_for_timeout(650)
  writes=page.evaluate("hgCalls.filter(x=>x[1]==='write')");assert len(writes)==1 and writes[0][3]['mode']=='apply',writes
  if name=='basic':
   page.evaluate("window.hgCalls=[];document.querySelector('#homegate-basic-form input[name=ddns_interval]').value='0'")
   page.locator('.cbi-page-actions > .cbi-button-save').click();page.wait_for_timeout(100)
   assert page.evaluate("hgCalls.filter(x=>x[1]==='write').length") == 0
   page.evaluate("document.querySelector('#homegate-basic-form input[name=ddns_interval]').value='300'")
  for mode in ('0','1'):
   page.evaluate("async ([n,m])=>{window.hgCalls=[];const v=await L.require('view.homegate.'+n);await v.handleSaveApply(null,m);}",[name,mode])
   writes=page.evaluate("hgCalls.filter(x=>x[1]==='write')");assert len(writes)==1 and writes[0][2]==name+'_apply' and writes[0][3]['mode']=='apply',writes
   assert not page.evaluate("hgCalls.some(x=>x[0]==='uci'&&x[1]==='apply')")
   action_cases.append([name,mode])
  if name=='maintenance':
   page.evaluate("async n=>{const v=await L.require('view.homegate.'+n);document.querySelector('.cbi-page-actions').remove();document.getElementById('view').appendChild(v.addFooter());}",name)
   page.locator('.cbi-page-actions').screenshot(path=str(out/'official-footer.png'))
  page.evaluate("async n=>{L.env.nodespec.readonly=true;const v=await L.require('view.homegate.'+n);document.querySelector('.cbi-page-actions').remove();document.getElementById('view').appendChild(v.addFooter());}",name)
  assert page.locator('.cbi-page-actions button').evaluate_all('bs=>bs.every(b=>b.disabled)')
  assert page.locator('.cbi-dropdown').get_attribute('disabled') is not None
  page.evaluate('L.env.nodespec.readonly=false')
 assert not errors,errors
 browser.close()
(out/'results.json').write_text(json.dumps({'official_ui_sources':'Pinned unmodified ui/validation/uci/fs/luci.js','theme_cases':theme_cases,'service_apply_cases':action_cases,'readonly_pages':4,'scope':'Both official apply choices use the plugin-specific HomeGate apply, without changing unrelated UCI configurations or promising network rollback'},indent=2),encoding='utf-8')
print('PASS official LuCI loader: seven modules, overview and four editable view constructors; official catalog path')
