import ast, html, json, os, re, shutil, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SRC=Path(os.environ.get('HOMEGATE_AUDIT_SOURCE',str(ROOT if (ROOT/'project').is_dir() else ROOT/'HomeGate_1.2.2-7_source')))
OUT=Path(os.environ.get('HOMEGATE_AUDIT_RESULTS',str(ROOT/'build/ui-regressions')))
OUT.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(ROOT/'audit-tools/python-packages'))
from playwright.sync_api import sync_playwright
from lupa.lua51 import LuaRuntime
app=SRC/'project/luci/lua/luasrc/view/homegate'
common=(app/'common.htm').read_text(encoding='utf-8')
public=(app/'public.htm').read_text(encoding='utf-8')
css=re.search(r'<style type="text/css">(.*?)</style>',common,re.S)[1]
script=re.search(r'<script type="text/javascript">(.*?)</script>',common,re.S)[1]
def extract(text,name):
    start=text.index('function '+name+'(')
    end=text.find('\nfunction ',start+1)
    return text[start:end] if end>=0 else text[start:text.index('</script>',start)]
public_functions='\n'.join(extract(public,n) for n in ('hgPublicTrim','hgPublicFullDomain','hgPublicConfirm'))
public_functions=re.sub(r'<%.*?%>','30',public_functions,flags=re.S)
results={}
def compile_template(text):
    chunks=['local out={}; local function write(s) out[#out+1]=tostring(s or "") end']
    pos=0
    for match in re.finditer(r'<%(.*?)%>',text,re.S):
        chunks.append('write('+json.dumps(text[pos:match.start()],ensure_ascii=False)+')')
        tag=match[1]
        if tag.startswith('='):chunks.append('write('+tag[1:]+')')
        elif tag.startswith(':'):chunks.append('write(pcdata(translate('+json.dumps(tag[1:],ensure_ascii=False)+')))')
        elif not tag.startswith('+'):chunks.append(tag)
        pos=match.end()
    chunks.append('write('+json.dumps(text[pos:],ensure_ascii=False)+'); return table.concat(out)')
    return '\n'.join(chunks)
lua=LuaRuntime(unpack_returned_tuples=True)
lua.execute('assert(loadstring(...))',(SRC/'project/luci/lua/luasrc/controller/homegate.lua').read_text(encoding='utf-8'))
translations={}; msgid=None
for line in (SRC/'project/luci/common/po/zh_Hans/homegate.po').read_text(encoding='utf-8').splitlines():
    if line.startswith('msgid '):msgid=ast.literal_eval(line[6:])
    elif line.startswith('msgstr ') and msgid:translations[msgid]=ast.literal_eval(line[7:])
lua.globals().translate=lambda s:translations.get(str(s),str(s))
lua.globals().pcdata=lambda s:html.escape(str(s or ''),quote=True)
lua.globals().url=lambda s:'/'+s
for name,value in {'services':[],'main':{},'dns_accounts':[],'certificates':[],'access_regions':[],'notice':'','error_message':'','token':'test-only','default_renew_days':'30','dns_provider_catalog':[{'name':'aliyun','display_name':'Aliyun DNS','credentials':[{'name':'key_id','label':'AccessKey ID','required':True},{'name':'secret','label':'AccessKey Secret','required':True}]}],'acme_ca_catalog':[{'name':'letsencrypt','display_name':"Let's Encrypt",'directories':{'production':'https://example.invalid/acme','staging':'https://example.invalid/staging'}}]}.items():
    lua.globals()[name]=lua.table_from(value,recursive=True) if isinstance(value,(dict,list)) else value
for p in app.glob('*.htm'):
    code=compile_template(p.read_text(encoding='utf-8'))
    lua.execute('assert(loadstring(...))',code)
results['luci_template_syntax']='5 templates compiled with Lua 5.1'
rendered_public=lua.execute(compile_template(public))
assert 'placeholder="默认不足30天时自动续期"' in rendered_public
rendered_common=lua.execute(compile_template(common))
lua.globals().default_renew_days='45'
dynamic_public=lua.execute(compile_template(public))
assert '默认不足45天时自动续期' in dynamic_public
lua.globals().default_renew_days='30'
for p in app.glob('*.htm'):
    blocks=re.findall(r'<script type="text/javascript">(.*?)</script>',p.read_text(encoding='utf-8'),re.S)
    if blocks:
        file=OUT/(p.stem+'.js')
        file.write_text(re.sub(r'<%.*?%>','TEMPLATE','\n'.join(blocks),flags=re.S),encoding='utf-8')
        subprocess.run(['node','--check',str(file)],check=True)
with sync_playwright() as pw:
    edge=Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
    executable=os.environ.get('HOMEGATE_BROWSER') or (str(edge) if edge.exists() else next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome') if shutil.which(x)),None))
    browser=pw.chromium.launch(**({'executable_path':executable} if executable else {}),headless=True)
    page=browser.new_page(viewport={'width':1200,'height':700})
    page.set_content('<html><body><script>'+script+'</script></body></html>')
    results['request_callback']=page.evaluate('''() => {
      let calls=0,thrown=false;
      window.XHR={get:(u,p,cb)=>cb({responseText:'{"ok":true}'},null)};
      try {hgGet('/test',()=>{calls++;throw new Error('callback failed');});} catch(e){thrown=true;}
      if(calls!==1||!thrown)throw new Error('callback invoked twice or error swallowed');
      window.XHR={get:(u,p,cb)=>cb({responseText:'invalid'},null)};
      let badCalls=0;hgGet('/test',d=>{badCalls++;if(d.ok!==false)throw new Error('bad JSON not reported');});
      if(badCalls!==1)throw new Error('bad JSON callback count');
      return {calls,thrown,badCalls};
    }''')
    results['dirty_snapshot']=page.evaluate('''() => {
      document.body.innerHTML='<form id="test"><textarea name="a"></textarea><textarea name="b"></textarea></form>';
      const form=document.getElementById('test');
      form.elements.a.value='x\\nb=y';form.elements.b.value='z';const first=hgFormSnapshot('test');
      form.elements.a.value='x';form.elements.b.value='y\\nb=z';const second=hgFormSnapshot('test');
      if(first===second)throw new Error('multiline form changes collide');return true;
    }''')
    results['latest_log_response']=page.evaluate('''() => {
      document.body.innerHTML='<div id="log"></div>';let pending=[];
      window.XHR={get:(u,p,cb)=>pending.push(cb)};
      hgLoadText('/logs','log');hgLoadText('/logs','log');
      pending[1]({responseText:'new'});pending[0]({responseText:'old'});
      if(document.getElementById('log').textContent!=='new')throw new Error('old log response overwrote new response');return true;
    }''')
    page.wait_for_timeout(100)
    page.evaluate('window.syncCount=0;window.hgSyncOpenModals=()=>{syncCount++;};for(let i=0;i<200;i++)window.dispatchEvent(new Event("resize"));')
    page.wait_for_timeout(100)
    count=page.evaluate('syncCount')
    assert count==1, count
    results['resize_coalesced']=count
    fields='''<input id="hg-public-edit-index" value=""><select id="hg-public-zone"><option>example.com</option></select>
    <input id="hg-public-host" value="home"><select id="hg-public-account"><option value="account" data-provider="aliyun">Account</option></select>
    <input id="hg-public-provider" value="aliyun"><input id="hg-public-target" value="http://192.168.1.100:8080">
    <input id="hg-public-https" type="checkbox" checked><input id="hg-public-cert-source" value="local"><input id="hg-public-renew-days" value="30">'''
    page.set_content('<html><body><div id="hg-public-modal" class="hg-modal-backdrop">'+fields+'</div><script>'+script+'</script><script>'+public_functions+'''\n
      var hgPublicConfirmPending=null,hgPublicRows=[],callbacks=[],commits=0;
      function hgPublicCurrentCA(){return 'letsencrypt';}function hgPublicCurrentEnvironment(){return 'production';}
      function hgPublicReadLocalPair(cb){callbacks.push(cb);}function hgPublicConfirmReady(){commits++;}
    </script></body></html>''')
    results['async_certificate']=page.evaluate('''() => {
      hgSetModalOpen('hg-public-modal',true);
      hgPublicConfirm();hgPublicConfirm();
      if(callbacks.length!==1)throw new Error('double confirm started two reads');
      hgSetModalOpen('hg-public-modal',false);hgSetModalOpen('hg-public-modal',true);
      hgPublicConfirm();if(callbacks.length!==2)throw new Error('new session blocked');
      callbacks[0]({uploaded:true});if(commits!==0)throw new Error('closed session committed');
      hgPublicConfirm();if(callbacks.length!==2)throw new Error('old callback released new pending request');
      callbacks[1]({uploaded:true});if(commits!==1)throw new Error('valid session did not commit once');
      hgSetModalOpen('hg-public-modal',false);hgSetModalOpen('hg-public-modal',true);
      hgPublicConfirm();hgSetModalOpen('hg-public-modal',false);callbacks[2]({uploaded:true});
      if(commits!==1)throw new Error('cancelled dialog committed');
      return {reads:callbacks.length,commits};
    }''')
    access_fn=re.sub(r'<%.*?%>','TEMPLATE',extract(public,'hgPublicAccessOpen'),flags=re.S)
    page.set_content('''<html><body><div id="hg-public-access-modal" class="hg-modal-backdrop"><input id="hg-public-access-allow-editor"><input id="hg-public-access-deny-editor"><input id="hg-public-access-allow-source"><input id="hg-public-access-deny-source"><table><tbody id="hg-public-access-body"></tbody></table></div><script>'''+script+'</script><script>'+access_fn+'''
      var hgPublicRecentRows=[],requests=[],renderCount=0;
      function hgPublicAccessHideAddRule(){}function hgGet(u,cb){requests.push(cb);}
      function hgPublicAccessSummaries(rows){return rows;}function hgPublicAccessRenderRecent(){renderCount++;}
    </script></body></html>''')
    results['latest_access_response']=page.evaluate('''() => {
      hgPublicAccessOpen();hgSetModalOpen('hg-public-access-modal',false);hgPublicAccessOpen();
      requests[1]({ok:true,entries:['new']});requests[0]({ok:true,entries:['old']});
      if(hgPublicRecentRows[0]!=='new'||renderCount!==1)throw new Error('old access response overwrote new session');return true;
    }''')
    geometry={}
    for theme in ('generic','boot','design'):
        for size,width in [('desktop',1200),('mobile',390)]:
            page.set_viewport_size({'width':width,'height':700})
            for kind,rows in [('short',2),('long',34)]:
                fields=''.join('<label>字段</label><input class="hg-control" value="test">' for _ in range(rows))
                doc=f'''<html class="hg-theme-foundation hg-theme-{theme}"><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{{margin:0}} button:hover,button:focus{{height:52px!important;position:relative;top:2px}}</style><style>{css}</style></head><body><div class="hg-modal-backdrop hg-open"><div class="hg-modal hg-public-service-modal"><div class="hg-public-service-scroll" id="scroll"><div class="hg-modal-grid">{fields}</div></div><div class="hg-modal-actions hg-public-service-footer" id="footer"><button class="cbi-button hg-btn-4" id="cancel">取消</button><button class="cbi-button hg-btn-4" id="confirm">确定</button></div></div></div></body></html>'''
                page.set_content(doc)
                page.evaluate('scroll.scrollTop=scroll.scrollHeight')
                before=page.evaluate('''() => {let s=document.getElementById('scroll'),f=document.getElementById('footer'),inputs=s.querySelectorAll('input');let r=s.getBoundingClientRect();return {gap:r.left+s.clientLeft+s.clientWidth-inputs[0].getBoundingClientRect().right,overflow:document.documentElement.scrollWidth>innerWidth,scrollTop:s.scrollTop,footerTop:f.getBoundingClientRect().top};}''')
                assert before['gap']>=11.5,(theme,size,kind,before)
                assert not before['overflow'],(theme,size,kind,before)
                page.locator('#cancel').hover();page.locator('#confirm').focus()
                after=page.evaluate('({scrollTop:document.getElementById("scroll").scrollTop,footerTop:document.getElementById("footer").getBoundingClientRect().top})')
                assert abs(after['footerTop']-before['footerTop'])<0.75 and after['scrollTop']==before['scrollTop'],(theme,size,kind)
                geometry[theme+'-'+size+'-'+kind]=before
                if theme=='design' and size=='desktop' and kind=='long':page.screenshot(path=str(OUT/'弹窗间距预览.png'))
    results['spacing_geometry']=geometry
    # Render and execute the actual LuCI public template against local mock APIs.
    page.set_viewport_size({'width':1000,'height':900})
    errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
    doc='<html class="hg-theme-foundation hg-theme-design"><head><meta charset="UTF-8"><style>body{margin:0;font:14px Arial,sans-serif;background:#eee}.hg-control{border:1px solid #ddd;border-radius:8px;padding:0 8px}.cbi-button{border:0;border-radius:8px;background:#337ab7;color:white}.hg-modal h3{color:#55aaa0}</style></head><body><script>window.XHR={get:function(u,p,cb){cb({responseText:"{}"},{ok:true,results:[],certificates:[],entries:[]});}};</script>'+rendered_common+rendered_public+'</body></html>'
    page.set_content(doc,wait_until='load')
    page.evaluate('hgPublicOpenAdd()')
    page.wait_for_timeout(100)
    assert not errors,errors
    # Host theme owns native checkbox dimensions; compare with a standard LuCI control.
    page.add_style_tag(content='.cbi-input-checkbox{width:18px;height:18px}')
    page.evaluate('''() => {let c=document.createElement("input");c.type="checkbox";c.className="cbi-input-checkbox";c.id="host-checkbox-reference";document.body.appendChild(c);}''')
    assert page.locator('#hg-public-https').bounding_box()['width']==page.locator('#host-checkbox-reference').bounding_box()['width']
    assert page.locator('#hg-public-account').evaluate('(e)=>e.tagName')=='SELECT'
    assert page.locator('#hg-public-account').evaluate('(e)=>getComputedStyle(e).borderRadius')==page.locator('#hg-public-provider').evaluate('(e)=>getComputedStyle(e).borderRadius')
    assert page.locator('#hg-public-cert-scope-label, #hg-public-cert-scope-picker').count()==0
    assert not page.locator('#hg-public-zone-note').is_visible()
    page.evaluate("hgPublicSetZoneOptions([], '', 'DNS authentication failed')")
    assert page.locator('#hg-public-zone option').inner_text()=='DNS authentication failed'
    assert not page.locator('#hg-public-zone-note').is_visible()
    page.evaluate("hgPublicSetZoneOptions(['example.com'], '', 'Domains discovered')")
    assert page.locator('#hg-public-zone').is_enabled()
    assert page.locator('#hg-public-zone-note').inner_text()=='Domains discovered'
    page.evaluate('hgPublicOpenAdd()')
    assert page.locator('#hg-public-renew-days').input_value()==''
    assert page.locator('#hg-public-renew-days').get_attribute('placeholder')
    assert '30' in page.locator('#hg-public-renew-days').get_attribute('placeholder')
    assert page.locator('#hg-public-renew-days').evaluate('(e)=>getComputedStyle(e,"::placeholder").color')=='rgb(156, 169, 183)'
    assert page.locator('#hg-public-access-label-time').inner_text()=='访问时间'
    assert page.locator('#hg-public-renew-note').count()==0
    assert page.locator('#hg-public-renew-days').evaluate('(e)=>getComputedStyle(e).appearance')=='textfield'
    page.locator('#hg-public-renew-days').fill('45')
    assert page.locator('#hg-public-renew-days').input_value()=='45'
    page.locator('#hg-public-renew-days').fill('')
    assert page.locator('#hg-public-renew-days').evaluate('(e)=>e.matches(":placeholder-shown")')
    page.select_option('#hg-public-cert-source','local')
    assert page.locator('#hg-public-local-cert-control .hg-field-note').count()==0
    page.evaluate('hgPublicOpenAdd()')
    real_gap=page.evaluate('''() => {let s=document.getElementById('hg-public-service-scroll'),r=s.getBoundingClientRect(),input=document.getElementById('hg-public-key-id');return r.left+s.clientLeft+s.clientWidth-input.getBoundingClientRect().right;}''')
    assert real_gap>=11.5,real_gap
    page.screenshot(path=str(OUT/'实际模板弹窗预览.png'))
    results['real_template']={'page_errors':errors,'gap':real_gap,'data':'local mock APIs, no router connection'}
    browser.close()
(OUT/'ui7-regressions.json').write_text(json.dumps(results,indent=2,ensure_ascii=False),encoding='utf-8')
print('New UI regression tests: PASS; spacing/footer/overflow 12 scenarios; JS syntax 5 templates')
