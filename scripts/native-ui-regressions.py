#!/usr/bin/env python3
"""Compare native JS rendering with Lua 5.1 and exercise the actual transport."""
import html
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from lupa.lua51 import LuaRuntime
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'project/luci'
JS = APP / 'js/htdocs/luci-static/resources/homegate'
OUT = ROOT / 'build/native-ui-regressions'
OUT.mkdir(parents=True, exist_ok=True)

def lua_template(text):
    chunks = ['local out={}; local function write(s) out[#out+1]=tostring(s or "") end']
    for part in re.split(r'(<%.*?%>)', text, flags=re.S):
        if not part.startswith('<%'): chunks.append('write(' + json.dumps(part,ensure_ascii=False) + ')'); continue
        tag = part[2:-2]
        if tag.startswith('='): chunks.append('write(' + tag[1:] + ')')
        elif tag.startswith(':'): chunks.append('write(pcdata(translate(' + json.dumps(tag[1:],ensure_ascii=False) + ')))')
        elif not tag.startswith('+'): chunks.append(tag)
    return '\n'.join(chunks) + '\nreturn table.concat(out)'

def legacy(page, data):
    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.globals().pcdata = lambda v: html.escape('' if v is None else str(v), quote=True)
    lua.globals().translate = lambda v: v
    lua.globals().url = lambda p: '/cgi-bin/luci/' + p
    for key, value in data.items():
        lua.globals()[key] = lua.table_from(value, recursive=True) if isinstance(value, (dict,list)) else value
    text = (APP / 'lua/luasrc/view/homegate' / (page + '.htm')).read_text(encoding='utf-8')
    text = text.replace('<%+homegate/common%>', (APP / 'lua/luasrc/view/homegate/common.htm').read_text(encoding='utf-8'))
    return lua.execute(lua_template(text))

data = dict(status={'service':{'running':True}},main={'enabled':'1','access_enabled':'1','access_region':'','access_allow':''}, packages={'product':'1.3.0-11','core':'1.3.0-11','luci':'1.3.0-11','i18n':'1.3.0-11','arch':'fixture_arch'},
            services=[], hosts=[], dns_accounts=[], certificates=[], access_regions=[{"key":"CN","label":"China / Mainland","updated":""}], retired_access_region=False, dns_provider_catalog=[], acme_ca_catalog=[],
            wol_interfaces=[{'name':'br-lan','kind':'bridge'},{'name':'eth0','kind':'ethernet'}], wol_clients=[], wol_selected_interface='br-lan',
            public_count=0, wol_count=0, notice='', error_message='', token='rpc', default_renew_days='30', resume_account='',resume_public='')
fixtures = [data, {**data,'status':{},'packages':{'core':'1.3.0-11','luci':'1.3.0-10','i18n':'1.3.0-11'},'default_renew_days':'45','notice':'<img onerror=alert(1)> & "\'','hosts':[{'id':'host_a','name':'','mac':'AA:BB:CC:DD:EE:FF'}],
                  'retired_access_region':True,'services':[{'web_id':'web_a','enabled':'1','https':'0','domain':'test.example','target':'http://192.168.1.2:80','cert_managed':False,'cert_shared':True}],
                  'dns_provider_catalog':[{'name':'aliyun','display_name':'Aliyun DNS','credentials':[{'name':'key_id','label':'AccessKey ID','required':True},{'name':'secret','label':'AccessKey Secret','required':True}]}]}]

node = r'''const fs=require('fs');const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));const L={url:(...p)=>'/cgi-bin/luci/'+p.join('/')};const path=require('path');const baseclass={extend:p=>{function C(){};C.prototype=p;return C;}};const Shared=new Function('L','_','baseclass',fs.readFileSync(path.join(path.dirname(process.argv[3]),'common.js'),'utf8'))(L,v=>v,baseclass);const shared=new Shared();const Renderer=new Function('L','_','shared','baseclass',fs.readFileSync(process.argv[3],'utf8'))(L,v=>v,shared,baseclass);process.stdout.write(new Renderer().render(input));'''
pages = {}
parity = []
with tempfile.TemporaryDirectory() as temp:
    temp = Path(temp); (temp/'render.cjs').write_text(node, encoding='utf-8')
    for i, fixture in enumerate(fixtures):
        (temp/'data.json').write_text(json.dumps(fixture), encoding='utf-8')
        for name in ('overview','basic','public','wol','maintenance'):
            native = subprocess.check_output(['node',str(temp/'render.cjs'),str(temp/'data.json'),str(JS/(name+'.js'))]).decode('utf-8')
            old = legacy(name,fixture)
            clean = lambda s: s.replace('\nvar HGXHR = window.homegateXHR;','').replace('HGXHR.','XHR.').replace('&#x27;','&#39;')
            if clean(native) != clean(old):
                import difflib
                print(''.join(list(difflib.unified_diff(clean(old).splitlines(True),clean(native).splitlines(True)))[:35]))
                raise AssertionError('Lua/JS HTML mismatch: ' + name + '/' + str(i))
            if name == 'overview':
                assert ('>Running</div>' in native) == (i == 0)
                assert ('>Unknown</div>' in native) == (i == 1)
            if name == 'maintenance':
                assert ('Packages match' in native) == (i == 0)
                assert ('Package versions require verification' in native) == (i == 1)
            if name == 'public':
                options=re.findall(r'<option value="([^"<>]*)"[^>]*>(.*?)</option>',native[native.index('id="hg-public-access-scope"'):native.index('</select>',native.index('id="hg-public-access-scope"'))],re.S)
                assert [v for v,_ in options] == ['', '__manual__', 'CN'], options
                warning='Province filtering has been retired.'
                assert (warning in native) == bool(fixture.get('retired_access_region')), 'migration warning mismatch'
            parity.append(name+'/'+str(i)); pages[name] = native
            (OUT/(name+'.html')).write_text(native,encoding='utf-8')

with sync_playwright() as pw:
    edge = Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
    executable = os.environ.get('HOMEGATE_BROWSER') or (str(edge) if edge.exists() else None)
    browser = pw.chromium.launch(**({'executable_path':executable} if executable else {}),headless=True)
    context = browser.new_context(viewport={'width':1200,'height':700})
    context.route('http://homegate.test/**',lambda route: route.fulfill(status=200,body='<html><body></body></html>'))
    page = context.new_page();page.goto('http://homegate.test/cgi-bin/luci/admin/services/homegate/public')
    errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
    for name,text in pages.items():
        page.set_content('<script>window.homegateXHR={get:(u,f,cb)=>cb({status:200,responseText:"{}"},{})};</script>'+text)
        page.wait_for_timeout(100)
        assert not errors,(name,errors)
    # Actual native transport, RPC responses mocked only at the ubus boundary.
    transport = (JS/'transport.js').read_text(encoding='utf-8')
    page.set_content('<form id="a" action="/cgi-bin/luci/admin/services/homegate/basic_apply"><input name="enabled" value="1"><button name="mode" value="save">Save</button></form>')
    page.evaluate(r'''code => {
      window.calls=[];window.notes=[];window.L={url:(...p)=>'/cgi-bin/luci/'+p.join('/')};window._=v=>v;
      const rpc={declare:def=>(...args)=>{calls.push([def.method,...args]);if(def.method==='write')return Promise.resolve({ok:true,job:'a'.repeat(32)});if(def.method==='poll')return Promise.resolve({ok:true,result:{ok:true}});if(def.method==='read')return Promise.resolve({ok:true,body:'{}'});return Promise.resolve({ok:true});}};
      const ui={addNotification:(a,b)=>notes.push(b.textContent)};
      window.E=(tag,attrs,text)=>{let e=document.createElement(tag);if(text)e.textContent=text;return e;};
      const baseclass={extend:p=>{function C(){};C.prototype=p;return C;}};const T=new Function('rpc','ui','baseclass',code)(rpc,ui,baseclass);window.transport=new T();transport.install(document.body);
    }''',transport)
    page.click('button');page.wait_for_timeout(750)
    calls=page.evaluate('calls')
    assert calls[0][0]=='write' and calls[0][2]['mode']=='save',calls
    assert [x[0] for x in calls]==['write','poll','ack'],calls
    page.evaluate("document.getElementById('a').submit();document.getElementById('a').submit()")
    page.wait_for_timeout(750)
    assert len([x for x in page.evaluate('calls') if x[0]=='write'])==2,'duplicate submit was not suppressed'
    # Dynamically created body forms follow the same path as modal helper posts.
    page.evaluate("let f=document.createElement('form');f.action='/cgi-bin/luci/admin/services/homegate/public_action';document.body.appendChild(f);f.submit()")
    page.wait_for_timeout(750)
    assert page.evaluate('calls.filter(x=>x[0]==="write").length')==3
    assert page.evaluate('notes.length')==0
    browser.close()
(OUT/'results.json').write_text(json.dumps({'html_parity':parity,'transport':['submitter-mode','job-poll-ack','duplicate-suppression','dynamic-form']},indent=2),encoding='utf-8')
print('Native/Lua HTML parity: PASS (10); native transport: PASS (4)')

