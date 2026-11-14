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
from production_runtime import payload

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

def legacy(page, data, rendered_files=None):
    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.globals().pcdata = lambda v: html.escape('' if v is None else str(v), quote=True)
    lua.globals().translate = lambda v: v
    lua.globals().url = lambda p: '/cgi-bin/luci/' + p
    for key, value in data.items():
        lua.globals()[key] = lua.table_from(value, recursive=True) if isinstance(value, (dict,list)) else value
    if rendered_files:
        text = rendered_files[page].replace('<%+homegate_legacy/common%>', rendered_files['common'])
        lua.globals().resource = '/luci-static/resources'
    else:
        text = (APP / 'lua/luasrc/view/homegate' / (page + '.htm')).read_text(encoding='utf-8')
        text = text.replace('<%+homegate/common%>', (APP / 'lua/luasrc/view/homegate/common.htm').read_text(encoding='utf-8'))
    return lua.execute(lua_template(text))

data = dict(status={'service':{'running':True}},main={'enabled':'1','access_enabled':'1','access_region':'','access_allow':''}, packages={'product':'1.3.0-11','core':'1.3.0-11','luci':'1.3.0-11','i18n':'1.3.0-11','arch':'fixture_arch'},
            services=[], hosts=[], dns_accounts=[], certificates=[], access_regions=[{"key":"CN","label":"China / Mainland","updated":""}], retired_access_region=False, dns_provider_catalog=[], acme_ca_catalog=[],
            wol_interfaces=[{'name':'br-lan','kind':'bridge'},{'name':'eth0','kind':'ethernet'}], wol_clients=[], wol_selected_interface='br-lan',
            public_count=0, wol_count=0, notice='', error_message='', token='rpc', default_renew_days='5', resume_account='',resume_public='')
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
                assert 'homegate-basic-form' in native and 'Quick Access' not in native
            if name == 'maintenance':
                assert 'Version Management' not in native and 'packages.core' not in native
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
    # Open actual generated LuCI markup, including the notice timer and external script.
    base='/cgi-bin/luci/admin/services/homegate'
    files=payload(ROOT)
    templates={name:files[f'usr/lib/lua/luci/view/homegate_legacy/{name}.htm'].decode()
               for name in ('overview','maintenance','common')}
    operations=files['www/luci-static/resources/homegate/native-operations.js'].decode()
    context.unroute('http://homegate.test/**')
    for name, mode, failure in [('maintenance','save',None),('overview','save',None),
                                ('overview','save','save'),('overview','apply',None),('overview','apply','apply'),
                                ('overview','apply','stop')]:
        stopping=failure=='stop'
        if stopping: failure=None
        calls=[]
        page.evaluate('sessionStorage.clear()')
        def operation_response(route):
            path=route.request.url.split(base,1)[-1]
            calls.append((path,route.request.post_data))
            if path=='/luci-static/resources/homegate/native-operations.js' or path.endswith('/homegate/native-operations.js'):
                route.fulfill(content_type='application/javascript',body=operations);return
            if path=='/'+name:
                markup=legacy(name,{**fixtures[0],'main':{'enabled':'1' if stopping else '0','log_max_lines':'1024'}},templates)
                route.fulfill(content_type='text/html; charset=utf-8',body='<script>window.XHR={get:(u,f,cb)=>cb({status:200,responseText:"{}"},{})};</script>'+markup);return
            if path in ('/basic_apply','/maintenance_apply'):
                data={'ok':True,'pending':True,'job':'b'*32}
            elif path.startswith('/compat_job/'):
                if mode=='apply' and sum(p.startswith('/compat_job/') for p,_ in calls)==1:
                    data={'ok':True,'pending':True,'configuration_saved':True,'applying_service':'stop' if stopping else 'start'}
                else:
                    result={'ok':not failure,'configuration_saved':failure!='save','runtime_applied':mode=='apply' and not failure and not stopping,
                            'redirect':base+'/'+name+('?notice=Saved+and+applied' if stopping else '?notice=Saved')}
                    if failure=='apply':result.update(uncertain=True,error='配置已保存，但服务尚未验证运行。')
                    if failure=='save':result.update(error='保存失败，请检查当前配置。')
                    data={'ok':True,'pending':False,'result':result}
            else:
                data={'ok':True,'pending':False}
            route.fulfill(json=data)
        context.route('http://homegate.test/**',operation_response)
        page.goto('http://homegate.test'+base+'/'+name)
        page.wait_for_timeout(3100)
        if name=='overview':
            page.locator('input[name=enabled]').set_checked(not stopping);dirty=page.locator('#hg-basic-dirty')
        else:
            page.locator('input[name=log_max_lines]').fill('1025');dirty=page.locator('#hg-maintenance-dirty')
        assert dirty.is_visible()
        page.locator('.cbi-page-actions .cbi-button-'+mode).click()
        status=page.locator('#hg-operation-status')
        assert status.evaluate("node => node.parentElement.classList.contains('hg-wrap') && node.nextElementSibling.classList.contains('hg-notice-pending')")
        assert not dirty.is_visible()
        if mode=='apply':
            status.filter(has_text='正在停用' if stopping else '正在启动').wait_for(state='visible',timeout=5000)
            assert not dirty.is_visible()
        outcome={'apply':'服务尚未验证运行','save':'保存失败'}.get(failure,'已保存并应用。' if stopping else ('HomeGate 已运行' if mode=='apply' else '已保存。'))
        status.filter(has_text=outcome).wait_for(state='visible',timeout=5000)
        assert page.url.endswith('/'+name) and not dirty.is_visible()
        assert status.evaluate("node => node.classList.contains('hg-notice') && getComputedStyle(node).borderLeftWidth === '3px'")
        assert not page.locator('.cbi-page-actions #hg-operation-status').count()
        if name=='maintenance':
            page.locator('input[name=log_max_lines]').fill('1026')
            assert dirty.is_visible() and not status.is_visible()
        if failure=='save':
            assert page.locator('input[name=enabled]').is_checked()
            assert dirty.evaluate("node => node.style.display !== 'none'")
        applied=[body for path,body in calls if path in ('/basic_apply','/maintenance_apply')]
        assert len(applied)==1 and 'mode='+mode in applied[0],calls
        assert any(p.startswith('/compat_ack/') for p,_ in calls) == (failure!='apply')
        context.unroute('http://homegate.test/**',operation_response)
    # Use real asynchronous requests to exercise shared-lock sequencing and
    # allow a previously displayed running status to become unknown.
    status_calls=[]
    stopped={'ok':True,'service':{'running':False,'healthy':True}}
    running={'ok':True,'service':{'running':True,'healthy':True},'runtime':{'pid':123}}
    unavailable={'ok':False,'state_unknown':True,'service':{'running':False,'healthy':False}}
    replies=[{'ok':False,'error':'Public response unavailable; inspect retained operation'},stopped,running]
    xhr='<script>window.XHR={get:async(u,f,cb)=>{const r=await fetch(u); const d=await r.json();cb({status:r.status},d)}};</script>'
    def status_response(route):
        path=route.request.url.split(base,1)[-1]
        if path=='/overview':
            route.fulfill(content_type='text/html; charset=utf-8',body=xhr+legacy('overview',fixtures[0],templates))
        elif path.endswith('/homegate/native-operations.js'):
            route.fulfill(content_type='application/javascript',body=operations)
        elif path=='/api/status':
            status_calls.append(path)
            route.fulfill(json=replies.pop(0) if replies else unavailable)
        elif path=='/api/network':
            status_calls.append(path)
            route.fulfill(json={'ok':True,'network':{'wan':{'public_ipv6':'2001:db8::1'}}})
        else:
            route.fulfill(status=404)
    context.route('http://homegate.test/**',status_response)
    page.goto('http://homegate.test'+base+'/overview')
    service=page.locator('#hg_service')
    page.locator('#hg_ipv6').filter(has_text='2001:db8::1').wait_for(timeout=5000)
    assert status_calls==['/api/status','/api/status','/api/network'],status_calls
    assert service.inner_text()=='Stopped'
    page.evaluate('window.hgRefreshService()')
    page.locator('#hg_pid').filter(has_text='PID 123').wait_for(timeout=5000)
    page.evaluate('window.hgRefreshService()')
    service.filter(has_text='Service status temporarily unavailable').wait_for(timeout=5000)
    assert page.locator('#hg_pid').inner_text()=='-'
    assert status_calls[3:]==['/api/status']*5,status_calls
    assert not errors,errors
    browser.close()
(OUT/'results.json').write_text(json.dumps({'html_parity':parity,'transport':['submitter-mode','job-poll-ack','duplicate-suppression','dynamic-form'],'production_http':['delayed-maintenance-save','delayed-overview-save','delayed-overview-save-error','delayed-inline-start-success','delayed-inline-uncertain-start','delayed-inline-stop','status-retry-before-network','status-unknown-clears-pid']},indent=2),encoding='utf-8')
print('Native/Lua HTML parity: PASS (10); native transport: PASS (4); production HTTP: PASS (8)')

