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
                  'wol_clients':[{'mac':'AA:BB:CC:DD:EE:FF','name':'Saved host','label':'Saved host & TV'},
                                 {'mac':'02:11:22:33:44:55','name':'New host','label':'New host'}],
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
    errors=[];page.on('pageerror',lambda e:errors.append(e.stack or str(e)))
    for name,text in pages.items():
        page.set_content('<script>window.homegateXHR={get:(u,f,cb)=>cb({status:200,responseText:"{}"},{})};</script>'+text)
        page.wait_for_timeout(100)
        assert not errors,(name,errors)
    installed=payload(ROOT)
    context.route('**/homegate/native-operations.js',lambda route:route.fulfill(
        status=200,content_type='application/javascript',body=installed['www/luci-static/resources/homegate/native-operations.js']))
    wol_views={f:installed['usr/lib/lua/luci/view/homegate_legacy/'+f+'.htm'].decode() for f in ('wol','common')}
    page.set_content('<script>window.confirmCalls=0;window.confirm=()=>{++confirmCalls;return false;};</script>'+
                     legacy('wol',fixtures[1],wol_views))
    bootstrap=(ROOT/'scripts/fixtures/legacy-bootstrap/cascade.css').read_text(encoding='utf-8')
    page.add_style_tag(content=bootstrap)
    add_host=page.get_by_role('button',name='Add',exact=True)
    choice=page.locator('#hg-wol-mac-choice')
    occupied=choice.locator('option[value="AA:BB:CC:DD:EE:FF"]')
    available=choice.locator('option[value="02:11:22:33:44:55"]')
    custom=choice.locator('option[value="__custom__"]')
    mac_input=page.locator('#hg-wol-mac-custom')
    confirm_host=page.get_by_role('button',name='Confirm',exact=True)
    cancel_host=page.get_by_role('button',name='Cancel',exact=True)
    add_host.click()
    assert occupied.is_disabled() and occupied.text_content()=='Saved host & TV'
    disabled_color=occupied.evaluate('option => getComputedStyle(option).color')
    assert disabled_color=='rgb(191, 191, 191)' and available.evaluate('option => getComputedStyle(option).color')!=disabled_color
    assert available.is_enabled() and custom.is_enabled()
    choice.select_option('__custom__')
    mac_input.fill(' aa-bb-cc-dd-ee-ff ')
    confirm_host.click()
    assert page.locator('input[name=wol_host_mac_2]').input_value()=='AA:BB:CC:DD:EE:FF'
    page.get_by_role('button',name='Delete',exact=True).last.click()
    page.get_by_role('button',name='Edit',exact=True).click()
    assert choice.is_hidden() and mac_input.is_visible() and mac_input.is_disabled()
    assert mac_input.evaluate('input => getComputedStyle(input).color')==disabled_color
    assert mac_input.input_value()=='AA:BB:CC:DD:EE:FF'
    page.locator('#hg-wol-name').fill('Renamed desktop')
    mac_input.evaluate("input => { input.value='02:11:22:33:44:55'; }")
    confirm_host.click()
    assert page.locator('input[name=wol_host_name_1]').input_value()=='Renamed desktop'
    assert page.locator('input[name=wol_host_mac_1]').input_value()=='AA:BB:CC:DD:EE:FF'
    add_host.click()
    assert choice.is_visible() and occupied.is_disabled() and mac_input.is_enabled() and mac_input.is_hidden()
    choice.select_option('02:11:22:33:44:55')
    confirm_host.click()
    add_host.click()
    assert occupied.is_disabled() and available.is_disabled()
    cancel_host.click()
    page.get_by_role('button',name='Delete',exact=True).last.click()
    page.evaluate("hgShowNotice(document.getElementById('hg-operation-status'),'Wake packet sent','success')")
    page.get_by_role('button',name='Delete',exact=True).click()
    assert page.evaluate('confirmCalls')==0
    assert page.locator('#hg-wol-hosts .hg-wol-row').count()==0
    assert page.locator('input[name=wol_host_count]').input_value()=='0'
    assert page.locator('#hg-wol-dirty').is_visible()
    assert page.locator('#hg-operation-status').is_hidden()
    page.locator('.hg-wrap > .hg-notice').first.wait_for(state='hidden',timeout=5000)
    assert page.locator('#hg-wol-dirty').is_visible()
    add_host.click()
    assert occupied.is_enabled() and occupied.text_content()=='Saved host & TV'
    assert available.is_enabled()
    public_fixture={**data,'services':[{'web_id':'web_a','ddns_id':'rule_a','account_id':'dns_a','cert_id':'cert_a',
        'enabled':'1','https':'1','domain':'files.example.test','zone':'example.test','host':'files.example.test',
        'target':'https://255.255.255.255:999999','cert_environment':'staging'}],
        'dns_accounts':[{'id':'dns_a','label':'Existing'}, {'id':'dns_b','label':'Other'}],
        'acme_ca_catalog':[{'name':'letsencrypt','display_name':"Let's Encrypt"}]}
    installed_views={f:installed['usr/lib/lua/luci/view/homegate_legacy/'+f+'.htm'].decode() for f in ('public','common')}
    public_html=legacy('public',public_fixture,installed_views)
    (OUT/'public-zones.html').write_text(public_html,encoding='utf-8')
    page.set_content('''<script>
    window.zones=[];
    window.XHR={get:(u,f,cb)=>{
      if(u.endsWith('/dns_zones')){zones.push({account:f.account,reply:cb});return;}
      const d=u.endsWith('/certs')?{ok:true,certificates:[{id:'cert_a',exists:true,identity_valid:true,valid:true,days:42}]}:
        (u.endsWith('/proxy')?{ok:true,running:false,state:'stopped'}:{});
      cb({status:200,responseText:JSON.stringify(d)},d);
    }}
    </script>'''+public_html)
    assert not errors,errors
    address=page.locator('.hg-public-url')
    hint=page.locator('.hg-public-hint')
    assert address.inner_text()=='https://files.example.test'
    assert 'Staging Environment' in hint.inner_text() and 'Certificate 42 days' in hint.inner_text()
    assert hint.bounding_box()['y']>address.bounding_box()['y']
    sizes=page.evaluate("""['.hg-public-hint','.hg-public-url','.hg-public-target']
      .map(s=>parseFloat(getComputedStyle(document.querySelector(s)).fontSize))""")
    assert sizes[0]<sizes[1]<sizes[2],sizes
    row=address.locator('xpath=ancestor::tr')
    centers=[]
    for cell in (row.locator('input[type=checkbox]'),row.locator('.hg-public-target'),row.get_by_role('button',name='Edit')):
        box=cell.bounding_box()
        centers.append(box['y']+box['height']/2)
    assert max(centers)-min(centers)<=2,centers
    page.evaluate("hgPublicRows[0].cert_environment='production';hgPublicRender()")
    assert 'Production Environment' in hint.inner_text()
    page.evaluate("hgPublicRows[0].cert_environment='staging';hgPublicRender()")
    assert page.locator('.hg-public-target').evaluate('''cell=>{
      const range=document.createRange();
      range.selectNodeContents(cell);
      return range.getClientRects().length===1 && range.getBoundingClientRect().right<=cell.getBoundingClientRect().right;
    }''')
    assert hint.evaluate('''node => {
      const original=node.textContent;
      node.textContent='正式环境 · DDNS 异常 · 续期失败（证书剩余 3650 天） · 代理异常';
      const range=document.createRange();
      range.selectNodeContents(node);
      const cell=node.closest('td').getBoundingClientRect();
      const visible=[...range.getClientRects()].every(rect=>rect.right<=cell.right && rect.bottom<=cell.bottom);
      node.textContent=original;
      return visible;
    }'''), 'Long Chinese status is clipped or crosses into the next column'
    page.evaluate('''() => {
      window.accessActions=[];
      const get=XHR.get;
      XHR.get=(u,f,cb)=>u.endsWith('/access_recent')?cb({status:200},{ok:true,entries:[
        {ip:'2409:aaaa:bbbb:cccc:dddd:eeee:ffff:1234',host:'files.example.test',
         allowed:true,reason:'region',time:'2026-11-16T09:04:41Z'}
      ]}):get(u,f,cb);
      window.homegateAccessAction=async (route,form)=>{
        accessActions.push({route,form});
        if(route==='access_update'){
          if(window.failRegionUpdate)return {ok:false,error:'Region data download failed'};
          return {ok:true,access_region_state:window.regionState||'published',access_region_updated:'2026/11/16 15:10'};
        }
        return {ok:true,access_rules:{
          allow:form.kind==='allow'?form.rule_token:'',
          deny:form.kind==='deny'?form.rule_token:'',
          origins:form.rule_token?{[form.rule_token]:form.rule_origin||'custom'}:{}
        }};
      };
      window.confirmCalls=0;
      confirm=()=>{++window.confirmCalls;return true;};
      hgPublicAccessOpen();
    }''')
    modal=page.locator('#hg-public-access-modal')
    assert 'Access Management' not in modal.inner_text()
    footer=modal.locator('.hg-access-footer')
    add=footer.get_by_role('button',name='Add Rule')
    close=footer.get_by_role('button',name='Close')
    assert abs(add.bounding_box()['y']-close.bounding_box()['y'])<3
    assert add.bounding_box()['x']<close.bounding_box()['x']
    page.locator('#hg-public-access-scope').select_option('CN', force=True)
    observed=modal.locator('tbody tr').last
    assert '2409:aaaa:bbbb:cccc:dddd:eeee:ffff:1234' in observed.inner_text()
    assert 'Allowed' in observed.inner_text()
    assert observed.locator('.hg-access-ip-edit').count()==0
    page.evaluate('window.savedRecent=hgPublicRecentRows;hgPublicRecentRows=[];hgPublicAccessRenderRecent()')
    assert modal.locator('tbody tr').count()==1
    assert observed.locator('.hg-access-ip-edit').count()==0
    page.evaluate('hgPublicRecentRows=savedRecent;hgPublicAccessRenderRecent()')
    assert observed.locator('.hg-access-action button').count()==2
    observed.get_by_role('button',name='Deny Access').click()
    assert modal.locator('tbody tr').count()==1
    assert 'Denied' in observed.inner_text()
    assert 'files.example.test' in observed.inner_text()
    assert observed.locator('.hg-access-ip-edit').count()==0
    assert page.evaluate('accessActions[0].form.rule_origin')=='observed'
    observed.get_by_role('button',name='Allow Access').click()
    assert modal.locator('tbody tr').count()==1
    assert 'Allowed' in observed.inner_text()
    assert observed.locator('.hg-access-ip-edit').count()==0
    add.click()
    draft=modal.locator('tbody tr').first
    assert draft.locator('input').input_value()==''
    assert draft.get_by_role('button',name='Deny Access').count()==1
    assert draft.locator('.hg-access-action button').count()==2
    assert page.evaluate('accessActions.length')==2
    draft.locator('input').fill('2001:db8::1')
    modal.locator('th').first.click()
    modal.get_by_role('button',name='2001:db8::1',exact=True).wait_for()
    assert page.locator('#hg-public-access-allow-source').input_value()=='2001:db8::1'
    assert page.locator('#hg-public-access-scope').input_value()=='CN'
    assert page.evaluate('hgPublicHasUnsaved')
    modal.get_by_role('button',name='2001:db8::1',exact=True).click()
    draft.locator('input').fill('2001:db8::2')
    draft.get_by_role('button',name='Deny Access').click()
    modal.get_by_text('2001:db8::2',exact=True).wait_for()
    assert page.locator('#hg-public-access-deny-source').input_value()=='2001:db8::2'
    footer.get_by_role('button',name='Clear Rules',exact=True).click()
    modal.get_by_text('2001:db8::2',exact=True).wait_for(state='hidden')
    assert page.evaluate('confirmCalls')==0
    close.click()
    page.wait_for_timeout(3100)
    update_region=page.locator('#hg-public-region-data-row').get_by_role('button',name='Update')
    update_region.click()
    region_status=page.locator('#hg-public-region-data-status')
    region_notice=page.locator('#hg-public-region-message')
    assert region_status.inner_text()=='Updated on 2026/11/16 15:10'
    assert region_notice.is_visible()
    access_heading=page.get_by_role('heading',name='Access Restriction')
    assert region_notice.bounding_box()['y']<access_heading.bounding_box()['y']
    assert page.evaluate('accessActions.map(action=>action.route)')==[
        'access_save_rule','access_save_rule','access_save_rule','access_save_rule','access_delete_all','access_update'
    ]
    region_notice.wait_for(state='hidden',timeout=5000)
    for state, message in (('cached','Region data is up to date'),('limited','Two region data updates have been applied today')):
        page.evaluate('value=>window.regionState=value',state)
        update_region.click()
        assert region_status.inner_text()=='Updated on 2026/11/16 15:10'
        assert message in region_notice.inner_text()
    assert 'hg-notice-pending' in region_notice.get_attribute('class')
    page.evaluate('window.failRegionUpdate=true')
    update_region.click()
    assert region_status.inner_text()=='Updated on 2026/11/16 15:10'
    assert region_notice.is_visible() and region_notice.inner_text()=='Region data download failed'
    page.wait_for_timeout(3100)
    assert region_notice.is_visible() and 'hg-notice-error' in region_notice.get_attribute('class')
    assert page.evaluate('zones.length')==0,'Background DNS query before opening the modal'
    timing=page.evaluate('''() => {
      const start=performance.now();
      hgPublicOpenIndex(0);
      return [performance.now()-start,document.getElementById('hg-public-zone').value];
    }''')
    assert timing[0]<3000 and timing[1]=='example.test',timing
    assert page.locator('#hg-public-host').input_value()=='files'
    assert page.locator('#hg-public-domain-preview').inner_text()=='-'
    assert page.evaluate("hgPublicHostPrefix('example.test','EXAMPLE.TEST.')")=='@'
    assert page.evaluate("hgPublicHostPrefix('example.test','deep.files.example.test')")=='deep.files'
    page.evaluate("hgPublicClose(); hgPublicOpenAdd()")
    assert page.locator('#hg-public-zone').input_value()=='example.test'
    assert page.evaluate('zones.length')==1,'Same account launched a duplicate fetch'
    page.wait_for_timeout(2900)
    assert not page.locator('#hg-public-zone-retry').is_visible()
    assert page.locator('#hg-public-zone').input_value()=='example.test'
    page.evaluate("zones[0].reply({status:200},{ok:true,zones:['aaa.test','example.test']})")
    assert page.locator('#hg-public-zone').input_value()=='example.test'
    assert page.locator('#hg-public-zone option').all_text_contents()==['aaa.test','example.test']
    page.locator('#hg-public-account').select_option('dns_b')
    assert page.locator('#hg-public-zone').input_value()==''
    page.evaluate("zones[1].reply({status:200},{ok:false,error_kind:'busy'})")
    page.wait_for_function('zones.length===3')
    assert not page.locator('#hg-public-zone-retry').is_visible()
    page.evaluate("zones[2].reply({status:503,responseText:''},null)")
    page.wait_for_function('zones.length===4')
    assert not page.locator('#hg-public-zone-retry').is_visible()
    page.evaluate("zones[3].reply({status:200},{ok:false,error_kind:'rate_limit',retryable:true})")
    assert page.locator('#hg-public-zone-retry').is_visible()
    assert page.locator('#hg-public-zone-retry').evaluate("b=>parseInt(getComputedStyle(b).marginTop,10)")>=6
    assert 'Unable to load primary domains' in page.locator('#hg-public-zone').inner_text()
    page.locator('#hg-public-zone-retry').click()
    assert page.evaluate('zones.length')==5,'Retry did not send a new request'
    page.evaluate("zones[4].reply({status:200},{ok:true,zones:{}})")
    assert not page.locator('#hg-public-zone-retry').is_visible()
    assert 'No managed primary domains' in page.locator('#hg-public-zone').inner_text()
    page.evaluate("hgPublicClose(); hgPublicZoneCache.dns_a.expires=0; hgPublicOpenIndex(0)")
    assert page.locator('#hg-public-zone').input_value()=='example.test'
    page.evaluate("zones[5].reply({status:200},{ok:false,error:'DNS status request refused'})")
    page.wait_for_function('zones.length===7')
    assert not page.locator('#hg-public-zone-retry').is_visible()
    assert page.locator('#hg-public-domain-preview').inner_text()=='-'
    page.evaluate("zones[6].reply({status:200},{ok:true,zones:['example.test','other.test']})")
    assert page.locator('#hg-public-zone option').all_text_contents()==['example.test','other.test']
    assert page.locator('#hg-public-zone').input_value()=='example.test'
    assert not errors,errors
    print('SAVED_PRIMARY_DOMAIN_MS='+str(round(timing[0],2)),flush=True)
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
               for name in ('overview','public','maintenance','common')}
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
                markup=legacy(name,{**fixtures[0],'runtime_enabled':'1' if stopping else '0','main':{'log_max_lines':'1024'}},templates)
                route.fulfill(content_type='text/html; charset=utf-8',body='<script>window.XHR={get:async(u,f,cb)=>{const r=await fetch(u);cb({status:r.status},await r.json())}};</script>'+markup);return
            if path=='/api/overview_status':
                completed=any(p.startswith('/compat_ack/') for p,_ in calls)
                running=stopping if not completed else mode=='apply' and not failure and not stopping
                data={'ok':True,'service':{'running':running,'healthy':True}}
            elif path in ('/basic_apply','/maintenance_apply'):
                data={'ok':True,'pending':True,'job':'b'*32}
            elif path.startswith('/compat_job/'):
                if sum(p.startswith('/compat_job/') for p,_ in calls)==1:
                    data={'ok':True,'pending':True}
                    if mode=='apply':
                        data.update(configuration_saved=True,applying_service='stop' if stopping else 'start')
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
        toolbar=page.locator('.cbi-page-actions')
        button=toolbar.locator('.cbi-button-'+mode)
        other=toolbar.locator('.cbi-button-'+('save' if mode=='apply' else 'apply'))
        reset=toolbar.locator('.cbi-button-reset')
        label,other_label=button.input_value(),other.input_value()
        button.click()
        assert button.input_value()==('正在应用…' if mode=='apply' else '正在保存…')
        assert other.input_value()==other_label
        assert button.is_disabled() and other.is_disabled() and reset.is_disabled()
        status=page.locator('.hg-operation-status')
        assert status.count()==1
        assert status.evaluate("node => node.parentElement.classList.contains('hg-wrap') && node.nextElementSibling.classList.contains('hg-notice-pending')")
        assert not dirty.is_visible()
        if mode=='apply':
            status.filter(has_text='正在停用' if stopping else '正在启动').wait_for(state='visible',timeout=5000)
            assert page.locator('#hg_service').inner_text()==('Stopping...' if stopping else 'Starting...')
            assert not dirty.is_visible()
        outcome={'apply':'服务尚未验证运行','save':'保存失败'}.get(failure,'已保存并应用。' if stopping else ('HomeGate 已运行' if mode=='apply' else '已保存。'))
        status.filter(has_text=outcome).wait_for(state='visible',timeout=5000)
        assert button.input_value()==label
        assert button.is_enabled() and other.is_enabled() and reset.is_enabled()
        assert page.url.endswith('/'+name) and not dirty.is_visible()
        assert status.evaluate("node => node.classList.contains('hg-notice') && getComputedStyle(node).borderLeftWidth === '3px'")
        assert not page.locator('.cbi-page-actions .hg-operation-status').count()
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
    # Account saving uses the production job bridge while the modal owns its feedback.
    account_requests=[]
    account_result={'ok':False,'error':'Account save failed in fixture'}
    account_redirect=base+'/public?resume_public=add&resume_account=dns_saved'
    def account_response(route):
        path=route.request.url.split(base,1)[-1]
        if path.endswith('/homegate/native-operations.js'):
            route.fulfill(content_type='application/javascript',body=operations);return
        if path.startswith('/public') and not path.startswith('/public_account_apply'):
            fixture=fixtures[1]
            if '?resume_public=' in path:
                fixture={**fixture,'resume_public':'add','resume_account':'dns_saved',
                         'dns_accounts':[{'id':'dns_saved','label':'Saved Account'}]}
            markup=legacy('public',fixture,templates)
            route.fulfill(content_type='text/html; charset=utf-8',body='<script>window.XHR={get:async(u,f,cb)=>{const r=await fetch(u);cb({status:r.status},await r.json())}};</script>'+markup);return
        if path=='/public_account_apply':
            account_requests.append(route.request.post_data)
            data={'ok':True,'pending':True,'job':'c'*32}
        elif path.startswith('/compat_job/'):
            data={'ok':True,'pending':not account_result,'result':account_result}
        elif path=='/api/dns_zones':
            data={'ok':True,'zones':['example.test']}
        else:
            data={'ok':True}
        route.fulfill(json=data)
    context.route('http://homegate.test/**',account_response)
    page.goto('http://homegate.test'+base+'/public')
    page.evaluate('hgPublicOpenAdd()')
    account_result={}
    account_save=page.get_by_role('button',name='Save Account',exact=True)
    page.locator('#hg-public-key-id').fill('fixture-key-id')
    page.locator('#hg-public-secret').fill('fixture-secret')
    account_save.click()
    assert account_save.is_disabled()
    page.wait_for_timeout(400)
    assert page.locator('#hg-operation-status').is_hidden()
    assert page.locator('#hg-public-account-result').is_hidden() and len(account_requests)==1
    account_result={'ok':False,'error':'Account save failed in fixture'}
    page.locator('#hg-public-account-result').filter(has_text=account_result['error']).wait_for()
    assert account_save.is_enabled() and page.locator('#hg-operation-status').is_hidden()
    assert page.locator('#hg-public-key-id').input_value()=='fixture-key-id'
    account_result={'ok':True,'redirect':account_redirect}
    account_save.click()
    page.get_by_role('dialog',name='Add Public Service').wait_for(state='visible')
    page.wait_for_function("document.getElementById('hg-public-account').value==='dns_saved'")
    assert len(account_requests)==2 and all('token=rpc' in body for body in account_requests)
    context.unroute('http://homegate.test/**',account_response)
    # WAN information must arrive independently of runtime status retries.
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
        elif path=='/api/overview_status':
            status_calls.append(path)
            route.fulfill(json=replies.pop(0) if replies else unavailable)
        elif path=='/api/overview_ipv6':
            status_calls.append(path)
            route.fulfill(json={'ok':True,'public_ipv6':'2001:db8::1'})
        else:
            route.fulfill(status=404)
    context.route('http://homegate.test/**',status_response)
    page.goto('http://homegate.test'+base+'/overview')
    service=page.locator('#hg_service')
    page.locator('#hg_ipv6').filter(has_text='2001:db8::1').wait_for(timeout=5000)
    service.filter(has_text='Stopped').wait_for(timeout=5000)
    enabled=page.locator('input[name=enabled]')
    assert enabled.is_enabled() and not enabled.is_checked()
    interval=page.locator('input[name=ddns_interval]')
    original=interval.input_value()
    interval.fill('900')
    assert status_calls.count('/api/overview_ipv6')==1,status_calls
    assert status_calls.index('/api/overview_ipv6') < [i for i,p in enumerate(status_calls) if p=='/api/overview_status'][1],status_calls
    page.evaluate('window.hgRefreshService()')
    page.locator('#hg_pid').filter(has_text='PID 123').wait_for(timeout=5000)
    assert enabled.is_checked() and page.locator('#hg-basic-dirty').is_visible()
    interval.fill(original)
    assert not page.locator('#hg-basic-dirty').is_visible()
    page.evaluate('window.hgRefreshService()')
    service.filter(has_text='Service status temporarily unavailable').wait_for(timeout=5000)
    assert page.locator('#hg_pid').inner_text()=='-'
    assert enabled.is_disabled()
    assert status_calls.count('/api/overview_status')==7,status_calls
    assert status_calls.count('/api/overview_ipv6')==1,status_calls
    assert not errors,errors
    # Bootstrap's form margin must not add space below the URL buttons.
    theme=(ROOT/'scripts/fixtures/legacy-bootstrap/cascade.css').read_text(encoding='utf-8')
    def footer_geometry(markup,backdrop,open_dialog):
        page.set_content(xhr+markup)
        page.evaluate("document.documentElement.lang='zh-cn'")
        page.add_style_tag(content=theme)
        page.evaluate(open_dialog)
        return page.locator(backdrop+' .hg-modal').evaluate('''modal => {
            const rect=modal.getBoundingClientRect();
            return [...modal.querySelectorAll('.hg-modal-actions button')].map(button => {
                const b=button.getBoundingClientRect();
                return [b.width,b.height,rect.bottom-b.bottom];
            });
        }''')
    context.unroute('http://homegate.test/**',status_response)
    context.route('http://homegate.test/**',lambda route: route.fulfill(json={'ok':True}))
    for width in (1200,390):
        page.set_viewport_size({'width':width,'height':700})
        public_footer=footer_geometry(legacy('public',fixtures[1]),'#hg-public-modal','hgPublicOpenAdd()')
        placeholder_style='e=>{const style=getComputedStyle(e,"::placeholder");return [style.color,style.opacity];}'
        assert page.locator('#hg-public-renew-days').evaluate(placeholder_style)==page.locator('#hg-public-target').evaluate(placeholder_style)
        maintenance=legacy('maintenance',fixtures[0])
        url_footer=footer_geometry(maintenance,'#hg-plugin-update-modal','hgMaintenanceOpenUpdateUrl()')
        license_footer=footer_geometry(maintenance,'#hg-plugin-license-modal',"hgSetModalOpen('hg-plugin-license-modal',true)")
        assert public_footer[0][0]>=60 and public_footer[0][1]>=28
        assert url_footer==public_footer and license_footer==public_footer[:1],(width,public_footer,url_footer,license_footer)
    page.set_viewport_size({'width':1200,'height':700})
    def action_geometry(markup):
        page.set_content(xhr+markup)
        page.add_style_tag(content=theme)
        return page.locator('.hg-public-table, .hg-wol-table').evaluate('''table => {
            const head=table.querySelector('.hg-action-head');
            const buttons=[...table.querySelectorAll('tbody .hg-action-cell button')].map(button=>button.getBoundingClientRect());
            return [head.getBoundingClientRect().left+parseFloat(getComputedStyle(head).paddingLeft),
                    buttons[0].left,buttons[1].left-buttons[0].right,buttons[2].left-buttons[1].right];
        }''')
    public=action_geometry(legacy('public',fixtures[1]))
    assert page.locator('#hg-public-target').evaluate('input => getComputedStyle(input,"::placeholder").color')==disabled_color
    wol=action_geometry(legacy('wol',fixtures[1]))
    assert all(abs(a-b)<=1 for a,b in zip(public,wol)) and abs(wol[0]-wol[1])<=1 and wol[2:]==[4,4],(public,wol)
    with_port={**fixtures[1],'services':[{**fixtures[1]['services'][0],'external_port':'8443','port_suffix':':8443',
                                      'https':'1','enabled':'0','cert_id':'cert_test'}]}
    def management_page(domains,saved='',wan='0'):
        response=json.dumps({'ok':True,'domains':domains})
        stub='<script>window.XHR={get:(u,f,cb)=>cb({status:200},u.endsWith("/management_domains")?'+response+':{})};</script>'
        page.set_content(stub+legacy('public',{**with_port,'main':{**with_port['main'],'management_domain':saved,'management_wan':wan}}))

    management_page([])
    selector=page.get_by_label('Router Management URL')
    management=page.get_by_label('Allow WAN Management')
    dirty=page.locator('#hg-public-dirty')
    assert selector.is_disabled() and management.is_disabled()
    assert selector.locator('option').text_content()=='No management domain available'
    assert page.locator('[name=management_domain]').count()==0
    management_page(['a.example.test','router.example.test'])
    assert selector.input_value()=='a.example.test' and management.is_enabled()
    assert selector.locator('option').all_text_contents()==['https://a.example.test','https://router.example.test']
    assert dirty.is_hidden()
    assert page.locator('[name=management_domain]').input_value()=='a.example.test'
    selector.select_option('router.example.test')
    assert not management.is_disabled() and dirty.is_visible()
    management_page(['a.example.test','router.example.test'],'router.example.test')
    assert selector.input_value()=='router.example.test'
    assert dirty.is_hidden()
    assert page.locator('[name=management_domain]').count()==0
    management_page(['a.example.test'],'router.example.test','1')
    assert selector.input_value()=='router.example.test' and management.is_checked()
    assert selector.locator('option').last.text_content()=='https://router.example.test'
    assert selector.locator('option').last.is_disabled()
    management.uncheck()
    assert management.is_disabled() and page.locator('[name=management_wan]').input_value()=='0'
    management_page(['router.example.test'])
    management_heading=page.get_by_role('heading',name='Router Management')
    y=management_heading.bounding_box()['y']
    assert page.get_by_role('heading',name='Access Restriction').bounding_box()['y']<y
    assert y<page.get_by_role('heading',name='Service List').bounding_box()['y']
    assert not management.is_checked()
    assert selector.input_value()=='router.example.test'
    assert selector.locator('option').count()==1 and dirty.is_hidden()
    assert selector.locator('option').text_content()=='https://router.example.test'
    assert page.locator('[name=management_domain]').input_value()=='router.example.test'
    assert page.get_by_role('columnheader',name='External URL').is_visible()
    assert page.get_by_role('columnheader',name='LAN URL').is_visible()
    management.check()
    assert page.locator('[name=management_domain]').input_value()=='router.example.test'
    assert page.locator('[name=management_wan]').input_value()=='1'
    management.uncheck()
    assert page.locator('[name=management_wan]').input_value()=='0'
    page.evaluate("hgPublicCerts.cert_test={exists:true,valid:true,days:89};hgPublicRender()")
    assert page.locator('.hg-public-url').text_content()=='https://test.example:8443'
    hint=page.locator('.hg-public-hint')
    assert hint.text_content().endswith(' · Not enabled') and '89' in hint.text_content()
    page.locator('.hg-web-enabled-check').check()
    assert not hint.text_content().endswith(' · Not enabled')
    page.locator('.hg-web-enabled-check').uncheck()
    assert hint.text_content().endswith(' · Not enabled')
    page.get_by_role('button',name='Edit',exact=True).click()
    public_port=page.locator('#hg-public-external-port')
    assert public_port.input_value()=='8443'
    assert public_port.evaluate("input => input.previousElementSibling.previousElementSibling.id")=='hg-public-host'
    page.locator('#hg-public-zone').evaluate("select => {select.add(new Option('example.test','example.test'));select.value='example.test';}")
    page.locator('#hg-public-host').fill('vault')
    public_port.fill('56813')
    address=page.locator('#hg-public-domain-preview')
    assert address.evaluate('value => value.previousElementSibling.textContent')=='External URL'
    assert page.get_by_label('LAN URL').is_visible()
    assert address.text_content()=='https://vault.example.test:56813'
    public_port.fill('')
    assert address.text_content()=='-'
    assert public_port.get_attribute('placeholder')=='Choose a port other than 80 or 443'
    public_port.fill('443')
    assert address.text_content()=='-'
    page.locator('#hg-public-https').uncheck()
    public_port.fill('80')
    assert address.text_content()=='-'
    public_port.fill('18080')
    assert address.text_content()=='http://vault.example.test:18080'
    page.get_by_role('button',name='Cancel',exact=True).click()
    assert page.locator('#hg-public-block-standard-ports, input[name=block_standard_public_ports]').count()==0
    assert not errors,errors
    browser.close()
(OUT/'results.json').write_text(json.dumps({'html_parity':parity,'transport':['submitter-mode','job-poll-ack','duplicate-suppression','dynamic-form'],'production_http':['delayed-maintenance-save','delayed-overview-save','delayed-overview-save-error','delayed-inline-start-success','delayed-inline-uncertain-start','delayed-inline-stop','network-independent-of-status-retry','status-unknown-clears-pid','account-save-modal-feedback']},indent=2),encoding='utf-8')
print('Native/Lua HTML parity: PASS (10); native transport: PASS (4); production HTTP: PASS (9)')

