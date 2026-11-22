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
                assert 'hg-zerossl-eab-modal' not in native
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
    assert add_host.is_disabled()
    page.evaluate('hgWolOpenAdd()')
    assert choice.is_hidden()
    page.get_by_role('button',name='Delete',exact=True).last.click()
    assert add_host.is_enabled()
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
    cancel_host.click()
    page.set_content(legacy('wol',{**fixtures[1],'wol_pending_add':'host_a'}))
    assert add_host.is_disabled()
    public_fixture={**data,'services':[{'web_id':'web_a','ddns_id':'rule_a','account_id':'dns_a','cert_id':'cert_a',
        'enabled':'1','https':'1','domain':'files.example.test','zone':'example.test','host':'files.example.test',
        'target':'https://255.255.255.255:999999','cert_environment':'staging'}],
        'dns_accounts':[{'id':'dns_a','label':'Existing','provider':'aliyun'}, {'id':'dns_b','label':'Other'}],
        'public_history':[{'account_id':'dns_a','zone':'example.test','host':'archived.example.test',
                           'external_port':'18083','target':'http://192.168.1.3','https':'0'}],
        'acme_ca_catalog':[{'name':'letsencrypt','display_name':"Let's Encrypt"}]}
    installed_views={f:installed['usr/lib/lua/luci/view/homegate_legacy/'+f+'.htm'].decode() for f in ('public','common')}
    public_html=legacy('public',public_fixture,installed_views)
    (OUT/'public-zones.html').write_text(public_html,encoding='utf-8')
    page.set_content('''<script>
    window.zones=[];window.hostQueries=[];
    window.XHR={get:(u,f,cb)=>{
      if(u.endsWith('/dns_zones')){
        if(f.zone){hostQueries.push({account:f.account,zone:f.zone,reply:cb});return;}
        zones.push({account:f.account,reply:cb});return;
      }
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
    assert hint.evaluate('node=>getComputedStyle(node).color')=='rgb(191, 191, 191)'
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
    account_notice=page.locator('#hg-public-account-result')
    host_toggle=page.get_by_role('button',name='Show host records')
    host_input=page.locator('#hg-public-host')
    port=page.locator('#hg-public-external-port')
    menu=page.locator('#hg-public-host-options')
    refresh_status=menu.locator('.hg-host-refresh-time')
    options=menu.get_by_role('button')
    port_top=port.bounding_box()['y']
    host_toggle.click()
    assert refresh_status.inner_text()=='Not yet refreshed'
    assert refresh_status.get_attribute('aria-disabled')=='true'
    assert refresh_status.evaluate('node=>getComputedStyle(node).color')=='rgb(191, 191, 191)'
    assert port.bounding_box()['y']==port_top,'Dropdown displaced the next field'
    host_box=host_input.bounding_box()
    picker_box=host_toggle.bounding_box()
    menu_box=menu.bounding_box()
    assert picker_box['x']>host_box['x']+host_box['width'],'Controls still joined'
    assert abs(picker_box['width']-picker_box['height'])<1,picker_box
    assert abs(picker_box['height']-host_box['height'])<1,(picker_box,host_box)
    assert abs(menu_box['x']-host_box['x'])<1,(menu_box,host_box)
    assert abs(menu_box['x']+menu_box['width']-picker_box['x']-picker_box['width'])<1,(menu_box,picker_box)
    assert abs(menu_box['y']-host_box['y']-host_box['height']-3)<1,(menu_box,host_box)
    chevron=host_toggle.evaluate('node=>getComputedStyle(node).backgroundPositionX')
    assert chevron=='calc(50% - 2px), calc(50% + 2px)',chevron
    options.first.hover()
    active_color=options.first.evaluate('node=>getComputedStyle(node).backgroundColor')
    red,green,blue=map(int,re.findall(r'\d+',active_color))
    assert blue>red and blue>green,active_color
    assert options.first.bounding_box()['width']>=menu_box['width']-3
    assert refresh_status.evaluate('node=>getComputedStyle(node).backgroundColor')!=active_color
    host_toggle.press('ArrowDown')
    assert options.first.evaluate('node=>node===document.activeElement')
    options.first.press('ArrowDown')
    assert options.nth(1).evaluate('node=>node===document.activeElement')
    assert options.nth(1).evaluate('node=>getComputedStyle(node).backgroundColor')==active_color
    options.nth(1).press('Escape')
    assert menu.is_hidden() and host_toggle.evaluate('node=>node===document.activeElement')
    assert page.evaluate('[zones.length,hostQueries.length]')==[0,0]
    assert account_notice.is_hidden()

    page.evaluate("hgPublicClose(); hgPublicOpenAdd()")
    assert page.locator('#hg-public-zone').input_value()=='example.test'
    assert page.evaluate('[zones.length,hostQueries.length]')==[0,0]
    refresh_account=page.get_by_role('button',name='Refresh Account',exact=True)
    assert refresh_account.is_enabled()
    assert page.get_by_role('button',name='Save Account',exact=True).is_disabled()
    host_input.fill('typed')
    port.fill('18084')
    page.locator('#hg-public-target').fill('http://192.168.1.5')
    page.evaluate('hgPublicConfirm()')
    assert 'before confirming' in account_notice.inner_text()
    refresh_account.click()
    assert 'hg-notice-pending' in account_notice.get_attribute('class')
    assert refresh_account.is_disabled()
    page.wait_for_timeout(3150)
    assert account_notice.is_visible() and account_notice.inner_text()=='Refreshing DNS account...'
    page.evaluate("zones[0].reply({status:200},{ok:true,zones:['aaa.test','example.test']})")
    assert page.locator('#hg-public-zone').input_value()=='example.test'
    assert page.locator('#hg-public-zone option').all_text_contents()==['aaa.test','example.test']
    assert page.evaluate('hostQueries.length')==1
    assert 'hg-notice-pending' in account_notice.get_attribute('class')
    page.evaluate("hostQueries[0].reply({status:200},{ok:true,hosts:['cloud','files']})")
    assert account_notice.inner_text()=='DNS account refreshed.'
    assert host_input.input_value()=='typed'
    host_toggle.click()
    timestamp=refresh_status.inner_text()
    assert re.fullmatch(r'Last refreshed \d{2}/\d{2} \d{2}:\d{2}',timestamp)
    assert options.locator('span').all_text_contents()==['Cloud and local','Cloud only','Local only']
    assert page.evaluate('[zones.length,hostQueries.length]')==[1,1]
    host_toggle.press('End')
    archived=options.filter(has_text='archived')
    assert archived.evaluate('node=>node===document.activeElement')
    archived.press('Enter')
    assert host_input.input_value()=='archived' and menu.is_hidden()
    history_choice = page.locator('#hg-public-history-choice')
    assert history_choice.locator('option').all_text_contents() == ['Select previous settings', '18083 ｜ http://192.168.1.3']
    history_choice.select_option('0')
    assert port.input_value()=='18083'
    assert page.locator('#hg-public-target').input_value()=='http://192.168.1.3'
    assert not page.locator('#hg-public-https').is_checked()
    account_notice.wait_for(state='hidden',timeout=5000)
    host_input.fill('typed')
    assert page.locator('#hg-public-history-choice').is_hidden()

    refresh_account.click()
    page.evaluate("zones[1].reply({status:200},{ok:true,zones:['example.test']})")
    page.evaluate("hostQueries[1].reply({status:200},{ok:false,error_kind:'busy'})")
    assert 'hg-notice-pending' in account_notice.get_attribute('class')
    page.wait_for_function('hostQueries.length===3')
    page.evaluate("hostQueries[2].reply({status:200},{ok:true,hosts:['cloud','files']})")
    assert account_notice.inner_text()=='DNS account refreshed.'
    assert host_input.input_value()=='typed'
    host_toggle.click()
    timestamp=refresh_status.inner_text()

    refresh_account.click()
    page.evaluate("zones[2].reply({status:200},{ok:true,zones:['example.test']})")
    page.evaluate("hostQueries[3].reply({status:200},{ok:false,error_kind:'busy'})")
    page.wait_for_function('hostQueries.length===5')
    page.evaluate("hostQueries[4].reply({status:200},{ok:false,error_kind:'busy'})")
    assert 'DNS account is busy' in account_notice.inner_text()
    assert host_input.input_value()=='typed'
    host_toggle.click()
    assert refresh_status.inner_text()==timestamp
    assert options.locator('span').all_text_contents()==['Cloud and local','Cloud only','Local only']
    page.wait_for_timeout(3150)
    assert account_notice.is_visible() and 'hg-notice-error' in account_notice.get_attribute('class')
    assert page.evaluate('[zones.length,hostQueries.length]')==[3,5]

    page.evaluate("hgPublicClose(); hgPublicOpenIndex(0)")
    assert account_notice.is_hidden()
    assert page.locator('#hg-public-zone').input_value()=='example.test'
    host_toggle.click()
    assert refresh_status.inner_text()==timestamp
    assert page.evaluate('[zones.length,hostQueries.length]')==[3,5]
    page.evaluate("hgPublicClose(); hgPublicOpenAdd();")
    page.locator('#hg-public-account').select_option('dns_b')
    assert page.locator('#hg-public-zone').input_value()==''
    assert page.evaluate('zones.length')==3
    refresh_account.click()
    page.evaluate("zones[3].reply({status:429,responseText:''},null)")
    assert account_notice.is_visible() and 'limited requests' in account_notice.inner_text()
    page.wait_for_timeout(1800)
    assert page.evaluate('zones.length')==4
    refresh_account.click()
    page.evaluate("zones[4].reply({status:200},{ok:true,zones:{}})")
    assert account_notice.inner_text()=='DNS account refreshed.'
    assert 'No managed primary domains' in page.locator('#hg-public-zone').inner_text()
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
    account_redirect=base+'/public?resume_public=add&resume_account=dns_saved&notice=saved'
    def account_response(route):
        path=route.request.url.split(base,1)[-1]
        if path.endswith('/homegate/native-operations.js'):
            route.fulfill(content_type='application/javascript',body=operations);return
        if path.startswith('/public') and not path.startswith('/public_account_apply'):
            fixture=fixtures[1]
            if '?resume_public=' in path:
                fixture={**fixture,'resume_public':'add','resume_account':'dns_saved','notice':'Saved DNS account',
                         'dns_accounts':[{'id':'dns_saved','label':'Saved Account','provider':'aliyun'}]}
            markup=legacy('public',fixture,templates)
            route.fulfill(content_type='text/html; charset=utf-8',body='<script>window.XHR={get:async(u,f,cb)=>{const r=await fetch(u);cb({status:r.status},await r.json())}};</script>'+markup);return
        if path=='/public_account_apply':
            account_requests.append(route.request.post_data)
            data={'ok':True,'pending':True,'job':'c'*32}
        elif path.startswith('/compat_job/'):
            data={'ok':True,'pending':not account_result,'result':account_result}
        elif path.startswith('/api/dns_zones'):
            data={'ok':True,'zones':['example.test'],'hosts':[]}
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
    assert page.locator('#hg-public-account-result').inner_text()=='Saving DNS account...'
    assert 'hg-notice-pending' in page.locator('#hg-public-account-result').get_attribute('class')
    assert len(account_requests)==1
    page.wait_for_timeout(3150)
    assert page.locator('#hg-public-account-result').is_visible()
    account_result={'ok':False,'error':'Account save failed in fixture'}
    page.locator('#hg-public-account-result').filter(has_text=account_result['error']).wait_for()
    assert account_save.is_enabled() and page.locator('#hg-operation-status').is_hidden()
    assert page.locator('#hg-public-key-id').input_value()=='fixture-key-id'
    account_result={'ok':True,'redirect':account_redirect}
    account_save.click()
    page.get_by_role('dialog',name='Add Public Service').wait_for(state='visible')
    page.wait_for_function("document.getElementById('hg-public-account').value==='dns_saved'")
    assert page.locator('#hg-public-account-result').inner_text()=='DNS account saved'
    assert page.locator('#hg-operation-status').is_hidden() and 'notice=' not in page.url
    assert len(account_requests)==2 and all('token=rpc' in body for body in account_requests)
    page.locator('#hg-public-account-result').wait_for(state='hidden',timeout=5000)
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
    stub='<script>window.confirm=()=>true;window.XHR={get:(u,f,cb)=>cb({status:200},u.endsWith("/dns_zones")?{ok:true,zones:["example.test"]}:{})};</script>'
    template=with_port['services'][0]
    router={**template,'domain':'router.example.test','zone':'example.test','host':'router','account_id':'dns_a'}
    companion={**router,'web_id':'web_b','external_port':'8444','port_suffix':':8444','https':'0','target':'http://192.168.1.3'}
    other={**router,'web_id':'web_c','domain':'other.example.test','host':'other','account_id':'dns_b',
           'external_port':'8445','port_suffix':':8445','target':'http://192.168.1.4'}
    router_services={**with_port,'services':[router,companion,other],
        'dns_accounts':[{'id':'dns_a','label':'Original account'},{'id':'dns_b','label':'Other account'}],
        'acme_ca_catalog':[{'name':'letsencrypt','display_name':"Let's Encrypt",'directories':{'production':'https://acme.test/'}}]}

    ready={'id':'ready','enabled':True,'valid':True,'identity_valid':True,'environment':'production','domains':['*.example.test']}
    def management_page(saved='',wan='0',certificates=(ready,),services=None):
        response=json.dumps({'ok':True,'certificates':certificates})
        routes=f'<script>window.fixtureCerts={response};</script>'+stub.replace(':{})',':u.endsWith("/certs")?window.fixtureCerts:{})')
        page.set_content(routes+legacy('public',{**router_services,'services':services or router_services['services'],
                                                'main':{**router_services['main'],'management_domain':saved,'management_wan':wan}}))

    management=page.get_by_label('Router Management Page')
    account=page.locator('#hg-public-account')
    selected=page.locator('[name=management_domain]')
    cancel=page.get_by_role('button',name='Cancel',exact=True)
    confirm=page.locator('#hg-public-modal button').filter(has_text='Confirm')
    bad=({**ready,'id':'expired','valid':False}, {**ready,'id':'wrong','identity_valid':False},
         {**ready,'id':'disabled','enabled':False}, {**ready,'id':'staging','environment':'staging'})
    management_page('router.example.test','1',bad)
    page.evaluate('hgPublicOpenIndex(0)')
    assert management.is_disabled() and not management.is_checked()
    assert selected.input_value()=='' and not page.locator('#hg-public-dirty').is_visible()
    cancel.click()
    page.evaluate('(cert)=>{window.fixtureCerts.certificates=[cert];hgPublicOpenIndex(0);}',ready)
    assert management.is_enabled() and not management.is_checked()
    cancel.click()

    management_page('router.example.test','0')
    page.evaluate('hgPublicOpenIndex(0)')
    assert management.is_enabled() and not management.is_checked()
    assert account.is_disabled() and account.input_value()=='dns_a'
    assert account.evaluate('e=>getComputedStyle(e).color')==disabled_color
    management.check()
    assert page.locator('#hg-public-management-url').text_content()=='https://router.example.test'
    confirm.click()
    assert selected.input_value()=='router.example.test'
    page.evaluate('hgPublicOpenIndex(1)')
    assert management.is_checked() and management.is_disabled() and not page.locator('#hg-public-https').is_checked()
    assert page.locator('#hg-public-management-url').is_visible()
    cancel.click()

    sibling={**companion,'domain':'sibling.example.test','host':'sibling'}
    management_page('router.example.test','0',services=[router,sibling,other])
    page.evaluate('hgPublicOpenIndex(1)')
    assert management.is_disabled() and not management.is_checked()
    cancel.click()

    management_page('router.example.test','1',services=[router,sibling,other])
    management_url=page.locator('#hg-public-management-url')
    https_toggle=page.locator('#hg-public-https')
    page.evaluate('hgPublicOpenIndex(1)')
    assert management.is_checked() and management.is_disabled() and not https_toggle.is_checked()
    assert management_url.is_visible() and management_url.text_content()=='https://router.example.test'
    https_toggle.check()
    assert management.is_enabled() and management.is_checked()
    assert management_url.text_content()=='https://router.example.test'
    confirm.click()
    assert selected.input_value()=='router.example.test'
    page.evaluate('hgPublicOpenIndex(1)')
    management.uncheck();confirm.click()
    assert selected.input_value()==''
    for index in (0,1,2):
        page.evaluate('(i)=>hgPublicOpenIndex(i)',index)
        assert management.is_enabled() and not management.is_checked() and not management_url.is_visible()
        cancel.click()

    management_page(certificates=({**ready,'domains':['other.example.test']},))
    page.evaluate('hgPublicOpenIndex(0)')
    assert management.is_disabled() and not management.is_checked()
    cancel.click()
    page.evaluate('hgPublicOpenIndex(2)')
    assert management.is_enabled() and not management.is_checked()
    cancel.click()

    management_page('router.example.test','1',certificates=({**ready,'domains':['router.example.test']},))
    page.evaluate('hgPublicOpenIndex(2)')
    assert management.is_disabled() and management.is_checked()
    assert page.locator('#hg-public-management-label').evaluate('e=>getComputedStyle(e).color')==disabled_color
    cancel.click()

    management_page('router.example.test','1')
    page.evaluate('hgPublicOpenIndex(2)')
    assert management.is_enabled() and management.is_checked()
    cancel.click()
    page.evaluate('hgPublicOpenAdd("dns_b")')
    page.locator('#hg-public-host').fill('router')
    assert management.is_checked() and account.is_disabled() and account.input_value()=='dns_a'
    cancel.click()
    page.evaluate('hgPublicDelete(0)')
    assert selected.input_value()==''
    page.evaluate('hgPublicDelete(0);hgPublicOpenIndex(0)')
    assert selected.input_value()=='' and management.is_enabled() and not management.is_checked()
    management.check();confirm.click()
    assert selected.input_value()=='other.example.test'

    management_page()
    page.evaluate('window.alert=(message)=>{window.lastPublicAlert=message;};hgPublicOpenIndex(2);')
    page.locator('#hg-public-external-port').fill('8443')
    confirm.click()
    assert page.evaluate('window.lastPublicAlert')=='This public port is already used by another service.'
    page.locator('#hg-public-external-port').fill('8445')
    page.locator('#hg-public-target').fill('http://192.168.1.2/')
    confirm.click()
    assert page.evaluate('window.lastPublicAlert')=='This LAN URL is already used by another service.'
    cancel.click()

    zerossl_services={**router_services,'services':[router],
        'acme_ca_catalog':[*router_services['acme_ca_catalog'],{'name':'zerossl','display_name':'ZeroSSL',
            'directories':{'production':'https://acme.zerossl.com/v2/DV90'}}]}
    kid=page.locator('#hg-public-eab-id');key=page.locator('#hg-public-eab-key')
    ca=page.locator('#hg-public-ca');https=page.locator('#hg-public-https')
    stage=page.locator('#hg-public-stage')
    page.set_content(stub+legacy('public',zerossl_services))
    page.evaluate('hgPublicOpenAdd("dns_a")')
    assert not kid.is_visible()
    ca.select_option('zerossl')
    assert kid.is_visible() and key.is_visible()
    assert not page.locator('#hg-public-eab-label, #hg-public-eab-status').count()
    assert kid.input_value()=='' and key.get_attribute('placeholder')==''
    cancel.click()
    page.evaluate('hgPublicOpenIndex(0)')
    https.check();ca.select_option('zerossl')
    confirm.click()
    assert page.locator('#hg-public-eab-error').is_visible()
    kid.fill('browser-test-id');key.fill('browser-test-hmac-123456')
    ca.select_option('letsencrypt')
    assert not kid.is_visible() and kid.input_value()=='' and key.input_value()==''
    ca.select_option('zerossl');https.uncheck()
    assert not kid.is_visible()
    https.check()
    kid.fill('browser-test-id');key.fill('browser-test-hmac-123456');confirm.click()
    assert page.locator('#hg-public-dirty').is_visible()
    assert stage.locator('[name=zerossl_eab_hmac]').count()==0
    page.evaluate('hgPublicSyncStage(true)')
    assert stage.locator('[name=zerossl_eab_hmac]').input_value()=='browser-test-hmac-123456'
    page.evaluate('hgPublicOpenIndex(0)')
    assert kid.input_value()=='browser-test-id' and key.is_visible() and key.input_value()==''
    assert key.get_attribute('placeholder')=='••••••••'
    cancel.click()

    page.set_content(stub+legacy('public',{**zerossl_services,'zerossl_eab_key_id':'stored-eab-id'}))
    page.evaluate('hgPublicOpenIndex(0)')
    https.check();ca.select_option('zerossl')
    assert kid.is_visible() and key.is_visible() and kid.input_value()=='stored-eab-id' and key.input_value()==''
    assert key.get_attribute('placeholder')=='••••••••'
    kid.fill('other-eab-id');confirm.click()
    assert page.locator('#hg-public-eab-error').is_visible() and key.get_attribute('placeholder')==''
    kid.fill('discarded-id');key.fill('discarded-hmac-123456');cancel.click()
    page.evaluate('hgPublicOpenAdd("dns_a")')
    assert not kid.is_visible() and not key.is_visible()
    cancel.click()
    page.evaluate('hgPublicOpenIndex(0)')
    https.check();ca.select_option('zerossl');confirm.click()
    page.evaluate('hgPublicSyncStage(true)')
    assert stage.locator('[name=zerossl_eab_hmac]').count()==0

    page.set_content(stub+legacy('public',with_port))
    assert page.get_by_role('columnheader',name='External URL').is_visible()
    assert page.get_by_role('columnheader',name='LAN URL').is_visible()
    assert page.locator('[name=management_wan]').input_value()=='0'
    page.evaluate("hgPublicCerts.cert_test={exists:true,valid:true,days:89};hgPublicRender()")
    assert page.locator('.hg-public-url').text_content()=='https://test.example:8443'
    hint=page.locator('.hg-public-hint')
    assert hint.text_content().endswith(' · Not enabled') and '89' in hint.text_content()
    page.evaluate('hgPublicCerts.cert_test.retry_at=Math.floor(Date.now()/1000)+1200;hgPublicRender()')
    assert 'Certificate request rate limited' in hint.text_content()
    assert not re.search(r'\d{1,2}:\d{2}:\d{2}',hint.text_content())
    assert page.locator('.hg-public-renew').is_disabled()
    page.evaluate('delete hgPublicCerts.cert_test.retry_at;hgPublicRender()')
    page.evaluate('hgPublicCerts.cert_test={exists:false,valid:false,retrying:true};hgPublicRender()')
    assert 'Certificate will be retried' in hint.text_content() and 'Certificate error' not in hint.text_content()
    page.evaluate('hgPublicCerts.cert_test={exists:false,valid:false,pending:true};hgPublicRender()')
    assert 'Certificate issuance in progress' in hint.text_content()
    page.evaluate('hgPublicCerts.cert_test={exists:true,valid:true,days:89};hgPublicRender()')
    page.locator('.hg-web-enabled-check').check()
    assert not hint.text_content().endswith(' · Not enabled')
    page.locator('.hg-web-enabled-check').uncheck()
    assert hint.text_content().endswith(' · Not enabled')
    page.get_by_role('button',name='Edit',exact=True).click()
    public_port=page.locator('#hg-public-external-port')
    assert public_port.input_value()=='8443'
    assert public_port.evaluate("input => Boolean(document.getElementById('hg-public-host').compareDocumentPosition(input) & Node.DOCUMENT_POSITION_FOLLOWING)")
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
    active_companion={**companion,'enabled':'1','ddns_id':'ddns_a'}
    grouped={**router_services,'services':[other,router,active_companion],'public_master_enabled':'0',
             'public_pending_add':active_companion['web_id']}
    page.set_content(stub+legacy('public',grouped))
    assert page.locator('.hg-public-url').all_text_contents()==[
        'http://router.example.test:8444','https://router.example.test:8443','https://other.example.test:8445']
    assert page.locator('.hg-public-hint').first.inner_text()=='HomeGate is disabled'
    assert page.locator('.hg-public-sync').first.is_disabled()
    assert page.get_by_role('button',name='Add',exact=True).is_disabled()
    urls=page.locator('.hg-public-url')
    before=urls.all_text_contents()
    check=page.locator('#hg-public-services input[type=checkbox]')
    check.nth(0).uncheck()
    check.nth(1).check()
    assert urls.all_text_contents()==before
    saved_only={**grouped,'public_applied_enabled':'','public_pending_add':''}
    page.set_content(stub+legacy('public',saved_only))
    assert urls.all_text_contents()==[
        'https://other.example.test:8445','https://router.example.test:8443','http://router.example.test:8444']
    applied={**grouped,'public_applied_enabled':router['web_id'],'public_pending_add':''}
    page.set_content(stub+legacy('public',applied))
    assert urls.all_text_contents()==[
        'https://router.example.test:8443','http://router.example.test:8444','https://other.example.test:8445']
    page.evaluate("document.getElementById('hg-public-access-allow-source').value=''")
    page.evaluate("document.getElementById('hg-public-access-deny-source').value=''")
    page.evaluate("window.hgPublicRecentRows=[{ip:'192.0.2.2',host:'other.example.test',allowed:true,reason:'disabled',current_region:'foreign',current_allowed:false,current_reason:'denied'}];hgPublicAccessRenderRecent()")
    page.evaluate("hgSetModalOpen('hg-public-access-modal',true)")
    access_row=page.locator('#hg-public-access-body tr').first
    assert access_row.locator('td').first.inner_text()=='Foreign · 192.0.2.2'
    assert access_row.locator('.hg-access-state').inner_text()=='Denied (Access Policy)'
    assert access_row.get_by_role('button',name='Allow Access',exact=True).count()==1
    page.evaluate("Object.assign(hgPublicRecentRows[0],{current_region:'',current_allowed:true,current_reason:'disabled'});hgPublicAccessRenderRecent()")
    assert access_row.locator('td').first.inner_text()=='192.0.2.2'
    assert access_row.locator('.hg-access-state').inner_text()=='Allowed (No Restriction)'
    assert access_row.get_by_role('button',name='Deny Access',exact=True).count()==1
    assert not errors,errors
    full_hosts=[{'id':f'wol_{i}','name':f'Host {i}','mac':f'02:11:22:33:44:{i:02X}'} for i in range(16)]
    full_services=[{**router,'web_id':f'web_{i}','external_port':str(48000+i)} for i in range(16)]
    for name,rows in (('wol',{'hosts':full_hosts}),('public',{'services':full_services})):
        page.set_content(stub+legacy(name,{**fixtures[0],**rows}))
        assert page.get_by_role('button',name='Add',exact=True).is_disabled()
        assert page.get_by_text('16-entry limit reached.',exact=True).is_visible()
    page.set_content(stub+legacy('maintenance',fixtures[0]))
    page.evaluate("window.confirm = message => { window.restoreMessage = message; return false; }")
    page.get_by_role('button',name='Restore Default Configuration',exact=True).click()
    assert 'certificates and keys' in page.evaluate('window.restoreMessage')
    assert not errors,errors
    browser.close()
(OUT/'results.json').write_text(json.dumps({'html_parity':parity,'transport':['submitter-mode','job-poll-ack','duplicate-suppression','dynamic-form'],'production_http':['delayed-maintenance-save','delayed-overview-save','delayed-overview-save-error','delayed-inline-start-success','delayed-inline-uncertain-start','delayed-inline-stop','network-independent-of-status-retry','status-unknown-clears-pid','account-save-modal-feedback']},indent=2),encoding='utf-8')
print('Native/Lua HTML parity: PASS (10); native transport: PASS (4); production HTTP: PASS (9)')

