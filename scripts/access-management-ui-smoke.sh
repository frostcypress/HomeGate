#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
PUBLIC="$ROOT/project/luci/lua/luasrc/view/homegate/public.htm"
OUT="$ROOT/build/access-management-ui-smoke"
rm -rf "$OUT"
mkdir -p "$OUT"
python3 - "$COMMON" "$PUBLIC" "$OUT/result.json" <<'PY'
from pathlib import Path
import json, shutil, sys
try:
    from playwright.sync_api import sync_playwright
except Exception:
    print('access management UI smoke: SKIP (python playwright not installed)')
    raise SystemExit(0)
common=Path(sys.argv[1]).read_text(); public=Path(sys.argv[2]).read_text(); out=Path(sys.argv[3])
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)), None)
if not chrome:
    print('access management UI smoke: SKIP (Chromium not installed)'); raise SystemExit(0)

def extract_function(text,name):
    needle='function '+name+'('
    start=text.find(needle)
    if start<0: raise SystemExit(name+' not found')
    brace=text.find('{',start); depth=0; quote=None; esc=False
    for i in range(brace,len(text)):
        ch=text[i]
        if quote:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch==quote: quote=None
        else:
            if ch in ('"',"'"): quote=ch
            elif ch=='{': depth+=1
            elif ch=='}':
                depth-=1
                if depth==0: return text[start:i+1]
    raise SystemExit(name+' closing brace not found')

names_common=['hgClearNode','hgCreateButton','hgAppendTableCell','hgTableMessage']
names_public=['hgPublicTrim','hgPublicAccessTokens','hgPublicAccessExactToken','hgPublicAccessTokenEqualsIp','hgPublicAccessHasExactIp','hgPublicAccessSyncRules','hgPublicAccessSetTokens','hgPublicAccessRemoveIp','hgPublicAccessRemoveToken','hgPublicAccessAddToken','hgPublicAccessFormatTime','hgPublicAccessRegionOptionLabel','hgPublicAccessGeoText','hgPublicAccessSourceText','hgPublicAccessScopeCoreLabel','hgPublicAccessBaseState','hgPublicAccessCurrentState','hgPublicAccessStateText','hgPublicAccessAllowIp','hgPublicAccessDenyIp','hgPublicAccessSummaries','hgPublicAccessRenderRecent']
js='\n'.join(extract_function(common,n) for n in names_common)+'\n'+'\n'.join(extract_function(public,n) for n in names_public)
# The production renderer contains LuCI-expanded POST route/token literals inside the delete callback.
# Replace only those template literals in the isolated browser harness; delete routing itself is
# asserted statically by ui-check/service lifecycle smoke.
js=js.replace("<%=url('admin/services/homegate/access_delete_rule')%>", '/access_delete_rule').replace("<%=pcdata(token)%>", 'test-token')
if '<%' in js: raise SystemExit('unexpected LuCI tag in extracted functions')
labels={
'hg-public-access-label-source':'来源','hg-public-access-label-domain':'域名','hg-public-access-label-result':'访问状态','hg-public-access-label-time':'时间','hg-public-access-label-actions':'操作',
'hg-public-recent-empty':'暂无访问记录。','hg-public-access-status-allowed-manual':'允许（手动放行）','hg-public-access-status-allowed-region':'允许（地区规则）','hg-public-access-status-allowed-disabled':'允许（未限制）',
'hg-public-access-status-denied-manual':'拒绝（手动拒绝）','hg-public-access-status-denied-region':'拒绝（地区规则）','hg-public-access-status-denied-list':'拒绝（名单限制）',
'hg-public-access-action-allow':'允许访问','hg-public-access-action-deny':'拒绝访问','hg-public-access-action-delete':'删除',
'hg-public-access-domestic':'国内','hg-public-access-abroad':'国外','hg-public-access-unknown':'未知'
}
label_html=''.join('<span id="%s">%s</span>'%(k,v) for k,v in labels.items())
doc=f'''<!doctype html><html><body>{label_html}
<input id="hg-public-access-allow-editor" type="hidden"><input id="hg-public-access-deny-editor" type="hidden">
<input id="hg-public-access-allow-source" type="hidden"><input id="hg-public-access-deny-source" type="hidden">
<select id="hg-public-access-scope"><option value="">不限地区</option><option value="__manual__">仅限名单</option><option value="CN" data-region-label="中国地区" data-region-core-label="China / Mainland">中国地区</option></select>
<table><tbody id="hg-public-access-body"></tbody></table>
<script>
function hgLabel(id){{var e=document.getElementById(id);return e?e.textContent:'';}}
function hgPublicRecomputeDirty(){{window.__dirty=(window.__dirty||0)+1;}}
function hgPublicSyncStage(){{window.__stage=(window.__stage||0)+1;}}
function hgPublicAccessRenderEmptyWarning(){{}}
function hgSubmitPost(url,token,data){{window.__posted={{url:url,data:data}};}}
function hgPublicAccessDeleteEntry(ip,host){{window.__deleted=[ip,host];}}
var hgPublicHasUnsaved=false;
var hgPublicRecentRows=[],hgPublicSavedAccessScope='',hgPublicSavedAccessAllow='',hgPublicSavedAccessDeny='';{js}
</script></body></html>'''
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True, executable_path=chrome, args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1100,'height':800}, timezone_id='Asia/Shanghai')
    page.set_content(doc,wait_until='load')
    result=page.evaluate('''() => {
      const allow=document.getElementById('hg-public-access-allow-editor'), deny=document.getElementById('hg-public-access-deny-editor'), scope=document.getElementById('hg-public-access-scope');
      allow.value='2409:895a::1/128, 192.0.2.0/24'; deny.value='198.51.100.0/24'; document.getElementById('hg-public-access-allow-source').value=allow.value; document.getElementById('hg-public-access-deny-source').value=deny.value; hgPublicSavedAccessScope='CN'; hgPublicSavedAccessAllow=allow.value; hgPublicSavedAccessDeny=deny.value;
      hgPublicRecentRows=[
        {time:'2026-09-08T16:12:54Z',ip:'2409:895a::1',host:'vault.example.com',geo:'CN-GD',current_allowed:true,current_reason:'ip',current_policy_mode:'region',current_region:'China / Mainland'},
        {time:'2026-09-08T16:10:00Z',ip:'2001:db8::2',host:'vault.example.com',geo:'FOREIGN',current_allowed:false,current_reason:'denied',current_policy_mode:'region'},
        {time:'2026-09-08T16:09:00Z',ip:'2409:895a::1',host:'vault.example.com',geo:'CN-GD',current_allowed:true,current_reason:'region',current_policy_mode:'region',current_region:'China / Mainland'}
      ];
      scope.value='CN'; hgPublicAccessRenderRecent();
      const snap=()=>Array.from(document.querySelectorAll('#hg-public-access-body tr')).map(tr=>({cells:Array.from(tr.children).map(td=>td.textContent),buttons:Array.from(tr.querySelectorAll('button')).map(b=>b.textContent)}));
      const initial=snap();
      document.querySelector('#hg-public-access-body tr button').click();
      const afterDeny=snap();
      document.querySelector('#hg-public-access-body tr button').click();
      const afterAllow=snap();
      scope.value=''; hgPublicAccessRenderRecent();
      const unrestrictedBefore=snap();
      const foreignRow=Array.from(document.querySelectorAll('#hg-public-access-body tr')).find(tr=>tr.children[0]&&tr.children[0].textContent.indexOf('2001:db8::2')>=0);
      foreignRow.querySelector('button').click();
      const unrestrictedDenied=snap();
      const foreignRow2=Array.from(document.querySelectorAll('#hg-public-access-body tr')).find(tr=>tr.children[0]&&tr.children[0].textContent.indexOf('2001:db8::2')>=0);
      foreignRow2.querySelector('button').click();
      const unrestrictedAllowed=snap();
      scope.value='__manual__'; hgPublicAccessRenderRecent();
      const listMode=snap();
      return {initial,afterDeny,afterAllow,unrestrictedBefore,unrestrictedDenied,unrestrictedAllowed,listMode,allow:allow.value,deny:deny.value,time:hgPublicAccessFormatTime('2026-09-08T16:12:54Z')};
    }''')
    browser.close()
fail=[]
initial=result['initial']
if len(initial)!=4: fail.append('one summary per IP+host plus unmatched allow/deny CIDR rows')
if initial[0]['cells'][0] != '国内 · 2409:895a::1': fail.append('geo merged into source')
if initial[0]['cells'][2] != '允许（手动放行）': fail.append('manual allow status')
if initial[0]['cells'][3] != '2026/9/9 00:12:54': fail.append('full local timestamp')
if initial[0]['buttons'] != ['拒绝访问','删除']: fail.append('allowed row opposite action + delete')
if initial[1]['cells'][2] != '拒绝（地区规则）' or initial[1]['buttons'] != ['允许访问','删除']: fail.append('region denied opposite action')
if result['afterDeny'][0]['cells'][2] != '拒绝（手动拒绝）' or result['afterDeny'][0]['buttons'][0] != '允许访问': fail.append('deny click flips state/action')
if result['afterAllow'][0]['cells'][2] != '允许（地区规则）' or result['afterAllow'][0]['buttons'][0] != '拒绝访问': fail.append('allow click returns to base region state')
# after staged switch to no restriction, foreign must be allowed despite saved current region-denied annotation
urow=next((r for r in result['unrestrictedBefore'] if '2001:db8::2' in r['cells'][0]),None)
if not urow or urow['cells'][2] != '允许（未限制）' or urow['buttons'][0] != '拒绝访问': fail.append('no-restriction staged state')
urow=next((r for r in result['unrestrictedDenied'] if '2001:db8::2' in r['cells'][0]),None)
if not urow or urow['cells'][2] != '拒绝（手动拒绝）' or urow['buttons'][0] != '允许访问': fail.append('no-restriction manual deny')
urow=next((r for r in result['unrestrictedAllowed'] if '2001:db8::2' in r['cells'][0]),None)
if not urow or urow['cells'][2] != '允许（未限制）' or urow['buttons'][0] != '拒绝访问': fail.append('remove deny restores no-restriction')
lrow=next((r for r in result['listMode'] if '2001:db8::2' in r['cells'][0]),None)
if not lrow or lrow['cells'][2] != '拒绝（名单限制）' or lrow['buttons'][0] != '允许访问': fail.append('allow-list restriction status')
# unmatched rule rows are visible in same unified table
manual=[r for r in initial if r['cells'][1]=='-']
if not any(r['cells'][0]=='192.0.2.0/24' and r['cells'][2]=='允许（手动放行）' and r['buttons']==['拒绝访问','删除'] for r in manual): fail.append('unmatched manual allow rule row')
if not any(r['cells'][0]=='198.51.100.0/24' and r['cells'][2]=='拒绝（手动拒绝）' and r['buttons']==['允许访问','删除'] for r in manual): fail.append('unmatched manual deny rule row')
if result['time']!='2026/9/9 00:12:54': fail.append('time formatter')
out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
if fail:
    print('access management UI smoke: FAIL:', ', '.join(fail)); print(json.dumps(result,ensure_ascii=False,indent=2)); raise SystemExit(1)
print('access management UI smoke: PASS')
PY
