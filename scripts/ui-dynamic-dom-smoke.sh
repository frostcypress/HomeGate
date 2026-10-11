#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
PUBLIC="$ROOT/project/luci/lua/luasrc/view/homegate/public.htm"
WOL="$ROOT/project/luci/lua/luasrc/view/homegate/wol.htm"
OUT="$ROOT/build/ui-dynamic-dom-smoke"
rm -rf "$OUT"
mkdir -p "$OUT"

python3 - "$COMMON" "$PUBLIC" "$WOL" "$OUT/result.txt" <<'PY'
from pathlib import Path
import json, re, shutil, sys
try:
    from playwright.sync_api import sync_playwright
except Exception:
    print('ui dynamic DOM smoke: SKIP (python playwright not installed)')
    raise SystemExit(0)

common=Path(sys.argv[1]).read_text()
public=Path(sys.argv[2]).read_text()
wol=Path(sys.argv[3]).read_text()
out=Path(sys.argv[4])
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)), None)
if not chrome:
    print('ui dynamic DOM smoke: SKIP (Chromium not installed)')
    raise SystemExit(0)

def extract_function(text, name):
    needle='function '+name+'('
    start=text.find(needle)
    if start < 0:
        raise SystemExit(name+' not found')
    brace=text.find('{', start)
    if brace < 0:
        raise SystemExit(name+' opening brace not found')
    depth=0
    quote=None
    esc=False
    i=brace
    while i < len(text):
        ch=text[i]
        if quote:
            if esc:
                esc=False
            elif ch=='\\':
                esc=True
            elif ch==quote:
                quote=None
        else:
            if ch in ('\"', "'"):
                quote=ch
            elif ch=='{':
                depth+=1
            elif ch=='}':
                depth-=1
                if depth==0:
                    return text[start:i+1]
        i+=1
    raise SystemExit(name+' closing brace not found')

common_names=['hgClearNode','hgAppendHidden','hgCreatePostForm','hgCreateButton','hgAppendTableCell','hgTableMessage']
common_js='\n'.join(extract_function(common,n) for n in common_names)
public_js='\n'.join([extract_function(public,'hgPublicTrim'), extract_function(public,'hgPublicAccessAddressText'), extract_function(public,'hgPublicRender')])
wol_js=extract_function(wol,'hgWolRender')
# Replace only the two LuCI-generated values used by the extracted WOL renderer.
wol_js=re.sub(r"<%=url\('admin/services/homegate/wol_action'\)%>", '/wol_action', wol_js)
wol_js=re.sub(r"<%=pcdata\(token\)%>", 'token-xyz', wol_js)
if '<%' in wol_js or '<%' in public_js:
    raise SystemExit('unexpected LuCI tag remains in extracted render function')

labels={
  'hg-public-label-empty':'No public services configured.',
  'hg-public-label-enabled':'Enabled','hg-public-label-address':'Access Address','hg-public-label-target':'LAN Target',
  'hg-public-label-yes':'Yes','hg-public-label-no':'No',
  'hg-public-label-actions':'Actions','hg-public-label-edit':'Edit','hg-public-label-sync':'Sync',
  'hg-public-label-renew':'Renew Certificate','hg-public-label-delete':'Delete',
  'hg-wol-label-empty':'No hosts.','hg-wol-label-name':'Name','hg-wol-label-mac':'MAC Address',
  'hg-wol-label-actions':'Actions','hg-wol-label-edit':'Edit','hg-wol-label-wake':'Wake','hg-wol-label-delete':'Delete'
}
label_html=''.join('<span id="%s">%s</span>'%(k,v) for k,v in labels.items())

doc=f'''<!doctype html><html><body>
{label_html}
<table><tbody id="hg-public-services"></tbody></table>
<table><tbody id="hg-wol-hosts"></tbody></table>
<script>
function hgLabel(id){{var e=document.getElementById(id);return e?e.textContent:'';}}
{common_js}
var hgPublicRows=[],hgPublicHasUnsaved=false;
function hgPublicSyncStage(){{}}
function hgPublicHintText(r){{return r.https?'Certificate 89 days':'';}}
function hgPublicRecomputeDirty(){{}}
function hgPublicOpenIndex(i){{window.__publicEdit=i;}}
function hgPublicPostAction(op,id){{window.__publicAction=[op,id];}}
function hgPublicDelete(i){{window.__publicDelete=i;}}
{public_js}
var hgWolRows=[],hgWolHasUnsaved=false;
function hgWolSyncStage(){{}}
function hgWolOpenIndex(i){{window.__wolEdit=i;}}
function hgWolDeleteIndex(i){{window.__wolDelete=i;}}
{wol_js}
</script>
</body></html>'''

with sync_playwright() as p:
    browser=p.chromium.launch(headless=True, executable_path=chrome, args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':390,'height':844})
    page.set_content(doc, wait_until='load')
    result=page.evaluate('''() => {
      hgPublicRows=[{enabled:true,domain:'home.example.com',target:'http://192.0.2.10:8080',https:true,ddns_id:'ddns1',cert_id:'cert1',dirty:false}];
      hgPublicHasUnsaved=false; hgPublicRender();
      const pr=document.querySelector('#hg-public-services tr');
      const pc=Array.from(pr.children);
      const pbuttons=Array.from(pr.querySelectorAll('button')).map(b=>({cls:b.className,disabled:b.disabled,type:b.type,text:b.textContent}));
      const pcheck=pr.querySelector('input[type=checkbox]');
      const publicRow={rowClass:pr.className,cells:pc.length,labels:pc.map(td=>td.getAttribute('data-label')),check:[pcheck.checked,pcheck.getAttribute('aria-label')],buttons:pbuttons,address:pc[1].textContent};
      hgPublicRows=[{enabled:true,domain:'plain.example.com',target:'http://192.0.2.11:8080',https:false,ddns_id:'ddns2',cert_id:'',cert_source:'auto',dirty:false}]; hgPublicRender();
      const httpButtons=Array.from(document.querySelectorAll('#hg-public-services button')).map(b=>b.textContent);
      hgPublicRows=[{enabled:true,domain:'local.example.com',target:'http://192.0.2.12:8080',https:true,ddns_id:'ddns3',cert_id:'cert-local',cert_source:'local',dirty:false}]; hgPublicRender();
      const localButtons=Array.from(document.querySelectorAll('#hg-public-services button')).map(b=>b.textContent);
      hgPublicRows=[]; hgPublicRender();
      const pem=document.querySelector('#hg-public-services td');
      const publicEmpty=[document.querySelectorAll('#hg-public-services tr').length,pem.colSpan,pem.className,pem.textContent];

      hgWolRows=[{id:'host1',name:'NAS',mac:'AA:BB:CC:DD:EE:FF',dirty:false}];hgWolHasUnsaved=false;hgWolRender();
      const wr=document.querySelector('#hg-wol-hosts tr');
      const wc=Array.from(wr.children);
      const wf=wr.querySelector('form.hg-wol-wake-form');
      const wfields={};Array.from(wf.elements).forEach(e=>{if(e.name)wfields[e.name]=e.value;});
      const wbuttons=Array.from(wr.querySelectorAll('button')).map(b=>({cls:b.className,disabled:b.disabled,type:b.type,text:b.textContent}));
      const wolRow={rowClass:wr.className,cellClasses:wc.map(td=>td.className),labels:wc.map(td=>td.getAttribute('data-label')),group:!!wr.querySelector('.hg-wol-actions-group'),form:[wf.method.toLowerCase(),wf.getAttribute('action'),wf.className,wfields],buttons:wbuttons};
      hgWolHasUnsaved=true;hgWolRender();
      const disabledWake=Array.from(document.querySelectorAll('#hg-wol-hosts button')).find(b=>b.textContent==='Wake');
      const wolDisabled=[disabledWake.type,disabledWake.disabled,!!document.querySelector('#hg-wol-hosts form.hg-wol-wake-form')];
      hgWolRows=[];hgWolHasUnsaved=false;hgWolRender();
      const wem=document.querySelector('#hg-wol-hosts td');
      const wolEmpty=[document.querySelectorAll('#hg-wol-hosts tr').length,wem.colSpan,wem.className,wem.textContent];
      return {publicRow,httpButtons,localButtons,publicEmpty,wolRow,wolDisabled,wolEmpty};
    }''')
    browser.close()

fail=[]
pr=result['publicRow']
if pr['rowClass']!='hg-public-row' or pr['cells']!=4: fail.append('public row structure')
if pr['labels']!=['Enabled','Access Address','LAN Target','Actions']: fail.append('public data-label parity')
if pr['check']!=[True,'Enabled']: fail.append('public checkbox aria')
if [b['cls'] for b in pr['buttons']]!=['cbi-button hg-btn-4 hg-public-edit','cbi-button hg-btn-4 hg-public-sync','cbi-button hg-btn-4 hg-public-renew','cbi-button hg-btn-4 hg-public-delete']: fail.append('public action classes')
if any(b['type']!='button' for b in pr['buttons']) or any(b['disabled'] for b in pr['buttons']): fail.append('public action state')
if pr['address']!='https://home.example.com（Certificate 89 days）': fail.append('public access address')
if result['httpButtons']!=['Edit','Sync','Delete']: fail.append('http actions must collapse without renew slot')
if result['localButtons']!=['Edit','Sync','Delete']: fail.append('local-cert actions must collapse without renew slot')
if result['publicEmpty']!=[1,4,'hg-table-message hg-muted','No public services configured.']: fail.append('public empty row')
wr=result['wolRow']
if wr['rowClass']!='hg-wol-row': fail.append('wol row class')
if wr['cellClasses']!=['hg-wol-name','hg-wol-mac','hg-actions hg-action-cell']: fail.append('wol cell classes')
if wr['labels']!=['Name','MAC Address','Actions'] or not wr['group']: fail.append('wol data-label/group')
if wr['form']!=['post','/wol_action','hg-wol-wake-form',{'token':'token-xyz','op':'wake','id':'host1'}]: fail.append('wol wake post form')
if [b['cls'] for b in wr['buttons']]!=['cbi-button hg-btn-4 hg-wol-edit','cbi-button hg-btn-4','cbi-button hg-btn-4 hg-wol-delete']: fail.append('wol action classes')
if [b['type'] for b in wr['buttons']]!=['button','submit','button']: fail.append('wol button types')
if result['wolDisabled']!=['button',True,False]: fail.append('wol staged wake disabled')
if result['wolEmpty']!=[1,3,'hg-table-message hg-muted','No hosts.']: fail.append('wol empty row')
out.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
if fail:
    print('ui dynamic DOM smoke: FAIL:', ', '.join(fail)); print(json.dumps(result,ensure_ascii=False,indent=2)); raise SystemExit(1)
print('ui dynamic DOM smoke:', json.dumps(result,ensure_ascii=False,sort_keys=True))
print('ui dynamic DOM smoke: PASS')
PY
