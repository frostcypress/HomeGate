#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
OUT="$ROOT/build/ui-common-helper-smoke"
rm -rf "$OUT"
mkdir -p "$OUT"

python3 - "$COMMON" "$OUT/result.txt" <<'PY'
from pathlib import Path
import html, re, shutil, sys
try:
    from playwright.sync_api import sync_playwright
except Exception:
    print('ui common helper smoke: SKIP (python playwright not installed)')
    raise SystemExit(0)
common=Path(sys.argv[1]).read_text()
m=re.search(r'<script type="text/javascript">(.*?)</script>', common, re.S)
if not m:
    raise SystemExit('common script block not found')
script=m.group(1)
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)), None)
if not chrome:
    print('ui common helper smoke: SKIP (Chromium not installed)')
    raise SystemExit(0)

doc=f'''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body>
<div id="label">标签文本</div>
<div id="box"><span>a</span><span>b</span></div>
<div id="log">old</div>
<table><tbody id="table-body"><tr><td>old</td></tr></tbody></table>
<div id="modal" class="hg-modal-backdrop" aria-hidden="true"><div class="hg-modal">x</div></div>
<script>
window.__submitted=null;
window.XHR={{get:function(url,params,cb){{cb({{responseText:'runtime-log'}});}}}};
HTMLFormElement.prototype.submit=function(){{
  var fields={{}};
  for(var i=0;i<this.elements.length;i++){{var e=this.elements[i];if(e.name)fields[e.name]=e.value;}}
  window.__submitted={{action:this.getAttribute('action')||'',method:(this.method||'').toLowerCase(),fields:fields}};
}};
</script>
<script>{script}</script>
</body></html>'''

with sync_playwright() as p:
    browser=p.chromium.launch(headless=True, executable_path=chrome, args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':390,'height':844})
    page.set_content(doc, wait_until='load')
    result=page.evaluate('''() => {
      const label=hgLabel('label');
      const cleared=hgClearNode('box');
      const scratch=document.createElement('form');
      hgAppendHidden(scratch,'alpha',123);
      const fields=Object.create({inherited:'no'}); fields.good='yes'; fields.zero=0;
      const postForm=hgCreatePostForm('/wake','token-456',{op:'wake',id:7},'wake-form');
      const postFields={}; for(let i=0;i<postForm.elements.length;i++){const e=postForm.elements[i];if(e.name)postFields[e.name]=e.value;}
      let clicked=0;
      const button=hgCreateButton('Edit','cbi-button hg-btn-4 hg-edit',function(){clicked++;},{title:'edit-title'});button.click();
      const disabledButton=hgCreateButton('Wake','cbi-button hg-btn-4',null,{type:'submit',disabled:true});
      const row=document.createElement('tr'); const tableCell=hgAppendTableCell(row,'value','Label','cell-x');
      const msg=hgTableMessage('table-body',5,'Loading','hg-muted');
      const msgCell=document.querySelector('#table-body td');
      hgSubmitPost('/action','token-123',fields);
      const submitted=window.__submitted;
      const opened=hgSetModalOpen('modal',true);
      const modal=document.getElementById('modal');
      const openState=[opened,modal.classList.contains('hg-open'),modal.getAttribute('aria-hidden')];
      hgModalBackdrop({target:modal,currentTarget:modal});
      const closeState=[modal.classList.contains('hg-open'),modal.getAttribute('aria-hidden')];
      hgLoadText('/logs','log');
      return {
        label:label,
        clear:[!!cleared,document.getElementById('box').childNodes.length],
        hidden:[scratch.elements.length,scratch.elements[0]&&scratch.elements[0].name,scratch.elements[0]&&scratch.elements[0].value],
        postForm:[postForm.method.toLowerCase(),postForm.getAttribute('action'),postForm.className,postFields],
        button:[button.type,button.className,button.textContent,button.title,clicked,disabledButton.type,disabledButton.disabled],
        tableCell:[row.children.length,tableCell.textContent,tableCell.getAttribute('data-label'),tableCell.className],
        tableMessage:[!!msg,document.getElementById('table-body').children.length,msgCell&&msgCell.colSpan,msgCell&&msgCell.textContent,msgCell&&msgCell.className],
        submitted:submitted,
        openState:openState,
        closeState:closeState,
        log:document.getElementById('log').textContent
      };
    }''')
    browser.close()

fail=[]
if result['label']!='标签文本': fail.append('hgLabel')
if result['clear']!=[True,0]: fail.append('hgClearNode')
if result['hidden']!=[1,'alpha','123']: fail.append('hgAppendHidden')
if result['postForm']!=['post','/wake','wake-form',{'token':'token-456','op':'wake','id':'7'}]: fail.append('hgCreatePostForm')
if result['button']!=['button','cbi-button hg-btn-4 hg-edit','Edit','edit-title',1,'submit',True]: fail.append('hgCreateButton')
if result['tableCell']!=[1,'value','Label','cell-x']: fail.append('hgAppendTableCell')
if result['tableMessage']!=[True,1,5,'Loading','hg-table-message hg-muted']: fail.append('hgTableMessage')
sub=result['submitted'] or {}
if sub.get('method')!='post' or sub.get('fields')!={'token':'token-123','good':'yes','zero':'0'} or 'inherited' in sub.get('fields',{}): fail.append('hgSubmitPost')
if result['openState']!=[True,True,'false'] or result['closeState']!=[False,'true']: fail.append('modal helpers')
if result['log']!='runtime-log': fail.append('hgLoadText')
Path(sys.argv[2]).write_text(repr(result)+'\n')
if fail:
    print('ui common helper smoke: FAIL:', ', '.join(fail)); print(result); raise SystemExit(1)
print('ui common helper smoke:', result)
print('ui common helper smoke: PASS')
PY
