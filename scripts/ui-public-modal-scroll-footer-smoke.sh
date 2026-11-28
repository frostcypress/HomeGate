#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
PUBLIC="$ROOT/project/luci/lua/luasrc/view/homegate/public.htm"
OUT="$ROOT/build/public-modal-scroll-footer-smoke"
rm -rf "$OUT"; mkdir -p "$OUT"

# Static structure: the Public Service form scrolls, while Cancel/Confirm live outside it.
grep -Fq 'class="hg-public-service-scroll" id="hg-public-service-scroll"' "$PUBLIC"
grep -Fq 'class="hg-modal-actions hg-public-service-footer"' "$PUBLIC"
grep -Fq '.hg-public-service-modal > .hg-public-service-footer { flex: 0 0 auto; }' "$COMMON"
grep -Fq 'overflow: hidden;' "$COMMON"
grep -Fq 'height: var(--hg-control-height) !important;' "$COMMON"

python3 - "$COMMON" "$OUT/result.txt" <<'PY'
from pathlib import Path
import re, shutil, sys
try:
    from playwright.sync_api import sync_playwright
except Exception:
    print('public modal scroll footer smoke: SKIP (python playwright not installed)')
    raise SystemExit(0)

common=Path(sys.argv[1]).read_text()
m=re.search(r'<style type="text/css">(.*?)</style>', common, re.S)
if not m: raise SystemExit('common style block not found')
css=m.group(1)
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)),None)
if not chrome:
    print('public modal scroll footer smoke: SKIP (Chromium not installed)')
    raise SystemExit(0)

host='''
html,body{margin:0;padding:0;width:100%;height:100%;font-family:sans-serif}
/* Simulate a hostile host theme that changes button vertical metrics on interaction. */
button.cbi-button:hover,button.cbi-button:focus,button.cbi-button:active{
  height:52px!important;min-height:52px!important;max-height:52px!important;
  padding-top:12px!important;padding-bottom:12px!important;
  position:relative!important;top:2px!important;transform:translateY(2px)!important;
}
'''

def make_html(rows):
    fields=''.join(f'<label>字段{i}</label><input class="hg-control" value="value-{i}">' for i in range(rows))
    return f'''<!doctype html><html lang="zh-CN" class="hg-theme-foundation hg-theme-design"><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>{host}</style><style>{css}</style></head><body>
<div class="hg-modal-backdrop hg-open"><div class="hg-modal hg-public-service-modal" id="modal" style="--hg-modal-vh:620px" role="dialog">
  <div class="hg-public-service-scroll" id="scroll">
    <div class="hg-modal-head"><h3>添加公网服务</h3></div>
    <div class="hg-modal-grid">{fields}</div>
    <div class="hg-field-note hg-modal-footnote">脚注</div>
  </div>
  <div class="hg-modal-actions hg-public-service-footer" id="footer">
    <button class="cbi-button hg-btn-4" id="cancel">取消</button>
    <button class="cbi-button cbi-button-save hg-btn-4" id="confirm">确定</button>
  </div>
</div></div></body></html>'''

def rect(page, id):
    return page.evaluate("id=>{const r=document.getElementById(id).getBoundingClientRect();return {left:r.left,top:r.top,width:r.width,height:r.height,right:r.right,bottom:r.bottom}}",id)

def near(a,b,tol=.75): return abs(a-b)<=tol

def geom_same(a,b):
    return all(near(a[k],b[k]) for k in ('left','top','width','height','right','bottom'))

results={}; fail=[]
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True, executable_path=chrome, args=['--no-sandbox'])
    for name,rows,viewport in [('short-desktop',4,{'width':1200,'height':700}),('long-desktop',34,{'width':1200,'height':700}),('long-mobile',34,{'width':390,'height':700})]:
        page=browser.new_page(viewport=viewport)
        page.set_content(make_html(rows),wait_until='load')
        metrics=page.evaluate('''() => {
          const s=document.getElementById('scroll'),m=document.getElementById('modal'),f=document.getElementById('footer');
          return {scroll:[s.clientHeight,s.scrollHeight,getComputedStyle(s).overflowY],modalOverflow:getComputedStyle(m).overflowY,footerParent:f.parentElement.id,scrollParent:s.parentElement.id};
        }''')
        if name.startswith('long'):
            page.evaluate("()=>{const s=document.getElementById('scroll');s.scrollTop=s.scrollHeight}")
            page.wait_for_timeout(50)
        base={i:rect(page,i) for i in ('modal','scroll','footer','cancel','confirm')}
        scroll0=page.evaluate("()=>{const s=document.getElementById('scroll');return {top:s.scrollTop,max:s.scrollHeight-s.clientHeight}}")
        page.hover('#cancel'); page.wait_for_timeout(80)
        cancel_hover={i:rect(page,i) for i in ('modal','scroll','footer','cancel','confirm')}
        scroll1=page.evaluate("()=>document.getElementById('scroll').scrollTop")
        page.mouse.move(5,5); page.evaluate("()=>document.activeElement&&document.activeElement.blur&&document.activeElement.blur()")
        page.hover('#confirm'); page.wait_for_timeout(80)
        confirm_hover={i:rect(page,i) for i in ('modal','scroll','footer','cancel','confirm')}
        scroll2=page.evaluate("()=>document.getElementById('scroll').scrollTop")
        results[name]={'metrics':metrics,'base':base,'cancel':cancel_hover,'confirm':confirm_hover,'scroll':[scroll0,scroll1,scroll2]}
        if metrics['modalOverflow'] not in ('hidden','clip'): fail.append(name+' modal shell is still scrollable')
        if name.startswith('short') and metrics['scroll'][1] > metrics['scroll'][0] + 1: fail.append('short form unexpectedly scrolls')
        if name.startswith('long') and metrics['scroll'][1] <= metrics['scroll'][0] + 1: fail.append('long form did not create inner scrollbar')
        for state,data in [('cancel-hover',cancel_hover),('confirm-hover',confirm_hover)]:
            for item in ('footer','cancel','confirm'):
                if not geom_same(base[item],data[item]): fail.append(f'{name} {state} changed {item} geometry')
        if name.startswith('long'):
            if abs(scroll0['top']-scroll0['max'])>1: fail.append('long form not at scroll bottom before hover')
            if abs(scroll1-scroll0['top'])>1 or abs(scroll2-scroll0['top'])>1: fail.append('hover changed inner scrollTop at bottom')
            # Fixed footer must remain below the inner scroll viewport, not inside its moving content.
            if base['footer']['top'] < base['scroll']['bottom'] - 1: fail.append('footer overlaps/participates in scroll viewport')
        page.close()
    browser.close()
Path(sys.argv[2]).write_text(repr(results)+'\n')
if fail:
    print('public modal scroll footer smoke: FAIL:', ', '.join(fail)); print(results); raise SystemExit(1)
print('public modal scroll footer smoke:', results)
print('public modal scroll footer smoke: PASS')
PY
