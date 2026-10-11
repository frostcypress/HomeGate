#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
OUT="$ROOT/build/access-desktop-geometry-smoke"
rm -rf "$OUT"; mkdir -p "$OUT"
python3 - "$COMMON" "$OUT/result.txt" <<'PY'
from pathlib import Path
import re, shutil, sys
try:
    from playwright.sync_api import sync_playwright
except Exception:
    print('access desktop geometry smoke: SKIP (python playwright not installed)'); raise SystemExit(0)
common=Path(sys.argv[1]).read_text(); m=re.search(r'<style type="text/css">(.*?)</style>',common,re.S)
if not m: raise SystemExit('common style block not found')
css=m.group(1)
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)),None)
if not chrome:
    print('access desktop geometry smoke: SKIP (Chromium not installed)'); raise SystemExit(0)
html=f'''<!doctype html><html lang="zh-CN" class="hg-theme-foundation hg-theme-boot"><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{{margin:0;padding:0}}body{{padding:30px}}.cbi-button{{box-sizing:border-box;min-width:68px;height:28px;padding:0 8px}}</style><style>{css}</style><style>
/* Hostile LuCI theme loaded after HomeGate: this used to break the real router. */
.hg-table th,.hg-table td{{padding:7px 14px;border-bottom:1px solid #999!important}}
.hg-modal-head{{padding-left:11px;padding-right:17px}}
.hg-modal-head h3{{margin-left:13px!important;padding-left:19px!important;text-indent:5px!important}}
.hg-modal-actions{{padding-right:23px}}
</style></head><body>
<div class="hg-modal hg-access-modal" id="modal">
  <div class="hg-modal-head hg-access-toolbar" id="toolbar">
    <div class="hg-access-title" id="title">访问管理</div>
    <div class="hg-access-toolbar-actions" id="toolbarActions"><button class="cbi-button hg-btn-4">添加规则</button><button id="clearAll" class="cbi-button hg-btn-4">清除全部</button></div>
  </div>
  <div class="hg-access-table-wrap hg-access-table-scroll" id="wrap">
    <table class="hg-table hg-access-table" id="table">
      <colgroup><col/><col style="width:145px"/><col style="width:150px"/><col style="width:170px"/><col class="hg-access-actions-col"/></colgroup>
      <thead><tr><th id="sourceHead">来源</th><th>域名</th><th>访问状态</th><th>时间</th><th id="actionHead" class="hg-action-head hg-access-action-head">操作</th></tr></thead>
      <tbody><tr id="row"><td class="hg-access-source" id="sourceCell">广东省 · 2408:8459:4ef0:69ff:84a1:82ff:fe54:acf2</td><td>vault.chenos.cn</td><td>允许（地区规则）</td><td class="hg-access-time">2026/9/9 00:12:54</td><td class="hg-action-cell hg-access-action" id="actionCell"><div class="hg-action-group hg-access-action-group"><button id="firstRowButton" class="cbi-button hg-btn-4">拒绝访问</button><button id="lastRowButton" class="cbi-button hg-btn-4">清除记录</button></div></td></tr></tbody>
    </table>
  </div>
  <div class="hg-modal-actions hg-access-footer" id="footer"><button id="closeButton" class="cbi-button hg-btn-4">关闭</button></div>
</div></body></html>'''
def near(a,b,tol=1.1): return abs(a-b)<=tol
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,executable_path=chrome,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1400,'height':700}); page.set_content(html,wait_until='load')
    r=page.evaluate('''() => {
      const q=id=>document.getElementById(id), R=id=>q(id).getBoundingClientRect();
      const sh=q('sourceHead'), sc=q('sourceCell'), ac=q('actionCell');
      const css=e=>getComputedStyle(e), num=(v)=>parseFloat(v)||0;
      return {
        modal:[q('modal').clientWidth,q('modal').scrollWidth],wrap:[q('wrap').clientWidth,q('wrap').scrollWidth,css(q('wrap')).overflowX],table:[q('table').clientWidth,q('table').scrollWidth],
        titleLeft:R('title').left,headerTextLeft:R('sourceHead').left+num(css(sh).paddingLeft),firstTextLeft:R('sourceCell').left+num(css(sc).paddingLeft),
        clearRight:R('clearAll').right,rowRight:R('lastRowButton').right,closeRight:R('closeButton').right,tableRight:R('table').right-num(css(ac).paddingRight),actionHeadLeft:R('actionHead').left+num(css(q('actionHead')).paddingLeft),firstActionLeft:R('firstRowButton').left,
        borders:[css(sh).borderBottomWidth,css(sc).borderBottomWidth,css(q('row')).borderBottomWidth],
        titleTag:q('title').tagName,timeWS:css(document.querySelector('.hg-access-time')).whiteSpace,actionsWidth:R('actionCell').width,actionsScroll:q('actionCell').scrollWidth
      };
    }''')
    browser.close()
fail=[]
if r['modal'][1]>r['modal'][0]+1: fail.append('modal horizontal overflow')
if r['wrap'][1]>r['wrap'][0]+1: fail.append('wrapper horizontal overflow')
if r['table'][1]>r['table'][0]+1: fail.append('table horizontal overflow')
if r['wrap'][2] != 'hidden': fail.append('wrapper overflow-x')
if not near(r['titleLeft'],r['headerTextLeft']) or not near(r['titleLeft'],r['firstTextLeft']): fail.append('shared left content edge')
if not near(r['actionHeadLeft'],r['firstActionLeft']): fail.append('Actions/first-action left alignment')
if not near(r['clearRight'],r['rowRight']) or not near(r['clearRight'],r['closeRight']) or not near(r['clearRight'],r['tableRight']): fail.append('shared right content edge')
if any(float(x[:-2] or 0)>0.1 for x in r['borders'] if x.endswith('px')): fail.append('separator lines survived hostile theme')
if r['titleTag']=='H3': fail.append('access title still host-theme h3')
if r['timeWS']!='nowrap': fail.append('full timestamp wraps')
if r['actionsScroll']>r['actionsWidth']+1: fail.append('two row actions overflow')
Path(sys.argv[2]).write_text(repr(r)+'\n')
if fail:
    print('access desktop geometry smoke: FAIL:',', '.join(fail)); print(r); raise SystemExit(1)
print('access desktop geometry smoke:',r); print('access desktop geometry smoke: PASS')
PY
