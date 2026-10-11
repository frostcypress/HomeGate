#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
OUT="$ROOT/build/public-desktop-geometry-smoke"
rm -rf "$OUT"; mkdir -p "$OUT"
python3 - "$COMMON" "$OUT/result.txt" <<'PY'
from pathlib import Path
import re, shutil, sys
try:
    from playwright.sync_api import sync_playwright
except Exception:
    print('public desktop geometry smoke: SKIP (python playwright not installed)'); raise SystemExit(0)
common=Path(sys.argv[1]).read_text(); m=re.search(r'<style type="text/css">(.*?)</style>',common,re.S)
if not m: raise SystemExit('common style block not found')
css=m.group(1)
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)),None)
if not chrome:
    print('public desktop geometry smoke: SKIP (Chromium not installed)'); raise SystemExit(0)
longaddr='https://this-is-a-very-long-service-name-that-must-never-be-ellipsized.home.chenos.cn（证书剩余 89 天）'
html=f'''<!doctype html><html lang="zh-CN" class="hg-theme-foundation hg-theme-boot"><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{{margin:0;padding:0}}#fixture{{width:820px}}.cbi-button{{height:28px;box-sizing:border-box}}</style><style>{css}</style></head><body>
<div class="hg-wrap" id="fixture"><div class="hg-table-scroll-wrap hg-public-list-wrap"><table class="hg-table hg-public-table" id="table">
<thead><tr><th>启用</th><th>访问地址</th><th>内网目标</th><th id="actionsHead" class="hg-action-head hg-public-action-head">操作</th></tr></thead>
<tbody><tr class="hg-public-row"><td><input type="checkbox"></td><td class="hg-public-address" id="address">{longaddr}</td><td id="target">http://192.168.2.5</td><td class="hg-actions hg-action-cell hg-action-group" id="actions"><button id="edit" class="cbi-button hg-btn-4">编辑</button><button class="cbi-button hg-btn-4">同步</button><button class="cbi-button hg-btn-4">续期</button><button id="delete" class="cbi-button hg-btn-4">删除</button></td></tr></tbody>
</table></div></div></body></html>'''
def near(a,b,tol=1.1): return abs(a-b)<=tol
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,executable_path=chrome,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1050,'height':520}); page.set_content(html,wait_until='load')
    r=page.evaluate('''() => {const q=id=>document.getElementById(id),R=id=>q(id).getBoundingClientRect(),cs=id=>getComputedStyle(q(id)); const range=document.createRange();range.selectNodeContents(q('address'));const rects=Array.from(range.getClientRects()).filter(x=>x.width>0&&x.height>0);const hp=parseFloat(cs('actionsHead').paddingLeft)||0;return {table:[q('table').clientWidth,q('table').scrollWidth],headerLeft:R('actionsHead').left+hp,editLeft:R('edit').left,deleteRight:R('delete').right,actionRight:R('actions').right,address:[R('address').width,R('address').height,rects.length,cs('address').textOverflow,cs('address').whiteSpace,cs('address').overflowWrap],targetWidth:R('target').width,actionGap:cs('actions').gap};}''')
    browser.close()
fail=[]
if not near(r['headerLeft'],r['editLeft']): fail.append('Actions/Edit left alignment')
if r['deleteRight']>r['actionRight']+1: fail.append('action overflow')
if r['table'][1]>r['table'][0]+1: fail.append('desktop intrinsic horizontal overflow')
if r['address'][2] < 2: fail.append('long address did not wrap')
if r['address'][3] == 'ellipsis': fail.append('address uses ellipsis')
if r['address'][4] == 'nowrap': fail.append('address cannot wrap')
if r['address'][5] not in ('anywhere','break-word'): fail.append('address overflow-wrap missing')
Path(sys.argv[2]).write_text(repr(r)+'\n')
if fail:
    print('public desktop geometry smoke: FAIL:',', '.join(fail));print(r);raise SystemExit(1)
print('public desktop geometry smoke:',r);print('public desktop geometry smoke: PASS')
PY
