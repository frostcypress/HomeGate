#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
OUT="$ROOT/build/action-column-contract-smoke"
rm -rf "$OUT"; mkdir -p "$OUT"
python3 - "$COMMON" "$OUT/result.txt" <<'PY'
from pathlib import Path
import re, shutil, sys
try:
    from playwright.sync_api import sync_playwright
except Exception:
    print('action-column contract smoke: SKIP (python playwright not installed)'); raise SystemExit(0)
common=Path(sys.argv[1]).read_text(); m=re.search(r'<style type="text/css">(.*?)</style>',common,re.S)
if not m: raise SystemExit('common style block not found')
css=m.group(1)
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)),None)
if not chrome:
    print('action-column contract smoke: SKIP (Chromium not installed)'); raise SystemExit(0)
html=f'''<!doctype html><html lang="zh-CN" class="hg-theme-foundation hg-theme-boot"><head><meta name="viewport" content="width=device-width,initial-scale=1">
<style>html,body{{margin:0;padding:0}}body{{padding:20px}}.fixture{{margin:0 0 24px}}.cbi-button{{box-sizing:border-box;height:28px}}</style>
<style>{css}</style>
<style>
/* Hostile late theme: positional rules that used to cause Access empty/action drift. */
.hg-table th:last-child,.hg-table td:last-child{{text-align:right!important;padding-left:17px!important;padding-right:13px!important}}
.hg-table td[colspan]{{text-align:right!important}}
</style></head><body>
<div class="hg-wrap fixture" id="pub" style="width:860px"><div class="hg-table-scroll-wrap"><table class="hg-table hg-public-table" id="pubTable">
<thead><tr><th>启用</th><th>访问地址</th><th>内网目标</th><th id="pubHead" class="hg-action-head hg-public-action-head">操作</th></tr></thead>
<tbody id="pubBody"><tr><td></td><td class="hg-public-address">https://x.chenos.cn（证书剩余 89 天）</td><td>x</td><td id="pubCell" class="hg-actions hg-action-cell hg-action-group"><button id="pubFirst" class="cbi-button hg-btn-4">编辑</button><button class="cbi-button hg-btn-4">同步</button><button class="cbi-button hg-btn-4">续期</button><button id="pubLast" class="cbi-button hg-btn-4">删除</button></td></tr></tbody></table></div></div>
<div class="hg-wrap fixture" id="wol" style="width:720px"><div class="hg-table-scroll-wrap"><table class="hg-table hg-wol-table" id="wolTable"><colgroup><col style="width:34%"><col><col style="width:240px"></colgroup>
<thead><tr><th>名称</th><th>MAC 地址</th><th id="wolHead" class="hg-action-head hg-wol-action-head"><div class="hg-wol-actions-head">操作</div></th></tr></thead>
<tbody id="wolBody"><tr><td>x</td><td>x</td><td id="wolCell" class="hg-actions hg-action-cell"><div class="hg-action-group hg-wol-actions-group"><button id="wolFirst" class="cbi-button hg-btn-4">编辑</button><button class="cbi-button hg-btn-4">唤醒</button><button id="wolLast" class="cbi-button hg-btn-4">删除</button></div></td></tr></tbody></table></div></div>
<div class="hg-modal hg-access-modal fixture" id="access"><div class="hg-access-table-wrap"><table class="hg-table hg-access-table" id="accessTable"><colgroup><col><col style="width:145px"><col style="width:150px"><col style="width:170px"><col class="hg-access-actions-col"></colgroup>
<thead><tr><th>来源</th><th>域名</th><th>访问状态</th><th>时间</th><th id="accessHead" class="hg-action-head hg-access-action-head">操作</th></tr></thead>
<tbody id="accessBody"><tr><td>广东省 · 2408::1</td><td>x</td><td>允许（地区规则）</td><td>2026/9/9 00:12:54</td><td id="accessCell" class="hg-action-cell hg-access-action"><div class="hg-action-group hg-access-action-group"><button id="accessFirst" class="cbi-button hg-btn-4">拒绝访问</button><button id="accessLast" class="cbi-button hg-btn-4">清除记录</button></div></td></tr></tbody></table></div></div>
<div class="hg-modal hg-access-modal fixture" id="emptyAccess"><div class="hg-access-table-wrap"><table class="hg-table hg-access-table" id="emptyTable"><colgroup><col><col style="width:145px"><col style="width:150px"><col style="width:170px"><col class="hg-access-actions-col"></colgroup><thead><tr><th>来源</th><th>域名</th><th>访问状态</th><th>时间</th><th class="hg-action-head hg-access-action-head">操作</th></tr></thead><tbody><tr><td id="emptyMsg" colspan="5" class="hg-table-message">暂无访问记录。</td></tr></tbody></table></div></div>
</body></html>'''
def near(a,b,tol=1.1): return abs(a-b)<=tol
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,executable_path=chrome,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1300,'height':900}); page.set_content(html,wait_until='load')
    r=page.evaluate('''() => {
      const q=id=>document.getElementById(id), R=id=>q(id).getBoundingClientRect(), cs=id=>getComputedStyle(q(id));
      const txtLeft=id=>R(id).left+(parseFloat(cs(id).paddingLeft)||0);
      const center=id=>{const r=R(id);return r.left+r.width/2};
      return {
        pub:[txtLeft('pubHead'),R('pubFirst').left,R('pubLast').right,R('pubCell').right],
        wol:[txtLeft('wolHead'),R('wolFirst').left,R('wolLast').right,R('wolCell').right],
        access:[txtLeft('accessHead'),R('accessFirst').left,R('accessLast').right,R('accessCell').right,R('accessTable').right],
        empty:[cs('emptyMsg').textAlign,center('emptyMsg'),center('emptyTable')],
        widths:[R('pubHead').left,R('wolHead').left,R('accessHead').left],
        over:[q('pubTable').scrollWidth-q('pubTable').clientWidth,q('wolTable').scrollWidth-q('wolTable').clientWidth,q('accessTable').scrollWidth-q('accessTable').clientWidth]
      }
    }''')
    # Simulate empty -> dynamic row redraw in Access; header/action column must not move.
    r2=page.evaluate('''() => {
      const body=document.getElementById('accessBody'); body.innerHTML='';
      let tr=document.createElement('tr'), td=document.createElement('td');td.colSpan=5;td.className='hg-table-message';td.textContent='暂无访问记录。';tr.appendChild(td);body.appendChild(tr);
      const head=document.getElementById('accessHead').getBoundingClientRect();
      const headLeft=head.left+(parseFloat(getComputedStyle(document.getElementById('accessHead')).paddingLeft)||0);
      const emptyCenter=td.getBoundingClientRect().left+td.getBoundingClientRect().width/2;
      const table=document.getElementById('accessTable').getBoundingClientRect();
      body.innerHTML='';tr=document.createElement('tr');
      for (const x of ['广东省 · 2408::2','x','拒绝（手动拒绝）','2026/9/9 00:15:00']) { const c=document.createElement('td');c.textContent=x;tr.appendChild(c); }
      const ac=document.createElement('td');ac.className='hg-action-cell hg-access-action';const g=document.createElement('div');g.className='hg-action-group hg-access-action-group';
      const b1=document.createElement('button');b1.className='cbi-button hg-btn-4';b1.textContent='允许访问';const b2=document.createElement('button');b2.className='cbi-button hg-btn-4';b2.textContent='清除记录';g.append(b1,b2);ac.appendChild(g);tr.appendChild(ac);body.appendChild(tr);
      const hr=document.getElementById('accessHead').getBoundingClientRect();
      return {headBefore:headLeft,headAfter:hr.left+(parseFloat(getComputedStyle(document.getElementById('accessHead')).paddingLeft)||0),first:b1.getBoundingClientRect().left,last:b2.getBoundingClientRect().right,cellRight:ac.getBoundingClientRect().right,emptyCenter,tableCenter:table.left+table.width/2};
    }''')
    browser.close()
fail=[]
for name,vals in [('Public',r['pub']),('WOL',r['wol'])]:
    if not near(vals[0],vals[1]): fail.append(f'{name} header/first-action drift')
    if vals[2] > vals[3]+1: fail.append(f'{name} action overflow')
if not near(r['access'][0],r['access'][1]): fail.append('Access header/first-action drift')
if not near(r['access'][2],r['access'][3]) or not near(r['access'][2],r['access'][4]): fail.append('Access second-action/right-edge drift')
if r['empty'][0] != 'center' or not near(r['empty'][1],r['empty'][2]): fail.append('colspan message not centered')
if any(x>1 for x in r['over']): fail.append('desktop horizontal overflow')
if not near(r2['headBefore'],r2['headAfter']) or not near(r2['headAfter'],r2['first']): fail.append('Access empty/dynamic redraw shifts action column')
if not near(r2['last'],r2['cellRight']): fail.append('Access dynamic row right edge drift')
if not near(r2['emptyCenter'],r2['tableCenter']): fail.append('Access dynamic empty message off-center')
Path(sys.argv[2]).write_text(repr({'initial':r,'redraw':r2})+'\n')
if fail:
    print('action-column contract smoke: FAIL:',', '.join(fail));print(r);print(r2);raise SystemExit(1)
print('action-column contract smoke:',r);print('redraw:',r2);print('action-column contract smoke: PASS')
PY
