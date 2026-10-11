#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VIEW="$ROOT/project/luci/lua/luasrc/view/homegate/public.htm"
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"

grep -Fq '.hg-file-native { display: none !important; }' "$COMMON"
grep -Fq 'class="hg-file-native"' "$VIEW"
grep -Fq "onclick=\"hgPublicChooseFile('hg-public-local-cert')\"" "$VIEW"
grep -Fq "onclick=\"hgPublicChooseFile('hg-public-local-key')\"" "$VIEW"
grep -Fq 'class="hg-file-name"' "$VIEW"

python3 - <<'PY'
import shutil
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except Exception:
    print('file picker UI smoke: SKIP browser (python playwright not installed)')
    raise SystemExit(0)
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)),None)
if not chrome:
    print('file picker UI smoke: SKIP browser (Chromium not installed)')
    raise SystemExit(0)
html='''<!doctype html><style>.hg-file-native{display:none!important}.hg-file-picker{display:flex}</style>
<div class="hg-file-picker"><input type="file" id="f" class="hg-file-native" onchange="changed()"><button id="b" type="button" onclick="choose()">选择文件</button><span id="n" class="hg-file-name">未选择文件</span></div>
<script>function choose(){document.getElementById('f').click()} function changed(){document.getElementById('n').textContent=document.getElementById('f').files[0]?.name||'未选择文件'}</script>'''
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,executable_path=chrome,args=['--no-sandbox'])
    page=browser.new_page()
    page.set_content(html)
    count={'v':0}
    page.on('filechooser',lambda fc: count.__setitem__('v',count['v']+1))
    page.click('#n')
    page.wait_for_timeout(150)
    if count['v']!=0: raise SystemExit('filename display unexpectedly opened file chooser')
    page.click('#b')
    page.wait_for_timeout(150)
    if count['v']!=1: raise SystemExit('Choose File button did not open exactly one file chooser')
    browser.close()
print('file picker UI smoke: PASS')
PY
