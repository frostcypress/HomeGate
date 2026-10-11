#!/usr/bin/env python3
"""Theme styles for native footer must be identical with HomeGate CSS on/off."""
from pathlib import Path
import json,re,os
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1];out=ROOT/'build/native-theme-regressions';out.mkdir(parents=True,exist_ok=True)
theme=(ROOT/'scripts/fixtures/luci/bootstrap.css').read_text(encoding='utf-8')
props=['width','height','padding','margin','color','backgroundColor','borderRadius','display','justifyContent','transform','opacity']
results=[]
with sync_playwright() as pw:
 edge=Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe');exe=os.environ.get('HOMEGATE_BROWSER') or (str(edge) if edge.exists() else None)
 browser=pw.chromium.launch(**({'executable_path':exe} if exe else {}),headless=True)
 for name in ('basic','public','wol','maintenance'):
  text=(ROOT/'build/native-ui-regressions'/(name+'.html')).read_text(encoding='utf-8')
  css=re.search(r'<style type="text/css">(.*?)</style>',text,re.S)[1]
  body=re.sub(r'<script\b.*?</script>','',text,flags=re.S);body=re.sub(r'<style\b.*?</style>','',body,flags=re.S)
  for lang in ('zh-CN','en'):
   for width in (390,1400):
    page=browser.new_page(viewport={'width':width,'height':900})
    page.set_content(f'<html lang="{lang}" class="hg-theme-foundation hg-theme-boot"><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>{theme}</style><style id="hg">{css}</style></head><body>{body}</body></html>')
    if lang=='zh-CN':page.locator('.cbi-page-actions input').evaluate_all("bs=>bs.forEach((b,i)=>b.value=['保存并应用','保存','复位'][i])")
    assert page.locator('.cbi-page-actions').count()==1
    assert page.locator('.hg-wrap .cbi-page-actions').count()==0
    assert page.locator('.cbi-page-actions input').count()==3
    assert page.locator('.cbi-page-actions input[type=submit]').evaluate_all("bs=>bs.every(b=>b.form&&b.form.elements['mode'].value==='apply')")
    gap=page.evaluate("()=>document.querySelector('.cbi-page-actions').getBoundingClientRect().top-document.querySelector('.hg-wrap').lastElementChild.getBoundingClientRect().bottom");assert gap>=17.9,(name,lang,width,gap)
    take="ps=>[document.querySelector('.cbi-page-actions'),...document.querySelectorAll('.cbi-page-actions input')].map(b=>Object.fromEntries(ps.map(p=>[p,getComputedStyle(b)[p]])))"
    before=page.evaluate(take,props);page.evaluate("document.getElementById('hg').disabled=true");after=page.evaluate(take,props);assert before==after,(name,lang,width,before,after)
    page.evaluate("document.getElementById('hg').disabled=false")
    for state in ('hover','focus','disabled'):
     button=page.locator('.cbi-page-actions input').first
     if state=='hover':button.hover()
     elif state=='focus':button.focus()
     else:button.evaluate('b=>b.disabled=true')
     before=page.evaluate(take,props);page.evaluate("document.getElementById('hg').disabled=true");after=page.evaluate(take,props);assert before==after,(name,lang,width,state)
     page.evaluate("document.getElementById('hg').disabled=false")
    page.locator('.cbi-page-actions input').first.evaluate('b=>b.disabled=false')
    if name=='maintenance':
     # Includes fallback English inside Chinese document language, the old overlap case.
     failures=page.locator('.hg-log-actions button,.hg-button-row button').evaluate_all("bs=>bs.filter(b=>b.scrollWidth>b.clientWidth+1).map(b=>b.textContent)");assert not failures,(lang,width,failures)
    results.append([name,lang,width]);page.close()
 browser.close()
(out/'results.json').write_text(json.dumps({'native_footer_style_invariance':results,'minimum_content_gap_px':18,'theme':'Pinned upstream Bootstrap CSS','boundaries':'Does not certify every third party LuCI theme'},indent=2))
print('PASS native theme styles/forms: 16 page/language/viewport cases; maintenance fallback text fits')
