#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
OUT="$ROOT/build/theme-foundation-smoke"
rm -rf "$OUT"
mkdir -p "$OUT"

python3 - "$COMMON" "$OUT/result.txt" <<'PY'
from pathlib import Path
import re, shutil, sys
try:
    from playwright.sync_api import sync_playwright
except Exception:
    print('theme foundation smoke: SKIP (python playwright not installed)')
    raise SystemExit(0)
common=Path(sys.argv[1]).read_text()
m=re.search(r'<style type="text/css">(.*?)</style>', common, re.S)
if not m: raise SystemExit('common style block not found')
css=m.group(1)
chrome=next((shutil.which(x) for x in ('chromium','chromium-browser','google-chrome','google-chrome-stable') if shutil.which(x)), None)
if not chrome:
    print('theme foundation smoke: SKIP (Chromium not installed)')
    raise SystemExit(0)

def doc(classes, hostile=False):
    host='''html,body{margin:0;padding:0;width:100%;max-width:100%;} body{font-family:sans-serif;}'''
    if hostile:
        host+='''.cbi-section{min-width:780px!important;box-sizing:content-box!important;} input,select,textarea{min-width:520px!important;box-sizing:content-box!important;} .cbi-button{float:right;width:100%!important;text-indent:24px!important;} .cbi-button:before{content:"HOST"!important;display:inline!important;} button.cbi-button:focus,button.cbi-button:active{transform:scale(.82) translateY(3px)!important;translate:2px 3px!important;scale:.82!important;position:relative!important;top:3px!important;left:2px!important;box-shadow:inset 0 -3px 0 #fff!important;}'''
    return f'''<!doctype html><html lang="zh-CN" class="hg-theme-foundation {classes}"><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>{host}</style><style>{css}</style></head><body>
<main class="hg-wrap" id="wrap"><section class="cbi-section hg-section"><div class="hg-section-head"><h3>Theme</h3><button class="cbi-button hg-btn-4" id="add">添加</button></div>
<div class="hg-form-fields"><div class="hg-form-row" id="formrow"><label class="hg-form-label">设置标签</label><div class="hg-form-field"><input id="control" class="hg-control" value="value"></div></div></div>
<div class="hg-status-fields"><div class="hg-status-row" id="statusrow"><span class="hg-status-label">HomeGate</span><span class="hg-status-value">运行正常</span></div></div>
<div class="hg-notice" id="noticeOk">已保存</div><div class="hg-notice hg-notice-error" id="noticeError">错误</div><div class="hg-notice hg-notice-pending" id="noticePending">更改尚未保存</div>
<div class="hg-log-actions"><button id="refreshLog" class="cbi-button hg-btn-4">刷新</button></div>
<div class="hg-table-scroll-wrap hg-public-list-wrap"><table class="hg-public-table"><tbody><tr><td id="enabledCell" data-label="启用"><input id="enabledCheck" type="checkbox"></td><td data-label="域名">very-long.example.com</td><td data-label="内网目标">http://192.168.1.100:8080/very/long/path</td><td class="hg-actions" data-label="操作"><button class="cbi-button hg-btn-4">编辑</button><button class="cbi-button hg-btn-4">删除</button></td></tr></tbody></table></div>
</section></main>
<div class="cbi-page-actions" id="actions"><button class="cbi-button cbi-button-apply">保存&应用</button><button id="saveBtn" class="cbi-button cbi-button-save">保存</button><button id="resetBtn" class="cbi-button cbi-button-reset">复位</button></div>
<div class="hg-modal" id="modal"><div class="hg-modal-grid" id="modalGrid"><label id="modalLabel">字段</label><div><input class="hg-control" value="x"><div class="hg-field-note" id="modalNote">说明</div></div></div><div class="hg-modal-footnote" id="modalFootnote">脚注</div><div class="hg-modal-actions" id="modalActions"><button class="cbi-button">确定</button></div></div>
<div class="hg-modal-backdrop hg-open" id="accessBackdrop"><div class="hg-modal hg-access-modal" id="accessModal"><div class="hg-modal-head"><h3>访问管理</h3></div><div class="hg-access-table-wrap hg-access-table-scroll" id="accessScroll"><table class="hg-access-table"><tbody>{''.join('<tr><td data-label="IP 地址">2409:895b::1234</td><td data-label="域名">example.com</td><td data-label="结果">允许</td><td data-label="时间">2026/9/8 12:00:00</td><td class="hg-access-action" data-label="操作"><button class="cbi-button">允许</button></td></tr>' for _ in range(14))}</tbody></table></div><div class="hg-modal-actions"><button id="closeBtn" class="cbi-button">关闭</button></div></div></div>
</body></html>'''

def near(a,b,tol=0.75): return abs(a-b)<=tol
results={}
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True, executable_path=chrome, args=['--no-sandbox'])
    cases=[
      ('generic-mobile','hg-theme-generic',390,844,True),
      ('boot-mobile','hg-theme-boot',390,844,False),
      ('design-mobile','hg-theme-design',390,844,False),
      ('boot-desktop','hg-theme-boot',1400,900,False),
      ('design-desktop','hg-theme-design',1400,900,False),
    ]
    for name,cls,w,h,hostile in cases:
      page=browser.new_page(viewport={'width':w,'height':h})
      page.set_content(doc(cls,hostile), wait_until='load')
      r=page.evaluate('''() => {
        const d=document.documentElement,w=document.getElementById('wrap'),c=document.getElementById('control'),b=document.getElementById('add'),a=document.getElementById('actions'),m=document.getElementById('modal'),fr=document.getElementById('formrow'),srw=document.getElementById('statusrow');
        const b0=b.getBoundingClientRect(); b.focus(); const b1=b.getBoundingClientRect(), bs=getComputedStyle(b);
        const cr=c.getBoundingClientRect(), wr=w.getBoundingClientRect(), mr=m.getBoundingClientRect(), frr=fr.getBoundingClientRect(), srr=srw.getBoundingClientRect();
        const ec=document.getElementById('enabledCell'), chk=document.getElementById('enabledCheck'), save=document.getElementById('saveBtn'), reset=document.getElementById('resetBtn');
        const ar=document.getElementById('accessScroll'), am=document.getElementById('accessModal'), close=document.getElementById('closeBtn');
        const ecr=ec.getBoundingClientRect(), chkr=chk.getBoundingClientRect(), sr=save.getBoundingClientRect(), rr=reset.getBoundingClientRect();
        const cols=getComputedStyle(ec).gridTemplateColumns.split(' ').map(parseFloat), gap=parseFloat(getComputedStyle(ec).columnGap)||0;
        const expectedCheckLeft=ecr.left+(cols[0]||0)+gap;
        const fl=fr.querySelector('.hg-form-label'), sl=srw.querySelector('.hg-status-label');
        const ms=getComputedStyle(m), mg=getComputedStyle(document.getElementById('modalGrid')), ml=getComputedStyle(document.getElementById('modalLabel')), mn=getComputedStyle(document.getElementById('modalNote')), mf=getComputedStyle(document.getElementById('modalFootnote')), ma=getComputedStyle(document.getElementById('modalActions'));
        const nok=getComputedStyle(document.getElementById('noticeOk')), ner=getComputedStyle(document.getElementById('noticeError')), npe=getComputedStyle(document.getElementById('noticePending'));
        return {page:[d.scrollWidth,d.clientWidth],wrap:[w.scrollWidth,w.clientWidth],control:[cr.width,cr.height,cr.right,wr.right],buttonFocus:[b0.width,b0.height,b1.width,b1.height,b0.left,b0.top,b1.left,b1.top,bs.transform,bs.translate,bs.scale,bs.top,bs.left,bs.boxShadow],pseudo:getComputedStyle(b,'::before').content,pseudoDisplay:getComputedStyle(b,'::before').display,float:getComputedStyle(b).float,actions:getComputedStyle(a).display,modal:[mr.width,mr.height],modalRadius:ms.borderRadius,modalContract:{padding:[ms.paddingTop,ms.paddingRight,ms.paddingBottom,ms.paddingLeft],grid:mg.gridTemplateColumns,gaps:[mg.rowGap,mg.columnGap],labelColor:ml.color,note:[mn.color,mn.opacity],footnote:[mf.marginTop,mf.paddingTop,mf.borderTopColor],actions:[ma.gap,ma.marginTop]},notice:{ok:[nok.borderLeftColor,nok.backgroundColor],error:[ner.borderLeftColor,ner.backgroundColor],pending:[npe.borderLeftColor,npe.backgroundColor]},formColumns:getComputedStyle(fr).gridTemplateColumns,statusColumns:getComputedStyle(srw).gridTemplateColumns,rowHeights:[frr.height,srr.height],labelAlign:[getComputedStyle(fl).textAlign,getComputedStyle(sl).textAlign],labelWrap:[getComputedStyle(fl).whiteSpace,getComputedStyle(sl).whiteSpace],
          resetTag:reset.tagName,saveResetWidths:[sr.width,rr.width],checkbox:[chkr.left,expectedCheckLeft],access:{overflow:getComputedStyle(ar).overflowY,maxHeight:getComputedStyle(ar).maxHeight,modalOverflow:getComputedStyle(am).overflowY,width:am.getBoundingClientRect().width,modal:[am.clientHeight,am.scrollHeight],closeTop:close.offsetTop}};
      }''')
      page.close(); results[name]=r
    browser.close()

fail=[]
g=results['generic-mobile']
if g['page'][0]>g['page'][1]+1 or g['wrap'][0]>g['wrap'][1]+1 or g['control'][2]>g['control'][3]+1: fail.append('generic containment')
if not (g['pseudo'] in ('none','normal') or g['pseudoDisplay']=='none') or g['float']!='none': fail.append('generic button interference')
if not (near(g['buttonFocus'][0],g['buttonFocus'][2]) and near(g['buttonFocus'][1],g['buttonFocus'][3]) and near(g['buttonFocus'][4],g['buttonFocus'][6]) and near(g['buttonFocus'][5],g['buttonFocus'][7])): fail.append('generic button focus geometry changed')
if g['buttonFocus'][8] != 'none' or g['buttonFocus'][9] != 'none' or g['buttonFocus'][10] not in ('1','none') or g['buttonFocus'][11] not in ('auto','0px') or g['buttonFocus'][12] not in ('auto','0px'): fail.append('generic button focus transform/offset not neutralized')
if g['buttonFocus'][13] != 'none': fail.append('generic button focus shadow not neutralized')
if g['actions']=='grid': fail.append('generic incorrectly inherited BOOT mobile actions')
if results['boot-mobile']['actions']!='block': fail.append('BOOT native fixture actions')
if results['design-mobile']['actions']!='block': fail.append('Design native fixture actions')
if results['design-mobile']['resetTag']!='BUTTON' or not near(results['design-mobile']['saveResetWidths'][0],results['design-mobile']['saveResetWidths'][1],1.5): fail.append('Design mobile Save/Reset native element geometry')
if not near(results['boot-mobile']['checkbox'][0],results['boot-mobile']['checkbox'][1],1.5): fail.append('BOOT mobile checkbox value-column alignment')
a=results['design-mobile']['access']
if a['overflow']!='visible' or a['maxHeight']!='none' or a['modalOverflow'] not in ('auto','scroll') or a['modal'][1]<=a['modal'][0]: fail.append('mobile Access single-scroll contract')
if not near(results['boot-desktop']['control'][0],280) or not near(results['boot-desktop']['control'][1],28): fail.append('BOOT desktop control geometry')
if not near(results['design-desktop']['control'][0],560) or not near(results['design-desktop']['control'][1],38): fail.append('Design desktop control geometry')
if results['boot-desktop']['formColumns'] != '150px 280px' or results['boot-desktop']['statusColumns'].split()[0] != '150px': fail.append('BOOT semantic row geometry')
if results['design-desktop']['formColumns'] != results['design-desktop']['statusColumns']: fail.append('Design form/status token parity')
if results['design-desktop']['labelAlign'] != ['left','left'] or results['boot-desktop']['labelAlign'] != ['right','right']: fail.append('semantic label alignment')
if results['design-desktop']['labelWrap'] != ['normal','normal'] or results['boot-desktop']['labelWrap'] != ['nowrap','nowrap']: fail.append('semantic label wrapping')
for n in ('generic-mobile','boot-mobile','design-mobile'):
    if results[n]['formColumns'] != results[n]['statusColumns']: fail.append(n+' mobile form/status parity')
if results['boot-mobile']['modalRadius'] != '0px' or results['design-mobile']['modalRadius'] != '8px': fail.append('mobile modal radius adapter token')
if not near(results['boot-desktop']['modal'][0],500): fail.append('BOOT modal width')
if not near(results['design-desktop']['modal'][0],560): fail.append('Design modal width')
# Theme Foundation 1C: modal/component structure consumes semantic tokens while computed frozen geometry stays unchanged.
bm=results['boot-desktop']['modalContract']; dm=results['design-desktop']['modalContract']
if bm['padding'] != ['18.4px','20px','18.4px','20px'] or not bm['grid'].startswith('128px ') or bm['gaps'] != ['12px','14px'] or bm['actions'] != ['5.6px','16px']: fail.append('BOOT modal token contract')
if dm['padding'] != ['18px','20px','16px','20px'] or not dm['grid'].startswith('132px ') or dm['gaps'] != ['10px','16px'] or dm['actions'] != ['8px','14px']: fail.append('Design modal token contract')
if dm['note'][1] != '1' or bm['note'][1] != '0.72': fail.append('modal note token contract')
if not near(results['boot-desktop']['access']['width'],980) or not near(results['design-desktop']['access']['width'],980): fail.append('desktop access modal token width')
if results['design-mobile']['modalContract']['labelColor'] == results['design-desktop']['modalContract']['labelColor']: fail.append('Design mobile modal label token override')
expected_notice={
  'ok':['rgb(92, 184, 92)','rgba(92, 184, 92, 0.08)'],
  'error':['rgb(217, 83, 79)','rgba(217, 83, 79, 0.08)'],
  'pending':['rgb(240, 173, 78)','rgba(240, 173, 78, 0.09)']}
for n in ('generic-mobile','boot-desktop','design-desktop'):
    if results[n]['notice'] != expected_notice: fail.append(n+' semantic notice tokens')
Path(sys.argv[2]).write_text(repr(results)+'\n')
if fail:
    print('theme foundation smoke: FAIL:', ', '.join(fail)); print(results); raise SystemExit(1)
print('theme foundation smoke:', results)
print('theme foundation smoke: PASS')
PY
