#!/usr/bin/env python3
"""Real FileReader/DOM/XHR tests; only HTTP and ubus are boundary fixtures."""
import html
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from lupa.lua51 import LuaRuntime
from playwright.sync_api import sync_playwright
from project import ROOT

views=ROOT/'project/luci/lua/luasrc/view/homegate'
resources=ROOT/'project/luci/js/htdocs/luci-static/resources/homegate'
out=ROOT/'build/config-preview-regressions'
out.mkdir(parents=True,exist_ok=True)
data={'main':{},'packages':{},'notice':'','error_message':'','token':'fixture-csrf'}
text=(views/'maintenance.htm').read_text(encoding='utf-8').replace('<%+homegate/common%>',(views/'common.htm').read_text(encoding='utf-8'))
lua=LuaRuntime(unpack_returned_tuples=True)
lua.globals().pcdata=lambda v:html.escape('' if v is None else str(v),quote=True)
lua.globals().translate=lambda v:v
lua.globals().url=lambda p:'/cgi-bin/luci/'+p
for key,value in data.items():
    lua.globals()[key]=lua.table_from(value,recursive=True) if isinstance(value,dict) else value
chunks=['local out={};local function write(v) out[#out+1]=tostring(v or "") end']
for part in re.split(r'(<%.*?%>)',text,flags=re.S):
    if not part.startswith('<%'):chunks.append('write('+json.dumps(part,ensure_ascii=False)+')');continue
    tag=part[2:-2]
    if tag.startswith('='):chunks.append('write('+tag[1:]+')')
    elif tag.startswith(':'):chunks.append('write(pcdata(translate('+json.dumps(tag[1:],ensure_ascii=False)+')))')
    elif not tag.startswith('+'):chunks.append(tag)
legacy=lua.execute('\n'.join(chunks)+'\nreturn table.concat(out)')
node=r'''const fs=require('fs'),path=require('path');const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));const L={url:(...p)=>'/cgi-bin/luci/'+p.join('/')},baseclass={extend:p=>{function C(){};C.prototype=p;return C;}};const S=new Function('L','_','baseclass',fs.readFileSync(path.join(process.argv[3],'common.js'),'utf8'))(L,v=>v,baseclass);const T=new Function('L','_','shared','baseclass',fs.readFileSync(path.join(process.argv[3],'maintenance.js'),'utf8'))(L,v=>v,new S(),baseclass);process.stdout.write(new T().render(input));'''
with tempfile.TemporaryDirectory() as directory:
    temporary=Path(directory)
    (temporary/'render.cjs').write_text(node,encoding='utf-8')
    (temporary/'data.json').write_text(json.dumps(data),encoding='utf-8')
    modern=subprocess.check_output(['node',str(temporary/'render.cjs'),str(temporary/'data.json'),str(resources)]).decode('utf-8')
clean=lambda v:v.replace('\nvar HGXHR = window.homegateXHR;','').replace('HGXHR.','XHR.').replace('&#x27;','&#39;')
if clean(modern)!=clean(legacy):
    import difflib
    print(''.join(list(difflib.unified_diff(clean(legacy).splitlines(True),clean(modern).splitlines(True)))[:35]))
    raise AssertionError('Lua/JS preview rendering differs')
codec=lua.execute((ROOT/'project/luci/lua/luasrc/model/homegate/backup.lua').read_text(encoding='utf-8'))
cursor=lua.execute('return {foreach=function(self,pkg,kind,cb) if kind=="homegate" then cb({[".name"]="main",enabled="1",log_level="warn"}) end end}')
backup='# homegate-backup-format: 2\n# plugin: homegate\n# schema: public-uci-v1\n# secrets: omitted\nconfig homegate main\n option log_level info\nconfig wol_host host_a\n option name \'<img onerror="window.xss=1">\'\n option mac AA:BB:CC:DD:EE:FF\n'
report=json.loads(codec.json(codec.preview(cursor,backup)))
class LiveError:
    def __enter__(self): return self
    def __exit__(self,kind,error,trace):
        if kind:
            import traceback
            traceback.print_exception(kind,error,trace)
        return False

cases=[]
print('Lua/JS parity passed; starting browser',flush=True)
with sync_playwright() as pw, LiveError():
    edge=Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
    executable=os.environ.get('HOMEGATE_BROWSER') or (str(edge) if edge.exists() else None)
    browser=pw.chromium.launch(**({'executable_path':executable} if executable else {}),headless=True,timeout=15000)
    print('Browser started',flush=True)
    context=browser.new_context()
    context.set_default_timeout(10000)
    requests=[]
    response={'body':json.dumps(report)}
    def serve(route):
        if route.request.method=='POST':
            print('Received native preview POST',flush=True)
            requests.append({'method':route.request.method,'url':route.request.url,'body':route.request.post_data})
            route.fulfill(status=200,body=response['body'],content_type='application/json')
            print('Replied to native preview POST',flush=True)
        else:route.fulfill(status=200,body='<html><body></body></html>',content_type='text/html')
    context.route('http://homegate.test/**',serve)
    page=context.new_page();page.goto('http://homegate.test/cgi-bin/luci/admin/services/homegate/maintenance')
    errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
    for variant,markup in [('lua',legacy),('js',modern)]:
        print('Checking '+variant+' preview behavior',flush=True)
        page.set_content('<script>window.XHR={get:function(u,f,cb){cb({status:200,responseText:""},null);}};window.homegateXHR=window.XHR;window.homegatePreviewImport=null;window.xss=0;</script>'+markup,wait_until='domcontentloaded')
        theme=ROOT/'scripts/fixtures'/('legacy-bootstrap/cascade.css' if variant=='lua' else 'luci/bootstrap.css')
        page.add_style_tag(content=theme.read_text(encoding='utf-8'))
        print('Mounted '+variant+' fixture',flush=True)
        requests.clear()
        page.locator('#hg-config-import-file').set_input_files({'name':'public.conf','mimeType':'text/plain','buffer':backup.encode()})
        print('FileReader input delivered',flush=True)
        page.wait_for_function('document.querySelectorAll("#hg-config-preview-changes tr").length>0')
        print('Preview rendered',flush=True)
        assert len(requests)==1 and '/config_import' in requests[0]['url']
        assert requests[0]['body'].startswith('token=fixture-csrf&config_payload=')
        assert page.locator('#hg-config-preview-changes img').count()==0
        assert page.evaluate('window.xss')==0
        assert 'Preview only' in page.locator('#hg-config-preview').inner_text()
        assert page.locator('#hg-config-import-file').input_value()==''
        assert page.locator('#hg-config-import-payload').count()==0
        for mode in ('light','dark'):
            page.emulate_media(color_scheme=mode)
            for width in (360,768,1280):
                page.set_viewport_size({'width':width,'height':900})
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),(variant,mode,width)
                assert page.locator('#hg-config-preview-changes td').evaluate_all('cells=>cells.every(c=>c.getBoundingClientRect().width>0 && c.scrollWidth<=c.clientWidth+1)')
                cases.append([variant,mode,width])
        page.locator('#hg-config-preview').screenshot(path=str(out/(variant+'-preview.png')))
        # Real FileReader rejects oversized files before transmission.
        requests.clear()
        page.locator('#hg-config-import-file').set_input_files({'name':'large.conf','mimeType':'text/plain','buffer':b'x'*262145})
        assert 'too large' in page.locator('#hg-config-preview-message').inner_text()
        assert not requests
        # Invalid JSON and server failures clear previous rows and do not apply.
        response['body']='not JSON'
        page.locator('#hg-config-import-file').set_input_files({'name':'public.conf','mimeType':'text/plain','buffer':backup.encode()})
        page.wait_for_function('document.getElementById("hg-config-preview-message").textContent==="Unable to preview configuration."')
        print('Invalid JSON handled',flush=True)
        assert page.locator('#hg-config-preview-changes tr').count()==0
        response['body']=json.dumps(report)
        # Independent overlapping requests: second result wins; closing also
        # invalidates an in-flight response, without modifying configuration.
        page.evaluate('()=>{window.previewResolvers=[];window.homegatePreviewImport=()=>new Promise(r=>previewResolvers.push(r));}')
        for _ in range(2):
            page.locator('#hg-config-import-file').set_input_files({'name':'public.conf','mimeType':'text/plain','buffer':backup.encode()})
            page.wait_for_function('previewResolvers.length>='+str(_+1))
            print('Deferred preview '+str(_+1)+' queued',flush=True)
        page.evaluate('r=>previewResolvers[1](r)',report)
        page.wait_for_function('document.querySelectorAll("#hg-config-preview-changes tr").length>0')
        page.evaluate('previewResolvers[0]({ok:false,error:"STALE_RESPONSE"})')
        assert 'STALE_RESPONSE' not in page.locator('#hg-config-preview').inner_text()
        page.locator('#hg-config-import-file').set_input_files({'name':'public.conf','mimeType':'text/plain','buffer':backup.encode()})
        page.wait_for_function('previewResolvers.length===3')
        page.get_by_role('button',name='Close Preview',exact=True).click()
        page.evaluate('r=>previewResolvers[2](r)',report)
        assert page.locator('#hg-config-preview').is_hidden()
        assert page.locator('#hg-config-preview-changes tr').count()==0
        # A forged commit capability is never accepted by the preview UI.
        page.evaluate('r=>hgMaintenanceShowPreview({...r,can_commit:true})',report)
        assert page.locator('#hg-config-preview-changes tr').count()==0
        assert 'Unable to preview' in page.locator('#hg-config-preview-message').inner_text()
    # Exercise the actual JS transport's preview adapter and job polling/ack.
    transport=(resources/'transport.js').read_text(encoding='utf-8')
    page.evaluate('''([code,result])=>{
      window.rpcCalls=[];window._=v=>v;
      const rpc={declare:def=>(...args)=>{rpcCalls.push([def.method,...args]);if(def.method==='write')return Promise.resolve({ok:true,job:'b'.repeat(32)});if(def.method==='poll')return Promise.resolve({ok:true,result:{ok:true,body:JSON.stringify(result)}});return Promise.resolve({ok:true,body:'{}'});}};
      const baseclass={extend:p=>{function C(){};C.prototype=p;return C;}};
      const ui={addNotification:()=>{throw Error('unexpected notification')}};
      const T=new Function('rpc','ui','baseclass',code)(rpc,ui,baseclass);new T().install(document.body);
    }''',[transport,report])
    page.locator('#hg-config-import-file').set_input_files({'name':'public.conf','mimeType':'text/plain','buffer':backup.encode()})
    page.wait_for_function('document.querySelectorAll("#hg-config-preview-changes tr").length>0')
    calls=page.evaluate('rpcCalls.filter(x=>x[0]!=="read")')
    assert [c[0] for c in calls]==['write','poll','ack'],calls
    assert calls[0][1]=='config_import' and calls[0][2]['config_payload']==backup
    assert not errors,errors
    browser.close()
(out/'results.json').write_text(json.dumps({'render_parity':2,'geometry_cases':cases,'behavior':['native-post-csrf','real-file-reader','escaped-diff','large-file-before-network','invalid-json','second-preview-wins','close-invalidates-response','forged-commit-rejected','actual-js-job-poll-ack'],'scope':'Local/CI browser and read-only UCI boundary fixtures; no target LuCI, write backend or device acceptance'},indent=2),encoding='utf-8')
print('PASS Lua/JS preview: rendering parity, 12 geometry cases and 9 behavior contracts')
