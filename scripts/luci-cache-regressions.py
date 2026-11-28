#!/usr/bin/env python3
"""Real pinned LuCI ccache/dispatcher stale-menu regression in private paths."""
from pathlib import Path
import argparse,os,json,subprocess,tempfile,hashlib
from production_runtime import payload
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime-dir',type=Path,required=True);a=p.parse_args()
assert os.name=='posix' and os.getuid()!=0
runtime=a.runtime_dir.resolve();runtime=runtime/'prefix' if (runtime/'prefix').is_dir() else runtime
env={**os.environ,'LUA_PATH':str(runtime/'lib/lua/?.lua')+';'+str(runtime/'lib/lua/?/init.lua')+';;','LUA_CPATH':str(runtime/'lib/lua/?.so')+';;','LD_LIBRARY_PATH':str(runtime/'lib')+':'+os.environ.get('LD_LIBRARY_PATH','')}
cases=[]
def check(name,yes):assert yes,name;cases.append(name);print('PASS',name,flush=True)
with tempfile.TemporaryDirectory(prefix='homegate-menu-cache-') as td:
 work=Path(td);tmp=work/'tmp';tmp.mkdir();lib=work/'lib/luci';(lib/'controller').mkdir(parents=True);controller=lib/'controller/homegate.lua'
 # Seed the former menu semantics; the cache loader itself is unmodified.
 controller.write_text("""module('luci.controller.homegate',package.seeall)
function index()
 entry({'admin','services','homegate'},alias('admin','services','homegate','overview'),'HomeGate',56).dependent=false
 entry({'admin','services','homegate','overview'},call('overview'),'概览').leaf=true
 entry({'admin','services','homegate','settings'},alias('admin','services','homegate','settings','basic'),'设置',20)
 entry({'admin','services','homegate','maintenance'},call('maintenance'),'维护').leaf=true
end
""")
 loader=work/'menu.lua';loader.write_text('''package.path='''+json.dumps(str(work/'lib/?.lua')+';')+'''..package.path
package.preload['luci.http']=function()return {getenv=function()return nil end}end
package.preload['ubus']=function()return {connect=function()error('unexpected external ubus connection')end}end
package.preload['luci.model.homegate.legacy']=function()return {dispatch=function()end}end
local util=require'luci.util';util.libpath=function()return '''+json.dumps(str(lib))+'''end
require('luci.ccache').cache_enable('''+json.dumps(str(tmp/'luci-modulecache'))+''')
local d=require'luci.dispatcher';d.indexcache='''+json.dumps(str(tmp/'luci-indexcache'))+'''
local t=d.createtree();local n=t.nodes.admin.nodes.services.nodes.homegate
local tabs={};for name,v in pairs(n.nodes)do if v.title then tabs[#tabs+1]={name=name,order=v.order or 100}end end
table.sort(tabs,function(x,y)return x.order<y.order or x.order==y.order and x.name<y.name end)
local names={};for _,v in ipairs(tabs)do names[#names+1]=v.name end
io.write(require('luci.jsonc').stringify({tabs=names,settings=n.nodes.settings.target.req}))
''')
 def menu():
  r=subprocess.run(['lua5.1',str(loader)],env=env,capture_output=True,text=True,timeout=15)
  assert r.returncode==0,r.stderr;return json.loads(r.stdout)
 first=menu();check('real old menu cache seeded',first['tabs']==['settings','maintenance','overview'] and first['settings'][-1]=='basic')
 controller.write_bytes(payload(ROOT)['usr/lib/lua/luci/controller/homegate.lua'])
 second=menu();check('controller update alone still uses stale cached index',second==first)
 cache=tmp/'luci-modulecache';other=cache/'OTHER_PLUGIN_SENTINEL';other.write_text('keep');before=other.read_bytes()
 helper=work/'invalidate.lua';helper.write_text((ROOT/'packaging/production/native-luci-cache.lua').read_text().replace("'/tmp'",json.dumps(str(tmp))).replace("'/tmp/", "'"+str(tmp)+"/").replace('nx.getuid()==0','nx.getuid()=='+str(os.getuid())).replace('s.uid==0','s.uid=='+str(os.getuid())).replace('m.uid==0','m.uid=='+str(os.getuid())))
 def invalidate(mode='invalidate'):
  return subprocess.run(['lua5.1',str(helper),mode],env=env,capture_output=True,text=True,timeout=5)
 check('safe cache plan accepted',invalidate('check').returncode==0)
 check('cache invalidation succeeds',invalidate().returncode==0 and other.read_bytes()==before)
 third=menu();check('fresh dispatcher shows four ordered top-level tabs',third['tabs']==['overview','public','wol','maintenance'])
 check('hidden settings alias points at canonical public page',third['settings']==['admin','services','homegate','public'])
 sentinel=work/'configuration-sentinel';sentinel.write_text('keep');bad=tmp/'luci-indexcache.bad';bad.symlink_to(sentinel)
 r=invalidate();check('symlink cache entry refused without touching target',r.returncode==7 and sentinel.read_text()=='keep' and bad.is_symlink());bad.unlink()
 check('offline hook remains source-guarded','IPKG_INSTROOT' in (ROOT/'packaging/production/Makefile').read_text())
print(json.dumps({'passed':len(cases),'cases':cases,'scope':'Real pinned ccache and dispatcher, actual staged controller, private cache paths/host UID; HTTP and unused ubus transport fixtures; no target acceptance'},indent=2))
