-- Run the installed controller and native request/virtual-UCI adapter entirely
-- against memory. No provider, host command, router configuration or job write.
local base=assert(arg[0]:match('^(.*)/[^/]+$'))
local lib=assert(loadfile(base..'/native-web-store.lua'))('library')
local engine=assert(loadfile(base..'/native-web.lua'))('library')
local json=require('luci.jsonc');local nx=require('nixio')
return function(version)
 local sec,usec=nx.gettimeofday();local cases={};local passed=true
 local function check(name,ok)
  cases[#cases+1]={name=name,status=ok and 'PASS' or 'FAIL',scope='isolated-fake-host'}
  if not ok then passed=false end
 end
 local function host(route,write,form)
  local h={documents={homegate={{name='main',kind='homegate',values={enabled='0',ddns_interval='300',https_port='443',proxy_https_port='10443'}}}},commits=0,begins=0,calls=0,write=write}
  h.request='{"route":'..lib.encode(route)..',"form":'..(next(form or {}) and lib.encode(form) or '{}')..',"write":'..tostring(write)..'}'
  function h.shell(command)
   h.calls=h.calls+1
   if command:match('^for b in /sys/class/net/')then return 'B|br-lan\nM|br-lan|eth0|ethernet\n',0 end
   if command:match('^opkg status ')then return 'Package: homegate\nVersion: '..version..'\nArchitecture: all\n',0 end
   return '{"api_version":1,"ok":true,"version":'..lib.encode(version)..',"providers":[],"cas":[],"events":[]}',0
  end
  return h
 end
 local function execute(h)local ok,result=pcall(engine,h);return ok and result or {ok=false}end
 for name,route in pairs(lib.routes)do
  local h=host(name,false);local r=execute(h)
  if route.write then check('ACL/read-denies/'..name,not r.ok and h.begins==0 and h.calls==0 and h.commits==0)
  else check('read/'..name,r.ok and h.begins==0 and h.commits==0)end
 end
 local h=host('basic_apply',true,{mode='save',ddns_interval='600'});local r=execute(h)
 check('basic/save',r.ok and h.commits==1 and h.begins==1 and h.documents.homegate[1].values.ddns_interval=='600')
 h=host('basic_apply',true,{mode='save',ddns_interval='1'});r=execute(h)
 check('basic/reject-invalid',not r.ok and h.commits==0 and h.documents.homegate[1].values.ddns_interval=='300')
 h=host('basic_apply',true,{mode='save',ddns_interval='600'});h.fail_commit=true;r=execute(h)
 check('basic/commit-failure',not r.ok and h.commits==1 and h.documents.homegate[1].values.ddns_interval=='300')
 for name,request in pairs({['unknown-route']='{"route":"unknown","form":{}}',['invalid-field']='{"route":"basic","form":{"bad-field":"private-fixture"}}',['nul-field']='{"route":"basic","form":{"x":"a\\u0000b"}}',oversize='{"route":"basic","form":{"x":"'..string.rep('a',2097152)..'"}}'})do
  h=host('basic',false);h.request=request;r=execute(h)
  check('request/'..name,not r.ok and h.calls==0 and h.begins==0 and h.commits==0)
 end
 cases[#cases+1]={name='live-DNS-ACME-proxy-firewall-WOL',status='SKIP',scope='requires-router-and-external-infrastructure'}
 table.sort(cases,function(a,b)return a.name<b.name end)
 local after,micro=nx.gettimeofday()
 return {api_version=1,native=true,version=version,ok=passed,cases=cases,duration_ms=math.max(0,math.floor((after-sec)*1000+(micro-usec)/1000)),phase='selftest',effect='none',write_ready=false,target_ABI_verified=false}
end
