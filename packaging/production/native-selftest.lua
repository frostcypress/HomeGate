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
   if command=='sha256sum /etc/config/homegate 2>/dev/null'then return string.rep(h.changed_source and 'b' or 'a',64)..'  /etc/config/homegate\n',0 end
   if command:match('^for b in /sys/class/net/')then return 'B|br-lan\nM|br-lan|eth0|ethernet\n',0 end
   if command:match('^opkg status ')then return 'Package: homegate\nVersion: '..version..'\nArchitecture: all\n',0 end
   return '{"api_version":1,"ok":true,"version":'..lib.encode(version)..',"arch":"arm64","package_arch":"all","providers":[],"cas":[],"events":[]}',0
  end
  return h
 end
 local function execute(h)local ok,result=pcall(engine,h);return ok and result or {ok=false}end
 for name,route in pairs(lib.routes)do
  local h=host(name,false);local r=execute(h)
  if route.write then check('ACL/read-denies/'..name,not r.ok and h.begins==0 and h.calls==0 and h.commits==0)
  else check('read/'..name,r.ok and h.begins==0 and h.commits==0)end
 end
 local h=host('overview',false);local r=execute(h)
 check('overview/combined-settings-and-machine-architecture',r.ok and r.template=='homegate/overview' and r.data.main.enabled=='0' and r.data.packages.arch=='arm64' and r.data.packages.package_arch=='all')
 h=host('basic',false);r=execute(h)
 check('basic/bookmark-redirects-overview',r.ok and r.redirect=='/cgi-bin/luci/admin/services/homegate/overview')
 h=host('public',false);r=execute(h)
 check('renewal/default-five-days',r.ok and r.data.default_renew_days=='5' and h.commits==0)
 h=host('public',false);h.documents.homegate[1].values.renew_days='30';r=execute(h)
 check('renewal/explicit-thirty-days-preserved',r.ok and r.data.default_renew_days=='30' and h.commits==0)
 h=host('basic_apply',true,{mode='save',ddns_interval='600'});r=execute(h)
 check('basic/save',r.ok and r.redirect=='/cgi-bin/luci/admin/services/homegate/overview?notice=Saved' and h.commits==1 and h.begins==1 and h.documents.homegate[1].values.ddns_interval=='600')
 h=host('basic_apply',true,{mode='save',ddns_interval='1'});r=execute(h)
 check('basic/reject-invalid',not r.ok and h.commits==0 and h.documents.homegate[1].values.ddns_interval=='300')
 h=host('basic_apply',true,{mode='save',ddns_interval='600'});h.fail_commit=true;r=execute(h)
 check('basic/commit-failure',not r.ok and h.commits==1 and h.documents.homegate[1].values.ddns_interval=='300')
 for name,request in pairs({['unknown-route']='{"route":"unknown","form":{}}',['invalid-field']='{"route":"basic","form":{"bad-field":"private-fixture"}}',['nul-field']='{"route":"basic","form":{"x":"a\\u0000b"}}',oversize='{"route":"basic","form":{"x":"'..string.rep('a',2097152)..'"}}'})do
  h=host('basic',false);h.request=request;r=execute(h)
  check('request/'..name,not r.ok and h.calls==0 and h.begins==0 and h.commits==0)
 end
 h=host('config_export',true);r=execute(h)
 local backup=r.body and r.body:gsub("option ddns_interval '300'","option ddns_interval '600'")
 check('maintenance/export-attachment',r.ok and backup and r.headers['Content-Disposition']:find('homegate-config-backup.conf',1,true) and h.commits==0)
 h=host('config_import',true,{config_payload=backup,mode='check'});r=execute(h)
 local preview=r.body and lib.strict(r.body)
 check('maintenance/import-check-never-commits',r.ok and preview and preview.ok and preview.can_commit==true and type(preview.confirmation)=='string' and h.commits==0)
 local confirmation=preview and preview.confirmation or ''
 h=host('config_import',true,{config_payload=backup,mode='restore',confirmation=confirmation});r=execute(h)
 local imported=r.body and lib.strict(r.body)
 check('maintenance/import-confirmed-restores-disabled',r.ok and imported and imported.restored and h.commits==1 and h.documents.homegate[1].values.enabled=='0' and h.documents.homegate[1].values.ddns_interval=='600')
 for _,case in ipairs({'missing-confirmation','source-changed','candidate-changed','malformed','commit-failure'})do
  local form={config_payload=backup,mode='restore',confirmation=confirmation}
  if case=='missing-confirmation'then form.confirmation=''elseif case=='candidate-changed'then form.config_payload=backup:gsub('600','900')elseif case=='malformed'then form.config_payload='not a backup'end
  h=host('config_import',true,form);h.changed_source=case=='source-changed';h.fail_commit=case=='commit-failure';r=execute(h)
  local inner=r.body and lib.strict(r.body)
  check('maintenance/import-reject/'..case,inner and not inner.ok and h.documents.homegate[1].values.ddns_interval=='300' and h.commits==(case=='commit-failure' and 1 or 0))
 end
 for route,form in pairs({maintenance_apply={mode='save',log_level='warn',log_max_lines='512'},wol_apply={mode='save',wol_interface='br-lan',wol_host_count='0'}})do
  h=host(route,true,form);r=execute(h);check('shared-writer/'..route,r.ok and h.commits==1)
 end
 h=host('config_reset',true);r=execute(h);check('maintenance/reset-keeps-default-disabled',r.ok and h.commits==1 and h.documents.homegate[1].values.enabled=='0' and h.documents.homegate[1].values.renew_days=='5')
 h=host('diagnostic_download',true);r=execute(h);check('maintenance/diagnostic-attachment',r.ok and r.body and r.headers['Content-Disposition']:find('homegate-diagnostic.txt',1,true) and h.commits==0)
 cases[#cases+1]={name='live-DNS-ACME-proxy-firewall-WOL',status='SKIP',scope='requires-router-and-external-infrastructure'}
 table.sort(cases,function(a,b)return a.name<b.name end)
 local after,micro=nx.gettimeofday()
 return {api_version=1,native=true,version=version,ok=passed,cases=cases,duration_ms=math.max(0,math.floor((after-sec)*1000+(micro-usec)/1000)),phase='selftest',effect='none',write_ready=false,target_ABI_verified=false}
end
