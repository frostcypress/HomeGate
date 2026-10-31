-- Execute the frozen controller with a virtual UCI cursor and fixed host API.
-- No request selects Lua code, a shell command, a filesystem root or a writer.
local function run(fixture)
local base=assert(arg[0]:match('^(.*)/[^/]+$'));local proto=base..'/project/core/prototype'
local lib=assert(loadfile(base..'/native-web-store.lua'))('library')
local fs=require('nixio.fs');local json=require('luci.jsonc');local nx=require('nixio')
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local original_io,original_os=io,os
local write=fixture and fixture.write or arg[1]=='write'
local request,work
if fixture then
 local d,types=lib.strict(fixture.request)
 request=lib.validate(d,types or {},write)
 if not request then return {api_version=1,ok=false,error='Invalid request'}end
 work='/offline-memory'
else request=lib.request(arg[2],write);work=arg[2]:match('^(.*)/[^/]+$')end
local result={api_version=1,ok=false,headers={}};local bytes=0;local private={};local documents={};local files={};local revision
local needs_config_write=write and not ({config_export=true,config_import=true,diagnostic_download=true,log_clear=true})[request.route]
local effect_started=false
local pending_imports={}
local stopped_for_save=false
local function quote(s)return "'"..tostring(s):gsub("'","'\\''").."'"end
local function capture(command,limit)
 if fixture then return fixture.shell(command)end
 local f=assert(original_io.popen(command.." 2>/dev/null; printf '\\nHGWEBEXIT:%s\\n' \"$?\"",'r'))
 local raw=f:read((limit or 2097152)+65) or '';f:close()
 local body,code=raw:match('^(.*)\nHGWEBEXIT:(%d+)\n$');if not body or #body>(limit or 2097152)then error('bounded command response')end
 return body,tonumber(code)
end
local function call(argv,input,limit)
 local args={};for _,v in ipairs(argv)do args[#args+1]=quote(v)end
 local path=work..'/call-input';local command=table.concat(args,' ')
 if input then lib.write(path,input);command=command..' < '..quote(path)end
 local raw,code=capture(command,limit);if input then assert(fs.unlink(path))end
 return raw,code
end
local function core(args,input)
 if fixture then return fixture.shell('/usr/bin/homegate '..table.concat(args,' '))end
 -- Public read routes consume the compatible CLI reports. The virtual file
 -- adapter alone needs the typed single-certificate maintenance report.
 local entry=write and base..'/native-cli-internal.sh' or '/usr/bin/homegate'
 if not write and args[1]=='cert-status' and #args==2 then entry=base..'/native-cli-core.sh'end
 local argv={'ash',entry}
 for _,v in ipairs(args)do argv[#argv+1]=v end;return call(argv,input)
end
local function decoded(args,input)
 local raw,code=core(args,input);return json.parse(raw),code
end
local function validate_pair(cert,key)
 local job=work:match('/([0-9a-f]+)$');if not write or not job or #job~=32 then return '',1 end
 local raw,rc=call({'ash',base..'/native-web-cert-preview.sh',job},codec.json({certificate_pem=cert,private_key_pem=key}))
 if rc~=0 then result.failure_stage='certificate-validation';result.exit_code=rc end;return raw,rc
end
local function copy(v)if type(v)~='table'then return v end;local d={};for k,x in pairs(v)do d[k]=copy(x)end;return d end
local function load_document(pkg)
 if documents[pkg]then return documents[pkg]end
 if fixture then documents[pkg]=copy(fixture.documents[pkg] or {});return documents[pkg]end
 if pkg~='homegate'then
  local doc={};if pkg=='network' or pkg=='dhcp'then
   pcall(function()local count=0;require('luci.model.uci').cursor():foreach(pkg,nil,function(s)
    count=count+1;if count>512 then error('inventory limit')end
    local values={};for k,v in pairs(s)do if k:sub(1,1)~='.'then values[k]=copy(v)end end
    doc[#doc+1]={name=s['.name'],kind=s['.type'],values=values}
   end)end)
  end
  documents[pkg]=doc;return doc
 end
 local raw,code=capture('ash '..quote(proto..'/homegate-config-prototype.sh')..' --persistent editor-state-read 3>&1 >/dev/null')
 local state=code==0 and lib.strict(raw)
 if type(state)=='table' and type(state.configuration)=='table' and type(state.revision)=='number'then revision=state.revision;documents[pkg]=state.configuration
 else
  local f=original_io.open('/etc/config/homegate','rb');local source=f and f:read(262145);if f then f:close()end
  local d=source and #source<=262144 and codec.private_configuration(source)
  documents[pkg]=d and d.configuration or {}
  if d then for _,s in ipairs(documents[pkg])do
   local v=s.values;local flags=d.switches[s.name] or {};if flags.enabled then v.enabled=flags.enabled end;if flags.access_enabled then v.access_enabled=flags.access_enabled end
   for _,key in ipairs(s.kind=='dns_account' and {'key_id','secret','account_id','endpoint'} or s.kind=='ddns_rule' and {'url'} or s.kind=='web_rule' and {'target'} or {})do
    local prefix=s.kind=='dns_account' and v.provider or s.kind=='ddns_rule' and 'ddns' or 'web';local value=d.credentials[prefix..'.'..s.name..'.'..key];if value then v[key=='key_id' and 'id' or key]=value end
   end
  end end
  if needs_config_write then
   local factory=assert(original_io.open(base..'/factory.config','rb'));local expected=factory:read(262145);factory:close()
   if source~=expected then error('Source adoption required in configuration maintenance')end
   local _,rc=core({'prepare'});if rc~=0 then error('Configuration initialization unavailable')end
   documents[pkg]=nil;return load_document(pkg)
  end
 end
 for _,s in ipairs(documents[pkg])do
  if s.kind=='dns_account'then for _,k in ipairs({'id','secret','account_id','endpoint'})do local v=s.values[k];if v and v~=''then private[#private+1]=v end end
  elseif s.kind=='ddns_rule' and s.values.url then private[#private+1]=s.values.url
  elseif s.kind=='web_rule' and s.values.target then
   local credentials=s.values.target:match('^https?://([^/@]+)@');if credentials then private[#private+1]=credentials end
  end
 end
 return documents[pkg]
end
local function find(pkg,name)
 for _,s in ipairs(load_document(pkg))do if s.name==name then return s end end
end
local function masked(s)
 s=s:gsub('(https?://)[^/@%s]+@','%1[redacted]@')
 for _,v in ipairs(private)do if #v>=4 then s=s:gsub(v:gsub('([^%w])','%%%1'),'[redacted]')end end
 return s
end
local function public(v,key)
 if type(v)=='string'then if key=='secret' or key=='private_key_pem' or key=='key_id' or key=='provider_account_id' or key=='endpoint'then return ''end;return masked(v)end
 if type(v)~='table'then return v end;local d={};for k,x in pairs(v)do d[k]=public(x,k)end;return d
end
local function text(doc)
 local rows={}
 for _,s in ipairs(doc)do
  rows[#rows+1]='config '..s.kind..' '..quote(s.name)
  local keys={};for k in pairs(s.values)do if k:sub(1,1)~='.'then keys[#keys+1]=k end end;table.sort(keys)
  for _,k in ipairs(keys)do local value=s.values[k]
   if type(value)=='table'then for _,v in ipairs(value)do rows[#rows+1]=' list '..k..' '..quote(v)end
   elseif type(value)=='string'then rows[#rows+1]=' option '..k..' '..quote(value)else error('configuration value')end
  end
 end
 return table.concat(rows,'\n')..'\n'
end
local changed=false
local cursor={}
function cursor:get_all(pkg,name)local s=find(pkg,name);if not s then return nil end;local row=copy(s.values);row['.name']=s.name;row['.type']=s.kind;return row end
function cursor:get(pkg,name,key)local s=find(pkg,name);if s then if key then return s.values[key]end;return s.kind end end
function cursor:foreach(pkg,kind,cb)
 for i,s in ipairs(copy(load_document(pkg)))do if not kind or s.kind==kind then local row=copy(s.values);row['.name']=s.name;row['.type']=s.kind;row['.index']=i-1;cb(row)end end
end
function cursor:set(pkg,name,key,value)
 if not write or pkg~='homegate' or type(key)~='string' or not key:match('^[a-zA-Z0-9_]+$')then return false end
 local s=find(pkg,name);if not s then return false end
 if type(value)=='string' and type(s.values[key])=='string' and value==masked(s.values[key])then value=s.values[key]end
 s.values[key]=copy(value);changed=true;return true
end
function cursor:section(pkg,kind,name,values)
 if not write or pkg~='homegate' or find(pkg,name) or not name:match('^[a-zA-Z0-9_-]+$')then return false end
 local doc=load_document(pkg);doc[#doc+1]={name=name,kind=kind,values=copy(values or {})};changed=true;return name
end
function cursor:delete(pkg,name,key)
 if not write or pkg~='homegate'then return false end
 local s=find(pkg,name);if not s then return true end
 if key then s.values[key]=nil else local out={};for _,v in ipairs(load_document(pkg))do if v.name~=name then out[#out+1]=v end end;documents[pkg]=out end
 changed=true;return true
end
function cursor:revert(pkg)documents[pkg]=nil;changed=false;return true end
function cursor:commit(pkg)
 if not write or pkg~='homegate'then return false end
 if not changed then return true end
 if fixture then
  fixture.commits=fixture.commits+1
  if fixture.fail_commit then return false end
  fixture.documents[pkg]=copy(documents[pkg]);changed=false;return true
 end
 local body=text(load_document(pkg))
 local status,status_code=decoded({'status'})
 if status_code==0 and status and status.service and status.service.running then
  local _,rc=core({'service-stop','--confirm'});if rc~=0 then return false end
  local quiet=false
  for i=1,40 do local _,code=core({'service-quiescent'});if code==0 then quiet=true;break end;call({'sleep','.2'},nil,1)end
  if not quiet then result.failure_stage='runtime-stop';return false end
  stopped_for_save=true;result.runtime_stopped_for_save=true
 end
 effect_started=true
 local raw,code=call({'ash',proto..'/homegate-config-prototype.sh','--persistent','editor-preview',tostring(revision)},body)
 local preview=json.parse(raw);if code~=0 or type(preview)~='table' or type(preview.confirmation)~='string'then result.failure_stage='editor-preview';result.exit_code=code;return false end
 local d,rc=decoded({'config-commit',preview.confirmation});if rc~=0 or not d or not d.ok then result.failure_stage='editor-publish';result.exit_code=rc;return false end
 for id,pair in pairs(pending_imports)do
  local material,code=decoded({'cert-import-stdin',id},codec.json(pair))
  if code~=0 or not material or not material.ok then result.failure_stage='certificate-publication';result.uncertain=true;return false end
 end
 pending_imports={}
 changed=false;revision=d.configuration_revision or d.revision or revision+2;return true
end
local function words(command)
 command=command:gsub('%s+>%s*/dev/null%s+2>&1$',''):gsub('%s+2>/dev/null$','')
 local out,part,quotechar,active={},'',nil,false;local i=1
 while i<=#command do local c=command:sub(i,i)
  if quotechar then
   if c==quotechar then quotechar=nil elseif c=='\\' and quotechar=='"'then i=i+1;part=part..command:sub(i,i)else part=part..c end
  elseif c=='"' or c=="'"then quotechar=c;active=true
  elseif c:match('%s')then if active then out[#out+1]=part;part='';active=false end
  elseif c:find('[;&|<>$`()]')then return nil
  elseif c=='\\'then i=i+1;part=part..command:sub(i,i);active=true
  else part=part..c;active=true end;i=i+1
 end
 if quotechar then return nil end;if active then out[#out+1]=part end;return out
end
local function virtual_file(path,mode)
 if fixture then return nil end
 local writable=mode and (mode:find('w',1,true) or mode:find('a',1,true))
 if writable then
  if not write or not(path:match('^/tmp/homegate%-local%-cert%-%d+%.pem$') or path:match('^/tmp/homegate%-local%-key%-%d+%.pem$') or path:match('^/tmp/homegate%-access%-validate%-%d+$') or path=='/var/log/homegate.log')then return nil end
  files[path]=mode:find('a',1,true) and files[path] or ''
 elseif not files[path] or path=='/proc/sys/kernel/random/uuid'then
  if path=='/var/log/homegate.log'then local d=decoded({'log-events'});local rows={};for _,v in ipairs(d and d.events or {})do rows[#rows+1]=v.raw end;files[path]=table.concat(rows,'\n')
  elseif path=='/proc/sys/kernel/random/uuid' or path=='/proc/net/arp' or path=='/tmp/dhcp.leases'then
   local f=original_io.open(path,'rb');if not f then return nil end;files[path]=f:read(262145) or '';f:close();if #files[path]>262144 then return nil end
  else return nil end
 end
 local f={};local pos=1
 function f:read(spec)
  local raw=files[path] or '';if pos>#raw then return nil end
  if type(spec)=='number'then local r=raw:sub(pos,pos+spec-1);pos=pos+#r;return r end
  if spec=='*a'then local r=raw:sub(pos);pos=#raw+1;return r end
  local n=raw:find('\n',pos,true);local r=raw:sub(pos,n and n-1 or #raw);pos=n and n+1 or #raw+1;return r
 end
 function f:lines()return function()return self:read('*l')end end
 function f:write(...)
  if not writable then return nil end;local raw=table.concat({...});if #(files[path] or '')+#raw>1048576 then error('private file limit')end;files[path]=(files[path] or '')..raw;return self
 end
 function f:close()
  if writable and path=='/var/log/homegate.log'then
   local a=fs.lstat(path);if a and (a.type~='reg' or a.uid~=0 or a.modedec~=600 or a.nlink~=1)then error('unsafe log')end
   local fd=nx.open(path,nx.open_flags('wronly','creat','trunc'),'600');if not fd then error('log')end;assert(fd:close())
  end;return true
 end
 return f
end
local function shell(command)
 if fixture then return fixture.shell(command)end
 local isolated=command:match('^HOMEGATE_HOME_DIR=/tmp/homegate%-local%-validate%-%d+ (.+)$')
 if isolated then
  local a=words(isolated);if not write or not a or a[1]~='/usr/bin/homegate' or a[2]~='cert-import' or #a~=5 then return '',1 end
  local cert,key=files[a[4]],files[a[5]];if not cert or not key then return '',1 end
  return validate_pair(cert,key)
 end
 local argv=words(command)
 if argv and argv[1]=='/usr/bin/homegate'then
  table.remove(argv,1);local action=argv[1]
  if not write and not ({version=true,status=true,check=true,['network-resolve']=true,['ddns-status']=true,['cert-status']=true,['proxy-status']=true,['access-status']=true,['access-recent']=true,['firewall-status']=true,['wol-status']=true,['log-events']=true,['dns-zones']=true,['dns-provider-catalog']=true,['acme-ca-catalog']=true})[action]then return '',1 end
  if action=='access-validate-file'then
   local body=files[argv[2]];if not body then return '',1 end
   local raw,rc=call({'lua',base..'/native-adapters.lua','access-stdin'},body);return raw,rc
  end
  if action=='cert-import'then
   local cert,key=files[argv[3]],files[argv[4]];if not cert or not key then return '',1 end
   local raw,rc=validate_pair(cert,key);local d=json.parse(raw)
   if rc~=0 or not d or not d.ok then return raw,1 end
   pending_imports[argv[2]]={certificate_pem=cert,private_key_pem=key};return raw,0
  end
  if action=='cert-renew'then
   if not write or #argv~=2 then return '',1 end
   local job=work:match('/([0-9a-f]+)$');if not job or #job~=32 then return '',1 end
   local deadline=tonumber(lib.read(work..'/deadline',16));if not deadline then return '',1 end
   effect_started=true;result.native_job=job
   local d,rc=decoded({'acme-issue',argv[2],job,'--confirm'});if rc~=0 or not d or not d.ok then return codec.json(d or {ok=false,job=job}),1 end
   while true do
    local status,code=decoded({'acme-job',job})
    if code~=0 or not status then result.uncertain=true;return codec.json({ok=false,job=job}),1 end
    if status.pending==false then
     local success=status.ok and status.cleanup_required==false and (status.state=='issued' or status.state=='skipped')
     if not success and (status.cleanup_required or status.state=='unknown')then result.uncertain=true end
     return codec.json(status),success and 0 or 1
    end
    local now,nrc=call({'lua',proto..'/worker-process.lua','now'},nil,32)
    if nrc~=0 or not tonumber(now) or tonumber(now)>=deadline-15 then
     core({'acme-stop',job,'--confirm'});result.uncertain=true;return codec.json({ok=false,job=job,error='Certificate task retained for inspection'}),1
    end
    call({'sleep','.2'},nil,1)
   end
  end
  return core(argv)
 elseif argv and argv[1]=='/etc/init.d/homegate'then
  if not write or #argv~=2 or not({reload=true,start=true,stop=true,enable=true,disable=true})[argv[2]]then return '',1 end
  if argv[2]=='reload'then
   local main=find('homegate','main')
   if not main then return '',1 end
   if main.values.enabled~='1'then
    local _,rc=core({'service-stop','--confirm'});if rc~=0 then return '',rc end
    local raw,code=core({'lifecycle-disable','--confirm'});if code==0 then capture('exec 8>&-; /etc/init.d/homegate disable')end;return raw,code
   end
   local _,stop=core({'service-stop','--confirm'});if stop~=0 then return '',1 end
   local _,quiet=core({'service-quiescent'});if quiet~=0 then return '',1 end
   local ddns,certs,web={},{},{}
   for _,s in ipairs(load_document('homegate'))do
    if s.kind=='certificate' and fs.lstat('/etc/homegate/certs/'..s.name..'/fullchain.pem') and not fs.lstat('/etc/homegate/certs/'..s.name..'/current')then
     local _,rc=core({'cert-adopt',s.name,'--confirm'});if rc~=0 then result.failure_stage='legacy-certificate-adoption';return '',1 end
    end
    if s.values.enabled=='1'then
     if s.kind=='ddns_rule'then ddns[#ddns+1]=s.name
     elseif s.kind=='web_rule'then web[#web+1]=s.name
     elseif s.kind=='certificate' and s.values.source=='acme'then certs[#certs+1]=s.name end
    end
   end
   for _,list in ipairs({ddns,certs,web})do table.sort(list)end
   local _,enabled=core({'lifecycle-enable','--confirm'});if enabled~=0 then return '',1 end
   local grant,rc
   if #ddns==1 then grant,rc=decoded({'grant-preview',ddns[1]})
   elseif #ddns>1 then local raw;raw,rc=call({'ash',proto..'/homegate-ddns-authority.sh','preview-rules',table.concat(ddns,',')});grant=json.parse(raw)end
   if #ddns>0 then
    if rc~=0 or not grant or not grant.confirmation then return '',1 end
    local _,code=core({'grant-commit',grant.confirmation});if code~=0 then return '',1 end
   elseif fs.lstat('/etc/homegate/transactions/ddns-authority')then local _,code=core({'grant-revoke','--confirm'});if code~=0 then return '',1 end end
   local function selection(v)return #v>0 and table.concat(v,',') or '-'end
   local _,plan=core({'service-plan-set',selection(ddns),selection(certs),selection(web),main.values.access_enabled=='1' and 'allow' or 'open','--confirm'});if plan~=0 then return '',1 end
   local current=tonumber(lib.read('/etc/homegate/transactions/current',16));if not current then return '',1 end
   result.runtime_start={revision=current};return '',0
  end
  return capture('exec 8>&-; '..quote(argv[1])..' '..quote(argv[2]))
 elseif argv and argv[1]=='opkg' and argv[2]=='status' and #argv==3 then
  local name=argv[3]=='homegate' and 'homegate-core' or argv[3]
  if not ({['homegate-core']=true,['luci-app-homegate']=true,['luci-i18n-homegate-zh-cn']=true})[name]then return '',1 end
  local path='/usr/lib/opkg/info/'..name..'.control';local a=fs.lstat(path);if not a or a.type~='reg' or a.uid~=0 or a.size>65536 then return '',1 end
  local f=assert(original_io.open(path,'rb'));local raw=f:read(65537);f:close();return raw,0
 elseif command:match('^for b in /sys/class/net/%*; do')then
  local rows={};local listing=fs.dir('/sys/class/net');if not listing then return '',0 end;for name in listing do
   if name:match('^[a-zA-Z0-9_.:-]+$') and fs.stat('/sys/class/net/'..name..'/bridge')then
    rows[#rows+1]='B|'..name
    local p='/sys/class/net/'..name..'/brif';if fs.stat(p)then for member in fs.dir(p)do if member:match('^[a-zA-Z0-9_.:-]+$')then local wifi=fs.stat('/sys/class/net/'..member..'/wireless') or fs.stat('/sys/class/net/'..member..'/phy80211');rows[#rows+1]='M|'..name..'|'..member..'|'..(wifi and 'wifi' or 'ethernet')end end end
   end
  end;return table.concat(rows,'\n'),0
 elseif command=='cat /sys/class/net/*/address 2>/dev/null' or command=='ip neigh show 2>/dev/null' or command=='bridge fdb show 2>/dev/null'then return capture(command,262144)
 elseif command=='tail -n 300 /var/log/homegate.log 2>/dev/null'then local f=virtual_file('/var/log/homegate.log','r');return f and f:read('*a') or '',0
 elseif command:match('^rm %-f /var/run/homegate/acme%-renew/[a-zA-Z0-9_-]+%.json')then return '',0
 elseif command:match('^rm %-rf /etc/homegate/certs/[a-zA-Z0-9_-]+ >')then
  local id=command:match('^rm %-rf /etc/homegate/certs/([a-zA-Z0-9_-]+) >')
  if not id then return '',1 end
  local raw,code=core({'cert-purge',id,'--confirm'});if code~=0 then result.material_retained=true end;return raw,code
 end
 return '',1
end
local modules={}
modules['luci.model.uci']={cursor=function()return cursor end}
modules['luci.model.homegate.backup']=codec
modules['luci.model.homegate.writer']={run=function(route,fn)if not write or route~=request.route then error('writer route')end;if fixture then fixture.begins=fixture.begins+1 end;return fn()end}
modules['luci.jsonc']={parse=json.parse,stringify=codec.json}
modules['luci.sys']={exec=function(c)local raw=shell(c);return raw end,call=function(c)local _,rc=shell(c);return rc end}
modules['luci.dispatcher']={context={authtoken='rpc'},build_url=function(...)return '/cgi-bin/luci/'..table.concat({...},'/')end}
modules['luci.http']={formvalue=function(k)if k then return request.form[k]end;return request.form end,
 urlencode=function(v)return tostring(v):gsub('[^a-zA-Z0-9_.~-]',function(c)return string.format('%%%02X',c:byte())end)end,
 redirect=function(v)
  if type(v)~='string' or #v>4096 or v:find('[\r\n%z]') or not v:match('^/cgi%-bin/luci/admin/services/homegate/[%w_/]+[?]?')then error('redirect')end
  result.redirect=v;if result.material_retained then result.error='证书材料已保留，尚未完成清理。请先在维护中核对，不要重复操作。';result.redirect=nil
  elseif v:find('[?&]error=')then result.error=result.failure_stage=='runtime-confirmation-required' and '配置已保存。请在任务授权与运行操作中确认新范围后启动服务。' or 'HomeGate operation refused; configuration or retained operation requires attention'end
  if result.redirect and not result.error and stopped_for_save and not result.runtime_start then
   local notice=modules['luci.http'].urlencode('配置已保存，任务已停止；应用后重新启动。');result.redirect=result.redirect:gsub('([?&]notice=)[^&]*',function(prefix)return prefix..notice end)
  end
 end,
 prepare_content=function(v)result.headers['Content-Type']=v end,
 header=function(k,v)if k~='Content-Disposition' or #v>256 or v:find('[\r\n%z]')then error('header')end;result.headers[k]=v end,
 write=function(v)if type(v)~='string'then error('response')end;bytes=bytes+#v;if bytes>2097152 then error('response limit')end;result.body=(result.body or '')..v end}
modules['luci.template']={render=function(name,data)
 if not name:match('^homegate/[a-z]+$')then error('template')end;result.template=name;result.data=public(data)
end}
modules['nixio.fs']={chmod=function(path)if files[path]then return true end;return false end,stat=function(path)
 if fixture then return nil end
 local cid=path:match('^/etc/homegate/certs/([a-zA-Z0-9_-]+)/fullchain%.pem$') or path:match('^/etc/homegate/certs/([a-zA-Z0-9_-]+)/privkey%.pem$')
 if cid then local d=decoded({'cert-status',cid});return d and d.exists and {mtime=0,size=0} or nil end
 if path=='/etc/homegate/access/regions/CN.cidr'then return fs.stat('/etc/homegate/access/CN.cidr')end
 return nil
end}
local env={_M=nil,module=function()end,package={seeall=true},require=function(name)if not modules[name]then error('module unavailable')end;return modules[name]end,
 io={open=virtual_file},os={time=os.time,date=os.date,remove=function(p)if files[p]then files[p]=nil;return true end;return false end},math=math,string=string,table=table,tonumber=tonumber,tostring=tostring,type=type,pairs=pairs,ipairs=ipairs,next=next,assert=assert,error=error,pcall=pcall,select=select,unpack=unpack,_=function(s)return s end}
env._M=env
local ok,err=pcall(function()
 local fn=assert(loadfile(base..'/legacy-controller.lua'));setfenv(fn,env);fn()
 local handler=env[lib.routes[request.route].handler];if type(handler)~='function'then error('route handler')end;handler()
 result.ok=result.error==nil
end)
if not ok then result={api_version=1,ok=false,error='Native Web operation unavailable; inspect current configuration and retained tasks',error_site=tostring(err):match('%.lua:(%d+):'),uncertain=effect_started or nil}end
if result.body then result.body=masked(result.body)end
if result.redirect then result.redirect=masked(result.redirect)end
if result.headers and next(result.headers)==nil then result.headers=nil end
if fixture then return result end
io.write(codec.json(result),'\n')
end
-- Only the fixed installed selftest invokes this library with a memory host.
-- Ordinary CLI/HTTP requests cannot select or serialize a fixture capability.
if ...=='library'then return run end
run()
