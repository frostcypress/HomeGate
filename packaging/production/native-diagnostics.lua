-- Collect bounded status and receipts for the maintenance download.
local fs=require('nixio.fs')
local json=require('luci.jsonc')
local nx=require('nixio')
local run='/var/run/homegate'

local function read(path, limit, private)
 local before=fs.lstat(path)
 if not before or before.type~='reg' or before.uid~=0 or before.nlink~=1 or before.size>limit then return nil end
 if before.modedec~=600 and (private or before.modedec~=644) then return nil end
 local file=io.open(path,'rb')
 if not file then return nil end
 local body=file:read(limit+1) or ''
 file:close()
 local after=fs.lstat(path)
 if not after or after.ino~=before.ino or after.dev~=before.dev or after.size~=before.size or #body~=before.size then return nil end
 return body
end

local function decode(raw)
 local data=raw and json.parse(raw)
 return type(data)=='table' and data or {}
end

local function fields(data, keys)
 local selected={}
 if type(data)~='table' then return selected end
 for key in keys:gmatch('%S+') do
  local value=data[key]
  local kind=type(value)
  if kind=='number' or kind=='boolean' or (kind=='string' and #value<=128 and value:match('^[%w_.:+%-]+$')) then
   selected[key]=value
  end
 end
 return selected
end

local reports={
 {'homegate status','status','ok state_unknown configuration_revision'},
 {'configuration transaction','config-status','ok revision history_capacity history_remaining credential_capacity preview_present application_pending application_phase workers_pending service_intent_bound persistent_fence_pending'},
 {'recovery','recovery-status','ok phase status state reason pending uncertain'},
 {'network','network-resolve','ok phase state reason'},
 {'ddns','ddns-status','ok phase state interval_seconds configuration_revision'},
 {'ddns scheduler','schedule-status','ok status running reason ticks last_effect admission_limit'},
 {'certificates','cert-status','ok phase state'},
 {'proxy','proxy-status','ok state configured enabled generation routes policy access_region access_enabled cn_available cn_snapshot audit_available health_checked http_listening https_listening http_port https_port reload_state firewall_cleanup_ok'},
 {'access','access-status','ok state region cache_valid cache_stale cache_updated cache_updated_epoch ipv4 ipv6 policy runtime_active'},
 {'firewall','firewall-status','ok known active state managed automatic_reconcile backend family effect wan'},
 {'wol','wol-status','ok state running configured pending'}
}

local function report_source(raw,code)
 local data=decode(raw)
 return data,type(code)=='number' and code or nil
end

return function(core, call, config, lib, work)
 local lines={'HomeGate diagnostic report','generated='..os.date('!%Y-%m-%dT%H:%M:%SZ'),'format=2'}
 local function section(title, data)
  lines[#lines+1]=''
  lines[#lines+1]='['..title..']'
  lines[#lines+1]=next(data) and lib.encode(data) or 'unavailable'
 end
 local function invoke(fn, args)
  local ok,raw,code=pcall(fn,args)
  if ok then return raw,code end
 end
 local system=nx.uname()
 local version=report_source(invoke(core,{'version'}))
 local firmware='\n'..(read('/etc/openwrt_release',8192) or '')..'\n'
 section('system',fields({
  version=version.version, architecture=version.system_arch or system.machine,
  kernel=system.release,
  firmware=firmware:match("\nDISTRIB_ID=['\"]?([%w_.%-]+)['\"]?\n"),
  firmware_release=firmware:match("\nDISTRIB_RELEASE=['\"]?([%w_.%-]+)['\"]?\n")
 },'version architecture kernel firmware firmware_release'))
 local packages={}
 for _,name in ipairs({'homegate-core','luci-app-homegate','luci-i18n-homegate-zh-cn'}) do
  local control=read('/usr/lib/opkg/info/'..name..'.control',8192) or ''
  packages[name]=fields({
   version=('\n'..control):match('\nVersion: ([^\r\n]+)'),
   architecture=('\n'..control):match('\nArchitecture: ([^\r\n]+)')
  },'version architecture')
 end
 section('packages',packages)

 for _,item in ipairs(reports) do
  local title,command,keys=unpack(item)
  local data,code=report_source(invoke(core,{command}))
  local report=fields(data,keys..' error_kind')
  report.exit_code=code
  if data.error=='Shared writer is busy' then report.error_kind='shared_writer_busy' end
  if data.error=='Configuration busy' then report.error_kind='configuration_busy' end
  if command=='status' then
   report.service=fields(data.service,'configured enabled running healthy')
   report.coordinator=fields(data.coordinator,'state reason')
  elseif command=='network-resolve' then
   local network=type(data.network)=='table' and data.network or data
   report.wan=fields(network.wan,'device interface available source')
   report.wan_public_ipv6=type(network.wan)=='table' and type(network.wan.public_ipv6)=='string' or false
  elseif command=='ddns-status' or command=='cert-status' then
   local entries=command=='ddns-status' and (data.results or data.rules) or data.certificates
   if type(entries)=='table' then
    report.entries={}
    for i=1,math.min(#entries,128) do
     report.entries[i]=fields(entries[i],
      'rule certificate state status enabled environment ca valid exists identity_valid days pending error_kind retryable event_at at last_result last_effect')
    end
   end
  elseif command=='firewall-status' and type(data.mappings)=='table' then
   report.mappings={}
   for i=1,math.min(#data.mappings,8) do report.mappings[i]=fields(data.mappings[i],'public private') end
  end
  section(title,report)
 end
 section('service receipt',fields(decode(read(run..'/native-service.json',16384,true)),
  'ok version state reason pid running healthy configuration_revision cleanup_confirmed'))
 local proxy_receipt=lib.dir(run..'/proxy') and read(run..'/proxy/report',16384,true)
 section('proxy receipt',fields(decode(proxy_receipt),
  'state reason reload_state firewall_cleanup_ok error_kind'))
 local update=run..'/access-update'
 local region={}
 if lib.dir(update) then
  region=fields(decode(read(update..'/report',4096,true)),'state error_kind')
  region.transport_exit=tonumber(read(update..'/transport',16,true))
  region.http_status=tonumber(read(update..'/http',16,true))
 end
 local data,code=report_source(invoke(call,{'ash','/usr/libexec/homegate/project/core/prototype/homegate-access-region.sh','status'}))
 region.cache=fields(data,'ok state error_kind running cache_valid cache_stale ipv4 ipv6 cache_updated')
 region.status_exit=code
 section('region update',region)
 local curl=invoke(call,{'/usr/bin/curl','-V'}) or ''
 local curl_version=curl:match('^curl ([%d.]+)')
 local features=curl:match('\nFeatures: ([%w .%-]+)')
 section('download transport',{curl_version=curl_version, features=features})

 local settings,counts={},{}
 for _,item in ipairs(config) do
  if item.kind=='homegate' and item.name=='main' then
   settings=fields(item.values,'enabled access_enabled access_region auto_firewall ddns_interval https_port http_port proxy_https_port proxy_http_port log_level log_max_lines')
   if settings.log_level=='debug' then settings.log_level='info' end
  elseif ({dns_account=true,ddns_rule=true,web_rule=true,certificate=true,wol_host=true})[item.kind] then
   counts[item.kind]=(counts[item.kind] or 0)+1
  end
 end
 local pending={}
 for _,name in ipairs({'package-state','package-config','transactions/application','transactions/startup-intent',
  'transactions/dns-operation','transactions/dns-batch-results','transactions/dns-retirement','transactions/dns-collection'}) do
  pending[name]=fs.lstat('/etc/homegate/'..name)~=nil
 end
 section('configuration',{settings=settings,counts=counts,pending=pending})

 local jobs={}
 local entries=lib.dir(lib.root) and fs.dir(lib.root)
 if entries then
  for name in entries do
   local path=lib.root..'/'..name
   if lib.id(name) and path~=work and lib.dir(path) then
    local receipt=read(path..'/result',32768,true)
    local job=fields(decode(receipt),
     'ok failure_stage runtime_failure_reason uncertain configuration_saved runtime_applied runtime_stopped_for_save init_start_exit receipt_exit error_site editor_stage editor_blocker access_region_state')
    local request=decode(read(path..'/request',8192,true))
    if type(request.route)=='string' and lib.routes[request.route] then job.route=request.route end
    job.result_present=fs.lstat(path..'/result')~=nil
    job.owner_receipt_present=fs.lstat(path..'/owner.lock')~=nil
    jobs[#jobs+1]=job
    if #jobs>=8 then break end
   end
  end
 end
 section('retained web tasks',{count=#jobs,jobs=jobs})
 local logs=report_source(invoke(core,{'log-events','512'}))
 lines[#lines+1]=''
 lines[#lines+1]='[recent log, UTC, newest first]'
 if type(logs.events)=='table' then
  local bytes=0
  for i=#logs.events,1,-1 do
   local row=logs.events[i]
   if type(row)=='table' and type(row.raw)=='string' then
    local raw=row.raw:sub(1,4096)
    bytes=bytes+#raw+1
    if bytes>131072 then lines[#lines+1]='[older log entries omitted]';break end
    lines[#lines+1]=raw
   end
  end
 else lines[#lines+1]='unavailable' end
 return table.concat(lines,'\n')..'\n'
end
