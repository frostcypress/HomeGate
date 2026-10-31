-- Public report compatibility only. No action, credential value or retry here.
local base=assert(arg[0]:match('^(.*)/[^/]+$'));local fs=require('nixio.fs');local json=require('luci.jsonc')
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local command=arg[1]
local function read(p,n,public)
 local a=fs.lstat(p);assert(a and a.type=='reg' and a.uid==0 and a.nlink==1 and a.size<=n and (a.modedec==600 or public and a.modedec==644))
 local f=assert(io.open(p,'rb'));local raw=f:read(n+1) or '';assert(f:close());local b=assert(fs.lstat(p))
 assert(#raw<=n and a.dev==b.dev and a.ino==b.ino and a.size==b.size and a.modedec==b.modedec);return raw
end
local function version()
 local v,r=read(base..'/VERSION',64,true),read(base..'/RELEASE',64,true)
 assert(v:match('^%d+%.%d+%.%d+\n$') and r:match('^[1-9]%d*\n$'));return v:sub(1,-2)..'-r'..r:sub(1,-2)
end
local function configuration()
 local doc=assert(codec.private_configuration(read('/etc/config/homegate',262144)));local by={}
 for _,s in ipairs(doc.configuration)do by[s.name]=s end
 return doc,by,assert(by.main).values
end
local function enabled(doc,name)return (doc.switches[name] or {}).enabled=='1'end
local function emit(d)io.write(codec.json(d),'\n')end
local function rule_metadata(s)
 local host,zone=s.values.host,s.values.zone
 if host=='@' or host==''then host=zone elseif host~=zone and host:sub(-#zone-1)~='.'..zone then host=host..'.'..zone end
 return {rule=s.name,name=s.values.name~='' and s.values.name or host,domain=host}
end
if command=='ddns-context'then
 local ok,d=pcall(function()
  local revision=tonumber(read('/etc/homegate/transactions/current',16));assert(revision)
  local doc,_,main=configuration();local rows={};local selected=arg[2] or ''
  for _,s in ipairs(doc.configuration)do if s.kind=='ddns_rule' and (selected=='' or selected==s.name)then rows[#rows+1]=rule_metadata(s)end end
  assert(tonumber(read('/etc/homegate/transactions/current',16))==revision)
  return {revision=revision,interval_seconds=assert(tonumber(main.ddns_interval)),started_at=os.date('!%Y-%m-%dT%H:%M:%SZ'),rules=rows}
 end)
 if not ok then emit({api_version=1,ok=false,version=version(),phase='ddns',interval_seconds=0,results={},error='DDNS configuration unavailable'});os.exit(1)end
 emit(d);return
end
if command=='log-max'then
 local v=arg[2] or '';if arg[3] or not v:match('^%+?[0-9]+$')then os.exit(2)end
 v=v:gsub('^%+',''):gsub('^0+','');local n=#v<=5 and tonumber(v)
 if not n or n<1 or n>20000 then os.exit(2)end;io.write(n,'\n');return
end
if command=='ca-selection'then
 local ca=(arg[2] or ''):match('^%s*(.-)%s*$'):lower();local env=(arg[3] or ''):match('^%s*(.-)%s*$'):lower()
 if ca=='' or ca=='le'then ca='letsencrypt'end;if env==''then env='production'end
 if arg[4] or ca~='letsencrypt' or (env~='production' and env~='staging')then os.exit(1)end
 io.write(ca,':',env,'\n');return
end
local queries={status=true,['recovery-status']=true,['network-resolve']=true,['dns-provider-catalog']=true,['acme-ca-catalog']=true,['ddns-status']=true,['cert-status']=true,['proxy-status']=true,['access-status']=true,['access-recent']=true,['firewall-status']=true,['wol-status']=true,['log-events']=true,['web-job-status']=true,['web-job-ack']=true}
local phases={status='common-runtime',check='common-runtime',['dns-provider-status']='dns-provider',['dns-zones']='dns-provider',['ddns-status']='ddns',['cert-status']='acme',['cert-renew']='acme',['cert-import']='certificate-import',['access-status']='access',['access-recent']='access',['access-clear-all']='access',['access-clear-entry']='access',['access-clear-denied']='access'}
local function run()
 local raw=io.stdin:read(16777300) or '';assert(#raw<=16777280)
 local body,code=raw:match('^(.*)\nHGCLI:(%d+)\n$');assert(body);code=tonumber(code)
 local context
 if command=='ddns-sync' or command=='ddns-delete'then
  local head,rest=body:match('^HGCTX:([^\n]+)\n(.*)$');assert(head);context=assert(json.parse(head));body=rest
 end
 local d=json.parse(body)
 if not d and body=='' and code~=0 and command=='log-events'then d={api_version=1,ok=false,phase='log-events',error='Log source unavailable',events={},count=0,events_unknown=true}end
 assert(type(d)=='table' and (type(d.ok)=='boolean' or command=='version'))
 d.api_version=d.api_version or 1;d.version=d.version or version()
 if phases[command] and d.phase~=phases[command]then d.native_phase=d.phase;d.phase=phases[command]end
 if command=='status' or command=='check'then
  if not d.service then d.service={configured=false,enabled=false,running=false,healthy=false};d.state_unknown=true end
 elseif command=='dns-provider-status' or command=='dns-zones'then
  d.account=d.account or arg[2] or ''
  if command=='dns-provider-status'then d.capabilities=d.capabilities or {};d.credentials_valid=d.credentials_valid==true
  else d.zones=d.zones or {}end
 elseif command=='cert-import' or command=='cert-renew'then
  if command=='cert-renew' and arg[2]==''then d.results=d.results or {}else d.certificate=d.certificate or arg[2] or ''end
 elseif command=='log-events'then
  if not d.events then d.events={};d.count=0;d.events_unknown=true end
 elseif command=='web-submit'then
  -- The fixed entry already validated the request file. A queue/admission
  -- failure is a valid response, matching the frozen CLI's submit semantics.
  if code~=0 then d.ok=false;d.error='Unable to queue action';d.queue_unavailable=true;code=0 end
 elseif command=='ddns-sync' or command=='ddns-delete'then
  d.ok=d.ok and code==0
  d.native_phase=d.phase;d.phase='ddns';d.interval_seconds=context.interval_seconds;d.results={}
  if d.configuration_revision and d.configuration_revision~=context.revision then d.ok=false;d.metadata_unknown=true
  else
   local metadata={};for _,r in ipairs(context.rules)do metadata[r.rule]=r end
   local rows=d.rule and {d} or d.rules or {}
   for _,r in ipairs(rows)do
    local m=metadata[r.rule];assert(m)
    local outcome=r.result or r.status;local success=outcome=='created' or outcome=='updated' or outcome=='unchanged' or outcome=='deleted'
    local status=success and (command=='ddns-delete' and 'deleted' or outcome) or 'error'
    d.results[#d.results+1]={rule=m.rule,name=m.name,domain=m.domain,status=status,at=context.started_at,at_scope='request-start',error_kind=r.error_kind~='' and r.error_kind or nil,retryable=r.retryable or false,native_status=outcome,native_effect=r.effect,reconciliation_required=r.reconciliation_required}
   end
  end
  d.updated_at=context.started_at
  if not d.ok and not d.error then d.error='one or more DDNS rules failed or require attention'end
 elseif command=='ddns-status'then
  local doc,by,main=configuration();d.interval_seconds=tonumber(main.ddns_interval);assert(d.interval_seconds)
  d.results={};for _,r in ipairs(d.rules or {})do
   local s=assert(by[r.rule]);local m=rule_metadata(s)
   local outcome=r.last_result or 'none';local failed=outcome=='inflight' or outcome=='unknown' or outcome=='paused' or outcome=='retry_wait'
   if failed then d.ok=false end
   if r.event_at and (not d.updated_at or r.event_at>d.updated_at)then d.updated_at=r.event_at end
   d.results[#d.results+1]={rule=r.rule,name=m.name,domain=m.domain,status=failed and 'error' or outcome,at=r.event_at or '',at_unknown=not r.event_at,last_result=r.last_result,error_kind=r.error_kind,native_observation=true,last_effect=r.last_effect,native_status=r.status}
  end
  if not d.ok and not d.error then d.error='one or more DDNS rules failed or require attention'end
 elseif command=='cert-status'then
  local doc,by=configuration()
  d.certificates=d.certificates or {}
  for _,r in ipairs(d.certificates or {})do local s=assert(by[r.certificate]);assert(s.kind=='certificate');r.id=r.certificate;r.name=s.values.name;r.enabled=enabled(doc,s.name);r.ca=s.values.ca end
 elseif command=='access-status'then
  local doc,_,main=configuration();d.enabled=(doc.switches.main or {}).access_enabled=='1'
  d.mode=not d.enabled and 'disabled' or main.access_region~='' and 'region' or 'manual'
  local function count(v)local seen,n={},0;for p in (v or ''):gmatch('[^,;%s]+')do if not seen[p]then seen[p]=true;n=n+1 end end;return n end
  d.manual_prefixes=count(main.access_allow);d.deny_prefixes=count(main.access_deny);d.region=main.access_region
  if d.enabled and d.mode=='region' and not d.cache_valid then d.ok=false;d.error='Configured region cache unavailable'end
  d.cache_ipv4=d.ipv4 or 0;d.cache_ipv6=d.ipv6 or 0;d.region_prefixes=d.cache_ipv4+d.cache_ipv6
  if type(d.cache_updated)=='number'then d.cache_updated_epoch=d.cache_updated;d.cache_updated=d.cache_updated>0 and os.date('!%Y-%m-%dT%H:%M:%SZ',d.cache_updated) or nil end
 elseif command=='proxy-status'then
  local doc,_,main=configuration();d.configured=0;d.enabled=0;d.domains={}
  for _,s in ipairs(doc.configuration)do if s.kind=='web_rule'then d.configured=d.configured+1;if enabled(doc,s.name)then d.enabled=d.enabled+1;d.domains[#d.domains+1]=s.values.domain end end end
  table.sort(d.domains);d.access_enabled=(doc.switches.main or {}).access_enabled=='1';d.access_region=main.access_region
  -- Never infer a listening socket from a live supervisor alone.
  d.http_listening=false;d.https_listening=false
  if d.running==true and d.state=='running'then
   local proof=assert(loadfile(base..'/native-public-listeners.lua'))()
   local ports=proof();d.http_listening=ports[tonumber(main.proxy_http_port)] or false;d.https_listening=ports[tonumber(main.proxy_https_port)] or false
   if d.http_listening then d.http_port=tonumber(main.proxy_http_port)end;if d.https_listening then d.https_port=tonumber(main.proxy_https_port)end
  end
 end
 emit(d)
 if queries[command]then return 0 end
 return code==0 and 0 or 1
end
local ok,code=pcall(run)
if not ok then emit({api_version=1,ok=false,error='Public response unavailable; inspect retained operation'});os.exit(1)end
os.exit(code)
