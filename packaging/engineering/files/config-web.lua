-- Fixed Web configuration request codec. Secrets leave only through stdin.
local base=arg[0]:match('^(.*)/[^/]+$');if not base then os.exit(1) end
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local json=require('luci.jsonc')
local function readfd(fd,limit)
 local f=io.open('/proc/self/fd/'..fd,'rb');if not f then return nil end
 local raw=f:read(limit+1) or '';local closed=f:close();if not closed or #raw>limit then return nil end;return raw
end
local function id(v)return type(v)=='string' and #v<=64 and v:match('^[a-zA-Z0-9_-]+$') end
local function hex(v)return type(v)=='string' and #v==32 and v:match('^[0-9a-f]+$') end
local schemas={backup_export={},backup_preview={'backup'},rollback_preview={'generation'},wol_status={},wol_send={'id','consent'},wol_direct={'interface','mac','consent'},preview_wol_host={'id','name','mac'},preview_wol_settings={'interface','selected_host'},firewall_status={},firewall_apply={'consent'},firewall_cleanup={'consent'},preview_access={'allow','deny','region'},access_update={'consent'},access_refresh={'consent'},access_status={},access_recent={},access_clear={'consent'},access_clear_denied={'consent'},access_stop={'consent'},access_reap={'consent'},preview_web_rule={'id','domain','https','certificate'},web_target_put={'id','value','consent'},proxy_start={'selection','policy','consent'},proxy_status={},proxy_stop={'consent'},proxy_reap={'consent'},acme_schedule_start={'id','consent'},acme_schedule_stop={'consent'},acme_schedule_status={},acme_schedule_reap={'consent'},acme_issue={'id','job','consent'},acme_renew={'id','job','consent'},acme_status={'job'},acme_stop={'job','consent'},acme_cleanup={'job','consent'},preview_acme_certificate={'id','name','account','zone','domains','email','environment'},cert_status={'id'},cert_import={'id','certificate_pem','private_key_pem','consent'},cert_resume={'id','consent'},cert_cancel={'id','consent'},preview_local_certificate={'id','name','domains'},recover={'consent'},production_copy_preview={},production_copy_commit={'confirmation','consent'},lifecycle_status={},lifecycle_enable={'consent'},lifecycle_disable={'consent'},read={},prepare={},cancel={},activate_preview={},schedule_status={},
 provider_status={'id'},zones={'id'},delete_rule={'id','consent'},
 schedule_serve={'consent'},schedule_start={'consent'},schedule_stop={'consent'},schedule_reap={'consent'},
 preview_account={'id','name','provider'},preview_rule={'id','account','zone','host','source','interface'},
 secret_put={'id','provider','slot','value','consent'},apply={'confirmation','consent'},finish={'confirmation','consent'}}
local function request()
 local raw=readfd(3,1572864);local d=raw and json.parse(raw)
 if type(d)~='table' or type(d.action)~='string' or not schemas[d.action] then return nil end
 local allowed={action=true};for _,k in ipairs(schemas[d.action])do allowed[k]=true end
 local count=0;for k,v in pairs(d)do
  if not allowed[k] or type(v)~='string' or v:find('%z') or #v>(k=='backup' and 262144 or k=='certificate_pem' and 65536 or k=='private_key_pem' and 16384 or k=='domains' and 8192 or (k=='value' or k=='allow' or k=='deny') and 4096 or 512) then return nil end;count=count+1
 end
 if count~=#schemas[d.action]+1 or #raw>(d.action=='backup_preview' and 1572864 or d.action=='cert_import' and 114688 or 32768) then return nil end
 if d.generation and (not d.generation:match('^[1-9]%d?$') or tonumber(d.generation)>32) then return nil end
 if d.action=='preview_access' and d.region~='' and d.region~='CN'then return nil end
 if d.action=='proxy_start' and (not ({open=true,allow=true})[d.policy] or not d.selection:match('^[a-zA-Z0-9_,%-]+$'))then return nil end
 if d.action=='preview_web_rule' and not ({['0']=true,['1']=true})[d.https]then return nil end
 if d.job and not hex(d.job) then return nil end
 if d.id and not id(d.id) then return nil end
 if d.provider and not ({cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true})[d.provider] then return nil end
 if d.consent and d.consent~='1' then return nil end
 if d.confirmation and not hex(d.confirmation) then return nil end
 if d.action=='preview_rule' and (not id(d.account) or not ({auto=true,interface=true})[d.source] or
    (d.source=='interface' and (#d.interface>32 or not d.interface:match('^[a-zA-Z0-9_.:-]+$')))) then return nil end
 if d.action=='secret_put' and (not ({key_id=true,secret=true,account_id=true,endpoint=true})[d.slot] or #d.value==0) then return nil end
 return d
end
if arg[1]=='request' or arg[1]=='payload' then
 local d=request();if not d then os.exit(1) end
 if arg[1]=='request' then
  io.write(d.action)
  if d.action=='rollback_preview'then io.write(':',d.generation)
  elseif d.action=='proxy_start'then io.write(':',d.selection,':',d.policy)
  elseif d.action=='wol_direct'then io.write(':',d.interface,',',d.mac)
  elseif d.action=='wol_send'then io.write(':',d.id)
  elseif d.action=='web_target_put'then io.write(':',d.id)
  elseif d.action=='acme_schedule_start' then io.write(':',d.id)
  elseif d.action=='acme_issue' or d.action=='acme_renew' then io.write(':',d.id,':',d.job)
  elseif d.action=='acme_status' or d.action=='acme_stop' or d.action=='acme_cleanup' then io.write(':',d.job)
  elseif d.action=='cert_import' or d.action=='cert_status' or d.action=='cert_resume' or d.action=='cert_cancel' or d.action=='provider_status' or d.action=='zones' or d.action=='delete_rule' then io.write(':',d.id)
  elseif d.action=='secret_put' then io.write(':',d.provider,':',d.id,':',d.slot)
  elseif d.confirmation then io.write(':',d.confirmation) end
  io.write('\n');return
 end
 if d.action=='backup_preview' then local canonical=codec.canonical(d.backup);if not canonical then os.exit(1)end;io.write(canonical);return end
 if d.action=='cert_import' then io.write(codec.json({certificate_pem=d.certificate_pem,private_key_pem=d.private_key_pem}));return end
 if d.action=='secret_put' or d.action=='web_target_put' then io.write(d.value);return end
 local raw=readfd(4,262144);local doc=raw and codec.parse(raw);if not doc then os.exit(1) end
 local kind=d.action=='preview_wol_host' and 'wol_host' or d.action=='preview_wol_settings' and 'homegate' or d.action=='preview_access' and 'homegate' or d.action=='preview_web_rule' and 'web_rule' or d.action=='preview_account' and 'dns_account' or d.action=='preview_rule' and 'ddns_rule' or (d.action=='preview_local_certificate' or d.action=='preview_acme_certificate') and 'certificate'
 if not kind then os.exit(1) end
 local values=kind=='dns_account' and {name=d.name,provider=d.provider} or
  {account=d.account,zone=d.zone,host=d.host,source=d.source,interface=d.source=='interface' and d.interface or ''}
 if d.action=='preview_access'then d.id='main';values={access_allow=d.allow:gsub('[\r\n\t]',' '),access_deny=d.deny:gsub('[\r\n\t]',' '),access_region=d.region}end
 if d.action=='preview_wol_settings'then d.id='main';values={wol_interface=d.interface,last_wol_host=d.selected_host}end
 if kind=='wol_host'then values={name=d.name,mac=d.mac}end
 if kind=='web_rule'then values={domain=d.domain,https=d.https,certificate=d.certificate,certificate_mode=d.certificate=='' and 'auto' or 'local'}end
 if kind=='certificate' then
  local domains={};for item in (d.domains..','):gmatch('(.-),')do domains[#domains+1]=item:match('^%s*(.-)%s*$') end
  if #domains<1 or #domains>32 then os.exit(1) end
  values={name=d.name,source='local',account='',zone='',domains=domains,environment='production'}
  if d.action=='preview_acme_certificate' then values.source='acme';values.account=d.account;values.zone=d.zone;values.email=d.email;values.ca='letsencrypt';values.environment=d.environment end
 end
 local found
 for _,s in ipairs(doc)do if s.name==d.id then if s.kind~=kind then os.exit(1) end;found=s end end
 if not found then found={kind=kind,name=d.id,values={}};doc[#doc+1]=found end
 for k,v in pairs(values)do found.values[k]=v end
 local cur={};function cur:foreach(_,t,callback)
  for _,s in ipairs(doc)do if s.kind==t then local row={['.name']=s.name};for k,v in pairs(s.values)do row[k]=v end;callback(row) end end
 end
 local result=codec.export(cur);if not result then os.exit(1) end;io.write(result);return
end
if arg[1]=='read' then
 local raw=io.stdin:read(262145);local doc=raw and #raw<=262144 and codec.parse(raw)
 if not doc then os.exit(1) end
 local accounts,rules,certificates,access={},{},{},{}
 for _,s in ipairs(doc)do
  if s.kind=='homegate'then access={allow=s.values.access_allow,deny=s.values.access_deny,region=s.values.access_region}
  elseif s.kind=='dns_account' then accounts[#accounts+1]={id=s.name,name=s.values.name,provider=s.values.provider}
  elseif s.kind=='certificate' then certificates[#certificates+1]={id=s.name,name=s.values.name,source=s.values.source,environment=s.values.environment,domains=s.values.domains}
  elseif s.kind=='ddns_rule' then rules[#rules+1]={id=s.name,account=s.values.account,zone=s.values.zone,
   host=s.values.host,source=s.values.source,interface=s.values.interface} end
 end
 io.write(codec.json({api_version=1,engineering=true,ok=true,accounts=accounts,rules=rules,certificates=certificates,access=access,effect='none',write_ready=false}),'\n');return
end
if arg[1]=='backup-export' then local raw=io.stdin:read(262145);local canonical=raw and #raw<=262144 and codec.canonical(raw);if not canonical then os.exit(1)end;io.write(codec.json({api_version=1,engineering=true,ok=true,backup=canonical,secrets_included=false,effect='none',write_ready=false}),'\n');return end
if arg[1]=='response' and arg[2] then
 local raw=io.stdin:read(524289);local d=raw and #raw<=524288 and json.parse(raw)
 if type(d)~='table' or d.api_version~=1 or type(d.ok)~='boolean' then os.exit(1) end
 -- Configuration previews are already projected through the shared public
 -- codec; credentials never enter that schema or this response whitelist.
 local allowed={device_wake_verified=true,raw_sent=true,udp_sent=true,interfaces=true,interface=true,mac=true,hosts=true,selected_host=true,host=true,name=true,firewall_status_separate=true,firewall_cleanup_ok=true,active=true,managed=true,automatic_reconcile=true,backend=true,family=true,wan_device=true,entries=true,best_effort=true,observations_only=true,clear_pending=true,cache_valid=true,cache_stale=true,cache_updated=true,ipv4=true,ipv6=true,cn_snapshot=true,generation=true,reload_state=true,routes=true,policy=true,health_checked=true,automatic_reload=true,cn_available=true,audit_available=true,firewall_changed=true,checks=true,next_check=true,job=true,state=true,succeeded=true,cleanup_required=true,ca=true,certificate=true,domains=true,source=true,environment=true,exists=true,pending=true,valid=true,identity_valid=true,renew=true,days=true,expires=true,trust_checked=true,imported=true,resumed=true,operation=true,migration_copied=true,legacy_source_retained=true,ok=true,api_version=true,phase=true,revision=true,configuration_revision=true,confirmation=true,
  changes=true,warnings=true,section_count=true,can_commit=true,apply_handle=true,application_pending=true,
  runtime_ready=true,baseline_ready=true,production_ready=true,cancelled=true,committed=true,
  projection_published=true,worker_acknowledged=true,readers_switched=true,business_restored=true,
  intent_applied=true,record_cancelled=true,active_overlay=true,main_enabled=true,known=true,requested_state=true,source_bound=true,continuous=true,running=true,status=true,reason=true,ticks=true,last_effect=true,admission_limit=true,
  account=true,provider=true,credentials_valid=true,capabilities=true,zones=true,error_kind=true,retryable=true,
  result=true,affected=true,reconciliation_required=true}
 local out={};for k,v in pairs(d)do if allowed[k] then out[k]=v end end
 local effect='none'
 if arg[3]=='wol_send' or arg[3]=='wol_direct' or arg[3]:match('^firewall_') then
  if d.effect~='none' and d.effect~='confirmed' and d.effect~='unknown'then os.exit(1)end
  effect=d.effect;out.effect=effect
 end
 if arg[3]=='delete_rule' then
  if d.effect~='none' and d.effect~='confirmed' and d.effect~='unknown' then os.exit(1) end
  effect=d.effect;out.effect=effect
 end
 if arg[2]~='0' then out.ok=false;out.error='Configuration operation unavailable; retained state requires attention' end
 io.write(codec.json({api_version=1,engineering=true,ok=out.ok,report=out,effect=effect,write_ready=false}),'\n');return
end
os.exit(1)
