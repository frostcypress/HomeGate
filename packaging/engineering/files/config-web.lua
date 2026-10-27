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
local schemas={read={},prepare={},cancel={},activate_preview={},schedule_status={},
 provider_status={'id'},zones={'id'},delete_rule={'id','consent'},
 schedule_start={'consent'},schedule_stop={'consent'},schedule_reap={'consent'},
 preview_account={'id','name','provider'},preview_rule={'id','account','zone','host','source','interface'},
 secret_put={'id','provider','slot','value','consent'},apply={'confirmation','consent'},finish={'confirmation','consent'}}
local function request()
 local raw=readfd(3,32768);local d=raw and json.parse(raw)
 if type(d)~='table' or type(d.action)~='string' or not schemas[d.action] then return nil end
 local allowed={action=true};for _,k in ipairs(schemas[d.action])do allowed[k]=true end
 local count=0;for k,v in pairs(d)do
  if not allowed[k] or type(v)~='string' or v:find('%z') or #v>(k=='value' and 4096 or 512) then return nil end;count=count+1
 end
 if count~=#schemas[d.action]+1 then return nil end
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
  if d.action=='provider_status' or d.action=='zones' or d.action=='delete_rule' then io.write(':',d.id)
  elseif d.action=='secret_put' then io.write(':',d.provider,':',d.id,':',d.slot)
  elseif d.confirmation then io.write(':',d.confirmation) end
  io.write('\n');return
 end
 if d.action=='secret_put' then io.write(d.value);return end
 local raw=readfd(4,262144);local doc=raw and codec.parse(raw);if not doc then os.exit(1) end
 local kind=d.action=='preview_account' and 'dns_account' or d.action=='preview_rule' and 'ddns_rule'
 if not kind then os.exit(1) end
 local values=kind=='dns_account' and {name=d.name,provider=d.provider} or
  {account=d.account,zone=d.zone,host=d.host,source=d.source,interface=d.source=='interface' and d.interface or ''}
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
 local accounts,rules={},{}
 for _,s in ipairs(doc)do
  if s.kind=='dns_account' then accounts[#accounts+1]={id=s.name,name=s.values.name,provider=s.values.provider}
  elseif s.kind=='ddns_rule' then rules[#rules+1]={id=s.name,account=s.values.account,zone=s.values.zone,
   host=s.values.host,source=s.values.source,interface=s.values.interface} end
 end
 io.write(codec.json({api_version=1,engineering=true,ok=true,accounts=accounts,rules=rules,effect='none',write_ready=false}),'\n');return
end
if arg[1]=='response' and arg[2] then
 local raw=io.stdin:read(524289);local d=raw and #raw<=524288 and json.parse(raw)
 if type(d)~='table' or d.api_version~=1 or type(d.ok)~='boolean' then os.exit(1) end
 -- Configuration previews are already projected through the shared public
 -- codec; credentials never enter that schema or this response whitelist.
 local allowed={ok=true,api_version=true,phase=true,revision=true,configuration_revision=true,confirmation=true,
  changes=true,warnings=true,section_count=true,can_commit=true,apply_handle=true,application_pending=true,
  runtime_ready=true,baseline_ready=true,production_ready=true,cancelled=true,committed=true,
  projection_published=true,worker_acknowledged=true,readers_switched=true,business_restored=true,
  running=true,status=true,reason=true,ticks=true,last_effect=true,admission_limit=true,
  account=true,provider=true,credentials_valid=true,capabilities=true,zones=true,error_kind=true,retryable=true,
  result=true,affected=true,reconciliation_required=true}
 local out={};for k,v in pairs(d)do if allowed[k] then out[k]=v end end
 local effect='none'
 if arg[3]=='delete_rule' then
  if d.effect~='none' and d.effect~='confirmed' and d.effect~='unknown' then os.exit(1) end
  effect=d.effect;out.effect=effect
 end
 if arg[2]~='0' then out.ok=false;out.error='Configuration operation unavailable; retained state requires attention' end
 io.write(codec.json({api_version=1,engineering=true,ok=out.ok,report=out,effect=effect,write_ready=false}),'\n');return
end
os.exit(1)
