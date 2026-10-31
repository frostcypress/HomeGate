-- Native service plan/report codec. Fixed private paths; no shell or credentials.
local base=assert(arg[0]:match('^(.*)/[^/]+$'))
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local json=require('luci.jsonc');local fs=require('nixio.fs')
local function fail()os.exit(7)end
local function read(p,n)
 local st=fs.lstat(p);if not st or st.type~='reg' or st.uid~=0 or st.nlink~=1 or st.modedec~=600 or st.size>n then fail()end
 local f=assert(io.open(p,'rb'));local raw=f:read(n+1) or '';if not f:close() or #raw>n then fail()end;return raw
end
local function version()
 local function line(n)local f=assert(io.open(base..'/'..n));local r=f:read(65);f:close();return r end
 local v,r=line('VERSION'),line('RELEASE');if not v:match('^%d+%.%d+%.%d+\n$') or not r:match('^[1-9]%d*\n$')then fail()end
 return v:sub(1,-2)..'-r'..r:sub(1,-2)
end
local function emit(d)io.write(codec.json(d),'\n')end
local function report(raw)local d=raw and json.parse(raw);if type(d)~='table' then fail()end;return d end
local function number(v,max)return type(v)=='number' and v>=0 and v<=max and v%1==0 end
local function identity(d)
 if not number(d.pid,999999999) or d.pid<2 or not number(d.process_start_ticks,9007199254740991)then return false end
 local function sample()
  local f=io.open('/proc/'..d.pid..'/stat');if not f then return nil end;local raw=f:read(8193);f:close()
  local model=assert(loadfile(base..'/project/core/prototype/runtime-health.lua'))();local p=model.process(raw,d.pid)
  if not p or p.state=='Z' or p.state=='X' or p.ticks~=d.process_start_ticks then return nil end
  f=io.open('/proc/'..d.pid..'/cmdline','rb');if not f then return nil end;raw=f:read(8193);f:close()
  if raw~='ash\0'..base..'/native-service.sh\0serve\0' then return nil end;return p.ticks
 end
 local a,b=sample(),sample();return a and a==b or false
end
local mode=arg[1]
if mode=='web-running'then
 if not fs.lstat('/var/run/homegate/native-service.json')then os.exit(3)end
 local d=report(read('/var/run/homegate/native-service.json',16384));local revision=tonumber(arg[2])
 if d.state=='failed' or d.state=='restart_required'then os.exit(1)end
 if d.configuration_revision~=revision or d.state~='running' or d.running~=true or d.healthy~=true or not identity(d)then os.exit(3)end
 if arg[3]then
  if not arg[3]:match('^[0-9a-f]+$') or #arg[3]~=64 or d.source_binding_digest~=arg[3] or d.phase~='native-service' or d.version~=version()then fail()end
  emit({api_version=1,native=true,ok=true,configuration_revision=revision,verification='source-bound-coordinator',service={configured=true,enabled=true,running=true,healthy=true}})
 end
 return
end
if mode=='web-ready'then
 local d=report(io.stdin:read(32769));local r=tonumber(arg[2]);if not r or not d.service or d.configuration_revision~=r or d.ok~=true or d.service.configured~=true or d.service.enabled~=true or d.service.running~=true or d.service.healthy~=true then fail()end;return
end
if mode=='plan' or mode=='plan-set'then
 local raw=read('/etc/config/homegate',262144);local doc=codec.private_configuration(raw);if not doc then fail()end
 local out={ddns={},certificates={},web={},policy='open'}
 for _,s in ipairs(doc.configuration)do
  local sw=doc.switches[s.name] or {};local enabled=sw.enabled=='1'
  if s.kind=='homegate' then
   if sw.access_enabled=='1' then out.policy='allow' end
   out.access_region=s.values.access_region;out.access_enabled=sw.access_enabled=='1'
   out.auto_firewall=s.values.auto_firewall=='1'
  elseif s.kind=='ddns_rule' and enabled then out.ddns[#out.ddns+1]=s.name
  elseif s.kind=='certificate' and enabled and s.values.source=='acme' then out.certificates[#out.certificates+1]=s.name
  elseif s.kind=='web_rule' and enabled then out.web[#out.web+1]=s.name end
 end
 local revision=tonumber(read('/etc/homegate/transactions/current',16))
 if not revision or revision<1 or revision>32 or type(arg[2])~='string' or #arg[2]>8192 then fail()end
 if mode=='plan-set'then
  local index={};for _,s in ipairs(doc.configuration)do index[s.name]=s end
  local function selection(raw,kind,acme)
   if type(raw)~='string' or #raw>2111 then fail()end;if raw=='-'then return {}end
   local list,seen={},{};for name in (raw..','):gmatch('(.-),')do
    if name=='' or seen[name] or not index[name] or index[name].kind~=kind or (acme and index[name].values.source~='acme')then fail()end
    seen[name]=true;list[#list+1]=name
   end;table.sort(list);return list
  end
  out.ddns=selection(arg[3],'ddns_rule');out.certificates=selection(arg[4],'certificate',true);out.web=selection(arg[5],'web_rule')
  if arg[6]~='open' and arg[6]~='allow'then fail()end;out.policy=arg[6]
  out.format='native-service-plan-v1';out.configuration_revision=revision;out.source_binding=arg[2]
 elseif fs.lstat('/etc/homegate/native-service-plan')then
  local saved=report(read('/etc/homegate/native-service-plan',16384))
  if saved.format~='native-service-plan-v1' or saved.configuration_revision~=revision or saved.source_binding~=arg[2] or (saved.policy~='open' and saved.policy~='allow')then fail()end
  for _,key in ipairs({'ddns','certificates','web'})do if type(saved[key])~='table'then fail()end end
  out=saved
 end
 if #out.ddns>32 or #out.web>16 or #out.certificates>32 then fail()end
 for _,k in ipairs({'ddns','certificates','web'})do table.sort(out[k])end
 emit(out);return
elseif mode=='field'then
 local d=report(io.stdin:read(16385));local key=arg[2]
 if key=='ddns' or key=='certificates' or key=='web' then
  if type(d[key])~='table' or #d[key]>32 then fail()end
  for _,v in ipairs(d[key])do if type(v)~='string' or #v>64 or not v:match('^[a-zA-Z0-9_-]+$')then fail()end end
  io.write(table.concat(d[key],key=='web' and ',' or ' '),'\n')
 elseif key=='policy' and (d.policy=='open' or d.policy=='allow')then io.write(d.policy,'\n')
 elseif key=='auto_firewall' and type(d.auto_firewall)=='boolean'then io.write(d.auto_firewall and 'true\n' or 'false\n')
 else fail()end;return
elseif mode=='ready'then
 local d=report(io.stdin:read(16385));if d.ok~=true then fail()end
 if arg[2]=='intent' then if d.known~=true or d.active_overlay~=true or d.main_enabled~=true or d.source_bound~=true then fail()end
 elseif arg[2]=='due' then if d.pending~=false or type(d.renew)~='boolean' or type(d.exists)~='boolean' or type(d.valid)~='boolean' then fail()end;if not d.renew and d.exists and d.valid then os.exit(3)end
 elseif arg[2]=='job' then if d.pending==true then os.exit(3)end;if d.pending~=false or d.cleanup_required~=false or (d.state~='issued' and d.state~='skipped')then fail()end
 elseif arg[2]=='running' then if d.running~=true then fail()end
  if d.phase=='proxy' and d.state=='starting' then os.exit(3)end
  if d.phase=='proxy' and d.state~='running' then fail()end
 else fail()end;return
elseif mode=='emit'then
 local states={starting=true,running=true,renewing=true,stopping=true,stopped=true,failed=true,restart_required=true}
 local state,pid,ticks,revision=arg[2],tonumber(arg[3]),tonumber(arg[4]),tonumber(arg[5]);local reason=arg[6]
 if not states[state] or not number(pid,999999999) or not number(ticks,9007199254740991) or not number(revision,32) or not reason or #reason>64 or reason:find('[^a-z_]')then fail()end
 local digest=arg[7];if not digest or #digest~=64 or not digest:match('^[0-9a-f]+$')then fail()end
 emit({api_version=1,native=true,ok=state~='failed' and state~='restart_required',phase='native-service',version=version(),state=state,pid=pid,process_start_ticks=ticks,configuration_revision=revision,source_binding_digest=digest,reason=reason,healthy=state=='running',running=state=='starting' or state=='running' or state=='renewing' or state=='stopping',effect='none',write_ready=false});return
elseif mode=='alive'then
 local d=report(read('/var/run/homegate/native-service.json',16384))
 if d.phase~='native-service' or d.running~=true or not identity(d)then fail()end;return
elseif mode=='status'then
 local config=report(io.stdin:read(8193));if type(config.service)~='table' or type(config.service.configured)~='boolean'then fail()end
 local intent=report(arg[2]);local live=arg[3]=='true';if arg[3]~='true' and arg[3]~='false'then fail()end
 local d={state='idle',running=false,healthy=false,reason=''}
 if fs.lstat('/var/run/homegate/native-service.json')then d=report(read('/var/run/homegate/native-service.json',16384)) end
 if d.phase and (d.phase~='native-service' or type(d.running)~='boolean' or type(d.healthy)~='boolean' or type(d.state)~='string' or d.version~=version())then fail()end
 local running=live and d.running and identity(d) or false
 local enabled=config.service.enabled
 local configured=config.service.configured
 if intent.known==true then
  if intent.source_bound~=true or type(intent.main_enabled)~='boolean' or intent.configuration_revision~=config.configuration_revision then fail()end
  -- Applied-intent status revalidates the private native candidate, including
  -- its source/generation/credential binding; the legacy raw main flag is 0.
  enabled=intent.main_enabled;configured=true
 end
 local healthy=configured and enabled==running and (not running or d.healthy==true and d.configuration_revision==config.configuration_revision)
 emit({api_version=1,native=true,ok=healthy,phase='common-runtime',version=version(),configuration_revision=config.configuration_revision,service={configured=configured,enabled=enabled,running=running,healthy=healthy},coordinator={state=d.state,reason=d.reason},effect='none',write_ready=false})
 if arg[4]=='check' and not healthy then os.exit(1)end;return
end
fail()
