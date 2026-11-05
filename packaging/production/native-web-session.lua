-- Start only fixed Web supervisors and the configuration service observer. nixio is an
-- existing runtime dependency; customized BusyBox images may omit setsid.
local function refuse()
 io.write('{"api_version":1,"ok":false,"error":"Web session unavailable; inspect retained task"}\n')
 os.exit(126)
end
local action,value=arg[1],arg[2]
local health=action=='observe-config-health'
if #arg~=(health and 4 or 2) or type(value)~='string' then refuse() end
if action=='read-owner' then
 if #value>4096 or value:sub(1,1)~='/' or value:find('[%z\1-\31\127]') then refuse() end
elseif action=='owner' or action=='observe-config-service' or health then
 if #value~=32 or value:find('[^0-9a-f]') then refuse() end
 if health then
  local revision,job=arg[3],arg[4]
  if not revision:match('^[1-9][0-9]?$') or tonumber(revision)>32
   or #job>9 or not job:match('^[1-9][0-9]*$') or tonumber(job)<2 then refuse() end
 end
else refuse() end
local ok,nx=pcall(require,'nixio')
if not ok or type(nx)~='table' then refuse() end
for _,name in ipairs({'getuid','getpid','setsid','exec'}) do
 if type(nx[name])~='function' then refuse() end
end
if nx.getuid()~=0 then refuse() end
local pid=nx.getpid()
local made,sid=pcall(nx.setsid)
if not made or type(pid)~='number' or sid~=pid then refuse() end
-- exec keeps this PID, PGID and SID for the existing deadline/group checks.
if action=='observe-config-service' or health then
 local watchdog='/usr/libexec/homegate/project/core/prototype/homegate-service-observer-watchdog.sh'
 if health then nx.exec('/bin/ash',watchdog,'--health-status',value,arg[3],arg[4])
 else nx.exec('/bin/ash',watchdog,value) end
else
 nx.exec('/bin/ash','/usr/libexec/homegate/native-web.sh',action,value)
end
refuse()
