-- Start fixed supervisors using nixio on firmware without the setsid command.
local function refuse()
 io.write('{"api_version":1,"ok":false,"error":"Web session unavailable; inspect retained task"}\n')
 os.exit(126)
end
local action,value=arg[1],arg[2]
local function number_arg(s,limit,minimum)
 return type(s)=='string' and #s<=limit and s:match('^[1-9][0-9]*$') and tonumber(s)>=minimum
end
local providers={['--cloudflare-check']=true,['--aliyun-check']=true,
 ['--dnspod-check']=true,['--huaweicloud-check']=true}
local function id(s)
 return #s>0 and #s<=64 and not s:find('[^a-zA-Z0-9_%-]')
end
local core='/usr/libexec/homegate/project/core/prototype/'
local watchdog=core..'homegate-service-observer-watchdog.sh'
local arity={['read-owner']=2,owner=2,['observe-config-service']=2,
 ['observe-config-health']=4,['observe-network']=5,['observe-dns']=7,['dns-records']=7,
 ['ddns-plan']=5,['ddns-work']=2,['ddns-schedule']=2,
 ['acme-work']=2,['acme-cleanup']=2,['acme-schedule']=3,
 ['certificate-validate']=3,['certificate-preview']=2}
if not action or #arg~=arity[action] or type(value)~='string' then refuse() end
local program,args=watchdog,nil
if action=='read-owner' then
 if #value>4096 or value:sub(1,1)~='/' or value:find('[%z\1-\31\127]') then refuse() end
elseif action=='ddns-schedule' then
 if value~='run' and value~='serve' then refuse() end
 program,args=core..'homegate-ddns-schedule.sh',{value,'--confirm'}
else
 if #value~=32 or value:find('[^0-9a-f]') then refuse() end
 if action=='observe-config-service' then
  args={value}
 elseif action=='ddns-work' then
  program,args=core..'homegate-ddns-job.sh',{'work',value}
 elseif action=='acme-work' or action=='acme-cleanup' then
  program,args=core..'homegate-acme-job.sh',{action=='acme-work' and 'work' or 'work-cleanup',value}
 elseif action=='acme-schedule' then
  if not id(arg[3]) then refuse() end
  program,args=core..'homegate-acme-schedule.sh',{'serve',arg[3],value}
 elseif action=='certificate-validate' then
  if not id(arg[3]) then refuse() end
  args={'--certificate-validate',value,arg[3]}
 elseif action=='certificate-preview' then
  program,args=core..'native-web-certificate-watchdog.sh',{'--certificate-validate',value,value}
 elseif action~='owner' then
  local revision,job=arg[3],arg[4]
  if not number_arg(revision,2,1) or tonumber(revision)>32 or not number_arg(job,9,2) then refuse() end
  if action=='observe-config-health' then
   args={'--health-status',value,revision,job}
  elseif action=='observe-network' then
   local bridge=arg[5]
   if #bridge==0 or #bridge>32 or bridge=='.' or bridge=='..' or bridge:find('[^a-zA-Z0-9_.:%-]') then refuse() end
   args={'--network-resolve',value,revision,job,bridge}
  elseif action=='ddns-plan' then
   local rule=arg[5]
   if rule~='' and not id(rule) then refuse() end
   args={'--ddns-plan',value,revision,job,rule}
  else
   local provider,account,mode=arg[5],arg[6],arg[7]
   if not providers[provider] or not id(account) then refuse() end
   if action=='observe-dns' then
    if mode~='check' and mode~='zones' then refuse() end
   elseif mode~='records' and mode~='reconcile' then refuse() end
   args={provider,value,account,revision,job,mode}
  end
 end
end
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
if args then
 nx.exec('/bin/ash',program,unpack(args))
else
 nx.exec('/bin/ash','/usr/libexec/homegate/native-web.sh',action,value)
end
refuse()
