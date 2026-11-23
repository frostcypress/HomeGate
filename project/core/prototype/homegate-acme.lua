-- Fixed ACME resource, transport and challenge codecs. Private data never enters status.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local json=require('luci.jsonc')
local mode,job=arg[1],arg[2]
local function fail()os.exit(1)end
local function id(s)return type(s)=='string' and #s>0 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$') end
local function hex(s,n)return type(s)=='string' and #s==n and s:match('^[0-9a-f]+$') end
local function read(path,max)local f=io.open(path,'rb');if not f then fail() end;local v=f:read(max+1) or '';f:close();if #v>max then fail() end;return v end
local function write(path,body)local f=io.open(path,'wb');if not f or not f:write(body) or not f:close() then fail() end end
local function parse(raw)local v=json.parse(raw);if type(v)~='table' then fail() end;return v end
local jobs='/etc/homegate/acme/jobs'
if mode=='eab-status' or mode=='eab-check' or mode=='eab-save' or mode=='eab-read' or mode=='eab-reset' then
 local fs=require('nixio.fs');local nx=require('nixio');require('nixio.util')
 local parent='/etc/homegate/acme'
 local path=parent..'/zerossl-eab.json'
 local function private_dir(name)
  local s=fs.lstat(name);return s and s.type=='dir' and s.uid==0 and s.modedec==700
 end
 local function valid(d)
  if type(d)~='table' or type(d.kid)~='string' or type(d.hmac)~='string' then return false end
  local key=d.hmac:gsub('=+$','')
  return #d.kid<=128 and d.kid:match('^[A-Za-z0-9_-]+$') and #d.hmac<=512 and #key>=16 and
         #d.hmac-#key<=2 and key:match('^[A-Za-z0-9_+/%-]+$') and #key%4~=1
 end
 local function credentials()
  if not private_dir('/etc/homegate') or not private_dir(parent) then return nil end
  local st=fs.lstat(path)
  if not st or st.type~='reg' or st.uid~=0 or st.modedec~=600 or st.nlink~=1 or st.size>2048 then return nil end
  local d=json.parse(read(path,2048))
  return valid(d) and (d.profile==nil or hex(d.profile,32)) and d or nil
 end
 if mode=='eab-status' then
  local d=credentials();if job or not d then fail() end
  io.write(d.kid,'\n');return
 end
 if mode=='eab-reset' then
  if job then fail() end
  if not fs.lstat('/etc/homegate') then return end
  if not private_dir('/etc/homegate') then fail() end
  if not fs.lstat(parent) then return end
  if not private_dir(parent) then fail() end

  -- Reset runs after the service and certificate workers are quiescent.
  -- Check every path before unlinking anything, and never follow symlinks.
  local removals={}
  local function collect(name,depth)
   local st=fs.lstat(name);if not st or st.uid~=0 then fail() end
   if st.type=='dir' and depth>0 and st.modedec==700 then
    for entry in assert(fs.dir(name)) do
     if entry~='.' and entry~='..' then collect(name..'/'..entry,depth-1) end
    end
    removals[#removals+1]={name,fs.rmdir}
   elseif st.type=='reg' and st.nlink==1 and st.modedec==600 then
    removals[#removals+1]={name,fs.unlink}
   else fail() end
  end
  local accounts=parent..'/accounts'
  local has_accounts=fs.lstat(accounts)~=nil
  if has_accounts then
   if not private_dir(accounts) then fail() end
   for name in assert(fs.dir(accounts)) do
    if name=='zerossl-production' or hex(name:match('^zerossl%-production%-(.+)$'),32) then
     collect(accounts..'/'..name,12)
    end
   end
  end
  for name in assert(fs.dir(parent)) do
   if hex(name:match('^%.eab%-(.+)$'),32) then collect(parent..'/'..name,0) end
  end
  if fs.lstat(path) then collect(path,0) end
  for _,entry in ipairs(removals) do if not entry[2](entry[1]) then fail() end end
  local sync='fsync '..parent..' /etc/homegate'..(has_accounts and ' '..accounts or '')
  if os.execute(sync..' >/dev/null 2>&1')~=0 then fail() end
  return
 end
 if mode=='eab-read' then
  if job then fail() end
  local d=credentials();if not d then fail() end
  io.write(d.kid,' ',d.hmac,' ',d.profile or 'original','\n');return
 end
 if job then fail() end
 local raw=io.stdin:read(2049) or '';local d=#raw<=2048 and json.parse(raw)
 if not valid(d) then fail() end
 if mode=='eab-check' then return end
 if not private_dir('/etc/homegate') then fail() end
 if not fs.lstat(parent) then fs.mkdir(parent,'700') end
 if not private_dir(parent) then fail() end
 local current=credentials()
 if fs.lstat(path) and not current then fail() end
 if current and current.kid==d.kid and current.hmac==d.hmac then return end
 local nonce=read('/proc/sys/kernel/random/uuid',38):gsub('[%-\n]','')
 if not hex(nonce,32) then fail() end
 local nextpath=parent..'/.eab-'..nonce
 local fd=nx.open(nextpath,nx.open_flags('wronly','creat','excl'),'600');if not fd then fail() end
 -- A different EAB pair must bind a new ACME account. Existing certificates
 -- and the original client state remain available during the switch.
 local body=codec.json({kid=d.kid,hmac=d.hmac,profile=current and nonce or nil})..'\n'
 local count=fd:writeall(body);local closed=fd:close()
 if count~=#body or not closed or os.execute('fsync '..nextpath..' >/dev/null 2>&1')~=0 or not fs.rename(nextpath,path) then
  fs.unlink(nextpath);fail()
 end
 if os.execute('fsync '..parent..' /etc/homegate >/dev/null 2>&1')~=0 then fail() end
 return
end
local function log_rate_limit(name,when)
 if id(name) and type(when)=='number' and when>=0 and when<=9999999999 and when%1==0 then
  os.execute('ash /usr/libexec/homegate/native-log.sh certificate-retry '..name..' '..string.format('%.0f',when)..' >/dev/null 2>&1')
 end
end
local function rate_limit(path)
 local fs=require('nixio.fs')
 local function private(name,max)
  local file=path..'/'..name
  local st=fs.lstat(file)
  if not st or st.type~='reg' or st.uid~=0 or st.modedec~=600 or st.nlink~=1 or st.size>max then return nil end
  local f=io.open(file,'rb');if not f then return nil end
  local data=f:read(max+1);f:close()
  if data and #data<=max then return data,st.mtime end
 end
 local raw,received=private('http.response',131072)
 local response=raw and json.parse(raw)
 if type(response)~='table' or response.type~='urn:ietf:params:acme:error:rateLimited' or tonumber(response.status)~=429 then return nil end
 local function utc(year,month,day,hour,min,sec)
  if not year or not month or not day or not hour or not min or not sec then return nil end
  return os.time({year=tonumber(year),month=tonumber(month),day=tonumber(day),hour=tonumber(hour),min=tonumber(min),sec=tonumber(sec),isdst=false})
 end
 local header=(private('http.header',65536) or ''):lower()
 local retry=header:match('\nretry%-after:[ \t]*([^\r\n]+)') or ''
 local seconds=retry:match('^(%d+)%s*$')
 local retry_at=seconds and received+tonumber(seconds) or nil
 if not retry_at then
  local day,month,year,hour,min,sec=retry:match('^%a+,%s+(%d+)%s+(%a+)%s+(%d%d%d%d)%s+(%d%d):(%d%d):(%d%d)%s+gmt%s*$')
  local months={jan=1,feb=2,mar=3,apr=4,may=5,jun=6,jul=7,aug=8,sep=9,oct=10,nov=11,dec=12}
  retry_at=utc(year,months[month],day,hour,min,sec)
 end
 if type(response.detail)=='string' then
  local y,m,d,h,minute,s=response.detail:match('retry after (%d%d%d%d)%-(%d%d)%-(%d%d) (%d%d):(%d%d):(%d%d) UTC')
  local detail_at=utc(y,m,d,h,minute,s)
  if detail_at then retry_at=math.max(retry_at or 0,detail_at) end
 end
 return received and (retry_at and retry_at>=received and retry_at<received+31536000 and retry_at or received+3600)
end
if mode=='rate-limit-observations' or mode=='rate-limit-check' or mode=='web-acme-observations' then
 local fs=require('nixio.fs');local now=os.time();local waits,observations={},{};local newest=0
 local requested=mode=='rate-limit-check' and parse(io.stdin:read(16385) or '') or nil
 local entries=fs.dir(jobs)
 if entries then for name in entries do
  if hex(name,32) then
   local path=jobs..'/'..name
   local st=fs.lstat(path)
   local function record(filename)
    local file=path..'/'..filename;local attr=fs.lstat(file)
    if not attr or attr.type~='reg' or attr.uid~=0 or attr.modedec~=600 or attr.nlink~=1 or attr.size>16384 then return nil end
    return json.parse(read(file,16384))
   end
   if st and st.type=='dir' and st.uid==0 and st.modedec==700 then
    local outcome=record('result');local identity=record('scope.json')
    if mode=='web-acme-observations' and type(identity)=='table' and id(identity.id) and codec.acme_directory(identity.ca,identity.environment) and type(identity.domains)=='table' then
     local key=identity.ca..'/'..identity.environment..'/'..codec.json(identity.domains)
     local lock=fs.lstat(path..'/lock')
     if not outcome and lock and lock.type=='reg' and lock.uid==0 and lock.modedec==600 and lock.nlink==1 and lock.size==0 and
        os.execute('(exec 8< '..path..'/lock && flock -n 8) >/dev/null 2>&1')~=0 then
      observations[key]={state='pending',time=now}
     elseif outcome and outcome.job==name and outcome.certificate==identity.id then
      local stamp=fs.lstat(path..'/result')
      if stamp and (not observations[key] or stamp.mtime>observations[key].time) then
       observations[key]={state=outcome.state,time=stamp.mtime}
      end
     end
    end
    if type(outcome)=='table' and outcome.job==name and outcome.state=='failed' and outcome.cleanup_required==false and
       type(identity)=='table' and identity.id==outcome.certificate and id(identity.id) and codec.acme_directory(identity.ca,identity.environment) then
     local until_at=rate_limit(path)
     if until_at and until_at>now then
      if requested and requested.ca==identity.ca and requested.environment==identity.environment and codec.json(requested.domains)==codec.json(identity.domains) then
       newest=math.max(newest,until_at)
      elseif not requested and type(identity.environment)=='string' and type(identity.domains)=='table' then
       local key=identity.ca..'/'..identity.environment..'/'..codec.json(identity.domains)
       waits[key]=math.max(waits[key] or 0,until_at)
      end
     end
    end
   end
  end
 end end
 if mode=='web-acme-observations' then io.write(codec.json({retries=waits,jobs=observations}),'\n')
 elseif not requested then io.write(codec.json(waits),'\n')
 elseif newest>0 then
  log_rate_limit(requested.id,newest)
  io.write(codec.json({ok=false,error_kind='rate_limited',certificate=requested.id,retry_at=newest}),'\n');os.exit(9)
 end
 return
end
if mode=='scope' then
 if not id(job) or arg[3] then fail() end
 local snap=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec);if not snap then fail() end
 local accounts={};for _,s in ipairs(snap.configuration)do if s.kind=='dns_account' then accounts[s.name]=s.values.provider end end
 for _,s in ipairs(snap.configuration)do if s.kind=='certificate' and s.name==job then
  local v=s.values;local provider=accounts[v.account];local slots={cloudflare={'secret'},aliyun={'key_id','secret'},dnspod={'key_id','secret'}}
  if v.source~='acme' or not codec.acme_directory(v.ca,v.environment) or not slots[provider] or #v.domains<1 or #v.domains>32 then fail() end
  for _,slot in ipairs(slots[provider])do if not snap.credentials[provider..'.'..v.account..'.'..slot] then fail() end end
  local domains={};for _,d in ipairs(v.domains)do domains[#domains+1]=d end;table.sort(domains)
  io.write(codec.json({id=job,source='acme',ca=v.ca,environment=v.environment,account=v.account,provider=provider,domains=domains,email=v.email,revision=snap.revision})..'\n');return
 end end;fail()
end
if mode=='certificate-ready' then
 if not id(job) or arg[3] then fail() end;local raw=io.stdin:read(16385) or '';if #raw>16384 then fail() end;local d=parse(raw)
 if d.phase~='certificate-status' or d.certificate~=job or d.pending~=false then fail() end;return
end
if mode:match('^session%-') then
 local root='/var/run/homegate/acme-schedule'
 local function selected()local d=parse(read(root..'/scope.json',16384));if not id(d.id) or d.source~='acme' then fail() end;return d.id end
 if mode=='session-id' then if arg[2] then fail() end;io.write(selected(),'\n');return end
 if mode=='session-due' then
  if arg[2] then fail() end;local raw=io.stdin:read(16385) or '';if #raw>16384 then fail() end;local d=parse(raw)
  if d.phase~='certificate-status' or d.certificate~=selected() or d.pending~=false or type(d.valid)~='boolean' or type(d.renew)~='boolean' then fail() end
  io.write(d.valid and not d.renew and 'skip\n' or 'issue\n');return
 end
 if mode=='session-pending' then
  if arg[2] then fail() end;local raw=io.stdin:read(16385) or '';if #raw>16384 then fail() end;local d=parse(raw)
  if d.phase~='acme-job' or d.certificate~=selected() or d.pending~=true then fail() end;return
 end
 if mode=='session-result' then
  if arg[2] then fail() end;local raw=io.stdin:read(16385) or '';if #raw>16384 then fail() end;local d=parse(raw)
  if d.phase~='acme-job' or d.certificate~=selected() or d.pending~=false or d.cleanup_required~=false or (d.state~='issued' and d.state~='skipped') then fail() end;return
 end
 local states={starting=true,checking=true,working=true,waiting=true,stopped=true,failed=true,interrupted=true,idle=true}
 if mode=='session-report' then
  local state,count,next_check,current=arg[2],tonumber(arg[3]),tonumber(arg[4]),arg[5]
  if not states[state] or not count or count<0 or count>2147483647 or count~=math.floor(count) or not next_check or next_check<0 or next_check~=math.floor(next_check) or (current~='-' and not hex(current,32)) or arg[6] then fail() end
  io.write(codec.json({api_version=1,engineering=true,ok=true,phase='acme-schedule',certificate=selected(),state=state,checks=count,next_check=next_check,job=current=='-' and '' or current,running=state=='starting' or state=='checking' or state=='working' or state=='waiting',effect='none',write_ready=false}),'\n');return
 end
 if mode=='session-status' then
  if arg[2]~='true' and arg[2]~='false' then fail() end
  local raw=read(root..'/report',16384);local d=parse(raw)
  if codec.json(d)..'\n'~=raw or d.phase~='acme-schedule' or d.certificate~=selected() or not states[d.state] or type(d.checks)~='number' or d.checks<0 or d.checks~=math.floor(d.checks) or type(d.next_check)~='number' or type(d.running)~='boolean' or (d.job~='' and not hex(d.job,32)) then fail() end
  if arg[2]=='false' and d.running then d.state='interrupted' end;d.running=arg[2]=='true';io.write(codec.json(d),'\n');return
 end
 fail()
end
if not hex(job,32) then fail() end
local base=jobs..'/'..job
local function scope()local d=parse(read(base..'/scope.json',16384));if not id(d.id) or not id(d.account) or d.source~='acme' or not codec.acme_directory(d.ca,d.environment) or type(d.domains)~='table' or #d.domains<1 or #d.domains>32 then fail() end;return d end
local function input()local d=parse(read(base..'/dns.input',4096));if d.resource~=scope().id then fail() end;return d end
if mode=='field' then
 local d=scope();local k=arg[3];if arg[4] then fail() end
 if k=='domains' then for _,v in ipairs(d.domains)do io.write(v,'\n') end;return end
 if k=='directory' then io.write(codec.acme_directory(d.ca,d.environment),'\n');return end
 if not ({id=true,account=true,provider=true,ca=true,environment=true,email=true,revision=true})[k] then fail() end
 io.write(tostring(d[k]),'\n');return
elseif mode=='transport' then
 local method,url=arg[3],arg[4];if arg[5] or not ({GET=true,POST=true,HEAD=true})[method] then fail() end
 local d=scope();local origin=codec.acme_directory(d.ca,d.environment):match('^https://[^/]+/')
 if type(url)~='string' or #url>2048 or url:find('[^a-zA-Z0-9_~%.:/?=&%%%-]') then fail() end
 local ari=d.ca=='zerossl' and method=='GET' and url:match('^https://ari%.trust%-provider%.com/renewalInfo/[a-zA-Z0-9_.%-]+$')
 if url:sub(1,#origin)~=origin and not ari then fail() end
 local body=io.stdin:read(131073) or '';if #body>131072 or body:find('%z') then fail() end
 write(base..'/http.body',body)
 local function q(v)return '"'..v:gsub('\\','\\\\'):gsub('"','\\"'):gsub('\r','\\r'):gsub('\n','\\n')..'"' end
 local config='url = '..q(url)..'\nrequest = '..q(method)..'\ndump-header = '..q(base..'/http.header')..'\n'
 if method=='HEAD' then config=config..'head = true\n' end
 if method=='POST' then config=config..'header = "Content-Type: application/jose+json"\ndata-binary = '..q('@'..base..'/http.body')..'\n' end
 write(base..'/http.curl',config);return
elseif mode=='bounded-response' then
 local body=io.stdin:read(131073) or '';if #body>131072 then fail() end;io.write(body);return
elseif mode=='validation-status' then
 if arg[3] then fail() end
 local reply=parse(read(base..'/http.response',131072))
 local status=reply.status
 if status=='pending' or status=='processing' or status=='valid' or status=='invalid' or
    status=='deactivated' or status=='expired' or status=='revoked' then io.write(status,'\n');return end
 fail()
elseif mode=='dns-input' then
 local action=arg[3];if (action~='add' and action~='remove') or arg[4] then fail() end
 local raw=io.stdin:read(4097) or '';local name,value=raw:match('^([^\n]+)\n([^\n]+)\n$');if #raw>4096 or not name or #value~=43 or value:find('[^a-zA-Z0-9_-]') then fail() end
 local d=scope();local domain
 for _,candidate in ipairs(d.domains)do local root=candidate:gsub('^%*%.','');if name=='_acme-challenge.'..root then domain=candidate;break end end
 if not domain then fail() end
 write(base..'/dns.input',codec.json({action=action,name=name,value=value,domain=domain,resource=d.id})..'\n');return
elseif mode=='dns-tuple' then local d=input();io.write(codec.json({name=d.name,value=d.value}),'\n');return
elseif mode=='dns-request' then local d=input();io.write(codec.json({operation=d.action=='add' and 'upsert' or 'delete',kind='dns01',resource=d.resource,domain=d.domain,value=d.value})..'\n');return
elseif mode=='challenge-write' then
 local key,state=arg[3],arg[4];if not hex(key,64) or not ({prepared=true,owned=true,preexisting=true,removed=true,unmodified=true,unknown=true})[state] or arg[5] then fail() end
 local d=input();d.state=state;write(base..'/challenges/'..key..'.next',codec.json(d)..'\n');return
elseif mode=='challenge-state' then
 local key=arg[3];if not hex(key,64) or arg[4] then fail() end
 local d=parse(read(base..'/challenges/'..key..'.json',4096));local now=input()
 if d.resource~=now.resource or d.name~=now.name or d.value~=now.value or not ({prepared=true,owned=true,preexisting=true,removed=true,unmodified=true,unknown=true})[d.state] then fail() end
 io.write(d.state,'\n');return
elseif mode=='dns-result' then
 local raw=io.stdin:read(4097) or '';local s=scope()
 if arg[3]=='1' and s.provider=='dnspod' then
  local records=assert(loadfile(dir..'/dnspod-records.lua'))()
  if raw==records.report(s.account,s.revision,'temporary',true,'pagination_changed','failed','none',0) then
   io.write('pagination-unmodified\n');return
  end
 end
 local d=parse(raw)
 if arg[3]~='0' or d.ok~=true or d.provider~=s.provider or d.account~=s.account or d.configuration_revision~=s.revision or (d.effect~='none' and d.effect~='confirmed') or not ({created=true,updated=true,unchanged=true,deleted=true,absent=true})[d.result] then fail() end
 io.write(d.effect=='confirmed' and 'owned\n' or 'preexisting\n');return
elseif mode=='challenge-load' then
 local key=arg[3];if not hex(key,64) or arg[4] then fail() end
 local d=parse(read(base..'/challenges/'..key..'.json',4096));if d.resource~=scope().id or d.state~='owned' then fail() end
 io.write(d.name,'\n',d.value,'\n');return
elseif mode=='clean-check' then
 -- Shell supplies only validated fixed record names; no glob/path from a caller.
 for i=3,#arg do local key=arg[i];if not hex(key,64) then fail() end;local d=parse(read(base..'/challenges/'..key..'.json',4096));if d.state~='removed' and d.state~='preexisting' and d.state~='unmodified' then fail() end end;return
elseif mode=='install' then
 local cert=read(base..'/issued/fullchain.pem',65536);local key=read(base..'/issued/privkey.pem',16384)
 io.write(codec.json({certificate_pem=cert,private_key_pem=key}));return
elseif mode=='renew-due' then
 local r=parse(io.stdin:read(16385) or '');if r.phase~='certificate-status' or r.certificate~=scope().id then fail() end
 io.write(r.valid==true and r.renew==false and 'skip\n' or 'issue\n');return
elseif mode=='report' then
 local d=scope();local state=arg[3];if not ({accepted=true,pending=true,issued=true,failed=true,interrupted=true,skipped=true,cleaned=true})[state] or arg[5] then fail() end
 local out={api_version=1,engineering=true,ok=true,phase='acme-job',job=job,certificate=d.id,ca=d.ca,environment=d.environment,pending=state=='accepted' or state=='pending',state=state,succeeded=state=='issued' or state=='skipped' or state=='cleaned',cleanup_required=arg[4]=='true',effect='none',write_ready=false}
 if state=='failed' and not out.cleanup_required then log_rate_limit(d.id,rate_limit(base)) end
 io.write(codec.json(out),'\n');return
elseif mode=='clear-result' then
 local d=parse(read(base..'/result',16384));if d.pending~=false or d.cleanup_required~=false then fail() end;return
elseif mode=='read-report' then
 local raw=read(base..'/result',16384);local d=parse(raw);local s=scope()
 if codec.json(d)..'\n'~=raw or d.api_version~=1 or d.phase~='acme-job' or d.job~=job or d.certificate~=s.id or d.ca~=s.ca or d.environment~=s.environment or d.pending~=false or type(d.cleanup_required)~='boolean' or not ({issued=true,failed=true,skipped=true,cleaned=true})[d.state] then fail() end
 if d.state=='failed' and d.cleanup_required==false then
  local retry_at=rate_limit(base)
  if retry_at then d.error_kind='rate_limited';d.retry_at=retry_at;raw=codec.json(d)..'\n' end
 end
 io.write(raw);return
end
fail()
