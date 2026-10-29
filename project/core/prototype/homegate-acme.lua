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
if mode=='scope' then
 if not id(job) or arg[3] then fail() end
 local snap=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec);if not snap then fail() end
 local accounts={};for _,s in ipairs(snap.configuration)do if s.kind=='dns_account' then accounts[s.name]=s.values.provider end end
 for _,s in ipairs(snap.configuration)do if s.kind=='certificate' and s.name==job then
  local v=s.values;local provider=accounts[v.account];local slots={cloudflare={'secret'},aliyun={'key_id','secret'},dnspod={'key_id','secret'},huaweicloud={'key_id','secret','account_id','endpoint'}}
  if v.source~='acme' or v.ca~='letsencrypt' or not slots[provider] or (v.environment~='staging' and v.environment~='production') or #v.domains<1 or #v.domains>32 then fail() end
  for _,slot in ipairs(slots[provider])do if not snap.credentials[provider..'.'..v.account..'.'..slot] then fail() end end
  local domains={};for _,d in ipairs(v.domains)do domains[#domains+1]=d end;table.sort(domains)
  io.write(codec.json({id=job,source='acme',ca='letsencrypt',environment=v.environment,account=v.account,provider=provider,domains=domains,email=v.email,revision=snap.revision})..'\n');return
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
local base='/etc/homegate/acme/jobs/'..job
local function scope()local d=parse(read(base..'/scope.json',16384));if not id(d.id) or not id(d.account) or d.source~='acme' or d.ca~='letsencrypt' or (d.environment~='staging' and d.environment~='production') or type(d.domains)~='table' or #d.domains<1 or #d.domains>32 then fail() end;return d end
local function input()local d=parse(read(base..'/dns.input',4096));if d.resource~=scope().id then fail() end;return d end
if mode=='field' then
 local d=scope();local k=arg[3];if arg[4] then fail() end
 if k=='domains' then for _,v in ipairs(d.domains)do io.write(v,'\n') end;return end
 if not ({id=true,account=true,provider=true,environment=true,email=true,revision=true})[k] then fail() end
 io.write(tostring(d[k]),'\n');return
elseif mode=='transport' then
 local method,url=arg[3],arg[4];if arg[5] or not ({GET=true,POST=true,HEAD=true})[method] then fail() end
 local d=scope();local host=d.environment=='staging' and 'acme-staging-v02.api.letsencrypt.org' or 'acme-v02.api.letsencrypt.org'
 if type(url)~='string' or #url>2048 or url:sub(1,#host+9)~='https://'..host..'/' or url:find('[^a-zA-Z0-9_~%.:/?=&%%%-]') then fail() end
 local body=io.stdin:read(131073) or '';if #body>131072 or body:find('%z') then fail() end
 write(base..'/http.body',body)
 local function q(v)return '"'..v:gsub('\\','\\\\'):gsub('"','\\"'):gsub('\r','\\r'):gsub('\n','\\n')..'"' end
 local config='url = '..q(url)..'\nrequest = '..q(method)..'\ndump-header = '..q(base..'/http.header')..'\n'
 if method=='HEAD' then config=config..'head = true\n' end
 if method=='POST' then config=config..'header = "Content-Type: application/jose+json"\ndata-binary = '..q('@'..base..'/http.body')..'\n' end
 write(base..'/http.curl',config);return
elseif mode=='bounded-response' then
 local body=io.stdin:read(131073) or '';if #body>131072 then fail() end;io.write(body);return
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
 local key,state=arg[3],arg[4];if not hex(key,64) or not ({prepared=true,owned=true,preexisting=true,removed=true,unknown=true})[state] or arg[5] then fail() end
 local d=input();d.state=state;write(base..'/challenges/'..key..'.next',codec.json(d)..'\n');return
elseif mode=='challenge-state' then
 local key=arg[3];if not hex(key,64) or arg[4] then fail() end
 local d=parse(read(base..'/challenges/'..key..'.json',4096));local now=input()
 if d.resource~=now.resource or d.name~=now.name or d.value~=now.value or not ({prepared=true,owned=true,preexisting=true,removed=true,unknown=true})[d.state] then fail() end
 io.write(d.state,'\n');return
elseif mode=='dns-result' then
 local d=parse(io.stdin:read(4097) or '');local s=scope()
 if arg[3]~='0' or d.ok~=true or d.provider~=s.provider or d.account~=s.account or d.configuration_revision~=s.revision or (d.effect~='none' and d.effect~='confirmed') or not ({created=true,updated=true,unchanged=true,deleted=true,absent=true})[d.result] then fail() end
 io.write(d.effect=='confirmed' and 'owned\n' or 'preexisting\n');return
elseif mode=='challenge-load' then
 local key=arg[3];if not hex(key,64) or arg[4] then fail() end
 local d=parse(read(base..'/challenges/'..key..'.json',4096));if d.resource~=scope().id or d.state~='owned' then fail() end
 io.write(d.name,'\n',d.value,'\n');return
elseif mode=='clean-check' then
 -- Shell supplies only validated fixed record names; no glob/path from a caller.
 for i=3,#arg do local key=arg[i];if not hex(key,64) then fail() end;local d=parse(read(base..'/challenges/'..key..'.json',4096));if d.state~='removed' and d.state~='preexisting' then fail() end end;return
elseif mode=='install' then
 local cert=read(base..'/issued/fullchain.pem',65536);local key=read(base..'/issued/privkey.pem',16384)
 io.write(codec.json({certificate_pem=cert,private_key_pem=key}));return
elseif mode=='renew-due' then
 local r=parse(io.stdin:read(16385) or '');if r.phase~='certificate-status' or r.certificate~=scope().id then fail() end
 io.write(r.valid==true and r.renew==false and 'skip\n' or 'issue\n');return
elseif mode=='report' then
 local d=scope();local state=arg[3];if not ({accepted=true,pending=true,issued=true,failed=true,interrupted=true,skipped=true,cleaned=true})[state] or arg[5] then fail() end
 local out={api_version=1,engineering=true,ok=true,phase='acme-job',job=job,certificate=d.id,ca='letsencrypt',environment=d.environment,pending=state=='accepted' or state=='pending',state=state,succeeded=state=='issued' or state=='skipped' or state=='cleaned',cleanup_required=arg[4]=='true',effect='none',write_ready=false}
 io.write(codec.json(out),'\n');return
elseif mode=='clear-result' then
 local d=parse(read(base..'/result',16384));if d.pending~=false or d.cleanup_required~=false then fail() end;return
elseif mode=='read-report' then
 local raw=read(base..'/result',16384);local d=parse(raw);local s=scope()
 if codec.json(d)..'\n'~=raw or d.api_version~=1 or d.phase~='acme-job' or d.job~=job or d.certificate~=s.id or d.environment~=s.environment or d.pending~=false or type(d.cleanup_required)~='boolean' or not ({issued=true,failed=true,skipped=true,cleaned=true})[d.state] then fail() end
 io.write(raw);return
end
fail()
