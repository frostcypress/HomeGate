-- Private certificate material codec. Never returns PEM/key bytes publicly.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local json=require('luci.jsonc')
local function fail()os.exit(1)end
local function read(path,max)local f=io.open(path,'rb');if not f then fail() end;local raw=f:read(max+1);f:close();if not raw or #raw>max then fail() end;return raw end
local function write(path,body)local f=io.open(path,'wb');if not f or not f:write(body) or not f:close() then fail() end end
local function id(v)return type(v)=='string' and #v>0 and #v<=64 and v:match('^[a-zA-Z0-9_-]+$') end
local mode,selected=arg[1],arg[2];if not id(selected) then fail() end
local root='/etc/homegate/certs/'..selected
local function scope()local d=json.parse(read(root..'/.pending/scope.json',16384));if type(d)~='table' or d.id~=selected or (d.source~='local' and d.source~='acme') or type(d.domains)~='table' then fail() end;return d end
local function pattern(v)
 if type(v)~='string' then return nil end;v=v:lower():gsub('%.$','')
 local body=v:gsub('^%*%.','');if #body<1 or #body>253 or body:find('[^a-z0-9.-]') or body:find('..',1,true) then return nil end
 for label in body:gmatch('[^.]+')do if #label<1 or #label>63 or label:sub(1,1)=='-' or label:sub(-1)=='-' then return nil end end
 if body:sub(1,1)=='.' or body:sub(-1)=='.' then return nil end;return v
end
if mode=='unreferenced'then
 if arg[3]then fail()end
 local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec);if not snapshot then fail()end
 for _,s in ipairs(snapshot.configuration)do if s.kind=='certificate' and s.name==selected or s.kind=='web_rule' and s.values.certificate==selected then fail()end end
 io.write('{"ok":true,"unreferenced":true}\n');return
end
if mode=='scope' or mode=='scope-acme' or mode=='scope-any' then
 if arg[3] then fail() end
 local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec);if not snapshot then fail() end
 for _,section in ipairs(snapshot.configuration)do if section.kind=='certificate' and section.name==selected then
  local v=section.values;if (mode=='scope' and v.source~='local') or (mode=='scope-acme' and v.source~='acme') or #v.domains<1 then fail() end
  local names={};for _,name in ipairs(v.domains)do names[#names+1]=name end;table.sort(names)
  io.write(codec.json({id=selected,source=v.source,environment=v.environment,domains=names,renew_days=tonumber(v.renew_days)})..'\n');return
 end end;fail()
end
local function pem(raw,types,max)
 if type(raw)~='string' or #raw<1 or #raw>max or raw:find('%z') then fail() end
 raw=raw:gsub('\r\n','\n');if raw:find('\r') then fail() end
 local blocks,pos={},1
 while pos<=#raw do
  local a,b,kind=raw:find('^%-%-%-%-%-BEGIN ([A-Z ]+)%-%-%-%-%-\n',pos)
  if not a or not types[kind] then fail() end
  local finish='-----END '..kind..'-----';local e,f=raw:find(finish,b+1,true);if not e then fail() end
  local body=raw:sub(b+1,e-1);if #body<1 or body:find('[^A-Za-z0-9+/=\n]') then fail() end
  blocks[#blocks+1]=raw:sub(a,f)..'\n';if #blocks>8 then fail() end
  pos=f+1;if raw:sub(pos,pos)=='\n' then pos=pos+1 end
 end
 if #blocks<1 then fail() end;return table.concat(blocks),blocks
end
if mode=='receive' then
 if arg[3] then fail() end
 local raw=io.stdin:read(114689);if not raw or #raw>114688 then fail() end;local d=json.parse(raw)
 if type(d)~='table' then fail() end;local n=0;for k in pairs(d)do if k~='certificate_pem' and k~='private_key_pem' then fail() end;n=n+1 end;if n~=2 then fail() end
 local chain=pem(d.certificate_pem,{CERTIFICATE=true},65536)
 local key,blocks=pem(d.private_key_pem,{['PRIVATE KEY']=true,['RSA PRIVATE KEY']=true,['EC PRIVATE KEY']=true},16384);if #blocks~=1 then fail() end
 write(root..'/.pending/fullchain.pem',chain);write(root..'/.pending/privkey.pem',key);return
end
if mode=='material' then
 if arg[3] then fail() end;local expected=scope();local base=root..'/.pending/'
 local _,blocks=pem(read(base..'fullchain.pem',65536),{CERTIFICATE=true},65536)
 pem(read(base..'privkey.pem',16384),{['PRIVATE KEY']=true,['RSA PRIVATE KEY']=true,['EC PRIVATE KEY']=true},16384)
 write(base..'leaf.pem',blocks[1]);return
end
local months={Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
local function moment(raw)
 local m,d,h,mi,se,y=raw:match('^(%a%a%a)%s+(%d+)%s+(%d%d):(%d%d):(%d%d)%s+(%d%d%d%d) GMT$')
 if not m or not months[m] then fail() end
 local ts=os.time({year=tonumber(y),month=months[m],day=tonumber(d),hour=tonumber(h),min=tonumber(mi),sec=tonumber(se),isdst=false})
 if not ts then fail() end;return ts,os.date('!%Y-%m-%dT%H:%M:%SZ',ts)
end
if mode=='validated' then
 local expected=scope();local base=root..'/.pending/'
 local dates=read(base..'dates',2048);local a,b=dates:match('^notBefore=([^\n]+)\nnotAfter=([^\n]+)\n$');if not a then fail() end
 local before,before_iso=moment(a);local expires,expires_iso=moment(b);local now=os.time();if now<before or now>=expires then fail() end
 local san=read(base..'san',16384);local rest=san:match('^X509v3 Subject Alternative Name:%s*\n(.*)');if not rest then fail() end
 local got={};rest=rest:gsub('\n',' ')
 for item in (rest..','):gmatch('(.-),')do
  item=item:match('^%s*(.-)%s*$')
  if item:sub(1,4)=='DNS:' then local v=pattern(item:sub(5));if not v then fail() end;got[v]=true end
 end
 local want={};for _,name in ipairs(expected.domains)do want[name]=true;if not got[name] then fail() end end
 for name in pairs(got)do if not want[name] then fail() end end
 io.write(codec.json({api_version=1,ok=true,phase='certificate-material',certificate=selected,domains=expected.domains,expires=expires_iso,not_before=before_iso,expires_epoch=expires,not_before_epoch=before,identity_valid=true,key_matches=true})..'\n');return
end
if mode=='status' then
 -- FD3 is the current expected public scope; FD4 is sealed pair metadata.
 local expected=json.parse(read('/proc/self/fd/3',16384));if not expected or expected.id~=selected then fail() end
 local exists=arg[3]=='true';local pending=arg[4]=='true';if arg[5] then fail() end
 local out={api_version=1,engineering=true,ok=true,phase='certificate-status',certificate=selected,source=expected.source,environment=expected.environment,domains=expected.domains,exists=exists,pending=pending,valid=false,identity_valid=false,renew=false,days=0,effect='none',write_ready=false,trust_checked=false}
 if exists then
  local pair=json.parse(read('/proc/self/fd/4',16384));local saved=json.parse(read('/proc/self/fd/5',16384))
  if not pair or pair.certificate~=selected or type(pair.expires_epoch)~='number' or type(pair.not_before_epoch)~='number' or pair.identity_valid~=true or pair.key_matches~=true or not saved then fail() end
  local function identities(d)return codec.json({id=d.id,source=d.source,environment=d.environment,domains=d.domains}) end
  out.identity_valid=identities(expected)==identities(saved);out.expires=pair.expires;out.days=math.floor((pair.expires_epoch-os.time())/86400)
  out.valid=out.identity_valid and os.time()>=pair.not_before_epoch and os.time()<pair.expires_epoch
  out.renew=out.days<=expected.renew_days;out.error_kind=not out.identity_valid and 'configuration_changed' or (out.valid and '' or 'validity')
 end
 io.write(codec.json(out)..'\n');return
end
fail()
