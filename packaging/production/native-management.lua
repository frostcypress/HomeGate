-- Resolve local uhttpd listeners separately from arbitrary LAN service targets.
local M={}
local base='/usr/libexec/homegate/project/core/prototype/'
local ip=assert(loadfile(base..'cloudflare-record-plan.lua'))()
local validation=assert(loadfile(base..'configuration-validation.lua'))()
local nixio=require('nixio')
local codec=assert(loadfile(base..'../../luci/lua/luasrc/model/homegate/backup.lua'))()

function M.domains(document,wan,observe,selected)
 local address=ip.ipv6(wan)
 local eligible={}
 if not address or not address:match('^[23]') then return eligible end
 local names={}
 local certificates={}
 local function add(value)
  local name=codec.management_domain(value)
  if name and name~='' and (not selected or selected==name) then names[name]=true end
 end
 for _,section in ipairs(document)do
  local values=section.values
  if section.kind=='homegate' then add(values.management_domain)
  elseif section.kind=='web_rule' then add(values.domain)
  elseif section.kind=='ddns_rule' and values.type=='AAAA' then
   add(values.host=='@' and values.zone or values.host)
  elseif section.kind=='certificate' and values.enabled=='1' and values.environment~='staging' then
   certificates[#certificates+1]=section
  end
 end
 table.sort(certificates,function(a,b)return a.name<b.name end)
 local validity={}
 for name in pairs(names)do
  local parent=name:match('^[^.]+%.(.+)$')
  local chosen,exact
  for _,cert in ipairs(certificates)do
   for _,pattern in ipairs(cert.values.domains or {})do
    local same=pattern==name
    if (same or pattern=='*.'..parent) and (not chosen or same and not exact) then
     if validity[cert.name]==nil then
      local ok,status=pcall(observe,cert.name,cert.values)
      validity[cert.name]=ok and type(status)=='table' and status.valid==true
     end
     if validity[cert.name] then chosen,exact=cert.name,same end
    end
   end
   if exact then break end
  end
  if chosen then
   local records=nixio.getaddrinfo(name..'.','inet6')
   local found,other=false,false
   for _,record in ipairs(records or {})do
    local resolved=ip.ipv6(record.address)
    if resolved==address then found=true
    elseif resolved then other=true end
   end
   if found and not other then eligible[name]=chosen end
  end
 end
 return eligible
end

local function address_key(address)
 local v6=ip.ipv6(address)
 if v6 and v6:sub(1,30)=='0000:0000:0000:0000:0000:ffff:' then
  local tail=v6:sub(31):gsub(':','')
  local parts={}
  for i=1,8,2 do parts[#parts+1]=tonumber(tail:sub(i,i+1),16) end
  return table.concat(parts,'.')
 end
 return v6 or address
end

local function listeners(read_option,interfaces)
 local local_addresses={['127.0.0.1']=true,[address_key('::1')]=true}
 for _,row in ipairs(interfaces)do
  if (row.family=='inet' or row.family=='inet6') and type(row.addr)=='string'then
   local_addresses[address_key((row.addr:gsub('%%.*$','')))]=true
  end
 end
 local out={ports={},local_addresses=local_addresses}
 for _,scheme in ipairs({'https','http'})do
  for binding in read_option(scheme):gmatch('%S+')do
   local host,port=binding:match('^%[([^%]]+)%]:(%d+)$')
   if not host then host,port=binding:match('^([^:]+):(%d+)$')end
   port=tonumber(port)
   if port and port>=1 and port<=65535 then
    out.ports[port]=true
    local address=({['0.0.0.0']='127.0.0.1',['::']='::1'})[host] or host
    if not out.backend and local_addresses[address_key(address)] then
     out.backend={scheme=scheme,authority=(address:find(':',1,true) and '['..address..']' or address)..':'..port}
    end
   end
  end
 end
 return out
end

function M.read()
 local function option(scheme)
  local pipe=io.popen('uci -q get uhttpd.main.listen_'..scheme..' 2>/dev/null','r')
  if not pipe then return '' end
  local value=pipe:read(4097) or '';pipe:close()
  return #value<=4096 and value or ''
 end
 local interfaces=nixio.getifaddrs()
 if not interfaces then return nil end
 local result=listeners(option,interfaces)
 -- Also reserve the conventional local listener ports when an option is absent.
 if next(result.ports)==nil then result.ports[80],result.ports[443]=true,true end
 return result
end

function M.ordinary_target(context,target,resolve)
 if not context or not validation.target(target,ip) then return nil,'invalid' end
 local scheme,authority=target:match('^(https?)://([^/?]+)')
 local host,port=authority:match('^%[([^%]]+)%]:(%d+)$')
 if not host then host,port=authority:match('^([^:]+):(%d+)$')end
 if not host then host=authority:match('^%[([^%]]+)%]$') or authority end
 port=tonumber(port) or (scheme=='https' and 443 or 80)
 if not context.ports[port] then return true end
 local addresses={}
 if ip.ipv6(host) or host:match('^[%d.]+$') then addresses[1]={address=host}
 else addresses=(resolve or nixio.getaddrinfo)(host) end
 if not addresses or #addresses==0 then return nil,'unresolved' end
 local upstreams,seen={},{}
 for _,row in ipairs(addresses)do
  local address=row.address
  if type(address)=='string' then
   local key=address_key(address)
   if context.local_addresses[key] or key:match('^127%.') or key=='0.0.0.0' or key==address_key('::') then return nil,'local_management' end
   if not seen[key] then
    seen[key]=true
    upstreams[#upstreams+1]=(ip.ipv6(address) and '['..address..']' or address)..':'..port
   end
  end
 end
 if #upstreams==0 or #upstreams>32 then return nil,'unresolved' end
 return true,nil,upstreams
end
return M
