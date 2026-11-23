-- Pure bounded APNIC statistics/cache codec. Registration economy, not geo-IP.
local M={limit=24*1024*1024,max_prefixes=262144}
local directory=... or arg[0]:match('^(.*)/[^/]+$')
local ip=assert(loadfile(directory..'/cloudflare-record-plan.lua'))()
local function bad()error('Invalid bounded CN allocation data',0)end
local function integer(v,lo,hi)if type(v)~='string' or not v:match('^%d+$') or #v>10 then bad()end;local n=tonumber(v);if n<lo or n>hi then bad()end;return n end
local function v4(s)
 local a,b,c,d=s:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$');if not a then return nil end
 local out={};for _,v in ipairs({a,b,c,d})do if #v>3 or (#v>1 and v:sub(1,1)=='0') or tonumber(v)>255 then return nil end;out[#out+1]=tonumber(v)end
 return ((out[1]*256+out[2])*256+out[3])*256+out[4]
end
local function addr(n)local d=n%256;n=math.floor(n/256);local c=n%256;n=math.floor(n/256);return math.floor(n/256)..'.'..n%256 ..'.'..c..'.'..d end
function M.prefix(s)
 if type(s)~='string' or #s>49 then bad()end
 local host,bits=s:match('^([^/]+)/(%d+)$');if not host then bad()end
 local n=v4(host)
 if n then local b=integer(bits,0,32);if n%2^(32-b)~=0 then bad()end;return addr(n)..'/'..b,'ipv4' end
 local full=ip.ipv6(host);if not full or full:sub(1,30)=='0000:0000:0000:0000:0000:ffff:' then bad()end
 local b=integer(bits,1,128);local index=0
 for group in full:gmatch('[^:]+')do local remaining=math.max(0,math.min(16,b-index*16));if tonumber(group,16)%2^(16-remaining)~=0 then bad()end;index=index+1 end
 return full..'/'..b,'ipv6'
end
function M.lines(stream)
 local total,carry,done=0,'',false
 return function()
  while true do
   local finish=carry:find('\n',1,true)
   if finish then local line=carry:sub(1,finish-1);carry=carry:sub(finish+1);if #line>1048576 then bad()end;return line end
   if done then if carry==''then return nil end;local line=carry;carry='';return line end
   local chunk=stream:read(8192)
   if not chunk then done=true else total=total+#chunk;if total>M.limit then bad()end;carry=carry..chunk;if #carry>1048576 then bad()end end
  end
 end
end
function M.parse(stream,output,now,daily)
 local header,records,counts,summaries=false,0,{asn=0,ipv4=0,ipv6=0},{}
 local seen,parts,v4n,v6n,bytes={}, {},0,0,0
 local function emit(prefix)
  local canonical,family=M.prefix(prefix);if seen[canonical]then return end;seen[canonical]=true
  bytes=bytes+#canonical+1;if bytes>M.limit or v4n+v6n>=M.max_prefixes then bad()end
  if family=='ipv4' then v4n=v4n+1 else v6n=v6n+1 end
  parts[#parts+1]=canonical..'\n'
 end
 for line in M.lines(stream)do
  line=line:match('^%s*(.-)%s*$')
  if line~='' and line:sub(1,1)~='#'then
   local f={};for field in (line..'|'):gmatch('(.-)|')do f[#f+1]=field:match('^%s*(.-)%s*$')end
   if not header then if #f~=7 or f[1]~='2' or f[2]~='apnic'then bad()end;header=integer(f[4],1,1000000)
   elseif #f==6 and f[2]=='*' and f[4]=='*' and f[6]=='summary'then
    if f[1]~='apnic' or counts[f[3]]==nil or summaries[f[3]]~=nil then bad()end;summaries[f[3]]=integer(f[5],0,1000000)
   else
    if #f<7 or f[1]~='apnic' or counts[f[3]]==nil then bad()end;records=records+1;counts[f[3]]=counts[f[3]]+1
    if f[2]=='CN' and (f[7]=='allocated' or f[7]=='assigned') and f[3]~='asn'then
     if f[3]=='ipv6' then emit(f[4]..'/'..integer(f[5],1,128))
     else
      local start=v4(f[4]);local n=integer(f[5],1,4294967295);if not start or start+n>4294967296 then bad()end
      while n>0 do local power=0;while power<31 and 2^(power+1)<=n and start%2^(power+1)==0 do power=power+1 end
       emit(addr(start)..'/'..(32-power));local step=2^power;start=start+step;n=n-step
      end
     end
    end
   end
  end
 end
 if not header or records~=header or v4n==0 or v6n==0 then bad()end
 for kind,count in pairs(counts)do if (count>0 and summaries[kind]~=count) or (summaries[kind] and summaries[kind]~=count)then bad()end end
 local header='HGREGION1|'..now..'|'..v4n..'|'..v6n
 if daily then header=header..'|'..daily.day..'|'..daily.count end
 if not output:write(header..'\n')then bad()end;for _,part in ipairs(parts)do if not output:write(part)then bad()end end
 return {updated=now,ipv4=v4n,ipv6=v6n,prefixes=v4n+v6n,stale=false,members=daily and seen or nil}
end
function M.cache(stream,output,now,keep_members)
 local lines=M.lines(stream);local header=lines();if not header then bad()end;local stamp,a,b=header:match('^HGREGION1|(%d+)|(%d+)|(%d+)$')
 local day,count
 if not stamp then
  stamp,a,b,day,count=header:match('^HGREGION1|(%d+)|(%d+)|(%d+)|(%d%d%d%d%d%d%d%d)|([12])$')
 end
 if not stamp then bad()end;stamp=integer(stamp,1,2147483647);a=integer(a,1,M.max_prefixes);b=integer(b,1,M.max_prefixes)
 if stamp>now+300 then bad()end
 local counts={ipv4=0,ipv6=0};local seen={}
 for line in lines do local canonical,kind=M.prefix(line);if canonical~=line or seen[line]then bad()end;seen[line]=true;counts[kind]=counts[kind]+1;if counts.ipv4+counts.ipv6>M.max_prefixes then bad()end;if output and not output:write(line..' 1;\n')then bad()end end
 if counts.ipv4~=a or counts.ipv6~=b then bad()end
 return {updated=stamp,ipv4=a,ipv6=b,prefixes=a+b,stale=now-stamp>604800,
  day=day,day_count=tonumber(count),members=keep_members and seen or nil}
end
-- Compile the same CIDRs used by the proxy for a read-only view of saved observations.
local function rule_members(value)
 local members={}
 for token in (value or ''):gmatch('[^,;%s]+') do
  if not token:find('/',1,true) then token=token..(token:find(':',1,true) and '/128' or '/32') end
  if token=='::/0' then
   members['0000:0000:0000:0000:0000:0000:0000:0000/0']=true
  else
   local ok,canonical=pcall(M.prefix,token)
   if ok then members[canonical]=true end
  end
 end
 return members
end
local function candidate_prefixes(address,lengths)
 local n=v4(address)
 local full=not n and ip.ipv6(address)
 if full and full:sub(1,30)=='0000:0000:0000:0000:0000:ffff:' then
  n=tonumber(full:sub(31,34),16)*65536+tonumber(full:sub(36,39),16)
 end
 local keys={}
 if n then
  for bits in pairs(lengths.ipv4) do
   local width=2^(32-bits)
   keys[#keys+1]=addr(n-n%width)..'/'..bits
  end
  local first,second=math.floor(n/16777216),math.floor(n/65536)%256
  local public=first>0 and first~=10 and first~=127 and first<224 and
   not (first==100 and second>=64 and second<=127 or first==169 and second==254 or
        first==172 and second>=16 and second<=31 or first==192 and second==168)
  return keys,public
 end
 if not full then return nil,false end
 local groups={}
 for group in full:gmatch('[^:]+') do groups[#groups+1]=tonumber(group,16) end
 local zeros=':0000:0000:0000:0000:0000:0000:0000'
 for bits in pairs(lengths.ipv6) do
  local index=math.max(1,math.ceil(bits/16))
  local offset=(index-1)*5
  local width=2^(index*16-bits)
  local value=groups[index]
  keys[#keys+1]=full:sub(1,offset)..string.format('%04x',value-value%width)..zeros:sub(1,(8-index)*5)..'/'..bits
 end
 return keys,groups[1]>=0x2000 and groups[1]<0x4000
end
function M.access_view(scope,allow,deny,cache_path)
 local allowed,denied=rule_members(allow),rule_members(deny)
 local members
 if scope=='CN' then
  local stream=io.open(cache_path or '/etc/homegate/access/CN.cidr','rb')
  if stream then
   local ok,cache=pcall(M.cache,stream,nil,os.time(),true)
   stream:close()
   if ok then members=cache.members end
  end
 end
 local lengths={ipv4={},ipv6={}}
 local function index_prefixes(set)
  for prefix in pairs(set) do
   local family=prefix:find(':',1,true) and 'ipv6' or 'ipv4'
   lengths[family][tonumber(prefix:match('/(%d+)$'))]=true
  end
 end
 index_prefixes(allowed)
 index_prefixes(denied)
 if members then index_prefixes(members) end
 return function(address)
  if type(address)~='string' then return '','unknown' end
  local keys,public=candidate_prefixes(address,lengths)
  if not keys then return '','unknown' end
  local function matches(set)
   for _,key in ipairs(keys) do if set[key] then return true end end
   return false
  end
  local domestic=members and matches(members)
  local region=domestic and 'CN' or members and public and 'foreign' or ''
  if matches(denied) then return region,'manual-deny',false end
  if matches(allowed) then return region,'manual-allow',true end
  if scope=='' then return '','disabled',true end
  if domestic then return region,'region',true end
  if scope=='CN' and not members then return '','unknown' end
  return region,'denied',false
 end
end
return M
