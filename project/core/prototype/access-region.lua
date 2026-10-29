-- Pure bounded APNIC statistics/cache codec. Registration economy, not geo-IP.
local M={limit=24*1024*1024,max_prefixes=262144}
local ip=assert(loadfile(arg[0]:match('^(.*)/[^/]+$')..'/cloudflare-record-plan.lua'))()
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
function M.parse(stream,output,now)
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
 if not output:write('HGREGION1|'..now..'|'..v4n..'|'..v6n..'\n')then bad()end;for _,part in ipairs(parts)do if not output:write(part)then bad()end end
 return {updated=now,ipv4=v4n,ipv6=v6n,prefixes=v4n+v6n,stale=false}
end
function M.cache(stream,output,now)
 local lines=M.lines(stream);local header=lines();if not header then bad()end;local stamp,a,b=header:match('^HGREGION1|(%d+)|(%d+)|(%d+)$')
 if not stamp then bad()end;stamp=integer(stamp,1,2147483647);a=integer(a,1,M.max_prefixes);b=integer(b,1,M.max_prefixes)
 if stamp>now+300 then bad()end
 local counts={ipv4=0,ipv6=0};local seen={}
 for line in lines do local canonical,kind=M.prefix(line);if canonical~=line or seen[line]then bad()end;seen[line]=true;counts[kind]=counts[kind]+1;if counts.ipv4+counts.ipv6>M.max_prefixes then bad()end;if output and not output:write(line..' 1;\n')then bad()end end
 if counts.ipv4~=a or counts.ipv6~=b then bad()end
 return {updated=stamp,ipv4=a,ipv6=b,prefixes=a+b,stale=now-stamp>604800}
end
return M
