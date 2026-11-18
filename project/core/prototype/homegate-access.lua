-- Fixed private CN cache/update adapter. Public output contains no file path.
local dir=assert(arg[0]:match('^(.*)/[^/]+$'));local model=assert(loadfile(dir..'/access-region.lua'))()
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))();local json=require('luci.jsonc')
local root='/var/run/homegate/access-update';local cache='/etc/homegate/access/CN.cidr'
local function fail()os.exit(1)end
local function read(p,n)local f=io.open(p,'rb');if not f then return nil end;local s=f:read(n+1);f:close();if not s or #s>n then fail()end;return s end
local mode=arg[1]
if mode=='parse' or mode=='cache-quota' or mode=='status' or mode=='display-time' then
 local tz=read('/etc/TZ',256)
 tz=tz and tz:match('^([^%c]+)%s*$')
 require('nixio').setenv('TZ',tz)
end
local function cached(output,keep_members)
 local f=io.open(cache,'rb');if not f then return nil end;local ok,d=pcall(model.cache,f,output,os.time(),keep_members);f:close();return ok and d or nil
end
local function daily_count(old,day)
 if not old then return 0 end
 if old.day then return old.day==day and old.day_count or 0 end
 return os.date('%Y%m%d',old.updated)==day and 1 or 0
end
local function display_time(stamp)return os.date('%Y/%m/%d %H:%M',stamp)end
if mode=='display-time' then
 local stamp=tonumber(arg[2]);if not stamp or stamp<=0 or stamp>2147483647 or stamp%1~=0 or arg[3]then fail()end
 io.write(display_time(stamp),'\n');return
end
if mode=='cache-quota' then
 if daily_count(cached(),os.date('%Y%m%d'))<2 then fail()end
 return
end
if mode=='parse'then
 local now=os.time();local day=os.date('%Y%m%d',now)
 local old=cached(nil,true)
 local count=daily_count(old,day)
 if count>=2 then os.exit(4)end
 local f=assert(io.open(root..'/download','rb'));local out=assert(io.open(root..'/candidate','wb'))
 local ok,d=pcall(model.parse,f,out,now,{day=day,count=count+1});f:close()
 if not out:close() or not ok then fail()end
 if old and old.prefixes==d.prefixes then
  for prefix in pairs(d.members)do if not old.members[prefix]then return end end
  os.exit(3)
 end
 return
end
if mode=='cache-check'then local d=cached();if not d then fail()end;return end
if mode=='cache-fresh'then local d=cached();if not d or d.stale then fail()end;return end
if mode=='snapshot'then
 local p=json.parse(assert(read('/var/run/homegate/proxy/plan.json',131072)));local f=assert(io.open('/var/run/homegate/proxy/cn.conf','wb'))
 if p.region=='CN'then local d=cached(f);f:close();if not d then fail()end else f:close()end;return
end
if mode=='status'then
 local d
 if arg[3]~='light' then d=cached()end
 local raw=read(root..'/report',4096);local report=raw and json.parse(raw)
 local state=report and report.state or 'idle'
 local reason=report and report.error_kind
 if arg[3]=='terminal' and (state=='starting' or state=='downloading')then state='failed';reason='worker_exit'end
 io.write(codec.json({api_version=1,engineering=true,ok=true,phase='access-region',running=arg[2]=='true',state=state,error_kind=reason,cache_valid=d~=nil,cache_stale=d and d.stale or false,ipv4=d and d.ipv4 or 0,ipv6=d and d.ipv6 or 0,cache_updated=d and d.updated or 0,cache_updated_local=d and display_time(d.updated) or nil,effect='none',write_ready=false})..'\n');return
end
if mode=='report'then
 if not ({starting=true,downloading=true,published=true,failed=true,stopped=true,cached=true,limited=true})[arg[2]]then fail()end
 local reason=arg[3];if reason==''then reason=nil end
 if reason and not ({transport=true,invalid_data=true,publish=true,timeout=true,worker_exit=true})[reason]then fail()end
 local f=assert(io.open(root..'/report.next','wb'));f:write(codec.json({state=arg[2],error_kind=reason})..'\n');f:close();assert(os.rename(root..'/report.next',root..'/report'));return
end
fail()
