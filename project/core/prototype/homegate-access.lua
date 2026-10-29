-- Fixed private CN cache/update adapter. Public output contains no file path.
local dir=assert(arg[0]:match('^(.*)/[^/]+$'));local model=assert(loadfile(dir..'/access-region.lua'))()
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))();local json=require('luci.jsonc')
local root='/var/run/homegate/access-update';local cache='/etc/homegate/access/CN.cidr'
local function fail()os.exit(1)end
local function read(p,n)local f=io.open(p,'rb');if not f then return nil end;local s=f:read(n+1);f:close();if not s or #s>n then fail()end;return s end
local function cached(output)
 local f=io.open(cache,'rb');if not f then return nil end;local ok,d=pcall(model.cache,f,output,os.time());f:close();return ok and d or nil
end
local mode=arg[1]
if mode=='parse'then
 local f=assert(io.open(root..'/download','rb'));local out=assert(io.open(root..'/candidate','wb'));local ok,d=pcall(model.parse,f,out,os.time());f:close();local closed=out:close();if not ok or not closed then fail()end;return
end
if mode=='cache-check'then local d=cached();if not d then fail()end;return end
if mode=='cache-fresh'then local d=cached();if not d or d.stale then fail()end;return end
if mode=='snapshot'then
 local p=json.parse(assert(read('/var/run/homegate/proxy/plan.json',131072)));local f=assert(io.open('/var/run/homegate/proxy/cn.conf','wb'))
 if p.region=='CN'then local d=cached(f);f:close();if not d then fail()end else f:close()end;return
end
if mode=='status'then
 local d=cached();local raw=read(root..'/report',4096);local report=raw and json.parse(raw)
 io.write(codec.json({api_version=1,engineering=true,ok=true,phase='access-region',running=arg[2]=='true',state=report and report.state or 'idle',cache_valid=d~=nil,cache_stale=d and d.stale or false,ipv4=d and d.ipv4 or 0,ipv6=d and d.ipv6 or 0,cache_updated=d and d.updated or 0,effect='none',write_ready=false})..'\n');return
end
if mode=='report'then
 if not ({starting=true,downloading=true,published=true,failed=true,stopped=true,cached=true})[arg[2]]then fail()end
 local f=assert(io.open(root..'/report.next','wb'));f:write(codec.json({state=arg[2]})..'\n');f:close();assert(os.rename(root..'/report.next',root..'/report'));return
end
fail()
