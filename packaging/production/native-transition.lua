-- Fixed offline kit and retained transition data. No package manager/database edits.
local fs=require('nixio.fs');local json=require('luci.jsonc')
local root='/etc/.homegate-transition';local kit='/tmp/homegate-native-kit';local info='/usr/lib/opkg/info'
local packages={'luci-i18n-homegate-zh-cn','luci-app-homegate','homegate'}
local function fail()os.exit(7)end
local function regular(p,max,public)
 local s=fs.lstat(p);if not s or s.type~='reg' or s.uid~=0 or s.nlink~=1 or s.size>max or (s.modedec~=600 and not(public and (s.modedec==644 or s.modedec==755)))then fail()end;return s
end
local function read(p,n,public)
 local a=regular(p,n,public);local f=assert(io.open(p,'rb'));local raw=f:read(n+1) or '';assert(f:close());local b=regular(p,n,public)
 if #raw>n or a.dev~=b.dev or a.ino~=b.ino or a.size~=b.size then fail()end;return raw
end
local function write(p,body,mode)
 if fs.lstat(p..'.next')then fail()end;if fs.lstat(p)then regular(p,262144,true)end
 local f=assert(io.open(p..'.next','wb'));assert(f:write(body));assert(f:close());assert(fs.chmod(p..'.next',mode or '600'));assert(fs.rename(p..'.next',p))
end
local stub='#!/bin/sh\n# Retained by the explicit HomeGate package transition.\nexit 0\n'
local mode=arg[1]
if mode=='kit'then
 local d=json.parse(read(kit..'/receipt.json',16384));if type(d)~='table' or d.format~='homegate-native-kit-v1' or d.architecture~='all' or type(d.version)~='string' or not d.version:match('^%d+%.%d+%.%d+%-r%d+$') or type(d.sha256)~='table'then fail()end
 local expected={'homegate-core.ipk','luci-app-homegate.ipk','luci-i18n-homegate-zh-cn.ipk','factory.config','native-transition.lua','native-transition.sh'}
 local count=0;for _ in pairs(d.sha256)do count=count+1 end;if count~=#expected then fail()end
 for _,name in ipairs(expected)do local h=d.sha256[name];if type(h)~='string' or #h~=64 or h:find('[^0-9a-f]')then fail()end
  regular(kit..'/'..name,67108864);io.write(h,'  ',kit,'/',name,'\n')
 end;return
elseif mode=='status'then
 local d=json.parse(io.stdin:read(16385));if type(d)~='table' or d.api_version~=1 or type(d.service)~='table' or type(d.service.running)~='boolean'then fail()end
 io.write(d.service.running and '1\n' or '0\n');return
elseif mode=='installed'then
 for _,p in ipairs(packages)do if fs.lstat(info..'/'..p..'.control')then regular(info..'/'..p..'.control',65536,true);io.write(p,'\n')end end;return
elseif mode=='native-installed'then
 -- opkg may report dependency errors yet return zero after keeping an older
 -- package. Read the real database before restoring source/releasing the hold.
 local d=json.parse(read(kit..'/receipt.json',16384));if type(d)~='table' or type(d.version)~='string' or not d.version:match('^%d+%.%d+%.%d+%-r%d+$')then fail()end
 local required={['homegate-core']=true,['luci-app-homegate']=true,['luci-i18n-homegate-zh-cn']=true};local found={}
 local function fields(raw)
  local out={};for line in (raw..'\n'):gmatch('(.-)\n')do
   local key,value=line:match('^([%w%-]+):[ \t]*(.-)[ \t]*$')
   if key then if out[key]then fail()end;out[key]=value end
  end;return out
 end
 local database=read(info..'/../status',1048576,true)
 for block in (database..'\n\n'):gmatch('(.-)\n\n')do
  local row=fields(block);local name=row.Package
  if required[name]then
   if found[name]or row.Version~=d.version or row.Status~='install ok installed'then fail()end
   local control=fields(read(info..'/'..name..'.control',65536,true))
   if control.Package~=name or control.Version~=d.version then fail()end;found[name]=true
  end
 end
 for name in pairs(required)do if not found[name]then fail()end end
 if fs.lstat(info..'/homegate.control')then fail()end;return
elseif mode=='hooks-save'then
 if not fs.lstat(info..'/homegate.control')then fail()end
 for _,p in ipairs(packages)do if fs.lstat(info..'/'..p..'.control')then
  write(root..'/'..p..'.control.saved',read(info..'/'..p..'.control',65536,true))
  for _,name in ipairs({'prerm','postrm'})do local path=info..'/'..p..'.'..name
   if fs.lstat(path)then local saved=root..'/'..p..'.'..name;if fs.lstat(saved)then fail()end;write(saved,read(path,262144,true))end
  end
 end end;return
elseif mode=='hooks-mask' or mode=='hooks-check' or mode=='hooks-restore'then
 if mode=='hooks-restore' and not fs.lstat(info..'/homegate.control')then return end
 for _,p in ipairs(packages)do for _,name in ipairs({'prerm','postrm'})do
  local saved=root..'/'..p..'.'..name;local path=info..'/'..p..'.'..name
  if fs.lstat(saved)then
   if fs.lstat(info..'/'..p..'.control') and read(info..'/'..p..'.control',65536,true)~=read(root..'/'..p..'.control.saved',65536)then fail()end
   if mode=='hooks-mask'then
    local a,b=read(saved,262144),read(path,262144,true);if a~=b then fail()end;write(path,stub,'755')
   elseif mode=='hooks-check'then if read(path,262144,true)~=stub then fail()end
   elseif fs.lstat(info..'/'..p..'.control')then
    if fs.lstat(path) and read(path,262144,true)~=stub and read(path,262144,true)~=read(saved,262144)then fail()end
    write(path,read(saved,262144),'755')
   end
  end
 end end;return
elseif mode=='source-stash'then
 local source='/etc/config/homegate';local target=root..'/source.config';if fs.lstat(target)then fail()end
 local a=regular(source,262144,true);assert(fs.chmod(source,'600'));assert(fs.rename(source,target));local b=regular(target,262144)
 if a.dev~=b.dev or a.ino~=b.ino then fail()end;return
elseif mode=='source-restore'then
 local source=root..'/source.config';local target='/etc/config/homegate';if not fs.lstat(source)then regular(target,262144,true);return end
 if fs.lstat(target) and read(target,262144,true)~=read(kit..'/factory.config',262144)then fail()end
 local a=regular(source,262144);assert(fs.rename(source,target));local b=regular(target,262144);if a.dev~=b.dev or a.ino~=b.ino then fail()end;return
elseif mode=='old-quiet'then
 -- Check actual executable inode, never a stored PID or command substring.
 local dev,ino=read(root..'/old-identity',96):match('^(%d+):(%d+)\n$');if not dev then fail()end
 for pid in fs.dir('/proc')do if pid:match('^%d+$')then local s=fs.stat('/proc/'..pid..'/exe');if s and s.dev==tonumber(dev) and s.ino==tonumber(ino)then fail()end end end;return
elseif mode=='old-identity'then
 local a=regular('/usr/bin/homegate',33554432,true);local target=root..'/old-identity'
 if fs.lstat(target)then fail()end;write(target,string.format('%.0f:%.0f\n',a.dev,a.ino));return
elseif mode=='old-move'then
 local source='/usr/bin/homegate';local target=root..'/old-core';local a=regular(source,33554432,true)
 if fs.lstat(target)then fail()end;assert(fs.rename(source,target));local b=regular(target,33554432,true)
 if a.dev~=b.dev or a.ino~=b.ino then fail()end;return
elseif mode=='old-restore'then
 if not fs.lstat(info..'/homegate.control')then return end
 local source=root..'/old-core';local target='/usr/bin/homegate'
 if not fs.lstat(source)then regular(target,33554432,true);return end
 if fs.lstat(target)then fail()end;regular(source,33554432,true);assert(fs.rename(source,target));return
end
fail()
