local json=require('luci.jsonc')
if arg[1]=='move-config' or arg[1]=='restore-config'then
 local fs=require('nixio.fs');local source='/etc/config/homegate';local stash='/etc/homegate/package-config'
 local function checked(p,public)
  local s=fs.lstat(p);if not s then return nil end
  assert(s.type=='reg' and s.uid==0 and s.nlink==1 and s.size<=262144 and (s.modedec==600 or public and s.modedec==644))
  return s
 end
 local function body(p)local f=assert(io.open(p,'rb'));local raw=f:read(262145) or '';assert(f:close() and #raw<=262144);return raw end
 local a,b=checked(source),checked(stash)
 if arg[1]=='move-config'then
  if b then assert(not a);return end;if not a then return end
  assert(fs.rename(source,stash)) -- No cross-filesystem copy fallback; retain inode.
  b=checked(stash);assert(b and b.dev==a.dev and b.ino==a.ino);return
 end
 if not b then return end
 if a then
  checked('/usr/libexec/homegate/factory.config',true)
  assert(body(source)==body('/usr/libexec/homegate/factory.config'))
 end
 assert(fs.rename(stash,source));a=checked(source);assert(a and a.dev==b.dev and a.ino==b.ino);return
end
local raw=io.stdin:read(16385);local d=raw and #raw<=16384 and json.parse(raw)
if type(d)~='table' or d.api_version~=1 or type(d.service)~='table' or type(d.service.running)~='boolean' then os.exit(7)end
io.write(d.service.running and '1\n' or '0\n')
