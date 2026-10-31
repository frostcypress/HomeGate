-- Typed public adapters. A private certificate pair leaves only through stdin.
local base=assert(arg[0]:match('^(.*)/[^/]+$'))
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local json=require('luci.jsonc');local fs=require('nixio.fs')
local function fail()os.exit(7)end
local function emit(d)io.write(codec.json(d),'\n')end
local function read(path,n,mode)
 if type(path)~='string' or #path>4096 or path:find('%z')then fail()end
 local a=fs.lstat(path);if not a or a.type~='reg' or a.uid~=0 or a.nlink~=1 or a.size>n or (a.modedec~=600 and not(mode=='public' and a.modedec==644))then fail()end
 local f=assert(io.open(path,'rb'));local raw=f:read(n+1) or '';if not f:close() or #raw>n then fail()end
 local b=fs.lstat(path);if not b or a.dev~=b.dev or a.ino~=b.ino or a.size~=b.size or a.modedec~=b.modedec then fail()end;return raw
end
local mode=arg[1]
local function version()
 local v,r=read(base..'/VERSION',64,'public'),read(base..'/RELEASE',64,'public')
 if not v:match('^%d+%.%d+%.%d+\n$') or not r:match('^[1-9]%d*\n$')then fail()end
 return v:sub(1,-2)..'-r'..r:sub(1,-2)
end
if mode=='version'then
 if arg[2]then fail()end
 local machine=require('nixio').uname().machine;local arch=({x86_64='amd64',aarch64='arm64',armv7l='arm',armv6l='arm',i686='386',mips='mips',mipsel='mipsle',mips64='mips64',mips64el='mips64le',riscv64='riscv64'})[machine] or machine
 emit({api_version=1,native=true,version=version(),arch=arch,package_arch='all',effect='none',write_ready=false});return
elseif mode=='legacy-import'then
 local id=arg[2];if type(id)~='string' or #id>64 or not id:match('^[a-zA-Z0-9_-]+$') or arg[3]then fail()end
 for _,p in ipairs({'/etc/homegate','/etc/homegate/certs','/etc/homegate/certs/'..id})do local a=fs.lstat(p);if not a or a.type~='dir' or a.uid~=0 or a.modedec~=700 then fail()end end
 emit({certificate_pem=read('/etc/homegate/certs/'..id..'/fullchain.pem',65536,'public'),private_key_pem=read('/etc/homegate/certs/'..id..'/privkey.pem',16384)});return
elseif mode=='import'then
 if not arg[2] or not arg[3] or arg[4] then fail()end
 emit({certificate_pem=read(arg[2],65536,'public'),private_key_pem=read(arg[3],16384)});return
elseif mode=='ids'then
 local raw=io.stdin:read(262145);local doc=raw and #raw<=262144 and codec.parse(raw);if not doc then fail()end
 if arg[2]~='certificate' then fail()end
 for _,s in ipairs(doc)do if s.kind==arg[2] then io.write(s.name,'\n')end end;return
elseif mode=='aggregate'then
 local rows={};local ok=true;local size=0
 for line in io.stdin:lines()do size=size+#line;if size>524288 or #rows>=128 then fail()end
  local d=json.parse(line);if type(d)~='table' or type(d.ok)~='boolean' or d.phase~='certificate-status' then fail()end
  rows[#rows+1]=d;if not d.ok then ok=false end
 end
 emit({api_version=1,native=true,ok=ok,version=version(),phase='certificate-status',certificates=rows,effect='none',write_ready=false});if not ok then os.exit(1)end;return
elseif mode=='selftest'then
 local report=assert(loadfile(base..'/native-selftest.lua'))()(version())
 emit(report);if not report.ok then os.exit(1)end;return
end
fail()
