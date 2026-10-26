-- Internal fixed-source configuration adapter. Never print private input.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local mode,revision=arg[1],arg[2]
if mode~='validate' or arg[3] or type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 then os.exit(7) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local reader=assert(loadfile(dir..'/private-snapshot.lua'))()
local model=assert(loadfile(dir..'/configuration-validation.lua'))()
local ip=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local function bounded(path,limit)
    local f=io.open(path,'rb');if not f then return nil end
    local raw=f:read(limit+1);if not f:close() or not raw or #raw>limit then return nil end;return raw
end
local version=bounded(dir..'/../../../VERSION',64)
local release=bounded(dir..'/../../../RELEASE',64)
if not version or not version:match('^%d+%.%d+%.%d+\n$') or not release or not release:match('^[1-9]%d*\n$') then os.exit(7) end
version=version:sub(1,-2)..'-r'..release:sub(1,-2)
local snapshot=reader.read(io.stdin,codec)
if not snapshot or snapshot.revision~=tonumber(revision) then os.exit(7) end
local raw=bounded('/etc/config/homegate',262144)
local candidate=raw and codec.private_configuration(raw)
if not candidate then os.exit(7) end
local counts,kind=model.validate(snapshot,candidate,codec.json,ip)
io.write(model.report(version,revision,counts,kind,codec.json));os.exit(counts and 0 or 1)
