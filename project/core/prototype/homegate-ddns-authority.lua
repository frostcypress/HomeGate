-- Read-only scope/credential validation; private normalized frame stays disabled.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local reader=assert(loadfile(dir..'/private-snapshot.lua'))()
local plan=assert(loadfile(dir..'/ddns-plan.lua'))()
local mode,revision,rule=arg[1],arg[2],arg[3]
if (mode~='scope' and mode~='snapshot') or arg[4] or type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 or not plan.id(rule) then os.exit(1) end
local raw=io.stdin:read(reader.limit+1) or '';local snapshot=reader.parse(raw,codec)
if not snapshot or snapshot.revision~=tonumber(revision) then os.exit(1) end
local intent,provider=assert(loadfile(dir..'/ddns-authority.lua'))().intent(snapshot,rule,plan.id)
if not intent then os.exit(1) end
if mode=='scope' then io.write(provider..'\n');return end
local function write(fd,body)local f=io.open('/proc/self/fd/'..fd,'wb');if not f or not f:write(body) or not f:close() then os.exit(1) end end
write(4,codec.json(intent)..'\n')
write(3,raw)
