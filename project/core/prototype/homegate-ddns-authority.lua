-- Read-only scope/credential validation; private normalized frame stays disabled.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local reader=assert(loadfile(dir..'/private-snapshot.lua'))()
local plan=assert(loadfile(dir..'/ddns-plan.lua'))()
local authority=assert(loadfile(dir..'/ddns-authority.lua'))()
if arg[1]=='selection' or arg[1]=='names' or arg[1]=='member' then
    local names=authority.selection(arg[2],plan.id)
    if not names or arg[4] then os.exit(1) end
    if arg[1]=='member' then
        if not plan.id(arg[3]) then os.exit(1) end
        for _,name in ipairs(names) do if name==arg[3] then return end end
        os.exit(1)
    end
    if arg[3] then os.exit(1) end
    io.write(arg[1]=='names' and codec.json(names)..'\n' or table.concat(names,',')..'\n');return
end
local mode,revision,rule=arg[1],arg[2],arg[3]
if (mode~='scope' and mode~='snapshot') or arg[4] or type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 then os.exit(1) end
local raw=io.stdin:read(reader.limit+1) or '';local snapshot=reader.parse(raw,codec)
if not snapshot or snapshot.revision~=tonumber(revision) then os.exit(1) end
local intent,provider=authority.intent(snapshot,rule,plan.id)
if not intent then os.exit(1) end
if mode=='scope' then io.write(provider..'\n');return end
local function write(fd,body)local f=io.open('/proc/self/fd/'..fd,'wb');if not f or not f:write(body) or not f:close() then os.exit(1) end end
write(4,codec.json(intent)..'\n')
write(3,raw)
