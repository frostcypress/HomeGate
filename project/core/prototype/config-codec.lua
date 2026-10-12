-- Internal codec adapter for the isolated Shell transaction experiment.
-- Paths below are allocated and checked by the caller; never exposed via RPC.
local function fail()
    io.stderr:write("Public configuration validation failed\n")
    os.exit(1)
end
local dir=arg[0]:match("^(.*)/[^/]+$")
if not dir then fail() end
local loader=loadfile(dir.."/../../luci/lua/luasrc/model/homegate/backup.lua")
if not loader then fail() end
local codec=loader()
local function read(path)
    local stream=path and io.open(path,"rb") or io.stdin
    if not stream then fail() end
    local body=stream:read(262145)
    if path then stream:close() end
    if not body or #body>262144 then fail() end
    return body
end
local function parsed(path)
    local doc=codec.parse(read(path))
    if not doc then fail() end
    return doc
end
local function allowed(doc)
    local slots={}
    for _,s in ipairs(doc) do
        if s.kind=="dns_account" then
            for _,slot in ipairs({"key_id","secret","account_id","endpoint"}) do
                slots[#slots+1]=s.values.provider.."."..s.name.."."..slot
            end
        elseif s.kind=="ddns_rule" then slots[#slots+1]="ddns."..s.name..".url"
        elseif s.kind=="web_rule" then slots[#slots+1]="web."..s.name..".target"
        end
    end
    return slots
end
if arg[1]=="normalize" and not arg[2] then
    local body=codec.canonical(read())
    if not body then fail() end
    io.write(body)
elseif arg[1]=="allowed" and arg[2] and not arg[3] then
    for _,slot in ipairs(allowed(parsed(arg[2]))) do io.write(slot,"\n") end
elseif arg[1]=="snapshot" and arg[2] and arg[3] and not arg[4] then
    local body=read(arg[2].."/public.conf")
    local doc=codec.parse(body)
    if not doc then fail() end
    local slots=allowed(doc); table.sort(slots)
    local records={}; local count=0
    for _,name in ipairs(slots) do
        local f=io.open(arg[2].."/credentials/"..name,"rb")
        if f then
            local value=f:read(4097); local closed=f:close()
            if not value or #value<1 or #value>4096 or not closed then fail() end
            count=count+1
            records[#records+1]=#name.."\n"..#value.."\n"..name..value
        end
    end
    local frame="HGPRIVATE1\n"..arg[3].."\n"..#body.."\n"..count.."\n"..body..table.concat(records).."END\n"
    local loader=loadfile(dir.."/private-snapshot.lua")
    if not loader or not loader().parse(frame,codec) then fail() end
    -- The parent already checks FD 3 is a pipe and owns the store flock.
    -- Validate the whole frame before delivering any private bytes.
    local f=io.open("/proc/self/fd/3","wb")
    if not f then fail() end
    local written=f:write(frame); local closed=f:close()
    if not written or not closed then fail() end
elseif arg[1]=="migrate" and arg[2] and arg[3] and not arg[4] then
    local body,slots=codec.migration(read(arg[2]))
    if not body then fail() end
    local function write(path,value)
        local f=io.open(path,"wb")
        if not f then fail() end
        local written=f:write(value)
        local closed=f:close()
        if not written or not closed then fail() end
    end
    -- The Shell caller holds the store lock and allocated an empty 0700
    -- generation. These are generated slot names, never caller-supplied paths.
    write(arg[3].."/public.conf",body)
    for slot,value in pairs(slots) do write(arg[3].."/credentials/"..slot,value) end
elseif arg[1]=="diff" and arg[2] and arg[3] and not arg[4] then
    local before=parsed(arg[2])
    local cursor={foreach=function(self,pkg,kind,cb)
        if pkg~="homegate" then fail() end
        for _,s in ipairs(before) do
            if s.kind==kind then
                local raw={['.name']=s.name,['.type']=s.kind}
                for key,value in pairs(s.values) do raw[key]=value end
                cb(raw)
            end
        end
    end}
    local report=codec.preview(cursor,read(arg[3]))
    if not report then fail() end
    local body=codec.json(report.changes)
    if #body>1048576 then fail() end
    io.write(body)
else fail() end
