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
if arg[1]=="normalize" and not arg[2] then
    local body=codec.canonical(read())
    if not body then fail() end
    io.write(body)
elseif arg[1]=="allowed" and arg[2] and not arg[3] then
    for _,s in ipairs(parsed(arg[2])) do
        if s.kind=="dns_account" then
            for _,slot in ipairs({"key_id","secret","account_id","endpoint"}) do
                io.write(s.values.provider,".",s.name,".",slot,"\n")
            end
        end
    end
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
