-- Isolated derived-state receipt, NOT DNS/ACME/proxy/firewall/service apply.
local function fail() os.exit(1) end
local dir=arg[0]:match("^(.*)/[^/]+$")
if not dir or (arg[1]~="apply" and arg[1]~="restore") or not arg[2] or #arg[2]~=32 or arg[2]:find("[^0-9a-f]") or arg[3] then fail() end
local store=os.getenv("HOMEGATE_CONFIG_PROTO_STORE")
if not store or not store:match("^/tmp/homegate%-config%-prototype%-") then fail() end
local codec=assert(loadfile(dir.."/../../luci/lua/luasrc/model/homegate/backup.lua"))()
local reader=assert(loadfile(dir.."/private-snapshot.lua"))()
local snapshot=reader.read(io.stdin,codec)
if not snapshot then fail() end
local main
for _,s in ipairs(snapshot.configuration) do if s.kind=="homegate" then main=s.values end end
if not main then fail() end
local f=io.open("/proc/self/stat","rb"); if not f then fail() end
local pid=(f:read(8192) or ""):match("^(%d+) "); f:close(); if not pid then fail() end
local temporary=store.."/.runtime."..pid
local body="homegate-worker-receipt:1\nrevision="..snapshot.revision.."\nrole="..arg[1].."\nhttps_port="..main.https_port.."\n"
f=io.open(temporary,"wb"); if not f then fail() end
local written=f:write(body); local closed=f:close()
if not written or not closed or not os.rename(temporary,store.."/runtime") then fail() end
