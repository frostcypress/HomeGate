-- Fixed read-only network commands inside the independently supervised family.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local planner=assert(loadfile(dir..'/ddns-plan.lua'))()
local revision,selected=arg[2],arg[3]
if arg[1]=='intent' then
    if type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 or selected then os.exit(1) end
    local raw=io.stdin:read(262145) or '';local switches=#raw<=262144 and codec.private_ddns_switches(raw)
    if not switches then os.exit(1) end
    local f=io.open('/proc/self/fd/4','wb');if not f or not f:write(codec.json({schema='HGDDNSINTENT1',revision=tonumber(revision),switches=switches})..'\n') or not f:close() then os.exit(1) end;return
end
if type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 or
    (selected~='' and not planner.id(selected)) then os.exit(1) end
if arg[1]=='result' then
    if arg[5] then os.exit(1) end
    local raw=io.stdin:read(65537) or '';local doc=shared.parse(raw)
    local checked=#raw<=65536 and planner.validate(raw,doc,revision,selected,arg[4])
    if not checked then os.exit(1) end;io.write(checked);return
end
if arg[1]~='run' or arg[4] then os.exit(1) end
local function write(fd,body)
    local f=io.open('/proc/self/fd/'..fd,'wb');if not f or not f:write(body) or not f:close() then os.exit(1) end
end
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
if not snapshot or snapshot.revision~=tonumber(revision) then write(3,planner.report(revision,selected,{},'invalid_configuration'));os.exit(1) end
local network=assert(loadfile(dir..'/wan6-plan.lua'))()
local records=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local commands={addresses='/sbin/ip -6 -o addr show scope global',routes='/sbin/ip -6 route show default',wan6='/bin/ubus call network.interface.wan6 status'}
local function execute(kind)
    local command=commands[kind];if not command then return nil,false end
    local pipe=io.popen("rc=0; "..command.." 0</dev/null 2>/dev/null 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- || rc=$?; printf '\\nHGNET:%s\\n' \"$rc\"",'r')
    if not pipe then return nil,false end
    local raw=pipe:read(65537) or '';pipe:close()
    if #raw>65536 then return nil,false end
    local body,rc=raw:match('^(.*)\nHGNET:(%d+)\n$');return body,rc=='0'
end
-- Reuse one bounded command result across automatic and explicit-device rules.
local samples={}
local function run(kind)
    if not samples[kind] then local raw,ok=execute(kind);samples[kind]={raw,ok} end
    return samples[kind][1],samples[kind][2]
end
-- Intent FD is opened only by the fixed worker after the producer reaches EOF.
local f=io.open('/proc/self/fd/5','rb');local intent_raw=f and (f:read(65537) or '')
if not f or not f:close() or #intent_raw>65536 then os.exit(1) end
local intent=shared.parse(intent_raw)
if not intent or codec.json(intent)..'\n'~=intent_raw then write(3,planner.report(revision,selected,{},'invalid_configuration'));os.exit(1) end
local plan,code=planner.build(snapshot,selected,function(source,interface)return network.sample(run,shared.parse,records,source=='interface' and interface or nil) end,records,intent)
if not plan then write(3,planner.report(revision,selected,{},code));os.exit(1) end
local private=codec.json(plan)..'\n';if #private>262144 then os.exit(1) end;write(4,private)
local public,ok=planner.report(revision,selected,plan.entries)
if not public or #public>65536 then os.exit(1) end;write(3,public);os.exit(ok and 0 or 1)
