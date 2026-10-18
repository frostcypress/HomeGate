-- Fixed private descriptors only. No network, shell commands or caller paths.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local planner=assert(loadfile(dir..'/ddns-plan.lua'))()
local sync=assert(loadfile(dir..'/ddns-sync.lua'))()
local revision,rule=arg[2],arg[3]
if type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 or (arg[1]~='source' and not planner.id(rule)) then os.exit(1) end
local function read(fd,limit)
    local f=io.open('/proc/self/fd/'..fd,'rb');if not f then os.exit(1) end
    local b=f:read(limit+1) or '';if not f:close() or #b>limit then os.exit(1) end;return b
end
if arg[1]=='work-source' or arg[1]=='source' then
    if arg[4] or (arg[1]=='source' and arg[3]) then os.exit(1) end
    local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
    if not snapshot or snapshot.revision~=tonumber(revision) then os.exit(1) end
    io.write('HGDDNSSOURCE1\n');return
elseif arg[1]=='dispatch' or arg[1]=='work-bound' or arg[1]=='work-bound-runtime' then
    if arg[4] then os.exit(1) end
    local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
    local raw=read(5,262144);local plan=shared.parse(raw)
    local intent_raw=read(8,65536);local intent=shared.parse(intent_raw)
    if not plan or codec.json(plan)..'\n'~=raw or not intent or codec.json(intent)..'\n'~=intent_raw or not snapshot or snapshot.revision~=tonumber(revision) then os.exit(1) end
    if arg[1]=='work-bound-runtime' then
        local expected=assert(loadfile(dir..'/ddns-authority.lua'))().intent(snapshot,rule,planner.id)
        if not expected or codec.json(expected)..'\n'~=intent_raw then os.exit(1) end
    end
    local public=read(9,65536);local doc=shared.parse(public)
    if not planner.validate(public,doc,revision,rule,'0') then os.exit(1) end
    local entry=sync.bind(snapshot,intent,plan,rule,planner,assert(loadfile(dir..'/wan6-plan.lua'))(),assert(loadfile(dir..'/cloudflare-record-plan.lua'))(),codec.json)
    if not entry or not doc.rules[1] or doc.rules[1].status~=entry.status or doc.rules[1].provider~=entry.provider then os.exit(1) end
    if entry.status=='disabled' then io.write('disabled\n');return end
    if arg[1]=='work-bound' or arg[1]=='work-bound-runtime' then
        if read(4,4096)~=codec.json(entry.request)..'\n' then os.exit(1) end
        local raw_context=read(3,8388608);local context=shared.parse(raw_context)
        if not context or codec.json(context)..'\n'~=raw_context or codec.json(context.request)~=codec.json(entry.request) then os.exit(1) end
        local plan=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
        local recovery=assert(loadfile(dir..'/'..entry.provider..'-reconcile-plan.lua'))()
        local records=entry.provider~='cloudflare' and assert(loadfile(dir..'/'..entry.provider..'-records.lua'))() or nil
        if not recovery.restore(snapshot,entry.account,revision,context,plan,records,codec.json) then os.exit(1) end
        io.write('HGDDNSBOUND1\n');return
    end
    local f=io.open('/proc/self/fd/4','wb');if not f or not f:write(codec.json(entry.request)..'\n') or not f:close() then os.exit(1) end
    io.write(entry.provider..':'..entry.account..'\n')
elseif arg[1]=='result' then
    local provider,account,rc=arg[4],arg[5],arg[6]
    if arg[7] or not planner.id(account) or (provider~='cloudflare' and provider~='aliyun' and provider~='dnspod' and provider~='huaweicloud') then os.exit(1) end
    local raw=io.stdin:read(4097) or '';local d=shared.parse(raw)
    local out,effect=sync.result(raw,d,provider,account,revision,rule,rc)
    if #raw>4096 or not out then os.exit(1) end
    -- Only a bound original success terminal is acceptable after a mutation.
    if effect=='confirmed' and read(9,4096)~=raw then os.exit(1) end
    io.write(out)
else os.exit(1) end
