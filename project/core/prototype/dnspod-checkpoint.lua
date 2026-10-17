-- Fixed private checkpoint binding. No transport or public private-frame output.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local mode,account,revision,phase=arg[1],arg[2],arg[3],arg[4]
if (mode~='receipt' and mode~='load' and mode~='receipt-terminal' and mode~='receipt-orphan' and mode~='receipt-checkpoint') or type(account)~='string' or #account>64 or not account:match('^[a-zA-Z0-9_-]+$') or
    type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 or arg[5] or
    (mode=='receipt' and phase~='initial' and phase~='advance') or
    (mode=='receipt-checkpoint' and phase~='initial' and phase~='advance' and phase~='current') or
    (mode~='receipt' and mode~='receipt-checkpoint' and phase) then os.exit(1) end
local json=require('luci.jsonc')
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local plan=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local records=assert(loadfile(dir..'/dnspod-records.lua'))()
local reconcile=assert(loadfile(dir..'/dnspod-reconcile-plan.lua'))()
local function read(fd)
    local f=io.open('/proc/self/fd/'..fd,'rb');if not f then os.exit(1) end
    local raw=f:read(8388609) or '';if not f:close() or #raw>8388608 then os.exit(1) end
    local c=json.parse(raw);if type(c)~='table' or codec.json(c)..'\n'~=raw then os.exit(1) end;return c
end
local c=read(8)
if mode=='receipt-terminal' then
    local raw=io.stdin:read(4097) or '';local doc=json.parse(raw)
    if #raw>4096 or c.account~=account or c.revision~=tonumber(revision) or
        not records.validate(raw,doc,account,revision,'0','HGDNPATTEMPT1\n',{['']=true},{}) or
        not reconcile.terminal(c,doc,codec.json) then os.exit(1) end
    io.write('HGDNPVALID1\n');return
end
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
if not snapshot or snapshot.revision~=tonumber(revision) then os.exit(1) end
local selected;for _,s in ipairs(snapshot.configuration) do if s.kind=='dns_account' and s.name==account then selected=s end end
if not selected or selected.values.provider~='dnspod' then os.exit(1) end
if mode=='receipt' then c=reconcile.export(c) end
c=reconcile.restore(snapshot,account,revision,c,plan,records,codec.json)
if not c then os.exit(1) end
if mode=='receipt-orphan' then
    local work=read(9);local f=io.open('/proc/self/fd/5','rb');if not f then os.exit(1) end
    local raw=f:read(4097) or '';if not f:close() or #raw>4096 then os.exit(1) end
    local request=json.parse(raw)
    if type(request)~='table' or codec.json(request)..'\n'~=raw or not reconcile.orphan(c,work,request,codec.json) then os.exit(1) end
    io.write('HGDNPOBOUND1\n');return
end
if mode=='receipt' or mode=='receipt-checkpoint' then
    if phase=='initial' then if c.affected~=0 then os.exit(1) end
    elseif phase=='advance' then
        local before=reconcile.restore(snapshot,account,revision,read(9),plan,records,codec.json)
        if not before or not reconcile.advance(before,c,codec.json) then os.exit(1) end
    end
end
if mode=='receipt-checkpoint' then io.write('HGDNPCVALID1\n');return end
local body=codec.json(c)..'\n';if #body>8388608 then os.exit(1) end
local f=io.open('/proc/self/fd/3','wb');if not f or not f:write(body) or not f:close() then os.exit(1) end
