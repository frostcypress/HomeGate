-- Fixed read-only OpenWrt sampler. Runs only inside the bounded observer session.
-- The caller supplies neither paths nor state booleans. No service actions.
local function fail() os.exit(1) end
if arg[1] then fail() end
local json= require('luci.jsonc')
local function read(path,limit,empty,vanishing)
    local f=io.open(path,'rb'); if not f then return nil end
    local body=f:read(limit+1); local ok=f:close()
    if body==nil and vanishing and ok then return nil end
    if not body and empty then body='' end
    if not body or #body>limit or not ok then fail() end
    return body
end
local function capture(command,limit)
    local p=io.popen(command,'r'); if not p then fail() end
    local body=p:read(limit+1); local ok=p:close()
    if not body or #body>limit or not ok then fail() end
    return body
end
local function boot()
    local s=read('/proc/sys/kernel/random/boot_id',37)
    if not s or not s:match('^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x\n$') then fail() end
    return s:sub(1,-2)
end
local function process(pid)
    local a=read('/proc/'..pid..'/stat',8192,false,true); if not a then return nil end
    local tail=a:match('^%d+ %(.+%) (.+)$'); if not tail then fail() end
    local fields={}; for v in tail:gmatch('%S+') do fields[#fields+1]=v end
    if #fields<20 or not fields[20]:match('^%d+$') then fail() end
    if fields[1]=='Z' or fields[1]=='X' then return nil end
    local command=read('/proc/'..pid..'/cmdline',8192,true)
    if command==nil then return nil end -- task may have exited while inspected
    local b=read('/proc/'..pid..'/stat',8192,false,true)
    if not b then
        if command=='/usr/bin/homegate\0daemon\0' then fail() end
        return nil
    end
    local bt=b:match('^%d+ %(.+%) (.+)$'); if not bt then fail() end
    local after={}; for v in bt:gmatch('%S+') do after[#after+1]=v end
    if after[20]~=fields[20] or after[1]=='Z' or after[1]=='X' then
        -- Unrelated short-lived tasks may exit during the bounded /proc scan.
        -- A tracked PID is still rejected by the caller when no identity is
        -- returned. A recognized daemon transition is never ignored.
        if command=='/usr/bin/homegate\0daemon\0' then fail() end
        return nil
    end
    return command,fields[20]
end
local function object(value)
    if type(value)~='table' then fail() end
    for key in pairs(value) do if type(key)~='string' then fail() end end
    return value
end
local function parse(body)
    if #body>65536 or not body:match('^%s*{') then fail() end
    -- The official jsonc convenience parse() accepts a following document.
    -- Incremental completion plus whitespace-only remainder closes that gap.
    local parser=json.new(); if not parser then fail() end
    local completed=false
    for i=1,#body do
        local c=body:sub(i,i)
        if completed then if not c:match('%s') then fail() end
        else
            local result=parser:parse(c)
            if result==nil then fail() end
            completed=result
        end
    end
    if not completed then fail() end
    local doc=object(parser:get())
    for name in pairs(doc) do if name~='homegate' then fail() end end
    if doc.homegate==nil then
        if not body:match('^%s*{%s*}%s*$') then fail() end
        return 0,nil
    end
    local service=object(doc.homegate)
    if service.instances==nil then
        -- jsonc maps both empty objects and arrays to an empty Lua table.
        -- Accept only the two known empty-service forms, never an empty array.
        if not body:match('^%s*{%s*"homegate"%s*:%s*{%s*}%s*}%s*$') and
           not body:match('^%s*{%s*"homegate"%s*:%s*{%s*"autostart"%s*:%s*false%s*}%s*}%s*$') then fail() end
        return 0,nil
    end
    local instances=object(service.instances); local count=0; local live
    for name,instance in pairs(instances) do
        count=count+1
        if count>1 or #name>64 or not name:match('^[a-zA-Z0-9_-]+$') then fail() end
        instance=object(instance)
        if type(instance.running)~='boolean' then fail() end
        local command=instance.command
        if type(command)~='table' or command[1]~='/usr/bin/homegate' or command[2]~='daemon' then fail() end
        local n=0; for k in pairs(command) do if k~=1 and k~=2 then fail() end; n=n+1 end
        if n~=2 then fail() end
        if instance.running then
            local pid=instance.pid
            if type(pid)~='number' or pid~=math.floor(pid) or pid<2 or pid>999999999 then fail() end
            live=string.format('%.0f',pid)
        elseif instance.pid~=nil then fail() end
    end
    -- procd omits "instances" when none exist. Empty tables/arrays are unknown.
    if count~=1 then fail() end
    return live and 1 or 0,live
end
local function sample()
    local enabled=capture('IPKG_INSTROOT= INIT_TRACE= /etc/init.d/homegate enabled >/dev/null 2>&1; printf "%s\\n" "$?"',16)
    if enabled~='0\n' and enabled~='1\n' then fail() end
    -- The sentinel is generated by a fixed shell after ubus exits; Lua 5.1
    -- pclose alone does not provide a portable child exit-status check.
    local raw=capture('/sbin/ubus -t 2 -S call service list \'{"name":"homegate","verbose":true}\'; printf "\\nHGSAMPLE-EXIT:%s\\n" "$?"',65568)
    local body,status=raw:match('^(.*)\nHGSAMPLE%-EXIT:(%d+)\n$')
    if not body or status~='0' then fail() end
    local running,pid=parse(body)
    local listing_raw=capture('ls -1 /proc; printf "\\nHGSAMPLE-EXIT:%s\\n" "$?"',65568)
    local listing,list_status=listing_raw:match('^(.*)\nHGSAMPLE%-EXIT:(%d+)\n$')
    if not listing or #listing>65536 or list_status~='0' then fail() end
    local inspected=0; local identity; local matching=0
    for p in listing:gmatch('[^\n]+') do
        if p:match('^[1-9]%d*$') then
            inspected=inspected+1; if inspected>4096 or #p>9 then fail() end
            local command,birth=process(p)
            if command=='/usr/bin/homegate\0daemon\0' then
                matching=matching+1
                if p~=pid then fail() end
                identity=p..':'..birth
            elseif p==pid then fail() end
        end
    end
    if (running==1 and (matching~=1 or not identity)) or (running==0 and matching~=0) then fail() end
    return enabled=='0\n' and 1 or 0,running,identity or 'none'
end
local before=boot()
local enabled,running,identity=sample()
local enabled2,running2,identity2=sample()
if enabled~=enabled2 or running~=running2 or identity~=identity2 or boot()~=before then fail() end
-- This FD is a private bounded scratch file owned by the locked coordinator.
local f=io.open('/proc/self/fd/3','wb'); if not f then fail() end
local ok=f:write('HGSERVICE1\n',enabled,'\n',running,'\n',before,'\n')
local closed=f:close(); if not ok or not closed then fail() end
