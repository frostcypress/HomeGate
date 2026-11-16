-- Fixed network CLI data adapter; no caller paths, commands or overrides.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local mode,revision,bridge=arg[1],arg[2],arg[3]
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local network=assert(loadfile(dir..'/wan6-plan.lua'))()
local report=assert(loadfile(dir..'/network-report.lua'))()
local plan=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local commands={addresses='/sbin/ip -6 -o addr show scope global',routes='/sbin/ip -6 route show default',wan6='/bin/ubus call network.interface.wan6 status'}
local samples={}
local function run(kind)
    if not samples[kind] then
        local command=commands[kind];if not command then return nil,false end
        local pipe=io.popen("rc=0; "..command.." 0</dev/null 2>/dev/null 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- || rc=$?; printf '\\nHGNET:%s\\n' \"$rc\"",'r')
        local output=pipe and (pipe:read(65537) or '')
        if pipe then pipe:close() end
        local body,rc
        if output and #output<=65536 then body,rc=output:match('^(.*)\nHGNET:(%d+)\n$') end
        samples[kind]={body,rc=='0'}
    end
    return samples[kind][1],samples[kind][2]
end
if mode=='overview-wan' then
    if revision then os.exit(1) end
    -- Only the overview needs the WAN address. Its parent bounds the read and
    -- provides a fixed system PATH; no LAN inventory or configuration lock.
    commands={addresses='ip -6 -o addr show scope global',routes='ip -6 route show default',wan6='ubus -t 2 call network.interface.wan6 status'}
    local raw,ip_ok=run('addresses')
    local addresses=ip_ok and network.addresses(raw,plan)
    local function global(address)
        local expanded=plan.ipv6(address)
        return expanded and expanded:match('^[23]') and report.ipv6(address,plan) or nil
    end
    local address
    local wan_known=addresses and true or false
    if addresses then
        local wan=report.resolve(run,shared.parse,plan,network)
        address=global(wan.public_ipv6)
    else
        -- Older ip applets may lack one-line output. Read only addresses
        -- assigned to the active WAN6 interface, never delegated prefixes.
        local status,ok=run('wan6')
        local wan=ok and shared.parse(status)
        if type(wan)=='table' and type(wan.up)=='boolean' then
            wan_known=true
            local assigned=wan['ipv6-address']
            if wan.up and type(assigned)=='table' then
                for _,item in ipairs(assigned) do
                    if type(item)=='table' and (item.valid==nil or type(item.valid)=='number' and item.valid>0)
                        and (item.preferred==nil or type(item.preferred)=='number' and item.preferred>0) then
                        address=global(item.address)
                        if address then break end
                    end
                end
            end
        end
    end
    io.write(codec.json({ok=wan_known,public_ipv6=address})..'\n');return
end
if type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>999999999 then os.exit(1) end
local function snapshot()
    local value=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
    if not value or value.revision~=tonumber(revision) then os.exit(1) end
    return value
end
if mode=='bridge' then
    if bridge then os.exit(1) end
    local value=report.bridge(snapshot(),network);if not value then os.exit(1) end
    io.write(value..'\n');return
end
local function source_line(name)
    local f=io.open(dir..'/../../../'..name,'rb');if not f then return nil end
    local raw=f:read(65);if not f:close() or not raw or #raw>64 then return nil end;return raw
end
local version,release=source_line('VERSION'),source_line('RELEASE')
if not version or not version:match('^%d+%.%d+%.%d+\n$') or not release or not release:match('^[1-9]%d*\n$') then os.exit(1) end
version=version:sub(1,-2)..'-r'..release:sub(1,-2)
if mode=='identity' then if bridge then os.exit(1) end;io.write('HGNETWORK1\n');return end
if not report.device(bridge,network) then os.exit(1) end
if mode=='source' then
    if arg[4] or report.bridge(snapshot(),network)~=bridge then os.exit(1) end
    io.write('HGNETWORKSOURCE1\n');return
end
if mode=='result' then
    if arg[4]~='0' or arg[5] then os.exit(1) end
    local raw=io.stdin:read(65537) or ''
    local checked=#raw<=65536 and report.validate(raw,shared.parse(raw),version,revision,bridge,plan,network,codec.json)
    if not checked then os.exit(1) end;io.write(checked);return
end
if mode~='run' or arg[4] or report.bridge(snapshot(),network)~=bridge then os.exit(1) end
local f=io.open('/proc/self/fd/4','rb');local raw=f and (f:read(65537) or '')
if not f or not f:close() then os.exit(1) end
local lan,lan_ok=report.lan(raw,bridge,network);if not lan then os.exit(1) end
local wan,wan_ok=report.resolve(run,shared.parse,plan,network)
local output=report.report(version,revision,wan,lan,wan_ok,lan_ok,codec.json)
if #output>65536 then os.exit(1) end
f=io.open('/proc/self/fd/3','wb');if not f or not f:write(output) or not f:close() then os.exit(1) end
-- The original network-resolve CLI returns 0 for a valid ok:false diagnostic.
os.exit(0)
