-- Pure WAN selection using the reference resolver's ordering; no commands.
local M={}
local function device(s)
    if type(s)~='string' then return nil end;s=s:gsub(':$',''):match('^([^@]+)')
    return s and #s>0 and #s<=32 and s:match('^[a-zA-Z0-9_.:%-]+$') and s or nil
end
M.device=device
function M.public_ipv6(s,plan)
    local v=plan.ipv6(s);if not v then return nil end
    if v=='0000:0000:0000:0000:0000:0000:0000:0000' or v=='0000:0000:0000:0000:0000:0000:0000:0001' or
        v:sub(1,2)=='ff' or v:sub(1,2)=='fc' or v:sub(1,2)=='fd' or v:sub(1,30)=='0000:0000:0000:0000:0000:ffff:' then return nil end
    local first=tonumber(v:sub(1,4),16);if first>=0xfe80 and first<=0xfebf then return nil end
    return v
end
local function lines(raw)
    if type(raw)~='string' or #raw>65536 or raw:find('[%z\1-\8\11-\31\127]') then return nil end
    local out={};for line in (raw..'\n'):gmatch('(.-)\n') do
        if #line>4096 then return nil end
        if line:find('%S') then out[#out+1]=line;if #out>4096 then return nil end end
    end;return out
end
function M.addresses(raw,plan)
    local input=lines(raw);if not input then return nil end;local out,seen={},{}
    for _,line in ipairs(input) do
        local f={};for v in line:gmatch('%S+') do f[#f+1]=v end
        local dev=device(f[2]);local cidr,unusable
        for i,v in ipairs(f) do
            if v=='inet6' then cidr=f[i+1] end
            if v=='tentative' or v=='dadfailed' or v=='deprecated' then unusable=true end
        end
        if cidr and dev and not unusable then
            local ip,prefix=cidr:match('^([^/]+)/(%d+)$');local value=ip and M.public_ipv6(ip,plan)
            if value and #prefix<=3 and tonumber(prefix)<=128 then
                local key=dev..'/'..value;if not seen[key] then seen[key]=true;out[#out+1]={device=dev,address=ip,key=value} end
            end
        end
    end;return out
end
function M.route(raw)
    local input=lines(raw);if not input then return nil end
    for _,line in ipairs(input) do local f={};for v in line:gmatch('%S+') do f[#f+1]=v end
        if f[1]=='default' then for i,v in ipairs(f) do if v=='dev' then return device(f[i+1]) end end end
    end;return ''
end
function M.owner(addresses,dev)
    if dev and dev~='' then for _,a in ipairs(addresses) do if a.device==dev then return {address=a.address,device=a.device,source='public-ip'} end end end
end
function M.choose(addresses,route,ubus,ubus_ok)
    local selected=M.owner(addresses,route);if selected then return selected end
    if ubus_ok and type(ubus)=='table' and ubus.up==false then return nil end
    if ubus_ok and type(ubus)=='table' and ubus.up==true then
        selected=M.owner(addresses,device(ubus.l3_device));if selected then return selected end
    end
    for _,prefix in ipairs({'pppoe-','ppp','wan','eth'}) do
        for _,a in ipairs(addresses) do if a.device:sub(1,#prefix)==prefix and a.device:sub(1,3)~='br-' then return {address=a.address,device=a.device,source='public-ip'} end end
    end
end
function M.sample(run,parse,plan)
    local raw,ok=run('addresses');if not ok then return nil,'network_unavailable' end
    local addresses=M.addresses(raw,plan);if not addresses then return nil,'network_unavailable' end
    raw,ok=run('routes');local route=ok and M.route(raw) or ''
    local selected=M.owner(addresses,route);if selected then return selected end
    raw,ok=run('wan6');local u=ok and parse(raw) or nil
    if ok and (type(u)~='table' or type(u.up)~='boolean' or (u.l3_device~=nil and not device(u.l3_device))) then return nil,'network_unavailable' end
    selected=M.choose(addresses,route,u,ok)
    return selected,selected and nil or 'network_unavailable'
end
return M
