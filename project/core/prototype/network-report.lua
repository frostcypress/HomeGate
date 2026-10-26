-- Pure network report/validation. No filesystem, process or network operations.
local M={}
function M.device(s,network)
    return type(s)=='string' and s~='.' and s~='..' and network.device(s)==s
end
function M.bridge(snapshot,network)
    local found
    for _,s in ipairs(snapshot.configuration) do
        if s.kind=='homegate' and s.name=='main' then
            if found then return nil end
            found=s.values.wol_interface or ''
        end
    end
    if found=='' then found='br-lan' end
    return M.device(found,network) and found or nil
end
function M.ipv6(ip,plan)
    local expanded=plan.ipv6(ip);if not expanded then return nil end
    local words={};for part in expanded:gmatch('[^:]+') do words[#words+1]=string.format('%x',tonumber(part,16)) end
    local first,size,at=0,1,1
    while at<=8 do
        if words[at]=='0' then
            local finish=at;while finish<=8 and words[finish]=='0' do finish=finish+1 end
            if finish-at>size then first=at;size=finish-at end
            at=finish
        else at=at+1 end
    end
    if first==0 then return table.concat(words,':') end
    return table.concat(words,':',1,first-1)..'::'..table.concat(words,':',first+size,8)
end
function M.lan(raw,bridge,network)
    if type(raw)~='string' or #raw>65536 then return nil end
    local status,body=raw:match('^HGLAN1\n([a-z]+)\n(.*)END\n$')
    if status=='unavailable' and body=='' then return {bridge=bridge,members={}},false end
    if status~='ok' then return nil end
    local names,seen,bytes={},{},0
    for name in body:gmatch('([^\n]*)\n') do
        if not M.device(name,network) or seen[name] or #names>=1024 then return nil end
        names[#names+1]=name;seen[name]=true;bytes=bytes+#name+1
    end
    if bytes~=#body then return nil end
    table.sort(names);return {bridge=bridge,members=names},true
end
function M.resolve(run,parse,plan,network)
    local selected=network.sample(run,parse,plan)
    if selected then
        return {public_ipv6=M.ipv6(selected.address,plan),device=selected.device,source='public-ip'},true
    end
    local raw,ok=run('routes');local dev=ok and network.route(raw)
    if M.device(dev,network) then return {device=dev,source='default-route'},false end
    raw,ok=run('wan6');local d=ok and parse(raw)
    dev=type(d)=='table' and network.device(d.l3_device)
    if M.device(dev,network) then return {device=dev,source='ubus'},false end
    return {},false
end
M.errors={wan='WAN6 address is unavailable',lan='LAN bridge information is unavailable',both='WAN6 and LAN bridge information are unavailable'}
function M.report(version,revision,wan,lan,wan_ok,lan_ok,json)
    local error=not wan_ok and (lan_ok and M.errors.wan or M.errors.both) or (not lan_ok and M.errors.lan)
    return '{"api_version":1,"prototype":true,"ok":'..tostring(wan_ok and lan_ok)..',"version":'..json(version)..
        ',"phase":"network-resolver","network":{"wan":'..(next(wan) and json(wan) or '{}')..',"lan":'..json(lan)..
        '},"effect":"none","write_ready":false,"configuration_revision":'..revision..
        (error and ',"error":'..json(error) or '')..'}\n'
end
local function keys(d,required,optional)
    if type(d)~='table' then return false end
    for k in pairs(required) do if d[k]==nil then return false end end
    for k in pairs(d) do if not required[k] and not (optional and optional[k]) then return false end end
    return true
end
function M.validate(raw,d,version,revision,bridge,plan,network,json)
    if not keys(d,{api_version=true,prototype=true,ok=true,version=true,phase=true,network=true,
        effect=true,write_ready=true,configuration_revision=true},{error=true}) or
        d.api_version~=1 or d.prototype~=true or type(d.ok)~='boolean' or d.version~=version or d.phase~='network-resolver' or
        d.effect~='none' or d.write_ready~=false or d.configuration_revision~=tonumber(revision) or
        not keys(d.network,{wan=true,lan=true}) or not keys(d.network.wan,{}, {public_ipv6=true,device=true,source=true}) or
        not keys(d.network.lan,{bridge=true,members=true}) or d.network.lan.bridge~=bridge or type(d.network.lan.members)~='table' then return nil end
    local wan,lan=d.network.wan,d.network.lan
    local wan_ok=wan.public_ipv6~=nil
    if wan_ok then
        if not M.device(wan.device,network) or wan.source~='public-ip' or not network.public_ipv6(wan.public_ipv6,plan) or
            M.ipv6(wan.public_ipv6,plan)~=wan.public_ipv6 then return nil end
    elseif next(wan) then
        if not M.device(wan.device,network) or (wan.source~='default-route' and wan.source~='ubus') then return nil end
    end
    local last='';if #lan.members>1024 then return nil end
    for k,v in pairs(lan.members) do
        if type(k)~='number' or k~=math.floor(k) or k<1 or k>#lan.members or not M.device(v,network) then return nil end
    end
    for _,v in ipairs(lan.members) do if v<=last then return nil end;last=v end
    local lan_ok=d.error~=M.errors.lan and d.error~=M.errors.both
    if not lan_ok and #lan.members~=0 then return nil end
    local expected=M.report(version,revision,wan,lan,wan_ok,lan_ok,json)
    if d.ok~=(wan_ok and lan_ok) or raw~=expected then return nil end
    return expected
end
return M
