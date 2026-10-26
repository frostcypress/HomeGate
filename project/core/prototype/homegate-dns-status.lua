-- Fixed account/result adapter; secrets remain in the inherited snapshot pipe.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local mode,revision,account=arg[1],arg[2],arg[3]
if type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 or
    type(account)~='string' or #account<1 or #account>64 or not account:match('^[a-zA-Z0-9_-]+$') then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local providers={cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true}
if mode=='select' then
    if arg[4] then os.exit(1) end
    local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
    if not snapshot or snapshot.revision~=tonumber(revision) then os.exit(1) end
    local provider
    for _,section in ipairs(snapshot.configuration) do
        if section.kind=='dns_account' and section.name==account then
            if provider then os.exit(1) end
            provider=section.values.provider
        end
    end
    io.write(not provider and 'not_found\n' or (providers[provider] and provider..'\n' or 'unsupported\n'))
    return
end
local function line(name)
    local f=io.open(dir..'/../../../'..name,'rb');if not f then return nil end
    local raw=f:read(65);if not f:close() or not raw or #raw>64 then return nil end;return raw
end
local version,release=line('VERSION'),line('RELEASE')
if not version or not version:match('^%d+%.%d+%.%d+\n$') or not release or not release:match('^[1-9]%d*\n$') then os.exit(1) end
if mode=='identity' then if arg[4] then os.exit(1) end;io.write('HGDNSSTATUS1\n');return end
local report={api_version=1,ok=false,version=version:sub(1,-2)..'-r'..release:sub(1,-2),phase='dns-provider',
    account=account,capabilities={},credentials_valid=false,prototype=true,effect='none',write_ready=false,
    configuration_revision=tonumber(revision)}
local zones_mode=mode=='zones-error' or mode=='zones-result'
if zones_mode then report.credentials_valid=nil;report.capabilities=nil;report.zones={} end
local messages={authentication='DNS credentials could not be validated',not_found='DNS account or resource was not found',
    unsupported='DNS provider is not supported',invalid_request='DNS validation request was refused',
    temporary='DNS validation is temporarily unavailable',network_unavailable='DNS validation network is unavailable',
    timeout='DNS validation timed out',rate_limit='DNS validation was rate limited',invalid_zone='DNS zone validation failed'}
if mode=='error' or mode=='zones-error' then
    if arg[5] or (arg[4]~='not_found' and arg[4]~='unsupported') then os.exit(1) end
    report.error_kind=arg[4];report.error=messages[arg[4]]
elseif mode=='result' or mode=='zones-result' then
    local provider,rc=arg[4],arg[5]
    if arg[6] or not providers[provider] or (rc~='0' and rc~='1') then os.exit(1) end
    local limit=zones_mode and (provider=='cloudflare' and 14350512 or 65536) or 4096
    local raw=io.stdin:read(limit+1) or ''
    if #raw>limit or raw:find('%z') then os.exit(1) end
    local d
    if zones_mode then d=require('luci.jsonc').parse(raw)
    else d=assert(loadfile(dir..'/cloudflare-codec.lua'))('library').parse(raw) end
    local fields={api_version=true,prototype=true,ok=true,phase=true,provider=true,account=true,
        configuration_revision=true,credentials_valid=true,check_scope=true,error_kind=true,retryable=true,provider_code=true}
    local count=0
    if zones_mode then fields.credentials_valid=nil;fields.zones=true end
    if type(d)~='table' then os.exit(1) end
    for k in pairs(d) do if not fields[k] then os.exit(1) end;count=count+1 end
    if count~=12 or d.api_version~=1 or d.prototype~=true or type(d.ok)~='boolean' or d.ok~=(rc=='0') or
        d.phase~='dns-provider' or d.provider~=provider or d.account~=account or d.configuration_revision~=tonumber(revision) or
        (not zones_mode and d.credentials_valid~=d.ok) or d.check_scope~=(zones_mode and 'zone-list' or 'zone-read') or type(d.retryable)~='boolean' or
        type(d.provider_code)~='string' or #d.provider_code>64 or not d.provider_code:match('^[a-zA-Z0-9_.-]*$') then os.exit(1) end
    if d.ok then
        if d.error_kind~='' or d.retryable or d.provider_code~='' then os.exit(1) end
    else
        if not messages[d.error_kind] then os.exit(1) end
        report.error_kind=d.error_kind;report.error=messages[d.error_kind]
        if d.retryable then report.retryable=true end
        if d.provider_code~='' then report.provider_code=d.provider_code end
    end
    if zones_mode then
        if type(d.zones)~='table' or #d.zones>50000 or (not d.ok and #d.zones~=0) then os.exit(1) end
        local domain=assert(loadfile(dir..'/aliyun-reader.lua'))('library').domain
        for key,name in pairs(d.zones) do
            if type(key)~='number' or key~=math.floor(key) or key<1 or key>#d.zones or domain(name)~=name then os.exit(1) end
        end
        local last=''
        for _,name in ipairs(d.zones) do if name<=last then os.exit(1) end;last=name end
        -- Reconstruct the original canonical envelope exactly. This rejects
        -- duplicate keys, object-for-array, escaped aliases and trailing data
        -- without imposing the status parser's smaller limit on zone lists.
        local expected=string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"%s","account":"%s","configuration_revision":%s,"check_scope":"zone-list","error_kind":"%s","retryable":%s,"provider_code":"%s","zones":%s}\n',
            tostring(d.ok),provider,account,revision,d.error_kind,tostring(d.retryable),d.provider_code,codec.json(d.zones))
        if raw~=expected then os.exit(1) end
        report.zones=d.zones
    else report.credentials_valid=d.ok end
    report.ok=d.ok;report.provider=provider
    report.capabilities={'credentials_validation','ddns','dns01','zone_discovery'}
else os.exit(1) end
io.write(codec.json(report)..'\n')
