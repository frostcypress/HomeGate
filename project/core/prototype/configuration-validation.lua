-- Pure private configuration validation. No filesystem, process or network API.
local M={}
local function indexed(doc)
    if type(doc)~='table' then return nil end
    local out={}
    for _,s in ipairs(doc) do
        if type(s)~='table' or type(s.name)~='string' or out[s.name] then return nil end
        out[s.name]={kind=s.kind,values=s.values}
    end
    return out
end
local function same(a,b,encode)
    return type(a)=='table' and type(b)=='table' and encode(a)==encode(b)
end
-- Bounded authority grammar; reject userinfo/fragments and unsafe bytes.
function M.target(value,ip)
    if type(value)~='string' or #value==0 or #value>4096 or value:find('[%z\1-\32\127]') or value:find('[\\#]') then return false end
    local scheme,rest=value:match('^(https?)://(.+)$')
    if not scheme then return false end
    local authority=rest:match('^([^/?]+)');if not authority or authority:find('@',1,true) then return false end
    local host,port
    if authority:sub(1,1)=='[' then
        host,port=authority:match('^%[([^%]]+)%]:(%d+)$')
        if not host then host=authority:match('^%[([^%]]+)%]$') end
        if not host or not ip.ipv6(host) then return false end
    else
        host,port=authority:match('^([^:]+):(%d+)$')
        if not host then host=authority:match('^([^:]+)$') end
        if not host or #host>253 or host:find('[^a-zA-Z0-9.%-]') then return false end
        if host:match('^[%d.]+$') then
            local n=0;for part in host:gmatch('[^.]+') do
                n=n+1;if #part>3 or tonumber(part)>255 or (#part>1 and part:sub(1,1)=='0') then return false end
            end
            if n~=4 or host:find('..',1,true) or host:sub(1,1)=='.' or host:sub(-1)=='.' then return false end
        else
            if host:sub(-1)=='.' then host=host:sub(1,-2) end
            if host=='' or host:sub(1,1)=='.' or host:find('..',1,true) then return false end
            for label in host:gmatch('[^.]+') do
                if #label>63 or label:sub(1,1)=='-' or label:sub(-1)=='-' then return false end
            end
        end
    end
    if port and (#port>5 or tonumber(port)<1 or tonumber(port)>65535) then return false end
    return true
end
function M.validate(snapshot,candidate,encode,ip)
    if type(snapshot)~='table' or type(candidate)~='table' then return nil,'invalid_configuration' end
    local expected,actual=indexed(snapshot.configuration),indexed(candidate.configuration)
    if not expected or not actual or not same(expected,actual,encode) or
       (not candidate.public_projection and not same(snapshot.credentials,candidate.credentials,encode)) then return nil,'source_mismatch' end
    local main=actual.main
    if not main or main.kind~='homegate' or type(candidate.switches)~='table' then return nil,'invalid_configuration' end
    local domains={};local counts={homegate=0,dns_account=0,ddns_rule=0,certificate=0,web_rule=0,wol_host=0}
    for name,s in pairs(actual) do
        local row=candidate.switches[name]
        if not row or row.kind~=s.kind or counts[s.kind]==nil then return nil,'invalid_configuration' end
        counts[s.kind]=counts[s.kind]+1
        if s.kind=='web_rule' and row.enabled=='1' then
            if not M.target((candidate.public_projection and snapshot.credentials or candidate.credentials)['web.'..name..'.target'],ip) then return nil,'invalid_web_target' end
            local v=s.values
            if (v.https=='1' and tonumber(main.values.proxy_https_port)==0) or tonumber(main.values.proxy_http_port)==0 then return nil,'web_port_unavailable' end
            if domains[v.domain] then return nil,'duplicate_web_domain' end
            domains[v.domain]=true
        end
    end
    return counts
end
function M.report(version,revision,counts,kind,encode)
    local ok=counts~=nil
    return encode({api_version=1,prototype=true,ok=ok,version=version,phase='configuration-validation',
        configuration_revision=tonumber(revision),scope='published-full-schema-and-web-constraints',
        health_checked=false,external_resources_checked=false,effect='none',write_ready=false,
        error_kind=kind or '',sections=counts or {}})..'\n'
end
return M
