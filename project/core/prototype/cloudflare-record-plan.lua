-- Pure data: bind a DNS operation to a validated private generation.
local M={}
local function id(s) return type(s)=='string' and #s>0 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$') end
local function name(s,wildcard)
    if type(s)~='string' then return nil end
    s=s:lower():gsub('%.$','');if wildcard then s=s:gsub('^%*%.','') end
    if #s<1 or #s>253 or s:find('[^a-z0-9.-]') or s:find('..',1,true) or s:sub(1,1)=='.' or s:sub(-1)=='.' then return nil end
    for label in s:gmatch('[^.]+') do if #label>63 or label:sub(1,1)=='-' or label:sub(-1)=='-' then return nil end end
    return s
end
local function in_zone(s,z) return s==z or s:sub(-#z-1)=='.'..z end
function M.ipv6(s)
    if type(s)~='string' or #s<2 or #s>45 or s:find('[^0-9a-fA-F:.]') or not s:find(':',1,true) or s:find(':::',1,true) then return nil end
    local ipv4=s:match('([^:]+%.[^:]+)$')
    if ipv4 then
        local a,b,c,d=ipv4:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$');if not a then return nil end
        for _,p in ipairs({a,b,c,d}) do if #p>3 or tonumber(p)>255 or (#p>1 and p:sub(1,1)=='0') then return nil end end
        s=s:sub(1,#s-#ipv4)..string.format('%x:%x',tonumber(a)*256+tonumber(b),tonumber(c)*256+tonumber(d))
    elseif s:find('.',1,true) then return nil end
    local compression=s:find('::',1,true)
    if compression and s:find('::',compression+2,true) then return nil end
    if (s:sub(1,1)==':' and s:sub(1,2)~='::') or (s:sub(-1)==':' and s:sub(-2)~='::') then return nil end
    if not compression and (s:sub(1,1)==':' or s:sub(-1)==':') then return nil end
    local groups={};for p in s:gmatch('[^:]+') do if #p>4 then return nil end;groups[#groups+1]=string.format('%04x',tonumber(p,16)) end
    if compression then
        if #groups>=8 then return nil end
        local before=0;for _ in s:sub(1,compression-1):gmatch('[^:]+') do before=before+1 end
        local missing=8-#groups;for _=1,missing do table.insert(groups,before+1,'0000') end
    elseif #groups~=8 then return nil end
    return table.concat(groups,':')
end
M.name=name
function M.bind(snapshot,account,revision,q)
    local function bad(code) return nil,'invalid_request',code or 'invalid_operation' end
    if not snapshot or snapshot.revision~=tonumber(revision) then return bad('generation_mismatch') end
    if type(q)~='table' or not id(q.resource) or (q.operation~='upsert' and q.operation~='delete') or
        (q.kind~='ddns' and q.kind~='dns01') or type(q.value)~='string' or #q.value>4096 then return bad() end
    local allowed={operation=true,kind=true,resource=true,value=true,domain=q.kind=='dns01',['all']=q.kind=='ddns' and q.operation=='delete'}
    for k in pairs(q) do if not allowed[k] then return bad() end end
    local found
    for _,section in ipairs(snapshot.configuration) do if section.name==q.resource and section.kind==(q.kind=='ddns' and 'ddns_rule' or 'certificate') then found=section.values end end
    if not found then return nil,'not_found','resource_missing' end
    if found.account~=account then return bad('account_mismatch') end
    local zone=name(found.zone);if not zone then return nil,'invalid_zone','invalid_zone' end
    local c={schema='HGCFRECORD1',account=account,revision=tonumber(revision),operation=q.operation,kind=q.kind,resource=q.resource,zone=zone,value=q.value,attempted=false,affected=0}
    if q.kind=='ddns' then
        if found.type~='AAAA' then return nil,'unsupported','record_type' end
        local host=found.host;local fqdn=host=='@' and zone or (in_zone(host,zone) and host or host..'.'..zone)
        c.fqdn=name(fqdn);if not c.fqdn then return bad('invalid_name') end;c.type='AAAA';c.ttl=tonumber(found.ttl)
        if q.operation=='delete' and q.value=='' then
            if q['all']~=true then return bad('explicit_all_required') end;c.delete_all=true
        else
            if q['all']~=nil or not M.ipv6(q.value) then return bad('invalid_address') end;c.value_key=M.ipv6(q.value)
        end
    else
        if found.source~='acme' or q.value=='' or q.value:find('[^ -~]') or type(q.domain)~='string' then return bad('invalid_challenge') end
        local domain=name(q.domain,true);local selected=false
        for _,v in ipairs(found.domains or {}) do if v==q.domain:lower():gsub('%.$','') then selected=true end end
        if not selected or not domain or not in_zone(domain,zone) or #domain+16>253 then return bad('domain_mismatch') end
        c.fqdn='_acme-challenge.'..domain;c.type='TXT';c.ttl=600
    end
    if not c.ttl or (c.ttl~=1 and (c.ttl<30 or c.ttl>86400)) then return bad('invalid_ttl') end
    return c
end
function M.record(c,r)
    if type(r)~='table' or type(r.id)~='string' or #r.id~=32 or r.id:find('[^0-9a-f]') or r.type~=c.type or
        type(r.name)~='string' or r.name:lower():gsub('%.$','')~=c.fqdn or type(r.content)~='string' or #r.content>4096 or r.content:find('[%z\1-\31\127]') then return nil end
    local key=r.content;if c.type=='AAAA' then key=M.ipv6(r.content) end
    if not key then return nil end
    return {id=r.id,key=key,content=r.content,match=c.delete_all or key==(c.value_key or c.value)}
end
return M
