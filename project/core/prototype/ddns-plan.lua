-- Configuration-bound automatic or exact-device AAAA preflight. No provider mutation or URL read.
local M={}
local providers={cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true}
local function id(s)return type(s)=='string' and #s>=1 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$') end
M.id=id
local statuses={ready={'',false},disabled={'',false},unsupported={'unsupported',false},invalid_rule={'invalid_request',false},network_unavailable={'network_unavailable',true}}
function M.build(snapshot,selected,sample,records,intent)
    if not snapshot or type(snapshot.configuration)~='table' or (selected~='' and not id(selected)) or type(intent)~='table' or
        intent.schema~='HGDDNSINTENT1' or intent.revision~=snapshot.revision or type(intent.switches)~='table' then return nil,'invalid_configuration' end
    local accounts,entries={},{}
    for k in pairs(intent) do if k~='schema' and k~='revision' and k~='switches' then return nil,'invalid_configuration' end end
    local seen={}
    for _,s in ipairs(snapshot.configuration) do
        if s.kind=='dns_account' then accounts[s.name]=s.values.provider
        elseif s.kind=='ddns_rule' then
            if intent.switches[s.name]~='0' and intent.switches[s.name]~='1' then return nil,'invalid_configuration' end;seen[s.name]=true
        end
    end
    for name in pairs(intent.switches) do if not seen[name] then return nil,'invalid_configuration' end end
    local sampled,cache=false,{}
    for _,s in ipairs(snapshot.configuration) do if s.kind=='ddns_rule' and (selected=='' or s.name==selected) then
        local v=s.values;local entry={rule=s.name,provider=providers[accounts[v.account]] and accounts[v.account] or '',status='ready'}
        if intent.switches[s.name]~='1' then entry.status='disabled'
        elseif v.type~='AAAA' or (v.source~='auto' and v.source~='interface') then entry.status='unsupported'
        elseif v.source=='interface' and (type(v.interface)~='string' or #v.interface==0 or #v.interface>32 or not v.interface:match('^[a-zA-Z0-9_.:%-]+$')) then entry.status='invalid_rule'
        elseif entry.provider=='' then entry.status='invalid_rule'
        else
            local key=v.source=='auto' and 'auto' or 'interface:'..v.interface
            if cache[key]==nil then
                sampled=true
                if v.source=='auto' then cache[key]=sample() or false
                else cache[key]=sample('interface',v.interface) or false end
            end
            local wan=cache[key]
            if not wan then entry.status='network_unavailable'
            else
                local q={operation='upsert',kind='ddns',resource=s.name,value=wan.address}
                local c=records.bind(snapshot,v.account,tostring(snapshot.revision),q)
                if not c then entry.status='invalid_rule' else entry.account=v.account;entry.request=q;entry.device=wan.device;entry.source=wan.source;if v.source=='interface' then entry.interface=v.interface end end
            end
        end
        entries[#entries+1]=entry
    end end
    if selected~='' and #entries==0 then return nil,'not_found' end
    return {schema='HGDDNSPLAN1',revision=snapshot.revision,selected=selected,entries=entries,sampled=sampled}
end
-- Explicit deletion uses only the configured exact hostname/type. It must not
-- depend on a WAN address that may have disappeared during teardown.
function M.build_delete(snapshot,selected,records,intent)
    if not id(selected) then return nil,'invalid_configuration' end
    local plan,err=M.build(snapshot,selected,function()return nil end,records,intent)
    if not plan then return nil,err end
    for _,e in ipairs(plan.entries)do
        if e.status=='network_unavailable' then
            local account
            for _,s in ipairs(snapshot.configuration)do if s.kind=='ddns_rule' and s.name==selected then account=s.values.account end end
            local q={operation='delete',kind='ddns',resource=selected,value='',['all']=true}
            if records.bind(snapshot,account,tostring(snapshot.revision),q) then
                e.status='ready';e.account=account;e.request=q
            else e.status='invalid_rule' end
        end
    end
    plan.sampled=false;plan.operation='delete';return plan
end
function M.report(revision,selected,entries,code)
    local rows={};code=code or ''
    for _,v in ipairs(entries or {}) do
        local status=statuses[v.status];if not status then return nil end
        if status[1]~='' then code='rule_failure' end
        rows[#rows+1]=string.format('{"rule":"%s","provider":"%s","status":"%s","error_kind":"%s","retryable":%s}',v.rule,v.provider,v.status,status[1],tostring(status[2]))
    end
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"ddns-plan","configuration_revision":%s,"rule":"%s","effect":"none","error_kind":"%s","rules":[%s]}\n',tostring(code==''),revision,selected,code,table.concat(rows,',')),code==''
end
function M.validate(raw,doc,revision,selected,rc)
    if type(doc)~='table' or type(doc.rules)~='table' or #doc.rules>192 or (rc~='0' and rc~='1') then return nil end
    local code=doc.error_kind;if code~='' and code~='rule_failure' and code~='not_found' and code~='invalid_configuration' then return nil end
    if (code=='not_found' or code=='invalid_configuration') and #doc.rules~=0 then return nil end
    local seen,has_error={},false
    for _,v in ipairs(doc.rules) do
        if type(v)~='table' or not id(v.rule) or (selected~='' and v.rule~=selected) or seen[v.rule] or
            (v.provider~='' and not providers[v.provider]) or not statuses[v.status] then return nil end
        seen[v.rule]=true
        if statuses[v.status][1]~='' then has_error=true end
    end
    if code=='rule_failure' and not has_error then return nil end
    local expected,ok=M.report(revision,selected,doc.rules,code)
    if raw~=expected or ok~=(rc=='0') or doc.ok~=ok then return nil end
    return expected
end
return M
