-- Data-only full-plan reconstruction and redacted per-rule batch rows.
local M={}
local providers={cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true}
local decisions={ready=true,stale=true,blocked=true,reconciliation_required=true,unauthorized=true,clock_invalid=true,paused=true,retry_wait=true,waiting=true}
local outcomes={none=true,inflight=true,created=true,updated=true,unchanged=true,retry_wait=true,paused=true,unknown=true}
local kinds={['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,invalid_zone=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true,invalid_configuration=true}
local function integer(n,max)return type(n)=='number' and n==math.floor(n) and n>=0 and n<=max end
function M.slice(snapshot,intent,plan,rule,planner,authority,network,records,json)
    if type(intent)~='table' or type(intent.switches)~='table' or type(plan)~='table' or type(plan.entries)~='table' or #plan.entries>32 then return nil end
    local names={};for name,value in pairs(intent.switches) do if value=='1' then names[#names+1]=name end end
    table.sort(names)
    local expected=authority.intent(snapshot,table.concat(names,','),planner.id)
    if not expected or json(expected)~=json(intent) or intent.switches[rule]~='1' then return nil end
    local rules,samples={},{}
    for _,section in ipairs(snapshot.configuration) do
        if section.kind=='ddns_rule' then rules[section.name]=section.values end
    end
    local function key(source,interface)
        if source==nil or source=='auto' then return 'auto' end
        if source=='interface' and type(interface)=='string' then return 'interface:'..interface end
    end
    for _,e in ipairs(plan.entries) do
        if type(e)~='table' then return nil end
        if e.status=='ready' or e.status=='network_unavailable' then
            local values=rules[e.rule]
            if not values or intent.switches[e.rule]~='1' then return nil end
            local group=key(values.source,values.interface);if not group then return nil end
            local sample=false
            if e.status=='ready' then
                if type(e.request)~='table' or not network.public_ipv6(e.request.value,records) or
                    type(e.device)~='string' or e.device=='' or network.device(e.device)~=e.device or e.source~='public-ip' then return nil end
                if values.source=='interface' and (e.interface~=values.interface or e.device~=values.interface) then return nil end
                sample={address=e.request.value,device=e.device,source=e.source}
            end
            if samples[group]~=nil and json(samples[group])~=json(sample) then return nil end
            samples[group]=sample
        end
    end
    local function sample(source,interface)
        local group=key(source,interface)
        return group and samples[group] or nil
    end
    local rebuilt=planner.build(snapshot,'',sample,records,intent)
    if not rebuilt or json(rebuilt)~=json(plan) then return nil end
    local narrow=authority.intent(snapshot,rule,planner.id)
    return planner.build(snapshot,rule,sample,records,narrow),narrow
end
function M.row(raw,d,revision,rule,rc,planner,sync,parse,observed)
    if type(d)~='table' or not planner.id(rule) or (rc~='0' and rc~='1' and rc~='4') then return nil end
    local provider,status,effect,kind,retry,wait=d.provider,nil,'none','',false,0
    if d.phase=='ddns-sync' then
        if not providers[provider] then return nil end
        local original=string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"%s","account":"a","configuration_revision":%s,"check_scope":"record-operation","error_kind":"%s","retryable":%s,"provider_code":"","result":"%s","effect":"%s","affected":%s,"reconciliation_required":%s}\n',tostring(d.ok),provider,revision,tostring(d.error_kind),tostring(d.retryable),tostring(d.result),tostring(d.effect),tostring(d.affected),tostring(d.reconciliation_required))
        if sync.result(original,parse(original),provider,'a',revision,rule,rc)~=raw then return nil end
        status,effect,kind,retry=d.result,d.effect,d.error_kind,d.retryable
    elseif d.phase=='ddns-plan' then
        if not planner.validate(raw,d,revision,rule,rc) or #d.rules~=1 then return nil end
        local row=d.rules[1];provider,status,kind,retry=row.provider,row.status,row.error_kind,row.retryable
    elseif d.phase=='ddns-state' then
        if (rc~='0' and rc~='4') or not providers[provider] or not decisions[d.status] or not outcomes[d.last_result] or not kinds[d.error_kind] or
            (d.last_effect~='none' and d.last_effect~='confirmed' and d.last_effect~='unknown') or not integer(d.failures,8) or not integer(d.retry_in,999999999) or
            type(d.authorized)~='boolean' or type(d.blocked)~='boolean' then return nil end
        if d.event_epoch~=nil and (not integer(d.event_epoch,253402300799) or d.event_epoch<1)then return nil end
        local extra=d.event_epoch and string.format(',"event_epoch":%.0f',d.event_epoch) or ''
        local expected=string.format('{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-state","configuration_revision":%s,"rule":"%s","provider":"%s","status":"%s","last_result":"%s","last_effect":"%s","error_kind":"%s","failures":%d,"retry_in":%d,"authorized":%s,"blocked":%s,"effect":"none","write_ready":false%s}\n',revision,rule,provider,d.status,d.last_result,d.last_effect,d.error_kind,d.failures,d.retry_in,tostring(d.authorized),tostring(d.blocked),extra)
        if raw~=expected then return nil end
        status,kind,retry,wait=d.status,d.error_kind,d.status=='retry_wait',d.retry_in
    else return nil end
    if not providers[provider] then return nil end
    local extra=''
    if observed and d.phase=='ddns-state'then
        extra=string.format(',"last_result":"%s","last_effect":"%s"',d.last_result,d.last_effect)
        if d.event_epoch then extra=extra..',"event_at":"'..os.date('!%Y-%m-%dT%H:%M:%SZ',d.event_epoch)..'"'end
    end
    return string.format('{"rule":"%s","provider":"%s","status":"%s","effect":"%s","error_kind":"%s","retryable":%s,"retry_in":%d%s}',rule,provider,status,effect,kind,tostring(retry),wait,extra),effect
end
return M
