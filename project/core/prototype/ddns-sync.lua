-- Data-only single-rule dispatch binding and redacted provider receipt adapter.
local M={}
local kinds={['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,invalid_zone=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true}
function M.bind(snapshot,intent,plan,selected,planner,network,records,json)
    if not planner.id(selected) or type(plan)~='table' or plan.schema~='HGDDNSPLAN1' or type(plan.entries)~='table' or #plan.entries~=1 then return nil end
    local e=plan.entries[1]
    if type(e)~='table' or (e.status~='ready' and e.status~='disabled') then return nil end
    if e.status=='ready' and (type(e.request)~='table' or not network.public_ipv6(e.request.value,records) or
        network.device(e.device)~=e.device or e.source~='public-ip') then return nil end
    local rebuilt=planner.build(snapshot,selected,function()if not e.request then return nil end;return {address=e.request.value,device=e.device,source=e.source} end,records,intent)
    if not rebuilt or json(rebuilt)~=json(plan) then return nil end
    return e
end
function M.result(raw,d,provider,account,revision,rule,rc)
    if (rc~='0' and rc~='1') or type(d)~='table' or not kinds[d.error_kind] or type(d.retryable)~='boolean' or
        type(d.provider_code)~='string' or #d.provider_code>32 or not d.provider_code:match('^[a-zA-Z0-9_-]*$') or
        type(d.affected)~='number' or d.affected<0 or d.affected>1 or d.affected~=math.floor(d.affected) or
        d.ok~=(rc=='0') or (d.effect~='none' and d.effect~='confirmed' and d.effect~='unknown') then return nil end
    if d.ok then
        if d.error_kind~='' or d.retryable or (d.result~='created' and d.result~='updated' and d.result~='unchanged') or
            (d.result=='unchanged' and (d.effect~='none' or d.affected~=0)) or
            (d.result~='unchanged' and (d.effect~='confirmed' or d.affected~=1)) then return nil end
    elseif d.error_kind=='' or d.result~='failed' or d.effect=='confirmed' or
        (d.effect=='none' and d.affected~=0) or (d.effect=='unknown' and d.retryable) then return nil end
    local canonical=string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"%s","account":"%s","configuration_revision":%s,"check_scope":"record-operation","error_kind":"%s","retryable":%s,"provider_code":"%s","result":"%s","effect":"%s","affected":%d,"reconciliation_required":%s}\n',tostring(d.ok),provider,account,revision,d.error_kind,tostring(d.retryable),d.provider_code,d.result,d.effect,d.affected,tostring(d.effect=='unknown'))
    if canonical~=raw then return nil end
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"ddns-sync","rule":"%s","provider":"%s","configuration_revision":%s,"result":"%s","effect":"%s","affected":%d,"error_kind":"%s","retryable":%s,"reconciliation_required":%s,"write_ready":false}\n',tostring(d.ok),rule,provider,revision,d.result,d.effect,d.affected,d.error_kind,tostring(d.retryable),tostring(d.effect=='unknown')),d.effect
end
return M
