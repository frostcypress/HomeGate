-- Pure, scoped DDNS grant overlay; never changes the normalized configuration.
local M={}
local slots={cloudflare={'secret'},aliyun={'key_id','secret'},dnspod={'key_id','secret'},huaweicloud={'key_id','secret','account_id'}}
function M.intent(snapshot,rule,valid_id)
    if not snapshot or type(snapshot.configuration)~='table' or type(snapshot.credentials)~='table' or not valid_id(rule) then return nil end
    local rules,accounts={},{}
    for _,s in ipairs(snapshot.configuration) do
        if s.kind=='ddns_rule' then rules[s.name]=s.values elseif s.kind=='dns_account' then accounts[s.name]=s.values.provider end
    end
    local selected=rules[rule];local provider=selected and accounts[selected.account]
    if not selected or selected.type~='AAAA' or selected.source~='auto' or not slots[provider] then return nil end
    for _,slot in ipairs(slots[provider]) do
        local v=snapshot.credentials[provider..'.'..selected.account..'.'..slot]
        if type(v)~='string' or #v<1 or #v>4096 then return nil end
    end
    local switches={};for name in pairs(rules) do switches[name]=name==rule and '1' or '0' end
    return {schema='HGDDNSINTENT1',revision=snapshot.revision,switches=switches},provider
end
return M
