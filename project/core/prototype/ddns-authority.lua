-- Pure, scoped DDNS grant overlay; never changes the normalized configuration.
local M={}
local slots={cloudflare={'secret'},aliyun={'key_id','secret'},dnspod={'key_id','secret'},huaweicloud={'key_id','secret','account_id'}}
function M.selection(raw,valid_id)
    if type(raw)~='string' or #raw<1 or #raw>2079 then return nil end
    local names,seen={},{}
    for name in (raw..','):gmatch('(.-),') do
        if not valid_id(name) or seen[name] or #names>=32 then return nil end
        names[#names+1]=name;seen[name]=true
    end
    table.sort(names);return names
end
function M.intent(snapshot,rule,valid_id)
    local names=M.selection(rule,valid_id)
    if not names or not snapshot or type(snapshot.configuration)~='table' or type(snapshot.credentials)~='table' then return nil end
    local rules,accounts={},{}
    for _,s in ipairs(snapshot.configuration) do
        if s.kind=='ddns_rule' then rules[s.name]=s.values elseif s.kind=='dns_account' then accounts[s.name]=s.values.provider end
    end
    local granted,provider={},nil
    for _,name in ipairs(names) do
        local selected=rules[name];local p=selected and accounts[selected.account]
        if not selected or selected.type~='AAAA' or selected.source~='auto' or not slots[p] then return nil end
        for _,slot in ipairs(slots[p]) do
            local v=snapshot.credentials[p..'.'..selected.account..'.'..slot]
            if type(v)~='string' or #v<1 or #v>4096 then return nil end
        end
        granted[name]=true;provider=p
    end
    if #names>1 then provider='multiple' end
    local switches={};for name in pairs(rules) do switches[name]=granted[name] and '1' or '0' end
    return {schema='HGDDNSINTENT1',revision=snapshot.revision,switches=switches},provider
end
return M
