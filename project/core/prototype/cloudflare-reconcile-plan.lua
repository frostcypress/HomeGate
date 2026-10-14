-- Pure data. Observations never establish mutation ownership or clear evidence.
local M={}
local function record_id(v) return type(v)=='string' and #v==32 and not v:find('[^0-9a-f]') end
local function integer(v,max) return type(v)=='number' and v>=0 and v<=max and v==math.floor(v) end
function M.restore(snapshot,account,revision,old,plan)
    local function bad(code) return nil,code or 'invalid_context' end
    if type(old)~='table' or old.schema~='HGCFRECORD1' or old.reconciliation~=nil or old.attempted~=true or
        old.account~=account or old.revision~=tonumber(revision) or not record_id(old.zone_id) or not integer(old.affected,100000) then return bad() end
    local c=plan.bind(snapshot,account,revision,old.request)
    if not c then return bad('generation_or_scope_mismatch') end
    for _,k in ipairs({'operation','kind','resource','zone','fqdn','type','ttl','value','value_key','delete_all'}) do
        if c[k]~=old[k] then return bad('generation_or_scope_mismatch') end
    end
    if c.operation=='upsert' then
        local stages={create=true,update=true,['verify-upsert']=true}
        if not stages[old.stage] or old.affected~=0 or
            (old.stage=='update' and (c.type~='AAAA' or not record_id(old.first_id))) or
            (old.stage=='verify-upsert' and not record_id(old.new_id)) then return bad() end
    else
        local stages={delete=true,['verify-delete']=true,['confirm-delete']=true}
        if not stages[old.stage] or type(old.delete_ids)~='table' or #old.delete_ids<1 or #old.delete_ids>100000 or
            not integer(old.position,100000) or old.position<1 or old.position>#old.delete_ids or old.affected>=old.position then return bad() end
        local seen={}
        for k,v in pairs(old.delete_ids) do
            if not integer(k,#old.delete_ids) or k<1 or not record_id(v) or seen[v] then return bad() end;seen[v]=true
        end
        c.targets=seen
    end
    c.reconciliation=true;c.expected_zone_id=old.zone_id;c.delete_ids={};c.present=0;c.conflict=false;c.matched=false
    return c
end
function M.observe(c,r)
    if c.operation=='upsert' then
        if r.match then c.matched=true end
    elseif c.targets[r.id] then
        c.present=c.present+1
        if not r.match then c.conflict=true end
    end
end
function M.result(c)
    if c.operation=='upsert' then return c.matched and 'desired-present' or 'desired-absent' end
    if c.conflict then return 'conflict' end
    return c.present==0 and 'planned-targets-absent' or 'planned-targets-present'
end
return M
