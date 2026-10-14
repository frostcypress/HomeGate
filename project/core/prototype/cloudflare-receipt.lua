-- Pure data: allowlisted private checkpoint; credentials never enter the journal.
local M={}
function M.export(c)
    if type(c)~='table' or c.schema~='HGCFRECORD1' or c.reconciliation or c.attempted~=true or
        (c.stage~='create' and c.stage~='update' and c.stage~='delete') or type(c.request)~='table' then return nil end
    local out={}
    for _,k in ipairs({'schema','account','revision','operation','kind','resource','zone','fqdn','type','ttl','value','value_key','delete_all',
        'request','attempted','affected','zone_id','stage','first_id','first_key','new_id','delete_ids','position'}) do out[k]=c[k] end
    return out
end
function M.terminal(c,r)
    if not M.export(c) or type(c.affected)~='number' or c.affected<0 or c.affected>100000 or c.affected~=math.floor(c.affected) or type(r)~='table' or r.ok~=true or r.effect~='confirmed' or r.error_kind~='' or
        r.provider_code~='' or r.retryable~=false or r.reconciliation_required~=false or r.account~=c.account or r.configuration_revision~=c.revision then return false end
    if c.operation=='upsert' then
        return c.affected==0 and r.affected==1 and ((c.stage=='create' and r.result=='created') or (c.stage=='update' and r.result=='updated'))
    end
    return c.operation=='delete' and c.stage=='delete' and type(c.affected)=='number' and c.affected>=0 and
        type(c.delete_ids)=='table' and type(c.position)=='number' and c.position==math.floor(c.position) and c.position>=1 and c.position<=#c.delete_ids and
        r.result=='deleted' and r.affected==c.affected+1 and r.affected<=#c.delete_ids
end
return M
