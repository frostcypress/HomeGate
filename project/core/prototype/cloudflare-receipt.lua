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
-- A new delete checkpoint may skip targets found absent, but cannot change the
-- frozen request/ID set or move backwards. This does not certify remote success.
function M.advance(before,after,codec)
    if before.operation~='delete' or after.operation~='delete' or before.stage~='delete' or after.stage~='delete' or
        after.position<=before.position or after.affected<before.affected or
        after.affected-before.affected>after.position-before.position then return false end
    local a,b={},{}
    for k,v in pairs(before) do if k~='position' and k~='affected' then a[k]=v end end
    for k,v in pairs(after) do if k~='position' and k~='affected' then b[k]=v end end
    return codec.json(a)==codec.json(b)
end
-- Only the original verified response stage can bind disposable work files.
function M.orphan(checkpoint,work,request,codec)
    if type(work)~='table' or type(request)~='table' or codec.json(request)~=codec.json(checkpoint.request) then return false end
    for _,k in ipairs({'schema','account','revision','operation','kind','resource','zone','fqdn','type','ttl','value','value_key','delete_all',
        'request','affected','zone_id','first_id','first_key','delete_ids','position','attempted'}) do
        if codec.json({value=checkpoint[k]})~=codec.json({value=work[k]}) then return false end
    end
    if checkpoint.operation=='upsert' then
        return work.stage=='verify-upsert' and
            ((checkpoint.stage=='create' and work.result=='created') or
             (checkpoint.stage=='update' and work.result=='updated' and work.new_id==checkpoint.first_id))
    end
    return checkpoint.operation=='delete' and checkpoint.stage=='delete' and work.stage=='verify-delete'
end
return M
