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
return M
