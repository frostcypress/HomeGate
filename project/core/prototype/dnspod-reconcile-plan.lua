-- Pure private evidence validation. Observations do not acknowledge ownership.
local M={}
local fields={'schema','account','revision','operation','kind','resource','zone','value','attempted','affected','fqdn','type','ttl','value_key','delete_all','rr','request','records','stage','position','target_id','first_id'}
local function integer(n,a,b)return type(n)=='number' and n==math.floor(n) and n>=a and n<=b end
function M.export(c)
    if type(c)~='table' or c.schema~='HGDNPRECORD1' or c.attempted~=true then return nil end
    local out={};for _,k in ipairs(fields) do out[k]=c[k] end
    if type(out.stage)~='string' then return nil end
    out.stage=out.stage:gsub('^verify%-','')
    return out
end
function M.restore(snapshot,account,revision,old,plan,records,encode)
    if type(old)~='table' or old.schema~='HGDNPRECORD1' or old.account~=account or old.revision~=tonumber(revision) or old.attempted~=true or
        not integer(old.affected,0,100000) or type(old.records)~='table' or #old.records>100000 then return nil end
    if old.position~=nil and not integer(old.position,1,100000) then return nil end
    local c=plan.bind(snapshot,account,revision,old.request);if not c then return nil end
    c.schema='HGDNPRECORD1';c.rr=c.fqdn==c.zone and '@' or c.fqdn:sub(1,#c.fqdn-#c.zone-1)
    for _,k in ipairs({'operation','kind','resource','zone','fqdn','type','ttl','value','value_key','delete_all','rr'}) do if c[k]~=old[k] then return nil end end
    c.request=old.request;c.attempted=true;c.affected=old.affected;c.stage=old.stage;c.records={}
    local seen,prior={ },0
    for i,r in ipairs(old.records) do
        if type(r)~='table' then return nil end
        local n=type(r.id)=='string' and tonumber(r.id)
        if type(n)~='number' or n<1 or n>9007199254740991 or string.format('%.0f',n)~=r.id then return nil end
        local parsed=records.record(c,{RecordId=n,Name=r.rr,Type=c.type,Value=r.value,TTL=r.ttl,Line=r.line,LineId=r.line_id,Status=r.enabled and 'ENABLE' or 'DISABLE',Weight=r.weight,Remark=r.remark},plan)
        if not parsed or encode(parsed)~=encode(r) or seen[r.id] then return nil end
        seen[r.id]=true;c.records[i]=parsed
        if old.position and i<old.position and parsed.match then prior=prior+1 end
    end
    if c.operation=='upsert' then
        if old.affected~=0 or old.position or old.target_id then return nil end
        for _,r in ipairs(c.records) do if r.match then return nil end end
        if old.stage=='CreateRecord' then
            if old.first_id or (#c.records>0 and c.type~='TXT') then return nil end
        elseif old.stage=='ModifyRecord' then
            if c.type~='AAAA' or not c.records[1] or c.records[1].id~=old.first_id or not c.records[1].enabled then return nil end
            c.first_id=old.first_id
        else return nil end
    else
        if old.stage~='DeleteRecord' or not integer(old.position,1,#c.records) or old.first_id or old.affected~=prior then return nil end
        local target=c.records[old.position]
        if not target.match or target.id~=old.target_id or not target.enabled then return nil end
        c.position=old.position;c.target_id=old.target_id
    end
    return encode(c)==encode(old) and c or nil
end
function M.advance(before,after,encode)
    if before.operation~='delete' or after.operation~='delete' or after.position<=before.position or after.affected<before.affected then return false end
    local a,b={},{};for k,v in pairs(before) do if k~='position' and k~='affected' and k~='target_id' then a[k]=v end end
    for k,v in pairs(after) do if k~='position' and k~='affected' and k~='target_id' then b[k]=v end end
    return encode(a)==encode(b)
end
function M.terminal(c,r,encode)
    local exported=M.export(c)
    if not exported or encode(exported)~=encode(c) or type(c.account)~='string' or #c.account<1 or #c.account>64 or
        not c.account:match('^[a-zA-Z0-9_-]+$') or not integer(c.revision,1,32) or not integer(c.affected,0,100000) or
        type(c.records)~='table' or #c.records>100000 or type(r)~='table' or r.ok~=true or r.effect~='confirmed' or r.error_kind~='' or
        r.provider~='dnspod' or r.provider_code~='' or r.retryable~=false or r.reconciliation_required~=false or
        r.account~=c.account or r.configuration_revision~=c.revision then return false end
    if c.operation=='upsert' then
        return c.affected==0 and r.affected==1 and
            ((c.stage=='CreateRecord' and r.result=='created') or (c.stage=='ModifyRecord' and r.result=='updated'))
    end
    if c.operation~='delete' or c.stage~='DeleteRecord' or not integer(c.position,1,#c.records) or
        r.result~='deleted' or r.affected~=c.affected+1 then return false end
    local count,last=0,0
    for i,v in ipairs(c.records) do
        if type(v)~='table' or type(v.match)~='boolean' then return false end
        if v.match then count=count+1;last=i end
    end
    return count==r.affected and last==c.position and c.records[last].id==c.target_id
end
function M.orphan(checkpoint,work,request,encode)
    if type(work)~='table' or type(request)~='table' or encode(request)~=encode(checkpoint.request) or
        work.stage~='verify-'..checkpoint.stage or type(work.last_id)~='string' or #work.last_id<1 or #work.last_id>64 or work.last_id:find('[^0-9]') then return false end
    local n=tonumber(work.last_id)
    if not n or n<1 or n>9007199254740991 or string.format('%.0f',n)~=work.last_id then return false end
    local allowed={last_id=true};for _,k in ipairs(fields) do allowed[k]=true end
    for k in pairs(work) do if not allowed[k] then return false end end
    local normalized=M.export(work)
    if not normalized or encode(normalized)~=encode(checkpoint) then return false end
    if checkpoint.stage=='ModifyRecord' then return work.last_id==checkpoint.first_id end
    if checkpoint.stage=='DeleteRecord' then return work.last_id==checkpoint.target_id end
    return checkpoint.stage=='CreateRecord'
end
function M.observe(c,current)
    if c.operation=='upsert' then for _,r in ipairs(current) do if r.match then return 'desired-present' end end;return 'desired-absent' end
    local targets={};for _,r in ipairs(c.records) do if r.match then targets[r.id]=r end end
    local present=false
    for _,r in ipairs(current) do if targets[r.id] then
        local old=targets[r.id];if r.key~=old.key or r.line_id~=old.line_id then return 'conflict' end;present=true
    end end
    return present and 'planned-targets-present' or 'planned-targets-absent'
end
function M.report(account,revision,kind,code,observation)
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"dnspod","account":"%s","configuration_revision":%s,"check_scope":"record-reconciliation","error_kind":"%s","retryable":false,"provider_code":"%s","observation":"%s","effect":"unknown","reconciliation_required":true}\n',tostring(kind==''),account,revision,kind,code or '',observation)
end
function M.validate(raw,doc,account,revision,rc,kinds,codes)
    local observations={['desired-present']=true,['desired-absent']=true,['planned-targets-present']=true,['planned-targets-absent']=true,conflict=true}
    if not doc or doc.ok~=(rc=='0') or not kinds[doc.error_kind] or type(doc.provider_code)~='string' or (doc.provider_code~='' and not codes[doc.provider_code]) then return nil end
    if doc.ok then if doc.error_kind~='' or doc.provider_code~='' or not observations[doc.observation] then return nil end
    elseif doc.error_kind=='' or doc.observation~='incomplete' then return nil end
    local expected=M.report(account,revision,doc.error_kind,doc.provider_code,doc.observation)
    return raw==expected and expected or nil
end
return M
