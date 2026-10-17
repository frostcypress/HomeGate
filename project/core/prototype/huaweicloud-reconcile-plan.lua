-- Pure frozen record-set evidence. Observation never acknowledges ownership.
local M={}
local fields={'schema','account','revision','operation','kind','resource','zone','value','attempted','affected','fqdn','type','ttl','value_key','delete_all','request','zone_id','records','stage','position','target_id','expected'}
local function integer(n,a,b)return type(n)=='number' and n==math.floor(n) and n>=a and n<=b end
function M.export(c)
    if type(c)~='table' or c.schema~='HGHWRECORD1' or c.attempted~=true then return nil end
    local out={};for _,k in ipairs(fields) do out[k]=c[k] end
    if type(out.stage)~='string' then return nil end;out.stage=out.stage:gsub('^verify%-','');return out
end
local function kept(c,r)
    local out={};for i,v in ipairs(r.records) do if not c.delete_all and r.keys[i]~=(c.value_key or c.value) then out[#out+1]=v end end;return out
end
local function body(c,r,values,ttl)
    return {name=r and r.name or c.fqdn..'.',type=c.type,ttl=ttl,description=r and r.description or '',records=values}
end
function M.restore(snapshot,account,revision,old,plan,records,encode)
    if type(old)~='table' or old.schema~='HGHWRECORD1' or old.account~=account or old.revision~=tonumber(revision) or old.attempted~=true or
        not integer(old.affected,0,100000) or not records.id(old.zone_id) or type(old.records)~='table' or #old.records>100000 then return nil end
    local c=plan.bind(snapshot,account,revision,old.request);if not c then return nil end
    for _,k in ipairs({'operation','kind','resource','zone','fqdn','type','ttl','value','value_key','delete_all'}) do if c[k]~=old[k] then return nil end end
    c.schema='HGHWRECORD1';c.request=old.request;c.zone_id=old.zone_id;c.attempted=true;c.affected=old.affected;c.records={}
    local seen,prior={},0
    for i,r in ipairs(old.records) do
        if type(r)~='table' or type(r.records)~='table' then return nil end
        local wire={id=r.id,zone_id=r.zone_id,name=r.name,type=r.type,ttl=r.ttl,description=r.description,status=r.status,default=r.default,records=r.records}
        local parsed=records.record(c,wire,plan,{children={records={kind='array',length=#r.records}}})
        if not parsed or encode(parsed)~=encode(r) or seen[r.id] then return nil end
        seen[r.id]=true;c.records[i]=parsed
        if type(old.position)=='number' and i<old.position and parsed.match then prior=prior+1 end
    end
    if c.operation=='upsert' then
        if old.affected~=0 or old.position then return nil end
        for _,r in ipairs(c.records) do if r.match then return nil end end
        local first=c.records[1]
        if not first then c.stage='POST';c.expected=body(c,nil,{c.type=='AAAA' and c.value or records.quote(c.value)},c.ttl)
        else
            if first.status~='ACTIVE' or first.default then return nil end
            local values={};if c.type=='TXT' then for i,v in ipairs(first.records) do values[i]=v end;values[#values+1]=records.quote(c.value) else values[1]=c.value end
            c.stage='PUT';c.target_id=first.id;c.expected=body(c,first,values,c.type=='TXT' and first.ttl or c.ttl)
        end
    else
        if not integer(old.position,1,#c.records) or old.affected~=prior then return nil end
        local r=c.records[old.position];if not r.match or r.status~='ACTIVE' or r.default then return nil end
        local values=kept(c,r);c.position=old.position;c.target_id=r.id;c.stage=#values==0 and 'DELETE' or 'PUT'
        if #values>0 then c.expected=body(c,r,values,r.ttl) end
    end
    return encode(c)==encode(old) and c or nil
end
function M.advance(before,after,encode)
    if before.operation~='delete' or after.operation~='delete' or after.position<=before.position or after.affected<before.affected then return false end
    local skip={position=true,affected=true,target_id=true,expected=true,stage=true};local a,b={},{}
    for k,v in pairs(before) do if not skip[k] then a[k]=v end end;for k,v in pairs(after) do if not skip[k] then b[k]=v end end
    return encode(a)==encode(b)
end
local function same(a,b)
    if #a~=#b then return false end;local counts={}
    for _,v in ipairs(a) do counts[v]=(counts[v] or 0)+1 end
    for _,v in ipairs(b) do if not counts[v] or counts[v]<1 then return false end;counts[v]=counts[v]-1 end;return true
end
function M.orphan(checkpoint,work,request,encode)
    if type(work)~='table' or type(request)~='table' or encode(request)~=encode(checkpoint.request) or
        work.stage~='verify-'..checkpoint.stage or type(work.last_id)~='string' or #work.last_id<1 or #work.last_id>128 or
        work.last_id:find('[^a-zA-Z0-9_-]') then return false end
    local allowed={last_id=true};for _,k in ipairs(fields) do allowed[k]=true end
    for k in pairs(work) do if not allowed[k] then return false end end
    local normalized=M.export(work)
    if not normalized or encode(normalized)~=encode(checkpoint) then return false end
    if checkpoint.stage=='PUT' or checkpoint.stage=='DELETE' then return work.last_id==checkpoint.target_id end
    return checkpoint.stage=='POST'
end
function M.observe(c,current)
    if c.operation=='upsert' then
        for _,r in ipairs(current) do if r.match then return r.status=='ACTIVE' and not r.default and 'desired-present' or 'conflict' end end
        return 'desired-absent'
    end
    local byid={};for _,r in ipairs(current) do byid[r.id]=r end;local present=false
    for _,old in ipairs(c.records) do if old.match then
        local r=byid[old.id];local remaining={}
        for _,k in ipairs(old.keys) do if not c.delete_all and k~=(c.value_key or c.value) then remaining[#remaining+1]=k end end
        if not r then if #remaining>0 then return 'conflict' end
        else
            for _,k in ipairs({'zone_id','name','type','ttl','description','status','default'}) do if old[k]~=r[k] then return 'conflict' end end
            if same(r.keys,old.keys) then present=true elseif not same(r.keys,remaining) then return 'conflict' end
        end
    end end
    return present and 'planned-targets-present' or 'planned-targets-absent'
end
function M.terminal(c,r,encode)
    local exported=M.export(c)
    if not exported or encode(exported)~=encode(c) or type(c.account)~='string' or #c.account<1 or #c.account>64 or
        not c.account:match('^[a-zA-Z0-9_-]+$') or not integer(c.revision,1,32) or not integer(c.affected,0,100000) or
        type(c.records)~='table' or #c.records>100000 or type(r)~='table' or r.ok~=true or r.effect~='confirmed' or r.error_kind~='' or
        r.provider~='huaweicloud' or r.provider_code~='' or r.retryable~=false or r.reconciliation_required~=false or
        r.account~=c.account or r.configuration_revision~=c.revision then return false end
    if c.operation=='upsert' then
        if c.affected~=0 or r.affected~=1 or c.position or (c.type~='AAAA' and c.type~='TXT') then return false end
        if c.stage=='POST' then return #c.records==0 and not c.target_id and r.result=='created' end
        return c.stage=='PUT' and c.records[1] and c.target_id==c.records[1].id and
            r.result==(c.type=='TXT' and 'created' or 'updated')
    end
    if c.operation~='delete' or (c.stage~='DELETE' and c.stage~='PUT') or not integer(c.position,1,#c.records) or
        r.result~='deleted' or r.affected~=c.affected+1 then return false end
    local count,last=0,0
    for i,v in ipairs(c.records) do
        if type(v)~='table' or type(v.match)~='boolean' then return false end
        if v.match then count=count+1;last=i end
    end
    if count~=r.affected or last~=c.position or c.records[last].id~=c.target_id then return false end
    local values=kept(c,c.records[last])
    if #values==0 then return c.stage=='DELETE' and c.expected==nil end
    return c.stage=='PUT' and encode(c.expected)==encode(body(c,c.records[last],values,c.records[last].ttl))
end
function M.report(account,revision,kind,code,observation)
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"huaweicloud","account":"%s","configuration_revision":%s,"check_scope":"record-reconciliation","error_kind":"%s","retryable":false,"provider_code":"%s","observation":"%s","effect":"unknown","reconciliation_required":true}\n',tostring(kind==''),account,revision,kind,code or '',observation)
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
