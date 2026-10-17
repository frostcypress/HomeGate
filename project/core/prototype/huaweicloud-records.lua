-- Pure configuration-bound v2 record-set operations; transport is fixed outside.
local M={}
local function integer(n,a,b)return type(n)=='number' and n==math.floor(n) and n>=a and n<=b end
local function id(s)return type(s)=='string' and #s>=1 and #s<=128 and not s:find('[^a-zA-Z0-9_-]') end
M.id=id
M.codes={invalid_context=true,invalid_operation=true,generation_mismatch=true,resource_missing=true,account_mismatch=true,invalid_zone=true,
    record_type=true,invalid_name=true,explicit_all_required=true,invalid_address=true,invalid_challenge=true,
    domain_mismatch=true,invalid_ttl=true,invalid_record=true,record_changed=true,record_unavailable=true,
    state_limit=true,invalid_receipt=true,zone_not_found=true,zone_ambiguous=true}
function M.txt(raw)
    if type(raw)~='string' or #raw>8448 or raw:find('[^ -~]') then return nil end
    if raw:sub(1,1)~='"' then if #raw>4096 or raw:find('"') then return nil end;return raw end
    local out,i={},1
    while i<=#raw do
        if raw:sub(i,i)~='"' then return nil end;i=i+1;local chunk={};local closed=false
        while i<=#raw do
            local ch=raw:sub(i,i);i=i+1
            if ch=='"' then closed=true;break end
            if ch=='\\' then
                ch=raw:sub(i,i);i=i+1
                if ch~='\\' and ch~='"' then return nil end
            end
            chunk[#chunk+1]=ch;if #chunk>255 then return nil end
        end
        if not closed then return nil end;out[#out+1]=table.concat(chunk)
        if i<=#raw then if raw:sub(i,i)~=' ' then return nil end;i=i+1;if i>#raw then return nil end end
    end
    local value=table.concat(out);if #value>4096 then return nil end;return value
end
function M.quote(value)
    local out={}
    for i=1,math.max(1,#value),255 do out[#out+1]='"'..value:sub(i,i+254):gsub('\\','\\\\'):gsub('"','\\"')..'"' end
    return table.concat(out,' ')
end
function M.report(account,revision,kind,retry,code,result,effect,affected)
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"huaweicloud","account":"%s","configuration_revision":%s,"check_scope":"record-operation","error_kind":"%s","retryable":%s,"provider_code":"%s","result":"%s","effect":"%s","affected":%d,"reconciliation_required":%s}\n',tostring(kind==''),account,revision,kind,tostring(retry),code or '',result,effect,affected,tostring(effect=='unknown'))
end
function M.validate(raw,doc,account,revision,rc,marker,kinds,codes)
    if not doc or doc.account~=account or doc.configuration_revision~=tonumber(revision) or doc.provider~='huaweicloud' or
        doc.check_scope~='record-operation' or type(doc.ok)~='boolean' or doc.ok~=(rc=='0') or not kinds[doc.error_kind] or
        type(doc.retryable)~='boolean' or type(doc.provider_code)~='string' or (doc.provider_code~='' and not codes[doc.provider_code]) or
        not integer(doc.affected,0,100000) then return nil end
    local attempted=marker=='HGHWATTEMPT1\n'
    if marker~='' and not attempted then return nil end
    if doc.ok then
        if doc.error_kind~='' or doc.retryable or doc.provider_code~='' then return nil end
        if attempted then
            if doc.effect~='confirmed' or doc.affected<1 or (doc.result~='created' and doc.result~='updated' and doc.result~='deleted') or
                ((doc.result=='created' or doc.result=='updated') and doc.affected~=1) then return nil end
        elseif doc.effect~='none' or doc.affected~=0 or doc.result~='unchanged' then return nil end
    else
        if doc.error_kind=='' or doc.result~='failed' or doc.effect~=(attempted and 'unknown' or 'none') or
            (attempted and doc.retryable) or (not attempted and doc.affected~=0) then return nil end
    end
    local expected=M.report(account,revision,doc.error_kind,doc.retryable,doc.provider_code,doc.result,doc.effect,doc.affected)
    return raw==expected and expected or nil
end
function M.record(c,r,plan,shape)
    if type(r)~='table' or not id(r.id) or r.zone_id~=c.zone_id or type(r.name)~='string' or r.name:lower():gsub('%.$','')~=c.fqdn or r.type~=c.type or
        not integer(r.ttl,1,2147483647) or type(r.description)~='string' or #r.description>1024 or r.description:find('[%z\1-\31\127]') or
        type(r.status)~='string' or #r.status>32 or type(r.default)~='boolean' or type(r.records)~='table' or #r.records<1 or #r.records>10000 or
        not shape or not shape.children.records or shape.children.records.kind~='array' or shape.children.records.length~=#r.records or r.line~=nil or r.weight~=nil or r.alias_target~=nil or r.set_identifier~=nil then return nil end
    local values,keys,matched={},{},false
    for i=1,#r.records do local v=r.records[i]
        if type(v)~='string' or #v>8448 or v:find('[%z\1-\31\127]') then return nil end
        local key;if c.type=='AAAA' then key=plan.ipv6(v) else key=M.txt(v) end;if not key then return nil end
        values[i]=v;keys[i]=key;if c.delete_all or key==(c.value_key or c.value) then matched=true end
    end
    return {id=r.id,zone_id=c.zone_id,name=r.name,type=r.type,ttl=r.ttl,description=r.description,status=r.status,default=r.default,records=values,keys=keys,match=matched}
end
function M.run(snapshot,account,revision,api)
    local function invalid(code)api.fail('temporary',true,code or 'invalid_response') end
    local c
    if api.reconciling then
        local raw=api.read(5,8388608);local old=api.context_parse(raw)
        if not old or api.encode(old)..'\n'~=raw then api.fail('invalid_request',false,'invalid_context') end
        old=api.reconcile.export(old)
        c=old and api.reconcile.restore(snapshot,account,revision,old,api.plan,M,api.encode)
        if not c then api.fail('invalid_request',false,'invalid_context') end
    else
        local raw=api.read(5,4096);local q=api.parse(raw)
        if not q or api.encode(q)..'\n'~=raw then api.fail('invalid_request',false,'invalid_operation') end
        local kind,code;c,kind,code=api.plan.bind(snapshot,account,revision,q);if not c then api.fail(kind,false,code) end
        c.schema='HGHWRECORD1';c.request=q;api.write(5,raw)
    end
    local function save(stage)
        c.stage=stage;c.attempted=api.state.attempted;c.affected=api.state.affected
        local body=api.encode(c)..'\n';if #body>8388608 then invalid('state_limit') end;api.write(6,body)
    end
    local function paged(path,params,key,visit)
        local total,rows,seen=nil,0,{}
        for page=1,1000 do
            params.offset=tostring((page-1)*100);params.limit='100'
            local d,s=api.fetch('GET',path,params)
            if not s or not s.children[key] or s.children[key].kind~='array' or not s.children.metadata or s.children.metadata.kind~='object' or
                type(d.metadata)~='table' or not integer(d.metadata.total_count,0,100000) or type(d[key])~='table' or #d[key]>100 or s.children[key].length~=#d[key] then invalid() end
            local count=d.metadata.total_count;if total and total~=count then invalid('pagination_changed') end;total=count
            for i=1,#d[key] do local r=d[key][i]
                if type(r)~='table' or not id(r.id) or seen[r.id] then invalid('invalid_record') end;seen[r.id]=true
                visit(r,s.children[key].children[i])
            end
            rows=rows+#d[key];if rows>total or (#d[key]==0 and rows<total) then invalid('pagination_changed') end
            if rows==total then return end
            if #d[key]<100 then invalid('pagination_changed') end
        end
        invalid('pagination_limit')
    end
    local found={}
    paged('/v2/zones',{type='public',name=c.zone,search_mode='equal'},'zones',function(r)
        if type(r.name)~='string' or r.zone_type~='public' or type(r.status)~='string' then invalid('invalid_zone') end
        if r.name:lower():gsub('%.$','')==c.zone then found[#found+1]=r end
    end)
    if #found~=1 then api.fail('invalid_zone',false,#found==0 and 'zone_not_found' or 'zone_ambiguous') end
    if found[1].status~='ACTIVE' then api.fail('unsupported',false,'record_unavailable') end
    if api.reconciling and c.zone_id~=found[1].id then api.fail('invalid_request',false,'invalid_context') end
    c.zone_id=found[1].id;local path='/v2/zones/'..c.zone_id..'/recordsets'
    local function checked(r,s)local v=M.record(c,r,api.plan,s);if not v then invalid('invalid_record') end;return v end
    local function available(r)if r.status~='ACTIVE' or r.default then api.fail('unsupported',false,'record_unavailable') end end
    local function list()
        local out,bytes={},0
        paged(path,{},'recordsets',function(r,s)
            if type(r.name)~='string' or type(r.type)~='string' or r.zone_id~=c.zone_id then invalid('invalid_record') end
            if r.name:lower():gsub('%.$','')==c.fqdn and r.type==c.type then
                local v=checked(r,s);bytes=bytes+#api.encode(v)+32;if bytes>8388608 then invalid('state_limit') end;out[#out+1]=v
            end
        end)
        return out
    end
    local function detail(old)
        local d,s=api.fetch('GET',path..'/'..old.id,{});local r=checked(d,s)
        if api.encode(r)~=api.encode(old) then invalid('record_changed') end;available(r);return r
    end
    local function same_values(actual,values)
        if #actual.records~=#values then return false end
        local counts={}
        for _,v in ipairs(values) do local k;if c.type=='AAAA' then k=api.plan.ipv6(v) else k=M.txt(v) end;if not k then return false end;counts[k]=(counts[k] or 0)+1 end
        for _,k in ipairs(actual.keys) do if not counts[k] or counts[k]<1 then return false end;counts[k]=counts[k]-1 end
        return true
    end
    local function mutate(method,old,values,ttl,result)
        if api.reconciling then api.fail('invalid_request',false,'invalid_operation') end
        local target=old and path..'/'..old.id or path
        local body
        if method~='DELETE' then body={name=old and old.name or c.fqdn..'.',type=c.type,ttl=ttl,description=old and old.description or '',records=values} end
        c.target_id=old and old.id or nil;c.expected=body
        api.state.attempted=true;save(method);api.write(7,'HGHWATTEMPT1\n');api.checkpoint()
        local d,s=api.fetch(method,target,{},body);local receipt=checked(d,s)
        if old and receipt.id~=old.id then invalid('invalid_receipt') end
        if method~='DELETE' and (not same_values(receipt,values) or receipt.ttl~=ttl or receipt.description~=body.description or receipt.default) then invalid('invalid_receipt') end
        c.last_id=receipt.id;save('verify-'..method)
        if method=='DELETE' then
            for _,r in ipairs(list()) do if r.id==old.id then invalid('invalid_receipt') end end
        else
            local actual,shape=api.fetch('GET',path..'/'..receipt.id,{});actual=checked(actual,shape)
            if actual.id~=receipt.id or actual.status~='ACTIVE' or actual.default or actual.ttl~=ttl or actual.description~=body.description or not same_values(actual,values) then invalid('invalid_receipt') end
        end
        api.state.affected=api.state.affected+1
        return result
    end
    local function finish(result)return M.report(account,revision,'',false,'',result,api.state.attempted and 'confirmed' or 'none',api.state.affected) end
    local records=list()
    if api.reconciling then return api.reconcile.report(account,revision,'','',api.reconcile.observe(c,records)) end
    c.records=records;save('planned')
    if c.operation=='upsert' then
        for _,r in ipairs(records) do if r.match then available(r);return finish('unchanged') end end
        if #records==0 then
            if #list()~=0 then invalid('record_changed') end
            mutate('POST',nil,{c.type=='AAAA' and c.value or M.quote(c.value)},c.ttl,'created');return finish('created')
        end
        local old=detail(records[1]);local values={}
        if c.type=='TXT' then for i,v in ipairs(old.records) do values[i]=v end;values[#values+1]=M.quote(c.value)
        else values[1]=c.value end
        local result=c.type=='TXT' and 'created' or 'updated'
        mutate('PUT',old,values,c.type=='TXT' and old.ttl or c.ttl,result);return finish(result)
    end
    for i,r in ipairs(records) do if r.match then
        detail(r);c.position=i;local kept={}
        for n,v in ipairs(r.records) do if not c.delete_all and r.keys[n]~=(c.value_key or c.value) then kept[#kept+1]=v end end
        mutate(#kept==0 and 'DELETE' or 'PUT',r,kept,r.ttl,'deleted')
    end end
    return finish(api.state.affected>0 and 'deleted' or 'unchanged')
end
return M
