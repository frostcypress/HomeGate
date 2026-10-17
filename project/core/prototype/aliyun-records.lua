-- Configuration-bound AliDNS AAAA/TXT operations. No transport or shell hooks.
local M={}
M.codes={invalid_operation=true,generation_mismatch=true,resource_missing=true,account_mismatch=true,invalid_zone=true,
    record_type=true,invalid_name=true,explicit_all_required=true,invalid_address=true,invalid_challenge=true,
    domain_mismatch=true,invalid_ttl=true,invalid_record=true,record_changed=true,record_unavailable=true,
    state_limit=true,invalid_receipt=true}
M.codes.invalid_context=true
local function integer(n,a,b)return type(n)=='number' and n==math.floor(n) and n>=a and n<=b end
local function id(s)return type(s)=='string' and #s>=1 and #s<=64 and not s:find('[^0-9]') end
function M.record(c,r,plan)
    if type(r)~='table' or not id(r.RecordId) or type(r.DomainName)~='string' or r.DomainName:lower():gsub('%.$','')~=c.zone or
        type(r.RR)~='string' or r.RR:lower()~=c.rr or r.Type~=c.type or type(r.Value)~='string' or #r.Value>4096 or r.Value:find('[%z\1-\31\127]') or
        not integer(r.TTL,1,86400) or type(r.Line)~='string' or #r.Line<1 or #r.Line>128 or r.Line:find('[^A-Za-z0-9_-]') or
        type(r.Locked)~='boolean' or (r.Status~='Enable' and r.Status~='Disable') then return nil end
    local key=r.Value;if c.type=='AAAA' then key=plan.ipv6(r.Value) end
    if not key then return nil end
    return {id=r.RecordId,key=key,value=r.Value,rr=r.RR,line=r.Line,ttl=r.TTL,locked=r.Locked,status=r.Status,
        match=c.delete_all or key==(c.value_key or c.value)}
end
function M.report(account,revision,kind,retry,code,result,effect,affected)
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"aliyun","account":"%s","configuration_revision":%s,"check_scope":"record-operation","error_kind":"%s","retryable":%s,"provider_code":"%s","result":"%s","effect":"%s","affected":%d,"reconciliation_required":%s}\n',tostring(kind==''),account,revision,kind,tostring(retry),code or '',result,effect,affected,tostring(effect=='unknown'))
end
function M.validate(raw,doc,account,revision,rc,marker,kinds,codes)
    if not doc or doc.account~=account or doc.configuration_revision~=tonumber(revision) or doc.provider~='aliyun' or
        doc.check_scope~='record-operation' or type(doc.ok)~='boolean' or doc.ok~=(rc=='0') or not kinds[doc.error_kind] or
        type(doc.retryable)~='boolean' or type(doc.provider_code)~='string' or (doc.provider_code~='' and not codes[doc.provider_code]) or
        not integer(doc.affected,0,100000) then return nil end
    local attempted=marker=='HGALIATTEMPT1\n'
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
function M.run(snapshot,account,revision,api)
    local function invalid(code)api.fail('temporary',true,code or 'invalid_response') end
    local c
    if api.reconciling then
        local raw=api.read(5,8388608);local old=api.context_parse(raw)
        if not old or api.encode(old)..'\n'~=raw then invalid('invalid_context') end
        c=api.reconcile.restore(snapshot,account,revision,api.reconcile.export(old),api.plan,M,api.encode)
        if not c then invalid('invalid_context') end
    else
        local raw=api.read(5,4096);local q=api.parse(raw)
        if not q or api.encode(q)..'\n'~=raw then api.fail('invalid_request',false,'invalid_operation') end
        local kind,code;c,kind,code=api.plan.bind(snapshot,account,revision,q)
        if not c then api.fail(kind,false,code) end
        c.schema='HGALIRECORD1';c.request=q
        c.rr=c.fqdn==c.zone and '@' or c.fqdn:sub(1,#c.fqdn-#c.zone-1)
        local input=io.open(api.work..'/input','wb')
        if not input or not input:write(raw) or not input:close() then invalid('state_limit') end
    end
    local function save(stage)
        c.stage=stage;c.attempted=api.state.attempted;c.affected=api.state.affected
        local body=api.encode(c)..'\n';if #body>8388608 then invalid('state_limit') end
        api.write(6,body)
    end
    local function checked(r)
        local record=M.record(c,r,api.plan);if not record then invalid('invalid_record') end;return record
    end
    local function list()
        local records,seen,total,rows,bytes={},{},nil,0,0
        for page=1,1000 do
            local doc,types,shape=api.fetch({DomainName=c.zone,SubDomain=c.fqdn,Type=c.type,PageNumber=tostring(page),PageSize='100'},'DescribeSubDomainRecords')
            if not types or types.DomainRecords~='object' or not shape.children.DomainRecords.children.Record or shape.children.DomainRecords.children.Record.kind~='array' or
                not integer(doc.TotalCount,0,100000) or doc.PageNumber~=page or doc.PageSize~=100 then invalid() end
            if total and total~=doc.TotalCount then invalid('pagination_changed') end;total=doc.TotalCount
            local items=doc.DomainRecords.Record
            if type(items)~='table' or #items>100 then invalid() end
            for _,r in ipairs(items) do
                local record=checked(r);if seen[record.id] then invalid('invalid_record') end
                seen[record.id]=true;bytes=bytes+#api.encode(record)+#record.id+16
                if bytes>8388608 then invalid('state_limit') end
                records[#records+1]=record
            end
            rows=rows+#items
            if rows>total then invalid('pagination_changed') end
            if rows==total then return records end
            if #items==0 then invalid('pagination_changed') end
        end
        invalid('pagination_limit')
    end
    local function detail(r)
        local d=checked(api.fetch({RecordId=r.id},'DescribeDomainRecordInfo'))
        if d.id~=r.id or d.key~=r.key or d.value~=r.value or d.rr~=r.rr or d.line~=r.line or d.ttl~=r.ttl or d.locked~=r.locked or d.status~=r.status then invalid('record_changed') end
        if d.locked or d.status~='Enable' then api.fail('unsupported',false,'record_unavailable') end
        return d
    end
    local function mutate(action,params)
        if api.reconciling then invalid('invalid_operation') end
        api.state.attempted=true;save(action)
        api.write(7,'HGALIATTEMPT1\n')
        api.checkpoint()
        local doc=api.fetch(params,action)
        if not id(doc.RecordId) or (params.RecordId and doc.RecordId~=params.RecordId) then invalid('invalid_receipt') end
        c.last_id=doc.RecordId;save('verify-'..action)
        return doc.RecordId
    end
    local function finish(result)
        return M.report(account,revision,'',false,'',result,api.state.attempted and 'confirmed' or 'none',api.state.affected)
    end
    local records=list()
    if api.reconciling then return api.reconcile.report(account,revision,'','',api.reconcile.observe(c,records)) end
    c.records=records;save('planned')
    if c.operation=='upsert' then
        for _,r in ipairs(records) do
            if r.match then
                if r.locked or r.status~='Enable' then api.fail('unsupported',false,'record_unavailable') end
                return finish('unchanged')
            end
        end
        local params={RR=c.rr,Type=c.type,Value=c.value,TTL=tostring(c.ttl),Line='default'}
        local result,action='created','AddDomainRecord'
        if #records>0 and c.type~='TXT' then
            local first=detail(records[1]);params.RecordId=first.id;params.Line=first.line
            c.first_id=first.id
            result,action='updated','UpdateDomainRecord'
        else params.DomainName=c.zone end
        local target=mutate(action,params)
        local actual=checked(api.fetch({RecordId=target},'DescribeDomainRecordInfo'))
        if actual.id~=target or actual.key~=(c.value_key or c.value) or actual.line~=params.Line or actual.ttl~=c.ttl or actual.locked or actual.status~='Enable' then invalid('invalid_receipt') end
        api.state.affected=1;return finish(result)
    end
    for position,r in ipairs(records) do
        if r.match then
            detail(r);c.target_id=r.id;c.position=position
            mutate('DeleteDomainRecord',{RecordId=r.id})
            for _,remaining in ipairs(list()) do if remaining.id==r.id then invalid('invalid_receipt') end end
            api.state.affected=api.state.affected+1
        end
    end
    return finish(api.state.affected>0 and 'deleted' or 'unchanged')
end
return M
