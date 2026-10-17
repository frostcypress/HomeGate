-- Configuration-bound DNSPod AAAA/TXT operations. No transport or shell hooks.
local M={}
M.codes={invalid_operation=true,generation_mismatch=true,resource_missing=true,account_mismatch=true,invalid_zone=true,
    record_type=true,invalid_name=true,explicit_all_required=true,invalid_address=true,invalid_challenge=true,
    domain_mismatch=true,invalid_ttl=true,invalid_record=true,record_changed=true,record_unavailable=true,
    state_limit=true,invalid_receipt=true}
M.codes.invalid_context=true
local function integer(n,a,b)return type(n)=='number' and n==math.floor(n) and n>=a and n<=b end
local function id(s)return type(s)=='string' and #s>=1 and #s<=64 and not s:find('[^0-9]') end
function M.report(account,revision,kind,retry,code,result,effect,affected)
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"dnspod","account":"%s","configuration_revision":%s,"check_scope":"record-operation","error_kind":"%s","retryable":%s,"provider_code":"%s","result":"%s","effect":"%s","affected":%d,"reconciliation_required":%s}\n',tostring(kind==''),account,revision,kind,tostring(retry),code or '',result,effect,affected,tostring(effect=='unknown'))
end
function M.validate(raw,doc,account,revision,rc,marker,kinds,codes)
    if not doc or doc.account~=account or doc.configuration_revision~=tonumber(revision) or doc.provider~='dnspod' or
        doc.check_scope~='record-operation' or type(doc.ok)~='boolean' or doc.ok~=(rc=='0') or not kinds[doc.error_kind] or
        type(doc.retryable)~='boolean' or type(doc.provider_code)~='string' or (doc.provider_code~='' and not codes[doc.provider_code]) or
        not integer(doc.affected,0,100000) then return nil end
    local attempted=marker=='HGDNPATTEMPT1\n'
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
function M.record(c,r,plan,detail)
    if type(r)~='table' then return nil end
    local rid,rr,typ,line,line_id=r.RecordId,r.Name,r.Type,r.Line,r.LineId
    if detail then rid,rr,typ,line,line_id=r.Id,r.SubDomain,r.RecordType,r.RecordLine,r.RecordLineId end
    local enabled=detail and r.Enabled==1 or (not detail and r.Status=='ENABLE')
    if not integer(rid,1,9007199254740991) or type(rr)~='string' or rr:lower()~=c.rr or typ~=c.type or
        type(r.Value)~='string' or #r.Value>4096 or r.Value:find('[%z\1-\31\127]') or not integer(r.TTL,1,604800) or
        type(line)~='string' or #line<1 or #line>256 or line:find('[%z\1-\31\127]') or
        type(line_id)~='string' or #line_id<1 or #line_id>128 or line_id:find('[^A-Za-z0-9_=%-]') or
        (detail and r.Enabled~=0 and r.Enabled~=1) or (not detail and r.Status~='ENABLE' and r.Status~='DISABLE') or
        (r.Weight~=nil and not integer(r.Weight,0,100)) or type(r.Remark)~='string' or #r.Remark>4096 or r.Remark:find('[%z\1-\31\127]') then return nil end
    local key=r.Value;if c.type=='AAAA' then key=plan.ipv6(r.Value) end
    if not key then return nil end
    return {id=string.format('%.0f',rid),key=key,value=r.Value,rr=rr,line=line,line_id=line_id,ttl=r.TTL,
        enabled=enabled,weight=r.Weight,remark=r.Remark,match=c.delete_all or key==(c.value_key or c.value)}
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
        c.schema='HGDNPRECORD1';c.request=q;c.rr=c.fqdn==c.zone and '@' or c.fqdn:sub(1,#c.fqdn-#c.zone-1)
        local input=io.open(api.work..'/input','wb')
        if not input or not input:write(raw) or not input:close() then invalid('state_limit') end
    end
    local function save(stage)
        c.stage=stage;c.attempted=api.state.attempted;c.affected=api.state.affected
        local body=api.encode(c)..'\n';if #body>8388608 then invalid('state_limit') end;api.write(6,body)
    end
    local function checked(r,detail)
        local record=M.record(c,r,api.plan,detail);if not record then invalid('invalid_record') end;return record
    end
    local function list()
        local out,seen,total,rows,bytes={},{},nil,0,0
        for page=1,1000 do
            -- Unfiltered domain pagination gives TotalCount one fixed meaning.
            local d,shape=api.fetch({Domain=c.zone,Offset=(page-1)*100,Limit=100,ErrorOnEmpty='no'},'DescribeRecordList')
            if not shape or not shape.children.RecordList or shape.children.RecordList.kind~='array' or
                not shape.children.RecordCountInfo or shape.children.RecordCountInfo.kind~='object' or
                type(d.RecordCountInfo)~='table' or not integer(d.RecordCountInfo.TotalCount,0,100000) or type(d.RecordList)~='table' or #d.RecordList>100 then invalid() end
            local count=d.RecordCountInfo.TotalCount;if total and total~=count then invalid('pagination_changed') end;total=count
            for _,r in ipairs(d.RecordList) do
                if type(r)~='table' or not integer(r.RecordId,1,9007199254740991) or seen[r.RecordId] or type(r.Name)~='string' or type(r.Type)~='string' then invalid('invalid_record') end
                seen[r.RecordId]=true
                if r.Name:lower()==c.rr and r.Type==c.type then
                    local record=checked(r);bytes=bytes+#api.encode(record)+32;if bytes>8388608 then invalid('state_limit') end;out[#out+1]=record
                end
            end
            rows=rows+#d.RecordList;if rows>total or (#d.RecordList==0 and rows<total) then invalid('pagination_changed') end
            if rows==total then return out end
            if #d.RecordList<100 then invalid('pagination_changed') end
        end
        invalid('pagination_limit')
    end
    local function detail(r)
        local doc=api.fetch({Domain=c.zone,RecordId=tonumber(r.id)},'DescribeRecord');local actual=checked(doc.RecordInfo,true)
        if api.encode(actual)~=api.encode(r) then invalid('record_changed') end
        if not actual.enabled then api.fail('unsupported',false,'record_unavailable') end;return actual
    end
    local function mutate(action,params)
        if api.reconciling then invalid('invalid_operation') end
        api.state.attempted=true;save(action);api.write(7,'HGDNPATTEMPT1\n')
        api.checkpoint()
        local doc=api.fetch(params,action);local rid=params.RecordId
        if action=='CreateRecord' then
            if not integer(doc.RecordId,1,9007199254740991) then invalid('invalid_receipt') end;rid=doc.RecordId
        end
        c.last_id=string.format('%.0f',rid);save('verify-'..action);return rid
    end
    local function finish(result)return M.report(account,revision,'',false,'',result,api.state.attempted and 'confirmed' or 'none',api.state.affected) end
    local records=list()
    if api.reconciling then return api.reconcile.report(account,revision,'','',api.reconcile.observe(c,records)) end
    c.records=records;save('planned')
    if c.operation=='upsert' then
        for _,r in ipairs(records) do if r.match then
            if not r.enabled then api.fail('unsupported',false,'record_unavailable') end
            return finish('unchanged')
        end end
        local params={Domain=c.zone,SubDomain=c.rr,RecordType=c.type,Value=c.value,TTL=c.ttl,RecordLine='默认',RecordLineId='0',Status='ENABLE'}
        local result,action='created','CreateRecord'
        if #records>0 and c.type=='AAAA' then
            local old=detail(records[1]);params.RecordId=tonumber(old.id);params.RecordLine=old.line;params.RecordLineId=old.line_id
            params.Weight=old.weight;params.Remark=old.remark;c.first_id=old.id;result,action='updated','ModifyRecord'
        end
        local target=mutate(action,params);local d=api.fetch({Domain=c.zone,RecordId=target},'DescribeRecord');local actual=checked(d.RecordInfo,true)
        if actual.id~=string.format('%.0f',target) or actual.key~=(c.value_key or c.value) or not actual.enabled or actual.ttl~=c.ttl or
            actual.line_id~=params.RecordLineId or (action=='ModifyRecord' and (actual.line~=params.RecordLine or actual.weight~=params.Weight or actual.remark~=params.Remark)) then invalid('invalid_receipt') end
        api.state.affected=1;return finish(result)
    end
    for position,r in ipairs(records) do if r.match then
        detail(r);c.target_id=r.id;c.position=position
        mutate('DeleteRecord',{Domain=c.zone,RecordId=tonumber(r.id)})
        for _,remaining in ipairs(list()) do if remaining.id==r.id then invalid('invalid_receipt') end end
        api.state.affected=api.state.affected+1
    end end
    return finish(api.state.affected>0 and 'deleted' or 'unchanged')
end
return M
