-- Fixed data adapter. Shell owns HTTP and the independent session deadline.
local json=require('luci.jsonc')
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local plan=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local reconcile=assert(loadfile(dir..'/cloudflare-reconcile-plan.lua'))()
local receipt=assert(loadfile(dir..'/cloudflare-receipt.lua'))()
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local account,revision=arg[2],arg[3]
if type(account)~='string' or #account<1 or #account>64 or not account:match('^[a-zA-Z0-9_-]+$') or type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 or arg[5] then os.exit(1) end
local c
local reconciling=arg[1]=='reconcile-begin' or arg[1]=='reconcile-response' or arg[1]=='reconcile-result'
local function report(kind,retry,code,result,effect,affected)
    if reconciling then
        return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"cloudflare","account":"%s","configuration_revision":%s,"check_scope":"record-reconciliation","error_kind":"%s","retryable":false,"provider_code":"%s","observation":"%s","effect":"unknown","reconciliation_required":true}',tostring(kind==''),account,revision,kind,code or '',result)..'\n'
    end
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"cloudflare","account":"%s","configuration_revision":%s,"check_scope":"record-operation","error_kind":"%s","retryable":%s,"provider_code":"%s","result":"%s","effect":"%s","affected":%d,"reconciliation_required":%s}',tostring(kind==''),account,revision,kind,tostring(retry),code or '',result,effect,affected,tostring(effect=='unknown'))..'\n'
end
local function write(fd,body)
    local f=io.open('/proc/self/fd/'..fd,'wb');if not f or not f:write(body) or not f:close() then os.exit(1) end
end
local function read(fd,limit)
    local f=io.open('/proc/self/fd/'..fd,'rb');if not f then os.exit(1) end
    local s=f:read(limit+1) or '';if not f:close() or #s>limit then os.exit(1) end;return s
end
local function fail(kind,retry,code)
    local attempted=c and c.attempted
    if attempted then retry=false end
    write(3,report(kind,retry,code,reconciling and 'incomplete' or 'failed',attempted and 'unknown' or 'none',c and c.affected or 0));os.exit(1)
end
local function invalid(code) fail('temporary',true,code or 'invalid_response') end
local function valid_id(s) return type(s)=='string' and #s==32 and not s:find('[^0-9a-f]') end
local function save()
    local body=codec.json(c)..'\n';if #body>8388608 then invalid('state_limit') end;write(5,body)
end
local function finish(result)
    write(3,report('',false,'',result,c.attempted and 'confirmed' or 'none',c.affected));io.write('HGDNSDONE1\n')
end
local function reset(stage)
    c.stage=stage;c.page=1;c.pages=-1;c.count=-1;c.rows=0;c.ids={}
end
local function target() return c.stage=='verify-upsert' and c.new_id or c.stage=='confirm-update' and c.first_id or c.delete_ids[c.position] end
local function issue()
    local method,path,body='GET','',nil
    if c.stage=='zones' then path='/zones?name='..c.zone..'&page='..c.page..'&per_page=50'
    elseif c.stage=='records' then path='/zones/'..c.zone_id..'/dns_records?type='..c.type..'&name='..c.fqdn..'&page='..c.page..'&per_page=100'
    else
        path='/zones/'..c.zone_id..'/dns_records'
        if c.stage~='create' then
            local id=target();if c.stage=='update' then id=c.first_id end
            if not valid_id(id) then invalid('invalid_target') end;path=path..'/'..id
        end
        if c.stage=='create' or c.stage=='update' then
            method=c.stage=='create' and 'POST' or 'PATCH'
            -- PATCH leaves existing proxy flags/comments/tags/settings intact.
            body=codec.json(c.stage=='create' and {type=c.type,name=c.fqdn,content=c.value,ttl=c.ttl} or {content=c.value,ttl=c.ttl})
        elseif c.stage=='delete' then method='DELETE' end
    end
    if method~='GET' then
        if reconciling then invalid('read_only_violation') end
        c.attempted=true
        -- Same-boot uncertainty marker, before issuing any mutation. No retry.
        write(9,'HGCFATTEMPT1\n')
    end
    save()
    local config='url = "https://api.cloudflare.com/client/v4'..path..'"\nrequest = "'..method..'"\nheader = "Authorization: Bearer '..shared.quote(c.token)..'"\n'
    if body then config=config..'header = "Content-Type: application/json"\ndata-binary = "'..shared.quote(body)..'"\n' end
    write(4,config);io.write(method=='GET' and 'HGDNSNEXT1\n' or 'HGDNSWRITE1\n')
end
local function next_delete(count)
    c.affected=c.affected+count;c.position=c.position+1
    if c.position>#c.delete_ids then finish(c.affected>0 and 'deleted' or 'unchanged')
    else c.stage='confirm-delete';issue() end
end
local function load_context()
    local raw=read(5,8388608);local doc=json.parse(raw)
    if type(doc)~='table' or codec.json(doc)..'\n'~=raw then os.exit(1) end
    c=doc
    local stages={zones=true,records=true,['confirm-update']=true,['confirm-delete']=true,create=true,update=true,delete=true,['verify-upsert']=true,['verify-delete']=true}
    if c.schema~='HGCFRECORD1' or c.account~=account or c.revision~=tonumber(revision) or not stages[c.stage] or
        type(c.attempted)~='boolean' or type(c.affected)~='number' or c.affected<0 or c.affected>100000 or c.affected~=math.floor(c.affected) or
        type(c.token)~='string' or #c.token<1 or #c.token>4096 or c.token:find('[^ -~]') or plan.name(c.zone)~=c.zone or
        type(c.fqdn)~='string' or #c.fqdn>253 or c.fqdn:find('[^a-z0-9_.-]') or type(c.value)~='string' or #c.value>4096 or c.value:find('[^ -~]') or
        (c.type~='AAAA' and c.type~='TXT') or (c.operation~='upsert' and c.operation~='delete') or
        type(c.ids)~='table' or type(c.delete_ids)~='table' or (c.zone_id~=nil and not valid_id(c.zone_id)) then invalid('invalid_context') end
end
if arg[1]=='receipt-checkpoint' and (arg[4]=='initial' or arg[4]=='advance' or arg[4]=='current') then
    local reader=assert(loadfile(dir..'/private-snapshot.lua'))()
    local snapshot=reader.read(io.stdin,codec)
    local function checked(fd)
        local raw=read(fd,8388608);local doc=json.parse(raw)
        if type(doc)~='table' or codec.json(doc)..'\n'~=raw then os.exit(1) end
        local exported=receipt.export(doc)
        if not exported or codec.json(exported)..'\n'~=raw or not reconcile.restore(snapshot,account,revision,doc,plan) then os.exit(1) end
        return doc
    end
    local candidate=checked(8)
    if arg[4]=='initial' and candidate.affected~=0 then os.exit(1) end
    if arg[4]=='advance' and not receipt.advance(checked(9),candidate,codec) then os.exit(1) end
    io.write('HGCFCVALID1\n')
elseif arg[1]=='receipt-orphan' and not arg[4] then
    local reader=assert(loadfile(dir..'/private-snapshot.lua'))()
    local snapshot=reader.read(io.stdin,codec)
    local function canonical(fd,limit)
        local raw=read(fd,limit);local doc=json.parse(raw)
        if type(doc)~='table' or codec.json(doc)..'\n'~=raw then os.exit(1) end
        return doc,raw
    end
    local checkpoint,raw=canonical(8,8388608)
    local exported=receipt.export(checkpoint)
    if not exported or codec.json(exported)..'\n'~=raw or not reconcile.restore(snapshot,account,revision,checkpoint,plan) then os.exit(1) end
    local work=canonical(9,8388608);local request=canonical(5,4096)
    if not reconcile.restore(snapshot,account,revision,work,plan) or not receipt.orphan(checkpoint,work,request,codec) then os.exit(1) end
    io.write('HGCFOBOUND1\n')
elseif arg[1]=='receipt-terminal' and not arg[4] then
    local raw=read(8,8388608);local original=json.parse(raw)
    if type(original)~='table' or codec.json(original)..'\n'~=raw then os.exit(1) end
    local exported=receipt.export(original)
    if not exported or codec.json(exported)..'\n'~=raw then os.exit(1) end
    local public=io.stdin:read(4097);local doc=public and shared.parse(public)
    if not doc or #public>4096 or not receipt.terminal(original,doc) or
        public~=report('',false,'',doc.result,'confirmed',doc.affected) then os.exit(1) end
    io.write('HGCFTVALID1\n')
elseif arg[1]=='receipt' and not arg[4] then
    load_context();local out=receipt.export(c)
    if not out then os.exit(1) end
    local raw=codec.json(out)..'\n';if #raw>8388608 then os.exit(1) end
    write(3,raw)
elseif arg[1]=='input' and not arg[4] then
    local raw=io.stdin:read(4097);local q=raw and shared.parse(raw)
    if not q or #raw>4096 or codec.json(q)..'\n'~=raw then fail('invalid_request',false,'invalid_operation') end
    write(5,raw);io.write('HGDNSINPUT1\n')
elseif (arg[1]=='begin' or arg[1]=='reconcile-begin') and not arg[4] then
    local reader=assert(loadfile(dir..'/private-snapshot.lua'))()
    local snapshot=reader.read(io.stdin,codec)
    local q,kind,code
    if reconciling then
        local raw=read(5,8388608);local original=json.parse(raw)
        if not original or codec.json(original)..'\n'~=raw then fail('invalid_request',false,'invalid_context') end
        c,code=reconcile.restore(snapshot,account,revision,original,plan)
        if not c then fail('invalid_request',false,code) end
    else
        q=shared.parse(read(8,4096));c,kind,code=plan.bind(snapshot,account,revision,q)
        if c then c.request=q end
    end
    if not c then fail(kind,false,code) end
    c.token,kind,code=shared.credential(snapshot,account)
    if not c.token then fail(kind,false,code) end
    if not reconciling then c.delete_ids={} end
    c.position=1;c.matched=false;reset('zones');issue()
elseif (arg[1]=='response' or arg[1]=='reconcile-response') and not arg[4] then
    load_context()
    if reconciling and (c.reconciliation~=true or c.attempted or (c.stage~='zones' and c.stage~='records')) then invalid('invalid_context') end
    local raw=io.stdin:read(65537);local absent=false
    local doc,types=shared.envelope(raw,function(kind,retry,code)
        if kind=='not_found' and (c.stage=='confirm-delete' or c.stage=='verify-delete') then absent=true;return end
        fail(kind,retry,code)
    end)
    if absent then next_delete(c.stage=='verify-delete' and 1 or 0);return end
    if c.stage=='zones' or c.stage=='records' then
        local per=c.stage=='zones' and 50 or 100
        if type(doc.result)~='table' or types.result~='array' or #doc.result>per then invalid() end
        for k in pairs(doc.result) do if type(k)~='number' or k<1 or k>#doc.result then invalid() end end
        for _,r in ipairs(doc.result) do
            if type(r)~='table' or not valid_id(r.id) or c.ids[r.id] then invalid() end
            c.ids[r.id]=true
            if c.stage=='zones' then
                if plan.name(r.name)~=c.zone or (c.zone_id and c.zone_id~=r.id) or (reconciling and c.expected_zone_id~=r.id) then fail('invalid_zone',false,'ambiguous_zone') end;c.zone_id=r.id
            else
                local rec=plan.record(c,r);if not rec then invalid('record_scope_mismatch') end
                if not c.first_id then c.first_id=rec.id;c.first_key=rec.key end
                if reconciling then
                    reconcile.observe(c,rec)
                elseif rec.match then c.matched=true;if c.operation=='delete' then c.delete_ids[#c.delete_ids+1]=rec.id end end
            end
        end
        local p,code=shared.pagination(c,doc,types,per,1000,per*1000);if not p then invalid(code) end
        c.pages,c.count,c.rows=p.pages,p.count,p.rows
        if not p.done then c.page=c.page+1;issue();return end
        if c.stage=='zones' then
            if not c.zone_id then fail('invalid_zone',false,'zone_not_found') end;reset('records');issue()
        elseif reconciling then finish(reconcile.result(c))
        elseif c.operation=='upsert' then
            if c.matched then finish('unchanged')
            else c.stage=c.type=='AAAA' and c.first_id and 'confirm-update' or 'create';issue() end
        elseif #c.delete_ids==0 then finish('unchanged')
        else c.stage='confirm-delete';issue() end
    elseif c.stage=='verify-delete' then invalid('deletion_unconfirmed')
    elseif c.stage=='delete' then
        if types.result~='object' or type(doc.result)~='table' or doc.result.id~=target() then invalid('mutation_unconfirmed') end
        c.stage='verify-delete';issue()
    else
        if types.result~='object' then invalid() end
        local rec=plan.record(c,doc.result);if not rec then invalid('record_scope_mismatch') end
        if c.stage~='create' and rec.id~=(c.stage=='update' and c.first_id or target()) then invalid('record_id_mismatch') end
        if c.stage=='confirm-delete' then
            if not rec.match then invalid('concurrent_change') end;c.stage='delete';issue()
        elseif c.stage=='confirm-update' then
            if rec.match then finish('unchanged')
            elseif rec.key~=c.first_key then invalid('concurrent_change')
            else c.stage='update';issue() end
        elseif not rec.match then invalid('mutation_unconfirmed')
        elseif c.stage=='verify-upsert' then c.affected=1;finish(c.result)
        else
            if c.stage=='create' and c.ids[rec.id] then invalid('record_id_mismatch') end
            c.result=c.stage=='create' and 'created' or 'updated';c.new_id=rec.id;c.stage='verify-upsert';issue()
        end
    end
elseif arg[1]=='reconcile-result' then
    if arg[4]~='0' and arg[4]~='1' then os.exit(1) end
    local raw=io.stdin:read(4097);local doc=raw and shared.parse(raw)
    local kinds={['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,invalid_zone=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true}
    local observations={['desired-present']=true,['desired-absent']=true,['planned-targets-absent']=true,['planned-targets-present']=true,conflict=true,incomplete=true}
    if not doc or #raw>4096 or doc.ok~=(arg[4]=='0') or not kinds[doc.error_kind] or not observations[doc.observation] or
        type(doc.provider_code)~='string' or #doc.provider_code>32 or not doc.provider_code:match('^[a-zA-Z0-9_-]*$') or
        (doc.ok and (doc.error_kind~='' or doc.observation=='incomplete')) or (not doc.ok and (doc.error_kind=='' or doc.observation~='incomplete')) or read(9,64)~='' then os.exit(1) end
    local expected=report(doc.error_kind,false,doc.provider_code,doc.observation,'unknown',0)
    if raw~=expected then os.exit(1) end;io.write(expected)
elseif arg[1]=='result' then
    if arg[4]~='0' and arg[4]~='1' then os.exit(1) end
    local raw=io.stdin:read(4097);local doc=raw and shared.parse(raw)
    if not doc or #raw>4096 or doc.ok~=(arg[4]=='0') then os.exit(1) end
    local kinds={['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,invalid_zone=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true}
    local results={created=true,updated=true,unchanged=true,deleted=true,failed=true};local effects={none=true,confirmed=true,unknown=true}
    if not kinds[doc.error_kind] or not results[doc.result] or not effects[doc.effect] or type(doc.retryable)~='boolean' or type(doc.provider_code)~='string' or #doc.provider_code>32 or not doc.provider_code:match('^[a-zA-Z0-9_-]*$') or
        type(doc.affected)~='number' or doc.affected<0 or doc.affected>100000 or doc.affected~=math.floor(doc.affected) then os.exit(1) end
    if (doc.ok and (doc.result=='failed' or doc.effect=='unknown' or (doc.result=='unchanged' and (doc.affected~=0 or doc.effect~='none')) or (doc.result~='unchanged' and (doc.affected<1 or doc.effect~='confirmed')))) or
        (not doc.ok and (doc.result~='failed' or doc.effect=='confirmed' or (doc.effect=='none' and doc.affected~=0) or (doc.effect=='unknown' and doc.retryable))) then os.exit(1) end
    local attempted=read(9,64)
    if attempted~='' and attempted~='HGCFATTEMPT1\n' then os.exit(1) end
    if (attempted~='')~=(doc.effect~='none') then os.exit(1) end
    local expected=report(doc.error_kind,doc.retryable,doc.provider_code,doc.result,doc.effect,doc.affected)
    if raw~=expected then os.exit(1) end;io.write(expected)
else os.exit(1) end
