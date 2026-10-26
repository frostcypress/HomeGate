-- Pure recovery observations. Never retries, clears or repairs a condition.
local M={}
local modules={ddns=true,acme=true,firewall=true,proxy=true,access=true}
local states={retrying=true,degraded=true,requires_user_action=true}
local kinds={temporary=true,authentication=true,rate_limit=true,not_found=true,invalid_zone=true,
    propagation_pending=true,network_unavailable=true,timeout=true,context_canceled=true,
    unsupported=true,invalid_request=true,invalid_configuration=true,runtime_failure=true,reconciliation_required=true,state_unavailable=true}
local function int(v) return type(v)=='number' and v==math.floor(v) and v>=0 and v<=999999999 end
local function hash(v) return type(v)=='string' and #v==64 and not v:find('[^0-9a-f]') end
local function keys(d,allowed)
    if type(d)~='table' then return false end
    for k in pairs(d) do if not allowed[k] then return false end end;return true
end
function M.binding(token)
    if type(token)~='string' or #token>160 then return nil end
    local identity,generation,writer,orphans=token:match('^([0-9a-f]+):([0-9a-f]+):([a-z]+):([01])$')
    if not hash(identity) or not hash(generation) or (writer~='clear' and writer~='pending' and writer~='unavailable') then return nil end
    return {identity=identity,generation=generation,writer=writer,orphans=orphans=='1'}
end
function M.context(config,binding,encode,ddns_proof)
    if not keys(config,{configured=true,enabled=true,error_kind=true}) or type(config.configured)~='boolean' or
       type(config.enabled)~='boolean' or config.configured~=(config.error_kind=='') or
       (not config.configured and (config.enabled or config.error_kind~='invalid_configuration')) then return nil end
    if not keys(binding,{identity=true,generation=true,writer=true,orphans=true}) or not hash(binding.identity) or not hash(binding.generation) or
       (binding.writer~='clear' and binding.writer~='pending' and binding.writer~='unavailable') or type(binding.orphans)~='boolean' then return nil end
    local out={config=config,binding=binding}
    if ddns_proof~=nil then
        if type(ddns_proof)~='string' or #ddns_proof>110 then return nil end
        if ddns_proof~='unavailable' then
            local h,b=ddns_proof:match('^([0-9a-f]+):([0-9a-f-]+)$')
            if not hash(h) or not b or #b~=36 then return nil end
        end
        out.ddns_proof=ddns_proof
    end
    return encode(out)
end
-- Every numeric field in this schema is a nonnegative integer. Check source
-- tokens too: json-c numeric conversion must not accept 0e0/0.0 as an integer.
function M.integer_tokens(raw)
    local i=1
    while i<=#raw do
        local c=raw:sub(i,i)
        if c=='"' then
            i=i+1
            while i<=#raw do
                c=raw:sub(i,i)
                if c=='\\' then i=i+2 elseif c=='"' then i=i+1;break else i=i+1 end
            end
        elseif c:match('[%d%-]') then
            local n=raw:match('([^,%}%]%s]+)',i)
            if not n or not n:match('^%d+$') then return false end;i=i+#n
        else i=i+1 end
    end
    return true
end
function M.record(raw,doc,types,version,revision,binding,time_valid)
    if type(raw)~='string' or #raw>65536 or not M.integer_tokens(raw) or
       not keys(doc,{api_version=true,ok=true,version=true,phase=true,degraded=true,modules=true,source=true}) or
       doc.api_version~=1 or doc.phase~='recovery' or type(doc.ok)~='boolean' or type(doc.degraded)~='boolean' or
       (doc.version~=version and doc.version~=version:gsub('%-r','-')) or type(doc.modules)~='table' or
       not types or types.modules~='array' or #doc.modules>5 then return nil end
    local seen,rows={},{}
    for _,r in ipairs(doc.modules) do
        if not keys(r,{module=true,state=true,retryable=true,attempt=true,max_attempts=true,next_retry_at=true,error_kind=true,error=true,updated_at=true}) or
           not modules[r.module] or seen[r.module] or not states[r.state] or type(r.retryable)~='boolean' or
           not time_valid(r.updated_at) or (r.attempt~=nil and not int(r.attempt)) or (r.max_attempts~=nil and not int(r.max_attempts)) or
           (r.next_retry_at~=nil and not time_valid(r.next_retry_at)) or
           (r.error_kind~=nil and (type(r.error_kind)~='string' or #r.error_kind>64)) or
           (r.error~=nil and (type(r.error)~='string' or #r.error>4096)) then return nil end
        local attempt,maximum=r.attempt or 0,r.max_attempts or 0
        if (maximum>0 and attempt>maximum) or
           (r.state=='retrying' and (not r.retryable or not r.next_retry_at or attempt==0 or maximum==0)) or
           (r.state=='requires_user_action' and (r.retryable or r.next_retry_at)) then return nil end
        seen[r.module]=true
        local row={module=r.module,state=r.state,retryable=r.retryable,updated_at=r.updated_at}
        if attempt>0 then row.attempt=attempt end;if maximum>0 then row.max_attempts=maximum end
        if r.next_retry_at then row.next_retry_at=r.next_retry_at end
        if r.error_kind and r.error_kind~='' then row.error_kind=kinds[r.error_kind] and r.error_kind or 'unclassified' end
        if r.error~=nil or row.error_kind then row.error='Recorded recovery condition requires inspection' end
        rows[#rows+1]=row
    end
    table.sort(rows,function(a,b)return a.module<b.module end)
    local source=doc.source
    if source==nil then return {rows=rows,bound=false,reason='unbound_state'} end
    if not keys(source,{schema=true,configuration_revision=true,identity=true,generation=true}) or source.schema~='HGRECOVERYSOURCE1' or
       not int(source.configuration_revision) or not hash(source.identity) or not hash(source.generation) then return nil end
    local bound=source.configuration_revision==tonumber(revision) and source.identity==binding.identity and source.generation==binding.generation
    return {rows=rows,bound=bound,reason=bound and '' or 'source_mismatch'}
end
function M.report(version,revision,context,record,observed,encode,contribution)
    local rows={};if record then for _,r in ipairs(record.rows) do rows[#rows+1]=r end end
    local function add(name,kind,message)
        rows[#rows+1]={module=name,state='requires_user_action',retryable=false,error_kind=kind,error=message,updated_at=observed}
    end
    if not record then add('recovery','state_unavailable','Recovery state unavailable')
    elseif not record.bound then add('recovery',record.reason,'Recovery record is not bound to this source') end
    if not context.config.configured then add('configuration','invalid_configuration','Configuration source unavailable') end
    if context.binding.writer~='clear' or context.binding.orphans then add('candidate','candidate_pending','Candidate recovery evidence requires inspection') end
    if contribution then
        local kept={};for _,r in ipairs(rows) do if r.module~='ddns' then kept[#kept+1]=r end end
        rows=kept;if contribution.row then rows[#rows+1]=contribution.row end
    end
    table.sort(rows,function(a,b)return a.module<b.module end)
    local out={api_version=1,prototype=true,ok=#rows==0,version=version,phase='recovery',degraded=#rows>0,modules=rows,
        configuration_revision=tonumber(revision),effect='none',write_ready=false,observation_only=true,complete_recovery_verified=false,
        record_valid=record~=nil,record_source_bound=record~=nil and record.bound or false,config_source_bound=context.config.configured,
        writer_state=context.binding.writer,orphan_evidence=context.binding.orphans,observed_at=observed}
    if contribution then out.ddns_observation=contribution.metadata end
    local body=encode(out)
    if #rows==0 then body=body:gsub('"modules":{}','"modules":[]',1) end
    return body..'\n'
end
-- Validate the published stored bytes by rebuilding the whole public contract.
-- Raw provider messages are intentionally absent; only fixed literals survive.
function M.validate(raw,doc,version,revision,context,encode,time_valid,project)
    if type(doc)~='table' or type(doc.modules)~='table' or not time_valid(doc.observed_at) or
       type(doc.record_valid)~='boolean' or type(doc.record_source_bound)~='boolean' then return nil end
    local contribution
    if context.ddns_proof~=nil then
        contribution=project and project(doc.ddns_observation,doc.observed_at,time_valid)
        if not contribution or (context.ddns_proof=='unavailable' and contribution.metadata.valid) then return nil end
    end
    local rows,reason={},nil
    local synthetic={candidate=true,configuration=true,recovery=true}
    for _,r in ipairs(doc.modules) do
        if type(r)~='table' then return nil end
        if contribution and r.module=='ddns' then
        elseif not synthetic[r.module] then rows[#rows+1]=r
        elseif r.module=='recovery' then reason=r.error_kind end
    end
    local record
    if doc.record_valid then
        if doc.record_source_bound then if reason then return nil end
        elseif reason~='unbound_state' and reason~='source_mismatch' then return nil end
        record={rows=rows,bound=doc.record_source_bound,reason=reason or ''}
    elseif #rows~=0 or doc.record_source_bound or reason~='state_unavailable' then return nil end
    if record then
        local seen,normalized={},{}
        for _,r in ipairs(rows) do
            if not keys(r,{module=true,state=true,retryable=true,attempt=true,max_attempts=true,next_retry_at=true,error_kind=true,error=true,updated_at=true}) or
               not modules[r.module] or seen[r.module] then return nil end;seen[r.module]=true
            if not states[r.state] or type(r.retryable)~='boolean' or not time_valid(r.updated_at) or
               (r.attempt~=nil and not int(r.attempt)) or (r.max_attempts~=nil and not int(r.max_attempts)) or
               (r.next_retry_at~=nil and not time_valid(r.next_retry_at)) or
               (r.error_kind and r.error_kind~='unclassified' and not kinds[r.error_kind]) or
               (r.error and r.error~='Recorded recovery condition requires inspection') then return nil end
            local attempt,maximum=r.attempt or 0,r.max_attempts or 0
            if (maximum>0 and attempt>maximum) or
               (r.state=='retrying' and (not r.retryable or not r.next_retry_at or attempt==0 or maximum==0)) or
               (r.state=='requires_user_action' and (r.retryable or r.next_retry_at)) then return nil end
            local n={module=r.module,state=r.state,retryable=r.retryable,updated_at=r.updated_at}
            if attempt>0 then n.attempt=attempt end;if maximum>0 then n.max_attempts=maximum end
            if r.next_retry_at then n.next_retry_at=r.next_retry_at end
            if r.error_kind then n.error_kind=r.error_kind end;if r.error then n.error=r.error end
            normalized[#normalized+1]=n
        end
        record.rows=normalized
    end
    local expected=M.report(version,revision,context,record,doc.observed_at,encode,contribution)
    if raw~=expected then return nil end;return expected
end
return M
