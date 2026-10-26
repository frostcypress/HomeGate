-- Pure DDNS contribution. This never clears other modules or schedules retries.
local M={}
local providers={cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true}
local function id(s)return type(s)=='string' and #s>0 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$') end
local function hex(s)return type(s)=='string' and #s==64 and not s:find('[^0-9a-f]') end
local function boot(s)return type(s)=='string' and #s==36 and s:match('^[0-9a-f-]+$') and s:sub(9,9)=='-' and s:sub(14,14)=='-' and s:sub(19,19)=='-' and s:sub(24,24)=='-' end
local function int(v,a,b)return type(v)=='number' and v==math.floor(v) and v>=a and v<=b end
function M.proof(s)
    if type(s)~='string' then return nil end
    if s=='unavailable' then return {unavailable=true} end
    local digest,b=s:match('^([0-9a-f]+):([0-9a-f-]+)$')
    if not hex(digest) or not boot(b) then return nil end;return {digest=digest,boot=b}
end
function M.inputs(snapshot,version,revision,identity,generation,b,cache,read,encode,now,state,parse)
    if not snapshot or snapshot.revision~=tonumber(revision) or not hex(identity) or not hex(generation) or not boot(b) or
       (cache~='absent' and cache~='valid' and cache~='unsafe' and cache~='incomplete') then return nil end
    local accounts,interval={},nil
    for _,s in ipairs(snapshot.configuration) do
        if s.kind=='dns_account' then accounts[s.name]=s.values.provider
        elseif s.kind=='homegate' then interval=tonumber(s.values.ddns_interval) end
    end
    if not int(interval,60,999999999) then return nil end
    local rows={}
    for _,s in ipairs(snapshot.configuration) do if s.kind=='ddns_rule' then
        local provider=accounts[s.values.account]
        if not id(s.name) or not providers[provider] or #rows>=32 then return nil end
        local raw=false
        if cache=='valid' or cache=='incomplete' then raw=read(s.name) or false end
        if raw~=false and (type(raw)~='string' or #raw>4096) then return nil end
        local d=type(raw)=='string' and parse(raw)
        rows[#rows+1]={rule=s.name,provider=provider,interval=interval,raw=raw,clock_valid=state.valid(d) and int(now,0,999999999) and d.updated<=now or false}
    end end
    table.sort(rows,function(a,c)return a.rule<c.rule end)
    local input={schema='HGDDNSRECOVERYINPUT1',version=version,revision=tonumber(revision),identity=identity,generation=generation,boot=b,cache_state=cache,rules=rows}
    local raw=encode(input);if #raw>262144 then return nil end;return raw..'\n'
end
local count_keys={'successful','retry_wait','paused','unknown','unobserved'}
local function summary_valid(s)
    if type(s)~='table' or not int(s.total,0,32) then return false end
    local sum=0;for _,k in ipairs(count_keys) do if not int(s[k],0,32) then return false end;sum=sum+s[k] end
    local n=0;for k in pairs(s) do if k~='total' and k~='successful' and k~='retry_wait' and k~='paused' and k~='unknown' and k~='unobserved' then return false end;n=n+1 end
    return n==6 and sum==s.total
end
local function module(s,cache,observed)
    local state,retryable,kind
    if s.unknown>0 then state,retryable,kind='requires_user_action',false,'reconciliation_required'
    elseif s.unobserved>0 or cache=='unsafe' or cache=='incomplete' then state,retryable,kind='requires_user_action',false,'state_unavailable'
    elseif s.paused>0 then state,retryable,kind='requires_user_action',false,'invalid_configuration'
    elseif s.retry_wait>0 then state,retryable,kind='degraded',true,'temporary'
    else return false end
    return {module='ddns',state=state,retryable=retryable,error_kind=kind,error='Recorded recovery condition requires inspection',updated_at=observed}
end
function M.make(version,revision,identity,generation,b,digest,summary,cache,observed,encode)
    if not hex(identity) or not hex(generation) or not hex(digest) or not boot(b) or not summary_valid(summary) or
       (cache~='absent' and cache~='valid' and cache~='unsafe' and cache~='incomplete') then return nil end
    return encode({schema='HGDDNSRECOVERY1',producer='homegate-ddns-state',version=version,
        source={schema='HGRECOVERYSOURCE1',configuration_revision=tonumber(revision),identity=identity,generation=generation},
        boot=b,input_digest=digest,summary=summary,cache_state=cache,updated_at=observed})..'\n'
end
function M.build(raw,input,digest,now,observed,state,parse,encode)
    if type(input)~='table' or input.schema~='HGDDNSRECOVERYINPUT1' or type(input.rules)~='table' or #input.rules>32 or
       encode(input)..'\n'~=raw or not int(now,0,999999999) then return nil end
    local s={total=#input.rules,successful=0,retry_wait=0,paused=0,unknown=0,unobserved=0};local last=''
    for _,r in ipairs(input.rules) do
        if not id(r.rule) or r.rule<=last or not providers[r.provider] or not int(r.interval,60,999999999) then return nil end;last=r.rule
        local d=type(r.raw)=='string' and parse(r.raw)
        local c={rule=r.rule,provider=r.provider,revision=input.revision,identity=input.identity,generation=input.generation,boot=input.boot,interval=r.interval}
        if not state.valid(d) or not state.same(d,c) or encode(d)..'\n'~=r.raw or r.clock_valid~=true or d.updated>now then s.unobserved=s.unobserved+1
        elseif d.outcome=='inflight' or d.outcome=='unknown' then s.unknown=s.unknown+1
        elseif d.outcome=='retry_wait' then s.retry_wait=s.retry_wait+1
        elseif d.outcome=='paused' then s.paused=s.paused+1
        else s.successful=s.successful+1 end
    end
    return M.make(input.version,input.revision,input.identity,input.generation,input.boot,digest,s,input.cache_state,observed,encode)
end
function M.decode(raw,doc,encode,time_valid)
    if type(raw)~='string' or #raw>8192 or type(doc)~='table' or doc.schema~='HGDDNSRECOVERY1' or doc.producer~='homegate-ddns-state' or
       type(doc.version)~='string' or not doc.version:match('^%d+%.%d+%.%d+%-r%d+$') or type(doc.source)~='table' or
       doc.source.schema~='HGRECOVERYSOURCE1' or not int(doc.source.configuration_revision,1,32) or not time_valid(doc.updated_at) then return nil end
    local expected=M.make(doc.version,doc.source.configuration_revision,doc.source.identity,doc.source.generation,doc.boot,doc.input_digest,doc.summary,doc.cache_state,doc.updated_at,encode)
    if not expected or expected~=raw then return nil end;return doc
end
function M.fresh(doc,version,revision,binding,proof)
    return doc and proof and not proof.unavailable and doc.version==version and doc.source.configuration_revision==tonumber(revision) and
        doc.source.identity==binding.identity and doc.source.generation==binding.generation and doc.boot==proof.boot and doc.input_digest==proof.digest
end
function M.pending(version,revision,identity,generation,b,digest,candidate,ticket,encode)
    if type(version)~='string' or not version:match('^%d+%.%d+%.%d+%-r%d+$') or not int(tonumber(revision),1,32) or
       not hex(identity) or not hex(generation) or not boot(b) or not hex(digest) or not hex(candidate) or
       type(ticket)~='string' or #ticket~=32 or ticket:find('[^0-9a-f]') then return nil end
    return encode({schema='HGDDNSRECOVERYPENDING2',version=version,
        source={schema='HGRECOVERYSOURCE1',configuration_revision=tonumber(revision),identity=identity,generation=generation},
        boot=b,input_digest=digest,candidate_sha256=candidate,ticket=ticket})..'\n'
end
function M.pending_decode(raw,doc,encode)
    if type(raw)~='string' or #raw>2048 or type(doc)~='table' or doc.schema~='HGDDNSRECOVERYPENDING2' or
       type(doc.source)~='table' or doc.source.schema~='HGRECOVERYSOURCE1' then return nil end
    local expected=M.pending(doc.version,doc.source.configuration_revision,doc.source.identity,doc.source.generation,
        doc.boot,doc.input_digest,doc.candidate_sha256,doc.ticket,encode)
    if not expected or expected~=raw then return nil end;return doc
end
function M.public(doc,reason)
    if not doc then return {valid=false,bound=false,reason=reason or 'state_unavailable'} end
    return {valid=true,bound=true,reason='',summary=doc.summary,cache_state=doc.cache_state,updated_at=doc.updated_at}
end
function M.project(meta,observed,time_valid)
    if type(meta)~='table' or type(meta.valid)~='boolean' or meta.bound~=meta.valid then return nil end
    local normalized,row
    if meta.valid then
        if meta.reason~='' or not summary_valid(meta.summary) or not time_valid(meta.updated_at) or
           (meta.cache_state~='absent' and meta.cache_state~='valid' and meta.cache_state~='unsafe' and meta.cache_state~='incomplete') then return nil end
        normalized={valid=true,bound=true,reason='',summary=meta.summary,cache_state=meta.cache_state,updated_at=meta.updated_at}
        row=module(meta.summary,meta.cache_state,meta.updated_at)
    else
        if meta.reason~='state_unavailable' and meta.reason~='source_mismatch' and meta.reason~='publication_pending' then return nil end
        normalized={valid=false,bound=false,reason=meta.reason}
        row={module='ddns',state='requires_user_action',retryable=false,error_kind='state_unavailable',error='Recorded recovery condition requires inspection',updated_at=observed}
    end
    return {metadata=normalized,row=row}
end
return M
