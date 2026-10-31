-- Data-only bounded status and scheduling policy. Never grants write authority.
local M={}
local providers={cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true}
local kinds={['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,invalid_zone=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true,invalid_configuration=true}
local outcomes={inflight=true,created=true,updated=true,unchanged=true,retry_wait=true,paused=true,unknown=true}
local function integer(v,a,b)return type(v)=='number' and v==math.floor(v) and v>=a and v<=b end
local function id(s)return type(s)=='string' and #s>0 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$') end
local function hex(s)return type(s)=='string' and #s==64 and s:match('^[0-9a-f]+$') end
function M.valid(d)
    if type(d)~='table' or d.schema~='HGDDNSSTATE1' or not id(d.rule) or not providers[d.provider] or
        not integer(d.revision,1,32) or not hex(d.identity) or not hex(d.generation) or type(d.boot)~='string' or
        #d.boot~=36 or not d.boot:match('^[0-9a-f-]+$') or not integer(d.interval,60,999999999) or
        not integer(d.updated,0,999999999) or not integer(d.failures,0,8) or not integer(d.delay,0,999999999) or
        not outcomes[d.outcome] or not kinds[d.error_kind] or (d.event_epoch~=nil and not integer(d.event_epoch,1,253402300799)) or
        (d.last_effect~='none' and d.last_effect~='confirmed' and d.last_effect~='unknown') then return false end
    local n=0;for k in pairs(d) do
        if k~='schema' and k~='rule' and k~='provider' and k~='revision' and k~='identity' and k~='generation' and k~='boot' and k~='interval' and k~='updated' and k~='failures' and k~='delay' and k~='outcome' and k~='error_kind' and k~='last_effect' and k~='event_epoch' then return false end;n=n+1
    end
    if n~=(d.event_epoch and 15 or 14) then return false end
    if d.outcome=='inflight' then return d.last_effect=='unknown' and d.error_kind=='' and d.delay==0 end
    if d.outcome=='unknown' then return d.last_effect=='unknown' and d.delay==0 and d.failures>=1 end
    if d.outcome=='created' or d.outcome=='updated' or d.outcome=='unchanged' then
        return d.last_effect==(d.outcome=='unchanged' and 'none' or 'confirmed') and d.error_kind=='' and d.failures==0 and d.delay==d.interval
    end
    if d.last_effect~='none' or d.error_kind=='' or d.failures<1 then return false end
    if d.outcome=='paused' then return d.delay==0 end
    return (d.error_kind=='temporary' or d.error_kind=='timeout' or d.error_kind=='rate_limit' or d.error_kind=='network_unavailable') and
        d.delay==math.max(d.interval,math.min(3600,60*2^(d.failures-1)))
end
function M.same(d,c)
    return d.rule==c.rule and d.provider==c.provider and d.revision==c.revision and d.identity==c.identity and d.generation==c.generation and d.boot==c.boot and d.interval==c.interval
end
function M.decision(d,c,now,blocked,authorized,incomplete)
    if blocked or incomplete then return 'blocked',0 end
    if d and (d.outcome=='inflight' or d.outcome=='unknown') then return 'reconciliation_required',0 end
    if not authorized then return 'unauthorized',0 end
    if not d then return 'ready',0 end
    if not M.same(d,c) then return 'stale',0 end
    if now<d.updated then return 'clock_invalid',0 end
    if d.outcome=='paused' then return 'paused',0 end
    local wait=math.max(0,d.updated+d.delay-now)
    if wait==0 then return 'ready',0 end
    return d.outcome=='retry_wait' and 'retry_wait' or 'waiting',wait
end
function M.begin(c,old,now)
    return {schema='HGDDNSSTATE1',rule=c.rule,provider=c.provider,revision=c.revision,identity=c.identity,generation=c.generation,boot=c.boot,interval=c.interval,updated=now,
        failures=old and M.same(old,c) and old.failures or 0,delay=0,outcome='inflight',error_kind='',last_effect='unknown'}
end
function M.finish(d,now,result,kind,effect,retryable)
    if not M.valid(d) or d.outcome~='inflight' or now<d.updated then return nil end
    local out={};for k,v in pairs(d) do out[k]=v end;out.updated=now
    if result=='created' or result=='updated' or result=='unchanged' then
        if kind~='' or retryable or effect~=(result=='unchanged' and 'none' or 'confirmed') then return nil end
        out.outcome=result;out.failures=0;out.delay=out.interval
    elseif result=='failed' then
        if not kinds[kind] or kind=='' or (effect~='unknown' and effect~='none') or (effect=='unknown' and retryable) then return nil end
        out.failures=math.min(8,out.failures+1)
        if effect=='unknown' then out.outcome='unknown';out.delay=0
        elseif retryable then
            if kind~='temporary' and kind~='timeout' and kind~='rate_limit' and kind~='network_unavailable' then return nil end
            out.outcome='retry_wait';out.delay=math.max(out.interval,math.min(3600,60*2^(out.failures-1)))
        else out.outcome='paused';out.delay=0 end
    else return nil end
    out.error_kind=kind;out.last_effect=effect
    return M.valid(out) and out or nil
end
function M.report(d,c,now,blocked,authorized,incomplete)
    local status,wait=M.decision(d,c,now,blocked,authorized,incomplete)
    if d and not M.same(d,c) then d=nil end -- never label another generation's history as current
    local extra=d and d.event_epoch and string.format(',"event_epoch":%.0f',d.event_epoch) or ''
    return string.format('{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-state","configuration_revision":%d,"rule":"%s","provider":"%s","status":"%s","last_result":"%s","last_effect":"%s","error_kind":"%s","failures":%d,"retry_in":%d,"authorized":%s,"blocked":%s,"effect":"none","write_ready":false%s}\n',c.revision,c.rule,c.provider,status,d and d.outcome or 'none',d and d.last_effect or 'none',d and d.error_kind or '',d and d.failures or 0,wait,tostring(authorized),tostring(blocked or incomplete),extra)
end
return M
