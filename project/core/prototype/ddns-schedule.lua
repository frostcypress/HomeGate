-- Bounded admission policy only. Never grants authority or performs maintenance.
local M={budget=900,limit=8}
local providers={cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true}
local statuses={ready=true,stale=true,waiting=true,retry_wait=true,paused=true,blocked=true,reconciliation_required=true,unauthorized=true,clock_invalid=true,created=true,updated=true,unchanged=true,failed=true,disabled=true,unsupported=true,invalid_rule=true,network_unavailable=true}
local kinds={['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,invalid_zone=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true,invalid_configuration=true}
local reasons={['']=true,stopped=true,budget=true,ticks=true,idle=true,changed=true,blocked=true,reconciliation_required=true,failed=true,clock_invalid=true,interrupted=true}
local function integer(n,a,b)return type(n)=='number' and n==math.floor(n) and n>=a and n<=b end
local function hex(s,n)return type(s)=='string' and #s==n and s:match('^[0-9a-f]+$') end
local function digits(s,n)return type(s)=='string' and #s<=n and s:match('^[1-9]%d*$') end
local function keys(d,n,allowed)
    if type(d)~='table' then return false end
    local count=0;for k in pairs(d) do if not allowed[k] then return false end;count=count+1 end;return count==n
end
function M.lease(d)
    local continuous=type(d)=='table' and d.continuous==true
    if type(d)=='table' and d.continuous~=nil and not continuous then return false end
    return keys(d,continuous and 12 or 11,{continuous=true,schema=true,identity=true,generation=true,grant=true,revision=true,boot=true,pid=true,birth=true,token=true,started=true,deadline=true}) and
        d.schema=='HGDDNSSCHEDULE1' and hex(d.identity,64) and hex(d.generation,64) and hex(d.grant,64) and integer(d.revision,1,32) and
        type(d.boot)=='string' and #d.boot==36 and d.boot:match('^[0-9a-f-]+$') and digits(d.pid,9) and tonumber(d.pid)>=2 and digits(d.birth,20) and hex(d.token,32) and
        integer(d.started,0,999999099) and d.deadline==(continuous and 0 or d.started+M.budget)
end
function M.report(d)
    local continuous=type(d)=='table' and d.continuous==true
    if type(d)=='table' and d.continuous~=nil and not continuous then return false end
    return keys(d,continuous and 13 or 12,{continuous=true,api_version=true,prototype=true,ok=true,phase=true,running=true,status=true,reason=true,ticks=true,last_effect=true,effect=true,write_ready=true,admission_limit=true}) and
        d.api_version==1 and d.prototype==true and type(d.ok)=='boolean' and d.phase=='ddns-schedule' and type(d.running)=='boolean' and
        (d.status=='idle' or d.status=='running' or d.status=='waiting' or d.status=='stopping' or d.status=='finished' or d.status=='interrupted') and
        reasons[d.reason] and integer(d.ticks,0,continuous and 2147483647 or M.limit) and (d.last_effect=='none' or d.last_effect=='confirmed' or d.last_effect=='unknown') and
        d.effect=='none' and d.write_ready==false and d.admission_limit==(continuous and 0 or M.limit)
end
function M.decision(rows)
    if type(rows)~='table' or #rows<1 or #rows>32 then return nil end
    local wait,ready,seen=nil,false,{}
    for _,d in ipairs(rows) do
        if type(d)~='table' or not d.rule or seen[d.rule] or not integer(d.retry_in,0,999999999) then return nil end;seen[d.rule]=true
        if d.status=='ready' or d.status=='stale' then if d.retry_in~=0 then return nil end;ready=true
        elseif d.status=='waiting' or d.status=='retry_wait' then if d.retry_in<1 then return nil end;wait=math.min(wait or d.retry_in,d.retry_in)
        elseif d.status=='paused' then if d.retry_in~=0 then return nil end
        else return 'blocked',0 end
    end
    if ready then return 'ready',0 end
    if wait then return 'wait',wait end
    return 'idle',0
end
function M.batch(raw,d,revision,rc,names,json)
    if type(d)~='table' or type(d.rules)~='table' or #d.rules>#names or d.configuration_revision~=tonumber(revision) or
        d.api_version~=1 or d.prototype~=true or d.phase~='ddns-batch' or d.ok~=(rc=='0') or type(d.sampled)~='boolean' or d.write_ready~=false or
        (d.effect~='none' and d.effect~='confirmed' and d.effect~='unknown') then return nil end
    local rows,aggregate={},'none'
    for i,row in ipairs(d.rules) do
        if not keys(row,7,{rule=true,provider=true,status=true,effect=true,error_kind=true,retryable=true,retry_in=true}) or row.rule~=names[i] or not providers[row.provider] or not statuses[row.status] or
            not kinds[row.error_kind] or type(row.retryable)~='boolean' or not integer(row.retry_in,0,999999999) or
            (row.effect~='none' and row.effect~='confirmed' and row.effect~='unknown') then return nil end
        if row.status=='created' or row.status=='updated' or row.status=='unchanged' then
            if row.effect~=(row.status=='unchanged' and 'none' or 'confirmed') or row.error_kind~='' or row.retryable or row.retry_in~=0 then return nil end
        elseif row.status=='failed' then
            if row.effect=='confirmed' or row.error_kind=='' or row.retry_in~=0 or (row.effect=='unknown' and row.retryable) then return nil end
        else
            if row.effect~='none' then return nil end
            if row.status=='waiting' or row.status=='retry_wait' then if row.retry_in<1 then return nil end
            elseif row.retry_in~=0 then return nil end
        end
        if row.effect=='unknown' then aggregate='unknown' elseif row.effect=='confirmed' and aggregate~='unknown' then aggregate='confirmed' end
        rows[i]=string.format('{"rule":"%s","provider":"%s","status":"%s","effect":"%s","error_kind":"%s","retryable":%s,"retry_in":%d}',row.rule,row.provider,row.status,row.effect,row.error_kind,tostring(row.retryable),row.retry_in)
    end
    local error=d.error~=nil
    if error then if d.error~='DDNS batch is unavailable' or rc=='0' or rc=='1' then return nil end
    elseif rc~='0' and rc~='1' and rc~='4' then return nil end
    if not error and (#d.rules~=#names or d.effect~=aggregate) then return nil end
    if error and d.effect~=aggregate and d.effect~='unknown' then return nil end
    local expected=string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"ddns-batch","configuration_revision":%s,"effect":"%s","sampled":%s,"write_ready":false,"rules":[%s]}\n',tostring(d.ok),revision,d.effect,tostring(d.sampled),table.concat(rows,','))
    if error then
        expected=string.format('{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-batch","effect":"%s","sampled":%s,"write_ready":false,"rules":[%s],"error":"DDNS batch is unavailable"}\n',d.effect,tostring(d.sampled),table.concat(rows,','))
    end
    if raw~=expected then return nil end
    return d.effect
end
return M
