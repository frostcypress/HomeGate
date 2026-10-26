-- Pure health-report and bounded runtime metadata rules. No process actions.
local M={}
local errors={invalid_configuration='Configuration unavailable',runtime_state_unavailable='Runtime state unavailable',
    runtime_identity_unavailable='Runtime process identity unavailable',runtime_unstable='Runtime observation changed'}
local function integer(n,low,high) return type(n)=='number' and n==math.floor(n) and n>=low and n<=high end
function M.timestamp(s)
    if type(s)~='string' or #s>40 then return false end
    local y,m,d,h,i,t,rest=s:match('^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)(.+)$')
    if not y then return false end
    y,m,d,h,i,t=tonumber(y),tonumber(m),tonumber(d),tonumber(h),tonumber(i),tonumber(t)
    local days={31,28,31,30,31,30,31,31,30,31,30,31}
    if y%4==0 and (y%100~=0 or y%400==0) then days[2]=29 end
    if m<1 or m>12 or d<1 or d>days[m] or h>23 or i>59 or t>59 then return false end
    if rest:sub(1,1)=='.' then
        local fraction,zone=rest:match('^%.(%d+)(.*)$')
        if not fraction or #fraction>9 then return false end;rest=zone
    end
    if rest=='Z' then return true end
    local zh,zm=rest:match('^[+-](%d%d):(%d%d)$')
    return zh~=nil and tonumber(zh)<=23 and tonumber(zm)<=59
end
function M.state(doc,raw)
    if type(doc)~='table' then return nil end
    if raw~=nil then
        if type(raw)~='string' then return nil end
        local pid=raw:match('"pid"%s*:%s*([^,%}%s]+)')
        local ticks=raw:match('"process_start_ticks"%s*:%s*([^,%}%s]+)')
        if not pid or not pid:match('^%-?%d+$') or
           (doc.process_start_ticks~=nil and (not ticks or not ticks:match('^%d+$'))) then return nil end
    end
    if not integer(doc.pid,-999999999,999999999) or not M.timestamp(doc.started_at) or
       type(doc.version)~='string' or #doc.version>64 or
       (doc.version~='' and not doc.version:match('^%d+%.%d+%.%d+%-r%d+$') and not doc.version:match('^%d+%.%d+%.%d+%-%d+$')) then return nil end
    for k in pairs(doc) do if k~='pid' and k~='started_at' and k~='version' and k~='process_start_ticks' then return nil end end
    local ticks=doc.process_start_ticks
    if ticks~=nil and not integer(ticks,0,9007199254740991) then return nil end
    local out={pid=doc.pid,started_at=doc.started_at,version=doc.version}
    if ticks and ticks~=0 then out.process_start_ticks=ticks end
    return out
end
function M.process(stat,pid)
    if type(stat)~='string' or #stat>8192 then return nil end
    local actual,tail=stat:match('^(%d+) %(.+%) (.+)$')
    if actual~=tostring(pid) then return nil end
    local fields={};for v in tail:gmatch('%S+') do fields[#fields+1]=v end
    if #fields<20 or not fields[1]:match('^[A-Z]$') or not fields[20]:match('^%d+$') or #fields[20]>16 then return nil end
    local ticks=tonumber(fields[20]);if not integer(ticks,0,9007199254740991) then return nil end
    return {state=fields[1],ticks=ticks}
end
function M.probe(state,read)
    if not state then return {running=false,error_kind='runtime_state_unavailable'} end
    if state.pid<=0 then return {running=false,state=state} end
    local function sample()
        local raw,kind=read('stat',state.pid,8192)
        if kind=='absent' then return {running=false,state=state} end
        local p=kind=='ok' and M.process(raw,state.pid)
        if not p then return {running=false,error_kind='runtime_identity_unavailable'} end
        if p.state=='Z' or p.state=='X' or (state.process_start_ticks and state.process_start_ticks~=p.ticks) then return {running=false,state=state} end
        local cmd,cmd_kind=read('cmdline',state.pid,8192)
        if cmd_kind~='ok' or cmd~='/usr/bin/homegate\0daemon\0' then return {running=false,error_kind='runtime_identity_unavailable'} end
        return {running=true,state=state,ticks=p.ticks}
    end
    local a,b=sample(),sample()
    if a.running~=b.running or a.error_kind~=b.error_kind or a.ticks~=b.ticks then return {running=false,error_kind='runtime_unstable'} end
    return a
end
function M.configuration(snapshot,raw,codec,validator,ip,revision)
    local bad={configured=false,enabled=false,error_kind='invalid_configuration'}
    if not snapshot or snapshot.revision~=tonumber(revision) then return bad end
    local candidate=raw and codec.private_configuration(raw)
    if not candidate then return bad end
    local counts=validator.validate(snapshot,candidate,codec.json,ip)
    if not counts then return bad end
    return {configured=true,enabled=candidate.switches.main.enabled=='1',error_kind=''}
end
function M.context(doc,encode)
    if type(doc)~='table' or type(doc.configured)~='boolean' or type(doc.enabled)~='boolean' or
       (doc.error_kind~='' and doc.error_kind~='invalid_configuration') or doc.configured~=(doc.error_kind=='') or
       (not doc.configured and doc.enabled) then return nil end
    return encode({configured=doc.configured,enabled=doc.enabled,error_kind=doc.error_kind})
end
function M.report(version,revision,config,probe,encode)
    local kind=config.error_kind~='' and config.error_kind or (probe.error_kind or '')
    local running=probe.running==true and not probe.error_kind
    running=running==true
    local healthy=config.configured and kind=='' and config.enabled==running
    local out={api_version=1,prototype=true,ok=healthy,version=version,phase='common-runtime',
        configuration_revision=tonumber(revision),effect='none',write_ready=false,error_kind=kind,
        service={configured=config.configured,enabled=config.enabled,running=running,healthy=healthy}}
    if probe.state then out.runtime=probe.state end
    if kind~='' then out.error=errors[kind] end
    return encode(out)..'\n'
end
function M.validate(raw,doc,version,revision,context,encode)
    if type(doc)~='table' or type(doc.service)~='table' or type(doc.service.running)~='boolean' or
       (doc.error_kind~='' and not errors[doc.error_kind]) then return nil end
    local state=doc.runtime and M.state(doc.runtime)
    if doc.runtime~=nil and not state then return nil end
    if doc.service.running and (not state or state.pid<=0) then return nil end
    local probe={running=doc.service.running,state=state}
    if doc.error_kind~='' and doc.error_kind~='invalid_configuration' then probe.error_kind=doc.error_kind end
    local expected=M.report(version,revision,context,probe,encode)
    if raw~=expected then return nil end;return expected,doc.ok
end
return M
