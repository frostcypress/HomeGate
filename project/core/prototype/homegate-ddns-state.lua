-- Fixed private-frame adapter and canonical cache codec. No shell or network.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local backup=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local planner=assert(loadfile(dir..'/ddns-plan.lua'))()
local state=assert(loadfile(dir..'/ddns-state.lua'))()
local mode,revision,rule=arg[1],arg[2],arg[3]
if not revision or not revision:match('^[1-9]%d*$') or tonumber(revision)>999999999 or not planner.id(rule) then os.exit(1) end
if mode=='scope' or mode=='reset-scope' then
    if arg[4] then os.exit(1) end
    local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,backup)
    if not snapshot or snapshot.revision~=tonumber(revision) then os.exit(1) end
    if mode=='reset-scope' then io.write('none:none:60\n');return end
    local intent,provider=assert(loadfile(dir..'/ddns-authority.lua'))().intent(snapshot,rule,planner.id)
    if not intent then os.exit(1) end
    local account,interval
    for _,s in ipairs(snapshot.configuration) do
        if s.kind=='ddns_rule' and s.name==rule then account=s.values.account
        elseif s.kind=='homegate' then interval=tonumber(s.values.ddns_interval) end
    end
    if not planner.id(account) or not interval or interval<60 or interval>999999999 or interval~=math.floor(interval) then os.exit(1) end
    io.write(provider..':'..account..':'..interval..'\n');return
end
local provider,account,identity,generation,boot,now,interval=arg[4],arg[5],arg[6],arg[7],arg[8],tonumber(arg[9]),tonumber(arg[10])
local blocked,authorized,incomplete=arg[11],arg[12],arg[13]
local result_arg,wan_sample,network_check=arg[14],arg[15],arg[16]
if result_arg=='-' then result_arg=nil end
if wan_sample=='-' then wan_sample=nil end
if arg[17] or (network_check and network_check~='true' and network_check~='false') or not planner.id(account) or (blocked~='true' and blocked~='false') or (authorized~='true' and authorized~='false') or (incomplete~='true' and incomplete~='false') then os.exit(1) end
local c={rule=rule,provider=provider,revision=tonumber(revision),identity=identity,generation=generation,boot=boot,interval=interval,wan_sample=wan_sample}
if not now or now<0 or now>999999999 or now~=math.floor(now) or not state.valid(state.begin(c,nil,now)) then os.exit(1) end
local f=io.open('/proc/self/fd/8','rb');local raw=f and (f:read(4097) or '')
if not f or not f:close() or #raw>4096 then os.exit(1) end
local old
if raw~='' then old=shared.parse(raw);if not state.valid(old) or old.rule~=rule or backup.json(old)..'\n'~=raw then os.exit(1) end end
local decision=state.decision(old,c,now,blocked=='true',authorized=='true',incomplete=='true',network_check=='true')
if mode=='decision-manual' or mode=='begin-manual' then
    mode=mode:gsub('%-manual$','')
    -- Explicit sync may recheck a successful rule. Error backoff and unknown
    -- writes still use the normal decision.
    if decision=='waiting' then decision='ready' end
end
if mode=='status' then
    if result_arg then os.exit(1) end
    io.write(state.report(old,c,now,blocked=='true',authorized=='true',incomplete=='true'))
elseif mode=='decision' or mode=='begin' then
    if result_arg then os.exit(1) end
    if mode=='decision' then io.write(decision..'\n');return end
    if decision~='ready' and decision~='stale' then os.exit(1) end
    local started=state.begin(c,old,now);started.event_epoch=os.time();if not state.valid(started)then os.exit(1)end
    io.write(backup.json(started)..'\n')
elseif mode=='finish' then
    local rc=result_arg;if (rc~='0' and rc~='1') or not old or not state.same(old,c) or old.outcome~='inflight' then os.exit(1) end
    local result_raw=io.stdin:read(65537) or '';if #result_raw>65536 then os.exit(1) end
    local d=shared.parse(result_raw);if not d then os.exit(1) end
    local result,kind,effect,retryable,wan_unavailable
    if d.phase=='ddns-sync' then
        local canonical=string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"%s","account":"%s","configuration_revision":%s,"check_scope":"record-operation","error_kind":"%s","retryable":%s,"provider_code":"","result":"%s","effect":"%s","affected":%s,"reconciliation_required":%s}\n',tostring(d.ok),provider,account,revision,tostring(d.error_kind),tostring(d.retryable),tostring(d.result),tostring(d.effect),tostring(d.affected),tostring(d.reconciliation_required))
        local checked=assert(loadfile(dir..'/ddns-sync.lua'))().result(canonical,shared.parse(canonical),provider,account,revision,rule,rc)
        if checked~=result_raw then os.exit(1) end
        result,kind,effect,retryable=d.result,d.error_kind,d.effect,d.retryable
    elseif d.phase=='ddns-plan' then
        if not planner.validate(result_raw,d,revision,rule,rc) then os.exit(1) end
        local r=d.rules[1]
        if rc~='1' or #d.rules~=1 or not r or r.provider~=provider then os.exit(1) end
        result,kind,effect,retryable='failed',r.error_kind,'none',r.retryable
        wan_unavailable=r.status=='network_unavailable'
    else os.exit(1) end
    local out=state.finish(old,now,result,kind,effect,retryable,wan_unavailable);if not out then os.exit(1) end
    io.write(backup.json(out)..'\n')
else os.exit(1) end
