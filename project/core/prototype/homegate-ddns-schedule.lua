-- Fixed descriptors, canonical control records and existing state/result codecs.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local policy=assert(loadfile(dir..'/ddns-schedule.lua'))()
local function fail()os.exit(1)end
local function read(path,limit)local f=io.open(path,'rb');if not f then fail() end;local s=f:read(limit+1) or '';if not f:close() or #s>limit then fail() end;return s end
local function record(fd,kind)
    local raw=read('/proc/self/fd/'..fd,4096);local body,digest=raw:match('^([^\n]+)\n([0-9a-f]+)\n$');local d=body and shared.parse(body)
    if not digest or #digest~=64 or not policy[kind](d) or codec.json(d)~=body then fail() end;return d
end
local mode=arg[1]
if mode=='event' then
    if arg[5] then fail() end
    local iface,dev,selection=arg[2],arg[3],arg[4]
    if type(iface)~='string' or #iface>64 or iface:find('[^a-zA-Z0-9_.:%-]') or type(dev)~='string' or #dev>32 or dev:find('[^a-zA-Z0-9_.:%-]') then fail() end
    local names=selection=='*' and {} or assert(loadfile(dir..'/ddns-authority.lua'))().selection(selection,assert(loadfile(dir..'/ddns-plan.lua'))().id)
    local raw=io.stdin:read(262145);local doc=raw and #raw<=262144 and codec.parse(raw)
    if not names or not doc then fail() end
    local selected={};for _,n in ipairs(names)do selected[n]=true end
    for _,s in ipairs(doc)do if s.kind=='ddns_rule' and (selection=='*' or selected[s.name]) then
        local v=s.values
        if (v.source=='auto' and (iface=='wan' or iface=='wan6')) or
           (v.source=='interface' and v.interface~='' and (v.interface==dev or v.interface==iface)) then io.write('true\n');return end
    end end
    io.write('false\n');return
elseif mode=='lease' then
    if arg[12] or (arg[11] and arg[11]~='run' and arg[11]~='serve') then fail() end
    local d={schema='HGDDNSSCHEDULE1',identity=arg[2],generation=arg[3],grant=arg[4],revision=tonumber(arg[5]),boot=arg[6],pid=arg[7],birth=arg[8],token=arg[9],started=tonumber(arg[10])};d.deadline=(d.started or -1000)+policy.budget
    if arg[11]=='serve' then d.continuous=true;d.deadline=0 end
    if not policy.lease(d) then fail() end;io.write(codec.json(d)..'\n');return
elseif mode=='inspect' then
    if arg[2] then fail() end;local d=record(3,'lease');io.write(table.concat({d.pid,d.birth,d.boot,d.token,d.revision,d.deadline,d.identity,d.generation,d.grant,d.started,d.continuous and 'serve' or 'run'},':')..'\n');return
elseif mode=='owner' then
    local pid=arg[2];local mode=arg[3] or 'run';if arg[4] or (mode~='run' and mode~='serve') or not pid or #pid>9 or not pid:match('^[1-9]%d*$') then fail() end
    local a={};for v in read('/proc/'..pid..'/cmdline',8192):gmatch('([^%z]+)%z') do a[#a+1]=v end
    local prefix=#a-3;local exe=a[1] and a[1]:match('([^/]+)$')
    if (prefix~=1 and prefix~=2) or (prefix==1 and exe~='ash') or (prefix==2 and (exe~='busybox' or a[2]~='ash')) or
        a[prefix+1]~=dir..'/homegate-ddns-schedule.sh' or a[prefix+2]~=mode or a[prefix+3]~='--confirm' then fail() end;return
elseif mode=='state' then
    if arg[4] then fail() end
    local raw=io.stdin:read(65537) or '';local d=shared.parse(raw)
    if #raw>65536 or not d or d.phase~='ddns-state' or not assert(loadfile(dir..'/ddns-batch.lua'))().row(raw,d,arg[2],arg[3],'0',assert(loadfile(dir..'/ddns-plan.lua'))(),assert(loadfile(dir..'/ddns-sync.lua'))(),shared.parse) then fail() end
    io.write(d.status..':'..d.retry_in..'\n');return
elseif mode=='decision' then
    if #arg<2 or #arg>33 then fail() end
    local rows={};for i=2,#arg do local rule,status,wait=arg[i]:match('^([a-zA-Z0-9_-]+):([a-z_]+):(%d+)$');if not rule or #rule>64 then fail() end;rows[#rows+1]={rule=rule,status=status,retry_in=tonumber(wait)} end
    local decision,wait=policy.decision(rows);if not decision then fail() end;io.write(decision..':'..wait..'\n');return
elseif mode=='batch' then
    if arg[5] then fail() end;local names={};for n in (arg[4] or ''):gmatch('[^,]+') do names[#names+1]=n end
    local raw=io.stdin:read(65537) or '';if #raw>65536 then fail() end
    local d=shared.parse(raw)
    -- Failure reports intentionally have no configuration_revision field.
    if d and d.error then d.configuration_revision=tonumber(arg[2]) end
    local effect=policy.batch(raw,d,arg[2],arg[3],names,codec.json);if not effect then fail() end;io.write(effect..'\n');return
elseif mode=='report' then
    if arg[8] or (arg[7] and arg[7]~='run' and arg[7]~='serve') then fail() end
    local d={api_version=1,prototype=true,ok=arg[2]=='true',phase='ddns-schedule',running=arg[3]=='running' or arg[3]=='waiting',status=arg[3],reason=arg[4],ticks=tonumber(arg[5]),last_effect=arg[6],effect='none',write_ready=false,admission_limit=policy.limit}
    if arg[7]=='serve' then d.continuous=true;d.admission_limit=0 end
    if not policy.report(d) then fail() end;io.write(codec.json(d)..'\n');return
elseif mode=='status' or mode=='check-report' then
    local d=record(3,'report');if mode=='check-report' then if arg[2] then fail() end;return end
    if arg[4] or (arg[2]~='true' and arg[2]~='false') or (arg[3]~='true' and arg[3]~='false') then fail() end
    local was_running=d.status=='running'
    d.running=arg[2]=='true' and (d.status=='running' or d.status=='waiting')
    if d.running and arg[3]=='true' then d.status='stopping'
    elseif not d.running and (d.status=='running' or d.status=='waiting') then d.status='interrupted';d.reason='interrupted';d.ok=false;if was_running then d.last_effect='unknown' end end
    io.write(codec.json(d)..'\n');return
end
fail()
