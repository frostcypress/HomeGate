-- Startup configuration preflight; never process/service/DNS actions.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(7) end
local mode,revision=arg[1],arg[2]
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local validator=assert(loadfile(dir..'/configuration-validation.lua'))()
local ip=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local intent=assert(loadfile(dir..'/startup-intent.lua'))()
local function read(path,limit)
    local f=io.open(path,'rb');if not f then return nil end
    local raw=f:read(limit+1);if not f:close() or not raw or #raw>limit then return nil end;return raw
end
local function flag(candidate)
    return assert(intent.marker(candidate))
end
local function version()
    local v,r=read(dir..'/../../../VERSION',64),read(dir..'/../../../RELEASE',64)
    if not v or not v:match('^%d+%.%d+%.%d+\n$') or not r or not r:match('^[1-9]%d*\n$') then os.exit(7) end
    return v:sub(1,-2)..'-r'..r:sub(1,-2)
end
if mode=='intent-report' then
    local d=intent.describe(arg[2]);if not d or arg[3] then os.exit(7) end
    io.write(codec.json({api_version=1,prototype=true,ok=true,version=version(),phase='lifecycle-source-intent',
        scope='current-source-enable-intent-only',source_valid=true,observed_enabled=d.observed_enabled,
        enable_intent=intent.public(arg[2]),enable_intent_confirmation_required=not d.known,
        adoption_checked=false,source_bound=false,start_authorized=false,daemon_started=false,
        metadata_changed=false,point_in_time=true,production_ready=false,effect='none',write_ready=false})..'\n');return
end
if mode=='source' then
    if arg[2] then os.exit(7) end
    local raw=io.stdin:read(262145) or ''
    local candidate=#raw<=262144 and codec.private_configuration(raw)
    if not candidate or not validator.validate(candidate,candidate,codec.json,ip) then os.exit(1) end
    io.write(flag(candidate)..'\n');return
end
if type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 then os.exit(7) end
if mode=='bound' then
    if arg[3] then os.exit(7) end
    local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
    local raw=read('/etc/config/homegate',262144)
    local config=assert(loadfile(dir..'/runtime-health.lua'))().configuration(snapshot,raw,codec,validator,ip,revision)
    if not config.configured then os.exit(7) end
    local candidate=codec.private_configuration(raw)
    if not candidate then os.exit(7) end
    io.write(flag(candidate)..'\n');return
end
local d=intent.describe(arg[3])
if mode=='request-report' or mode=='candidate-body' then
    local request=intent.request(arg[3],arg[4]);if not request or arg[5] then os.exit(7) end
    local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
    local raw=read('/etc/config/homegate',262144)
    local source=raw and codec.private_configuration(raw)
    if not snapshot or snapshot.revision~=tonumber(revision) or intent.marker(source)~=arg[3] then os.exit(7) end
    local model=assert(loadfile(dir..'/startup-candidate.lua'))()
    local candidate=model.build(snapshot,source,arg[4],codec,validator,ip,intent)
    if not candidate then os.exit(7) end
    if mode=='candidate-body' then io.write(codec.json(candidate)..'\n');return end
    io.write(codec.json({api_version=1,prototype=true,ok=true,version=version(),phase='lifecycle-intent-check',
        scope='enable-intent-application-preflight',configuration_revision=tonumber(revision),
        configuration_ready=true,source_bound=true,point_in_time=true,request=request,candidate=model.summary(candidate),
        apply_authorized=false,start_authorized=false,requires_apply_revalidation=true,intent_persisted=false,
        configuration_changed=false,daemon_started=false,readers_switched=false,production_ready=false,
        effect='runtime-metadata-preparation',write_ready=false})..'\n');return
end
if mode=='record-report' then
    if (arg[3]~='enabled' and arg[3]~='disabled') or (arg[4]~='staged' and arg[4]~='prepared') or
       (arg[5]~='save' and arg[5]~='resume' and arg[5]~='check') or arg[6] then os.exit(7) end
    io.write(codec.json({api_version=1,prototype=true,ok=true,version=version(),phase='lifecycle-intent-record',
        scope='private-main-switch-preparation-record',configuration_revision=tonumber(revision),requested_state=arg[3],
        record_state=arg[4],durability_reconfirmed=arg[5]~='check',intent_persisted=true,candidate_persisted=false,
        source_bound=true,point_in_time=true,requires_apply_revalidation=true,apply_authorized=false,start_authorized=false,
        configuration_changed=false,daemon_started=false,readers_switched=false,production_ready=false,write_ready=false,
        effect=arg[5]=='check' and 'runtime-metadata-preparation' or 'private-intent-record'})..'\n');return
end
if mode~='report' or not d or arg[4] then os.exit(7) end
io.write(codec.json({api_version=1,prototype=true,ok=true,version=version(),
    phase='lifecycle-startup',configuration_revision=tonumber(revision),scope='startup-configuration-and-existing-fences',
    configuration_ready=true,enabled=d.observed_enabled,runtime_ready=true,baseline_ready=true,
    enable_intent=intent.public(arg[3]),enable_intent_confirmation_required=not d.known,start_authorized=false,
    point_in_time=true,daemon_started=false,readers_switched=false,production_ready=false,
    effect='runtime-metadata-preparation',write_ready=false})..'\n')
