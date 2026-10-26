-- Fixed configuration/runtime reads inside the independently supervised family.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(7) end
local mode,revision=arg[1],arg[2]
if type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 then os.exit(7) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local model=assert(loadfile(dir..'/runtime-health.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local function read(path,limit)
    local f,msg,code=io.open(path,'rb');if not f then return nil,code==2 and 'absent' or 'error' end
    local raw=f:read(limit+1);if not f:close() or not raw or #raw>limit then return nil,'error' end;return raw,'ok'
end
local function version()
    local v=read(dir..'/../../../VERSION',64);local r=read(dir..'/../../../RELEASE',64)
    if not v or not v:match('^%d+%.%d+%.%d+\n$') or not r or not r:match('^[1-9]%d*\n$') then os.exit(7) end
    return v:sub(1,-2)..'-r'..r:sub(1,-2)
end
local source_version=version()
if mode=='result' then
    local action,context_raw=arg[3],arg[4]
    if (action~='status' and action~='check') or type(context_raw)~='string' or #context_raw>256 or arg[5] then os.exit(7) end
    local context=shared.parse(context_raw)
    if model.context(context,codec.json)~=context_raw then os.exit(7) end
    local raw=io.stdin:read(8193) or ''
    local checked,ok
    if #raw<=8192 then checked,ok=model.validate(raw,shared.parse(raw),source_version,revision,context,codec.json) end
    if not checked then os.exit(7) end;io.write(checked);os.exit(action=='check' and not ok and 1 or 0)
end
if mode~='configuration' and mode~='run' then os.exit(7) end
if (mode=='configuration' and arg[3]) or (mode=='run' and arg[4]) then os.exit(7) end
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
local raw=read('/etc/config/homegate',262144)
local config=model.configuration(snapshot,raw,codec,assert(loadfile(dir..'/configuration-validation.lua'))(),
    assert(loadfile(dir..'/cloudflare-record-plan.lua'))(),revision)
if mode=='configuration' then io.write(assert(model.context(config,codec.json))..'\n');return end
local runtime_mode=arg[3];local probe
if runtime_mode=='absent' then probe={running=false}
elseif runtime_mode=='invalid' then probe={running=false,error_kind='runtime_state_unavailable'}
elseif runtime_mode=='present' then
    local body=read('/proc/self/fd/4',4096)
    local state=body and model.state(shared.parse(body),body)
    probe=model.probe(state,function(kind,pid,limit)return read('/proc/'..pid..'/'..kind,limit) end)
    if read('/proc/self/fd/4',4096)~=body then probe={running=false,error_kind='runtime_unstable'} end
else os.exit(7) end
local output=model.report(source_version,revision,config,probe,codec.json)
if #output>8192 then os.exit(7) end
local f=io.open('/proc/self/fd/3','wb');if not f or not f:write(output) or not f:close() then os.exit(7) end
os.exit(0)
