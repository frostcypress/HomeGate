-- Fixed recovery record and source observation; no recovery action or transport.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(7) end
local mode,revision=arg[1],arg[2]
if type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 then os.exit(7) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local health=assert(loadfile(dir..'/runtime-health.lua'))()
local model=assert(loadfile(dir..'/recovery-report.lua'))()
local ddns=assert(loadfile(dir..'/ddns-recovery.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local function read(path,limit)
    local f=io.open(path,'rb');if not f then return nil end
    local raw=f:read(limit+1);if not f:close() or not raw or #raw>limit then return nil end;return raw
end
local v,r=read(dir..'/../../../VERSION',64),read(dir..'/../../../RELEASE',64)
if not v or not v:match('^%d+%.%d+%.%d+\n$') or not r or not r:match('^[1-9]%d*\n$') then os.exit(7) end
local version=v:sub(1,-2)..'-r'..r:sub(1,-2)
if mode=='result' then
    local context_raw=arg[3]
    if type(context_raw)~='string' or #context_raw>512 or arg[4] then os.exit(7) end
    local context=shared.parse(context_raw)
    if not context or (context.ddns_proof~=nil and not ddns.proof(context.ddns_proof)) or
       model.context(context.config,context.binding,codec.json,context.ddns_proof)~=context_raw then os.exit(7) end
    local raw=io.stdin:read(8193) or '';local doc,types=shared.parse(raw)
    local checked=#raw<=8192 and types and types.modules=='array' and model.validate(raw,doc,version,revision,context,codec.json,health.timestamp,ddns.project)
    if not checked then os.exit(7) end;io.write(checked);return
end
if mode~='context' and mode~='run' then os.exit(7) end
local token=mode=='context' and arg[3] or arg[4]
if (mode=='context' and arg[5]) or (mode=='run' and arg[7]) then os.exit(7) end
local proof_raw=mode=='context' and arg[4] or arg[5]
local proof=proof_raw and ddns.proof(proof_raw)
if proof_raw and not proof then os.exit(7) end
local binding=model.binding(token);if not binding then os.exit(7) end
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
local config=health.configuration(snapshot,read('/etc/config/homegate',262144),codec,
    assert(loadfile(dir..'/configuration-validation.lua'))(),assert(loadfile(dir..'/cloudflare-record-plan.lua'))(),revision)
local context={config=config,binding=binding,ddns_proof=proof_raw}
if mode=='context' then io.write(assert(model.context(config,binding,codec.json,proof_raw))..'\n');return end
local record
if arg[3]=='present' then
    local raw=read('/proc/self/fd/4',65536)
    local doc,types=shared.parse(raw or '')
    if raw then record=model.record(raw,doc,types,version,revision,binding,health.timestamp) end
    if read('/proc/self/fd/4',65536)~=raw then record=nil end
elseif arg[3]~='absent' and arg[3]~='invalid' then os.exit(7) end
local observed=os.date('!%Y-%m-%dT%H:%M:%SZ')
if not health.timestamp(observed) then os.exit(7) end
local contribution
if proof then
    local d,reason=nil,'state_unavailable'
    if arg[6]=='pending' then reason='publication_pending'
    elseif arg[6]=='present' and not proof.unavailable then
        local raw=read('/proc/self/fd/5',8192)
        d=raw and ddns.decode(raw,shared.parse(raw),codec.json,health.timestamp)
        if d and not ddns.fresh(d,version,revision,binding,proof) then d=nil;reason='source_mismatch' end
        if read('/proc/self/fd/5',8192)~=raw then d=nil;reason='state_unavailable' end
    elseif arg[6]~='absent' and arg[6]~='invalid' and arg[6]~='present' then os.exit(7) end
    contribution=ddns.project(ddns.public(d,reason),observed,health.timestamp)
    if not contribution then os.exit(7) end
end
local output=model.report(version,revision,context,record,observed,codec.json,contribution)
if #output>8192 then os.exit(7) end
local f=io.open('/proc/self/fd/3','wb');if not f or not f:write(output) or not f:close() then os.exit(7) end
