-- Internal producer codec. Private snapshots/inputs never enter public responses.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(7) end
local mode=arg[1]
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local model=assert(loadfile(dir..'/ddns-recovery.lua'))()
local health=assert(loadfile(dir..'/runtime-health.lua'))()
local function read(path,limit)
    local f=io.open(path,'rb');if not f then return nil end
    local raw=f:read(limit+1);if not f:close() or not raw or #raw>limit then return nil end;return raw
end
local v,r=read(dir..'/../../../VERSION',64),read(dir..'/../../../RELEASE',64)
if not v or not v:match('^%d+%.%d+%.%d+\n$') or not r or not r:match('^[1-9]%d*\n$') then os.exit(7) end
local version=v:sub(1,-2)..'-r'..r:sub(1,-2)
if mode=='pending' then
    if arg[9] then os.exit(7) end
    local out=model.pending(version,arg[2],arg[3],arg[4],arg[5],arg[6],arg[7],arg[8],codec.json)
    if not out then os.exit(7) end;io.write(out);return
elseif mode=='marker-current' then
    if arg[7] then os.exit(7) end
    local raw=io.stdin:read(2049) or ''
    local marker=model.pending_decode(raw,shared.parse(raw),codec.json)
    if not marker or not model.fresh(marker,version,arg[2],{identity=arg[3],generation=arg[4]},model.proof(arg[6]..':'..arg[5])) then os.exit(7) end
    io.write(marker.candidate_sha256..'\n');return
end
if mode=='inputs' then
    local revision,identity,generation,boot,cache=arg[2],arg[3],arg[4],arg[5],arg[6]
    if arg[8] then os.exit(7) end
    local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
    local out=model.inputs(snapshot,version,revision,identity,generation,boot,cache,function(rule)
        return read('/var/run/homegate/ddns-state/'..rule,4096)
    end,codec.json,tonumber(arg[7]),assert(loadfile(dir..'/ddns-state.lua'))(),shared.parse)
    if not out then os.exit(7) end;io.write(out);return
end
if mode=='build' then
    if arg[4] then os.exit(7) end
    local raw=io.stdin:read(262145) or '';if #raw>262144 then os.exit(7) end
    local observed=os.date('!%Y-%m-%dT%H:%M:%SZ');if not health.timestamp(observed) then os.exit(7) end
    local out=model.build(raw,shared.parse(raw),arg[2],tonumber(arg[3]),observed,assert(loadfile(dir..'/ddns-state.lua'))(),shared.parse,codec.json)
    if not out then os.exit(7) end;io.write(out);return
end
local raw=io.stdin:read(8193) or '';local doc=model.decode(raw,shared.parse(raw),codec.json,health.timestamp)
if not doc then os.exit(7) end
if mode=='owned' then
    if arg[3] or doc.source.identity~=arg[2] then os.exit(7) end;return
elseif mode=='validate' then
    if arg[7] or not model.fresh(doc,version,arg[2],{identity=arg[3],generation=arg[4]},model.proof(arg[6]..':'..arg[5])) then os.exit(7) end;return
end
os.exit(7)
