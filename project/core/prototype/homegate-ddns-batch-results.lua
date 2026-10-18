-- Fixed private descriptors; original source/context and receipt validation reused.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local backup=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local results=assert(loadfile(dir..'/ddns-batch-results.lua'))()
local sync=assert(loadfile(dir..'/ddns-sync.lua'))()
local store='/etc/homegate/transactions'
local function fail()os.exit(1)end
local function read(fd,limit)local f=io.open('/proc/self/fd/'..fd,'rb');if not f then fail() end;local raw=f:read(limit+1) or '';if not f:close() or #raw>limit then fail() end;return raw end
local function valid(d)return results.valid(d,backup.json,shared.parse,sync)end
local function record(fd)
    local raw=read(fd,524288);if raw=='' then return nil end
    local body,digest=raw:match('^([^\n]+)\n([0-9a-f]+)\n$');local d=body and shared.parse(body)
    if not digest or #digest~=64 or not valid(d) or backup.json(d)~=body then fail() end;return d
end
local mode=arg[1]
if mode=='candidate-info' then
    if arg[2] then fail() end
    local raw=io.stdin:read(524289) or '';local d=#raw<=524288 and shared.parse(raw)
    if not valid(d) or backup.json(d)..'\n'~=raw then fail() end
    local row=d.rows[#d.rows];io.write(row.provider..':'..row.account..':'..row.job..':'..d.revision..':'..row.state..'\n');return
elseif mode=='guard' or mode=='stage' then
    local previous,identity=arg[2],arg[3];if arg[5] then fail() end
    local old,next=record(3),record(4)
    if (old and old.identity~=identity) or (next and next.identity~=identity) then fail() end
    if next and not results.transition(old,next,previous,backup.json) then fail() end
    if mode=='stage' then if not next then fail() end;io.write(backup.json(next)..'\n');return end
    if arg[4]=='writer' then if next or not old or old.rows[#old.rows].state~='closed' then fail() end
    elseif arg[4]~='recovery' or (not old and not next) then fail() end
    return
elseif mode=='info' or mode=='status' or mode=='hashes' then
    if arg[2] then fail() end
    local d=record(3);if not d then fail() end;local row=d.rows[#d.rows]
    if mode=='info' then io.write(row.provider..':'..row.account..':'..row.job..':'..d.revision..':'..row.state..'\n')
    elseif mode=='hashes' then io.write(table.concat(row.hashes,':')..'\n')
    else
        local rows={};for _,r in ipairs(d.rows) do rows[#rows+1]=string.format('{"rule":"%s","provider":"%s","state":"%s"}',r.rule,r.provider,r.state) end
        io.write('{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-batch-results","effect":"none","write_ready":false,"historical":true,"rules":['..table.concat(rows,',')..']}\n')
    end;return
elseif mode=='closed' or mode=='retired' then
    local previous=arg[2];if arg[3] then fail() end
    local d=record(3);if not d then fail() end;local row=d.rows[#d.rows];local proof=read(4,2048)
    if not results.proof(row,d.identity,proof) then fail() end
    if mode=='retired' then return end
    if row.state~='recorded' then fail() end;row.state='closed';row.retired=proof;d.previous=previous
    if not valid(d) then fail() end;io.write(backup.json(d)..'\n');return
elseif mode~='capture' then fail() end
local rule,identity,generation,grant,boot,parent,previous,hashes=arg[2],arg[3],arg[4],arg[5],arg[6],arg[7],arg[8],arg[9]
if arg[10] then fail() end
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,backup)
local envelope_raw=read(5,524288);local envelope=shared.parse(envelope_raw)
if not snapshot or type(envelope)~='table' or backup.json(envelope)..'\n'~=envelope_raw or envelope.schema~='HGDDNSBATCH1' or envelope.identity~=identity or envelope.generation~=generation or envelope.grant~=grant or envelope.boot~=boot or envelope.parent~=parent or envelope.revision~=snapshot.revision then fail() end
local planner=assert(loadfile(dir..'/ddns-plan.lua'))();local authority=assert(loadfile(dir..'/ddns-authority.lua'))()
local plan=assert(loadfile(dir..'/ddns-batch.lua'))().slice(snapshot,envelope.intent,envelope.plan,rule,planner,authority,assert(loadfile(dir..'/wan6-plan.lua'))(),assert(loadfile(dir..'/cloudflare-record-plan.lua'))(),backup.json)
if not plan or not plan.entries[1] or plan.entries[1].status~='ready' then fail() end
local entry=plan.entries[1];local context_raw=read(3,8388608);local context=shared.parse(context_raw)
if not context or backup.json(context)..'\n'~=context_raw or backup.json(context.request)~=backup.json(entry.request) then fail() end
local records=entry.provider~='cloudflare' and assert(loadfile(dir..'/'..entry.provider..'-records.lua'))() or nil
if not assert(loadfile(dir..'/'..entry.provider..'-reconcile-plan.lua'))().restore(snapshot,entry.account,tostring(snapshot.revision),context,assert(loadfile(dir..'/cloudflare-record-plan.lua'))(),records,backup.json) then fail() end
-- The shell has checked these fixed members and retains both common locks.
local function fixed(path,limit)local f=io.open(path,'rb');if not f then fail() end;local raw=f:read(limit+1) or '';if not f:close() or #raw>limit then fail() end;return raw end
local active=fixed(store..'/dns-operation/current',2);if active~='1\n' and active~='2\n' then fail() end
local manifest={};for v in fixed(store..'/dns-operation/slot-'..active:sub(1,1)..'/manifest',512):gmatch('([^\n]*)\n') do manifest[#manifest+1]=v end
local formats={cloudflare='HGCFJOURNAL1',aliyun='HGALIJOURNAL1',dnspod='HGDNPJOURNAL1',huaweicloud='HGHWJOURNAL1'}
if #manifest~=10 or manifest[1]~=formats[entry.provider] or manifest[2]~='homegate' or manifest[3]~=identity or manifest[4]~=boot or manifest[5]~=tostring(snapshot.revision) or manifest[6]~=entry.account or manifest[8]~=generation then fail() end
local receipt=read(4,4096);local public=read(8,4096)
local original,effect=sync.result(receipt,shared.parse(receipt),entry.provider,entry.account,tostring(snapshot.revision),rule,'0')
if not original or original~=public or effect~='confirmed' then fail() end
local fingerprint={};for v in (hashes..':'):gmatch('(.-):') do fingerprint[#fingerprint+1]=v end
local row={rule=rule,provider=entry.provider,account=entry.account,job=manifest[7],receipt=receipt,result=public,hashes=fingerprint,state='recorded',retired=''}
local old=record(9)
local d=old and shared.parse(backup.json(old)) or {schema='HGDDNSBATCHRESULT1',identity=identity,generation=generation,grant=grant,revision=snapshot.revision,boot=boot,batch=parent,rows={}}
if #d.rows>=32 then fail() end
d.previous=previous;d.rows[#d.rows+1]=row
if not valid(d) or not results.transition(old,d,previous,backup.json) then fail() end
io.write(backup.json(d)..'\n')
