-- Fixed descriptors and current-source proof only; no caller paths or network.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local backup=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local planner=assert(loadfile(dir..'/ddns-plan.lua'))()
local authority=assert(loadfile(dir..'/ddns-authority.lua'))()
local batch=assert(loadfile(dir..'/ddns-batch.lua'))()
local function fail()os.exit(1)end
local function read(path,limit)local f=io.open(path,'rb');if not f then fail() end;local b=f:read(limit+1) or '';if not f:close() or #b>limit then fail() end;return b end
local function write(fd,body)local f=io.open('/proc/self/fd/'..fd,'wb');if not f or not f:write(body) or not f:close() then fail() end end
local function number(s,max)return type(s)=='string' and s:match('^[1-9]%d*$') and #s<=20 and tonumber(s)<=max end
if arg[1]=='parent' then
    local role,self,rule,parent=arg[2],arg[3],arg[4],arg[5]
    if arg[6] or not number(self,999999999) or not number(parent,999999999) or not planner.id(rule) then fail() end
    local function process(pid)
        local raw=read('/proc/'..pid..'/stat',8192);local tail=raw:match('^%d+ %(.+%) (.+)$');if not tail then fail() end
        local fields={};for v in tail:gmatch('%S+') do fields[#fields+1]=v end
        if #fields<20 or fields[1]=='Z' or fields[1]=='X' or not number(fields[2],999999999) or not number(fields[20],99999999999999999999) then fail() end
        return fields[2],fields[20]
    end
    local function command(pid,expected)
        local args={};for v in read('/proc/'..pid..'/cmdline',8192):gmatch('([^%z]+)%z') do args[#args+1]=v end
        local prefix=#args-#expected
        if prefix~=1 and prefix~=2 then fail() end
        local exe=args[1]:match('([^/]+)$')
        if (prefix==1 and exe~='ash') or (prefix==2 and (exe~='busybox' or args[2]~='ash')) then fail() end
        for i,v in ipairs(expected) do if args[prefix+i]~=v then fail() end end
    end
    if process(self)~=parent then fail() end
    local root,birth
    if role=='state' or role=='closeout' then root=parent
    elseif role=='read' then
        root=process(parent)
        command(parent,{dir..'/homegate-ddns-state.sh','batch-sync-internal',rule,root,'--confirm'})
    else fail() end
    local raw=read('/proc/'..root..'/cmdline',8192)
    local confirmation=raw:match('%z(%-%-confirm%-closeouts)%z$') and '--confirm-closeouts' or '--confirm'
    if role=='closeout' and confirmation~='--confirm-closeouts' then fail() end
    command(root,{dir..'/homegate-ddns-batch.sh','sync',confirmation});_,birth=process(root)
    io.write(root..':'..birth..'\n');return
end
local revision=arg[2]
if not number(revision,32) then fail() end
if arg[1]=='names' then
    if arg[3] then fail() end
    local raw=io.stdin:read(65537) or '';local d=shared.parse(raw)
    if #raw>65536 or type(d)~='table' or d.phase~='ddns-authority' or d.ok~=true or d.authorized~=true or d.configuration_revision~=tonumber(revision) then fail() end
    local names=d.rules or {d.rule};if #names<1 or #names>32 then fail() end
    local joined=table.concat(names,',');local checked=authority.selection(joined,planner.id)
    if not checked or backup.json(checked)~=backup.json(names) then fail() end
    io.write(table.concat(names,'\n')..'\n');return
elseif arg[1]=='row' or arg[1]=='row-closed' then
    if arg[5] then fail() end
    local raw=io.stdin:read(65537) or '';if #raw>65536 then fail() end
    local row=batch.row(raw,shared.parse(raw),revision,arg[3],arg[4],planner,assert(loadfile(dir..'/ddns-sync.lua'))(),shared.parse)
    if not row then fail() end
    if arg[1]=='row-closed' then local d=shared.parse(raw);if d.effect~='confirmed' then fail() end;row=row:sub(1,-2)..',"closeout":"retired"}' end
    io.write(row..'\n');return
end
local rule=arg[3];local first=arg[1]=='seal' and 3 or 4
local identity,generation,grant,boot,parent=arg[first],arg[first+1],arg[first+2],arg[first+3],arg[first+4]
if arg[first+5] then fail() end
for _,v in ipairs({identity,generation,grant}) do if type(v)~='string' or #v~=64 or not v:match('^[0-9a-f]+$') then fail() end end
if type(boot)~='string' or #boot~=36 or not boot:match('^[0-9a-f-]+$') or type(parent)~='string' or not parent:match('^[1-9]%d*:[1-9]%d*$') or #parent>30 then fail() end
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,backup)
if not snapshot or snapshot.revision~=tonumber(revision) then fail() end
local envelope,raw
if arg[1]=='seal' then
    local intent_raw=read('/proc/self/fd/4',65536);local plan_raw=read('/proc/self/fd/8',262144)
    local intent,plan=shared.parse(intent_raw),shared.parse(plan_raw)
    if not intent or not plan or backup.json(intent)..'\n'~=intent_raw or backup.json(plan)..'\n'~=plan_raw then fail() end
    local selected;for name,value in pairs(intent.switches or {}) do if value=='1' then selected=name;break end end
    if not selected then fail() end;rule=selected
    envelope={schema='HGDDNSBATCH1',revision=tonumber(revision),identity=identity,generation=generation,grant=grant,boot=boot,parent=parent,intent=intent,plan=plan}
elseif arg[1]=='slice' then
    raw=read('/proc/self/fd/5',524288);envelope=shared.parse(raw)
    if type(envelope)~='table' or backup.json(envelope)..'\n'~=raw then fail() end
else fail() end
local count=0;for k in pairs(envelope) do if k~='schema' and k~='revision' and k~='identity' and k~='generation' and k~='grant' and k~='boot' and k~='parent' and k~='intent' and k~='plan' then fail() end;count=count+1 end
if count~=9 or envelope.schema~='HGDDNSBATCH1' or envelope.revision~=tonumber(revision) or envelope.identity~=identity or envelope.generation~=generation or envelope.grant~=grant or envelope.boot~=boot or envelope.parent~=parent then fail() end
local plan,intent=batch.slice(snapshot,envelope.intent,envelope.plan,rule,planner,authority,assert(loadfile(dir..'/wan6-plan.lua'))(),assert(loadfile(dir..'/cloudflare-record-plan.lua'))(),backup.json)
if not plan then fail() end
if arg[1]=='seal' then local body=backup.json(envelope)..'\n';if #body>524288 then fail() end;io.write(body);return end
local narrow=read('/proc/self/fd/8',65536);if backup.json(intent)..'\n'~=narrow then fail() end
write(4,backup.json(plan)..'\n');local public,ok=planner.report(revision,rule,plan.entries);write(3,public);os.exit(ok and 0 or 1)
