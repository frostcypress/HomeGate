-- Data-only private snapshot/curl configuration/JSON adapter; no HTTP actions.
local json=require('luci.jsonc')
local dir=arg[0]:match('^(.*)/[^/]+$'); if not dir then os.exit(1) end
local function account_valid(s) return type(s)=='string' and #s>=1 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$') end
local function revision_valid(s) return type(s)=='string' and s:match('^[1-9]%d*$') and tonumber(s)<=32 end
local account,revision=arg[2],arg[3]
local function report(kind,retry,code)
    local ok=kind==''
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"cloudflare","account":"%s","configuration_revision":%s,"credentials_valid":%s,"check_scope":"zone-read","error_kind":"%s","retryable":%s,"provider_code":"%s"}',tostring(ok),account,revision,tostring(ok),kind,tostring(retry),code or '')
end
local function reject(kind,retry,code,fd)
    local f=fd and io.open('/proc/self/fd/3','wb') or io.stdout
    if not f or not f:write(report(kind,retry,code),'\n') then os.exit(1) end
    if fd and not f:close() then os.exit(1) end
    os.exit(1)
end
-- Native incremental jsonc ensures a single full document. The lexical walk
-- rejects duplicate decoded object keys at every depth, including escaped keys.
-- JSON grammar remains the official parser's responsibility.
local function parse(body)
    if type(body)~='string' or #body>65536 or body:find('%z') or body:lower():find('\\u0000',1,true) then return nil end
    local parser=json.new(); local complete=false
    for i=1,#body do
        local c=body:sub(i,i)
        if complete then if not c:match('%s') then return nil end
        else local result=parser:parse(c); if result==nil then return nil end;complete=result end
    end
    if not complete then return nil end
    local value=parser:get(); if type(value)~='table' or not body:match('^%s*{') then return nil end
    local stack={}; local root_types={}; local i=1
    while i<=#body do
        local c=body:sub(i,i);local top=stack[#stack]
        if c=='"' then
            local first=i;i=i+1
            while i<=#body do
                local ch=body:sub(i,i)
                if ch=='\\' then i=i+2 elseif ch=='"' then break else i=i+1 end
            end
            if i>#body then return nil end
            if top and top.kind=='object' and top.key_expected then
                local key=json.parse(body:sub(first,i))
                if type(key)~='string' or key:find('%z') or top.keys[key] then return nil end
                top.keys[key]=true;top.key=key;top.key_expected=false
            end
        elseif c=='{' or c=='[' then
            local kind=c=='{' and 'object' or 'array'
            if #stack==1 and top.key then root_types[top.key]=kind end
            stack[#stack+1]={kind=kind,keys={},key_expected=kind=='object'}
        elseif c=='}' or c==']' then stack[#stack]=nil
        elseif c==',' and top and top.kind=='object' then top.key_expected=true;top.key=nil end
        i=i+1
    end
    return value,root_types
end
if arg[1]=='nonce' and not arg[2] then
    local body=io.stdin:read(38)
    if not body or #body~=37 or body:sub(9,9)~='-' or body:sub(14,14)~='-' or body:sub(19,19)~='-' or body:sub(24,24)~='-' then os.exit(1) end
    local n=body:gsub('-',''):match('^([0-9a-f]+)\n$')
    if not n or #n~=32 then os.exit(1) end;io.write(n,'\n');return
end
if arg[1]=='context' and not arg[2] then
    local body=io.stdin:read(5);local n=body and body:match('^([1-9]%d*)\n$')
    if not n or not revision_valid(n) then os.exit(1) end;io.write(n,'\n');return
end
if not account_valid(account) or not revision_valid(revision) or (arg[4] and arg[1]~='result') or arg[5] then os.exit(1) end
if arg[1]=='request' then
    local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
    local reader=assert(loadfile(dir..'/private-snapshot.lua'))()
    local snapshot=reader.read(io.stdin,codec)
    if not snapshot or snapshot.revision~=tonumber(revision) then reject('invalid_request',false) end
    local found
    for _,s in ipairs(snapshot.configuration) do if s.kind=='dns_account' and s.name==account then found=s end end
    if not found then reject('not_found',false) end
    if found.values.provider~='cloudflare' then reject('unsupported',false) end
    local token=snapshot.credentials['cloudflare.'..account..'.secret']
    if type(token)~='string' or #token==0 then reject('authentication',false,'credentials_missing') end
    if #token>4096 or token:find('[^ -~]') then reject('authentication',false,'invalid_credentials') end
    if token:match('^ *$') then reject('authentication',false,'credentials_missing') end
    token=token:gsub('\\','\\\\'):gsub('"','\\"')
    local body='url = "https://api.cloudflare.com/client/v4/zones?page=1&per_page=1"\nrequest = "GET"\nheader = "Authorization: Bearer '..token..'"\n'
    local f=io.open('/proc/self/fd/4','wb')
    if not f or not f:write(body) or not f:close() then os.exit(1) end
    io.write('HGDNSREADY1\n')
elseif arg[1]=='response' then
    local raw=io.stdin:read(65537)
    if not raw or #raw>65536 then reject('temporary',true,'response_limit',true) end
    local body,http,transport=raw:match('^(.*)\nHGHTTP:(%d%d%d)\n\nHGTRANSPORT:(%d+)\n$')
    if not body or #transport>3 then reject('temporary',true,'invalid_response',true) end
    local rc=tonumber(transport);local status=tonumber(http)
    if rc~=0 then reject(rc==28 and 'timeout' or 'network_unavailable',true,nil,true) end
    local doc,types=parse(body)
    local code=''
    if doc and type(doc.errors)=='table' and type(doc.errors[1])=='table' then
        local n=doc.errors[1].code
        if type(n)=='number' and n==math.floor(n) and n>=1 and n<=99999999 then code=string.format('%.0f',n) end
    end
    if status==401 or status==403 then reject('authentication',false,code,true) end
    if status==429 then reject('rate_limit',true,code,true) end
    if status>=500 then reject('temporary',true,code,true) end
    if status==404 then reject('not_found',false,code,true) end
    if status<200 or status>=300 then reject('invalid_request',false,code,true) end
    if not doc or type(doc.success)~='boolean' then reject('temporary',true,'invalid_response',true) end
    if not doc.success then reject((code=='10000' or code=='9109') and 'authentication' or 'invalid_request',false,code,true) end
    if type(doc.result)~='table' or types.result~='array' or #doc.result>1 then reject('temporary',true,'invalid_response',true) end
    for k,v in pairs(doc.result) do
        if k~=1 or type(v)~='table' or type(v.id)~='string' or #v.id~=32 or v.id:find('[^0-9a-f]') or type(v.name)~='string' or #v.name<1 or #v.name>253 then reject('temporary',true,'invalid_response',true) end
    end
    local f=io.open('/proc/self/fd/3','wb');if not f or not f:write(report('',false),'\n') or not f:close() then os.exit(1) end
elseif arg[1]=='result' then
    if arg[4]~='0' and arg[4]~='1' then os.exit(1) end
    local raw=io.stdin:read(4097);local doc=raw and parse(raw)
    if not doc or #raw>4096 or type(doc.ok)~='boolean' or doc.ok~=(arg[4]=='0') then os.exit(1) end
    local kinds={['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true}
    local kind=doc.error_kind;local code=doc.provider_code
    if not kinds[kind] or type(doc.retryable)~='boolean' or type(code)~='string' or #code>32 or not code:match('^[a-zA-Z0-9_-]*$') then os.exit(1) end
    local expected=report(kind,doc.retryable,code)..'\n'
    if raw~=expected then os.exit(1) end
    io.write(expected)
else os.exit(1) end
