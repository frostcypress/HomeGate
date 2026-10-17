-- AliDNS RPC-v1 read-only adapter. SHA-1 is supplied by fixed OpenSSL, not Lua.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local function escape(s)
    return (s:gsub('[^A-Za-z0-9%-%._~]',function(c)return string.format('%%%02X',c:byte()) end))
end
local function canonical(params)
    local keys,parts={},{};for k in pairs(params) do keys[#keys+1]=k end;table.sort(keys)
    for _,k in ipairs(keys) do parts[#parts+1]=escape(k)..'='..escape(params[k]) end
    return table.concat(parts,'&')
end
local function b64(raw)
    local alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local out={}
    for i=1,#raw,3 do
        local a,b,c=raw:byte(i,i+2);local n=a*65536+(b or 0)*256+(c or 0)
        local x,y,z,w=math.floor(n/262144)%64,math.floor(n/4096)%64,math.floor(n/64)%64,n%64
        out[#out+1]=alphabet:sub(x+1,x+1)..alphabet:sub(y+1,y+1)..(b and alphabet:sub(z+1,z+1) or '=')..(c and alphabet:sub(w+1,w+1) or '=')
    end
    return table.concat(out)
end
local function pad(key,byte)
    local out={}
    for i=1,64 do
        local a,b,n,p=key:byte(i) or 0,byte,0,1
        for _=1,8 do if a%2~=b%2 then n=n+p end;a=math.floor(a/2);b=math.floor(b/2);p=p*2 end
        out[i]=string.char(n)
    end
    return table.concat(out)
end
local function domain(s)
    if type(s)~='string' or #s>255 then return nil end
    s=s:match('^%s*(.-)%s*$'):lower():gsub('%.$','')
    if #s<1 or #s>253 or s:find('[^a-z0-9.-]') or s:find('..',1,true) or s:sub(1,1)=='.' or s:sub(-1)=='.' then return nil end
    for label in s:gmatch('[^.]+') do if #label>63 or label:sub(1,1)=='-' or label:sub(-1)=='-' then return nil end end
    return s
end
if ...=='library' then return {escape=escape,canonical=canonical,base64=b64,pad=pad,domain=domain} end
local account,revision,mode,job=arg[2],arg[3],arg[4],arg[5]
if type(account)~='string' or #account<1 or #account>64 or not account:match('^[a-zA-Z0-9_-]+$') or
    type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 then os.exit(1) end
local records=assert(loadfile(dir..'/aliyun-records.lua'))()
local reconcile=assert(loadfile(dir..'/aliyun-reconcile-plan.lua'))()
local operation_state={attempted=false,affected=0}
local codes={credentials_missing=true,invalid_credentials=true,invalid_response=true,response_limit=true,pagination_limit=true,pagination_changed=true,
    provider_rejected=true,signing_unavailable=true,InvalidAccessKeyId=true,['InvalidAccessKeyId.NotFound']=true,SignatureDoesNotMatch=true,
    InvalidAccessKeySecret=true,Forbidden=true,['Forbidden.RAM']=true,Throttling=true,['Throttling.User']=true,InternalError=true,ServiceUnavailable=true}
for code in pairs(records.codes) do codes[code]=true end
local kinds={['']=true,invalid_zone=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true}
local function report(kind,retry,code,names,scope)
    if mode=='reconcile' then return reconcile.report(account,revision,kind,code,'incomplete') end
    if mode=='records' then
        if operation_state.attempted then retry=false end
        return records.report(account,revision,kind,retry,code,'failed',operation_state.attempted and 'unknown' or 'none',operation_state.affected)
    end
    scope=scope or (mode=='zones' and 'zone-list' or 'zone-read')
    local body=string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"aliyun","account":"%s","configuration_revision":%s,',tostring(kind==''),account,revision)
    if scope=='zone-read' then body=body..'"credentials_valid":'..tostring(kind=='')..',' end
    body=body..string.format('"check_scope":"%s","error_kind":"%s","retryable":%s,"provider_code":"%s"',scope,kind,tostring(retry),code or '')
    if scope=='zone-list' then
        local list={};for _,name in ipairs(names or {}) do list[#list+1]='"'..name..'"' end
        body=body..',"zones":['..table.concat(list,',')..']'
    end
    return body..'}\n'
end
if arg[1]=='result' or arg[1]=='reconcile-result' then
    if (mode~='0' and mode~='1') or (job~='check' and job~='zones' and job~='records' and job~='reconcile') or arg[6] then os.exit(1) end
    local raw=io.stdin:read(65537);local doc=shared.parse(raw)
    if job=='reconcile' then
        if arg[1]~='reconcile-result' then os.exit(1) end
        local checked=reconcile.validate(raw,doc,account,revision,mode,kinds,codes)
        if not checked then os.exit(1) end;io.write(checked);return
    end
    if arg[1]~='result' then os.exit(1) end
    if job=='records' then
        local marker=io.open('/proc/self/fd/9','rb');local value=marker and (marker:read(15) or '')
        if not marker or not marker:close() then os.exit(1) end
        local checked=records.validate(raw,doc,account,revision,mode,value,kinds,codes)
        if not checked then os.exit(1) end;io.write(checked);return
    end
    if not doc or #raw>65536 or type(doc.ok)~='boolean' or doc.ok~=(mode=='0') or not kinds[doc.error_kind] or
        type(doc.retryable)~='boolean' or type(doc.provider_code)~='string' or (doc.provider_code~='' and not codes[doc.provider_code]) then os.exit(1) end
    if doc.check_scope~=(job=='zones' and 'zone-list' or 'zone-read') then os.exit(1) end
    local names={}
    if doc.check_scope=='zone-list' then
        if type(doc.zones)~='table' or (#doc.zones>0 and doc.error_kind~='') then os.exit(1) end
        for i,name in ipairs(doc.zones) do if domain(name)~=name or (i>1 and name<=names[i-1]) then os.exit(1) end;names[i]=name end
    end
    local expected=report(doc.error_kind,doc.retryable,doc.provider_code,names,doc.check_scope)
    if raw~=expected then os.exit(1) end;io.write(expected);return
end
if arg[1]~='run' or (mode~='check' and mode~='zones' and mode~='records' and mode~='reconcile' and mode~='records-durable') or type(job)~='string' or #job>9 or not job:match('^[1-9]%d*$') or tonumber(job)<2 or arg[6] then os.exit(1) end
local durable=mode=='records-durable';if durable then mode='records' end
local function output(body)
    local f=io.open('/proc/self/fd/3','wb');if not f or not f:write(body) or not f:close() then os.exit(1) end
end
local function fail(kind,retry,code)output(report(kind,retry,code));os.exit(1) end
local function write(fd,data)
    local path='/proc/self/fd/'..fd
    if mode=='records' and (fd==6 or fd==7) then path='/var/run/homegate/.dns-check-'..job..'/'..(fd==6 and 'context' or 'attempt') end
    local f=io.open(path,'wb');if not f or not f:write(data) or not f:close() then fail('temporary',false,'signing_unavailable') end
end
local function read(fd,limit)
    local f=io.open('/proc/self/fd/'..fd,'rb');if not f then fail('temporary',false,'signing_unavailable') end
    local raw=f:read(limit+1) or '';if not f:close() or #raw>limit then fail('temporary',false,'signing_unavailable') end;return raw
end
local function sha1(raw)
    write(8,raw)
    local rc=os.execute('/usr/bin/openssl dgst -sha1 -binary < /proc/self/fd/8 > /proc/self/fd/9 3>&- 4>&- 5>&- 6>&- 7>&- 8<&- 9>&- 2>/dev/null')
    if rc~=0 then fail('temporary',false,'signing_unavailable') end
    local digest=read(9,20);if #digest~=20 then fail('temporary',false,'signing_unavailable') end;return digest
end
local function sign(key,text)
    key=key..'&';if #key>64 then key=sha1(key) end
    return b64(sha1(pad(key,92)..sha1(pad(key,54)..text)))
end
local backup=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,backup)
if not snapshot or snapshot.revision~=tonumber(revision) then fail('invalid_request',false) end
local selected;for _,s in ipairs(snapshot.configuration) do if s.kind=='dns_account' and s.name==account then selected=s end end
if not selected then fail('not_found',false) end
if selected.values.provider~='aliyun' then fail('unsupported',false) end
local id=snapshot.credentials['aliyun.'..account..'.key_id'];local secret=snapshot.credentials['aliyun.'..account..'.secret']
if type(id)~='string' or type(secret)~='string' or id:match('^%s*$') or secret:match('^%s*$') then fail('authentication',false,'credentials_missing') end
if #id>4096 or #secret>4096 then fail('authentication',false,'invalid_credentials') end
local work='/var/run/homegate/.dns-check-'..job
local function fetch(params,action)
    action=action or 'DescribeDomains'
    local actions={DescribeDomains=true,DescribeSubDomainRecords=true,DescribeDomainRecordInfo=true,AddDomainRecord=true,UpdateDomainRecord=true,DeleteDomainRecord=true}
    if not actions[action] or (mode~='records' and mode~='reconcile' and action~='DescribeDomains') or (mode=='reconcile' and action~='DescribeSubDomainRecords' and action~='DescribeDomainRecordInfo') then fail('invalid_request',false,'invalid_operation') end
    local nonce=io.open('/proc/sys/kernel/random/uuid','rb');local raw=nonce and nonce:read(38)
    if not nonce or not nonce:close() or not raw or #raw~=37 or not raw:match('^[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+\n$') then fail('temporary',false,'signing_unavailable') end
    params.Action=action;params.Version='2015-01-09';params.Format='JSON';params.AccessKeyId=id
    params.SignatureMethod='HMAC-SHA1';params.SignatureVersion='1.0';params.SignatureNonce=raw:sub(1,-2);params.Timestamp=os.date('!%Y-%m-%dT%H:%M:%SZ')
    local query=canonical(params);params.Signature=sign(secret,'GET&%2F&'..escape(query))
    write(4,'url = "https://alidns.aliyuncs.com/?'..canonical(params)..'"\nrequest = "GET"\n')
    local command="rc=0; /usr/bin/curl --disable --config '"..work.."/request' --proto '=https' --proto-redir '=https' --proxy '' --noproxy '*' --connect-timeout 3 --max-time 10 --cacert /etc/ssl/certs/ca-certificates.crt --silent --write-out '\\nHGHTTP:%{http_code}\\n' 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- 2>/dev/null || rc=$?; printf '\\nHGTRANSPORT:%s\\n' \"$rc\""
    local pipe=io.popen(command,'r');if not pipe then fail('network_unavailable',true) end
    local response=pipe:read(65537) or '';pipe:close()
    if #response>65536 then fail('temporary',true,'response_limit') end
    local body,status,transport=response:match('^(.*)\nHGHTTP:(%d%d%d)\n\nHGTRANSPORT:(%d+)\n$')
    if not body or #transport>3 then fail('temporary',true,'invalid_response') end
    if transport~='0' then fail(transport=='28' and 'timeout' or 'network_unavailable',true) end
    local doc,types,shape=shared.parse(body);status=tonumber(status)
    local code=doc and doc.Code
    if status<200 or status>=300 or code~=nil then
        local lower=type(code)=='string' and code:lower() or '';local kind,retry='invalid_request',false
        if status==429 or lower:find('throttl',1,true) or lower:find('flowcontrol',1,true) or lower:find('ratelimit',1,true) then kind,retry='rate_limit',true
        elseif status>=500 or lower:find('internalerror',1,true) or lower:find('serviceunavailable',1,true) then kind,retry='temporary',true
        elseif status==401 or status==403 or lower:find('accesskey',1,true) or lower:find('signature',1,true) or lower:find('forbidden',1,true) or lower:find('permission',1,true) or lower:find('securitytoken',1,true) then kind='authentication'
        elseif lower:find('notfound',1,true) then kind='not_found' end
        fail(kind,retry,codes[code] and code or 'provider_rejected')
    end
    if not doc or type(doc.RequestId)~='string' or #doc.RequestId<1 or #doc.RequestId>128 then fail('temporary',true,'invalid_response') end
    if action=='DescribeDomains' and (not types or types.Domains~='object' or not shape.children.Domains.children.Domain or shape.children.Domains.children.Domain.kind~='array') then fail('temporary',true,'invalid_response') end
    return doc,types,shape
end
if mode=='records' or mode=='reconcile' then
    local plan=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
    local function checkpoint()
        if durable then
            local helper="'"..(dir..'/homegate-dns-receipt.sh'):gsub("'","'\\''").."'"
            local rc=os.execute('ash '..helper..' --aliyun-internal checkpoint '..account..' '..revision..' '..job..' 3>&- 4>&- 5>&- 8>&- 9>&- >/dev/null 2>&1')
            if rc~=0 then fail('temporary',false,'invalid_receipt') end
        end
    end
    local body=records.run(snapshot,account,revision,{parse=shared.parse,context_parse=require('luci.jsonc').parse,encode=backup.json,plan=plan,reconcile=reconcile,reconciling=mode=='reconcile',work=work,read=read,write=write,fetch=fetch,fail=fail,state=operation_state,checkpoint=checkpoint})
    output(body);return
end
local function integer(n,low,high)return type(n)=='number' and n==math.floor(n) and n>=low and n<=high end
local per=mode=='zones' and 100 or 1
local total,rows,bytes,names,seen=nil,0,0,{},{}
for page=1,1000 do
    local doc=fetch({PageNumber=tostring(page),PageSize=tostring(per)})
    if not integer(doc.TotalCount,0,100000) or doc.PageNumber~=page or doc.PageSize~=per or type(doc.RequestId)~='string' or #doc.RequestId<1 or #doc.RequestId>128 or type(doc.Domains.Domain)~='table' or #doc.Domains.Domain>per then fail('temporary',true,'invalid_response') end
    if total and total~=doc.TotalCount then fail('temporary',true,'pagination_changed') end;total=doc.TotalCount
    local items=doc.Domains.Domain
    for k,item in pairs(items) do
        if not integer(k,1,#items) or type(item)~='table' then fail('temporary',true,'invalid_response') end
        local name=domain(item.DomainName)
        if not name and type(item.DomainName)=='string' and item.DomainName:find('[\128-\255]') then name=domain(item.PunyCode) end
        if not name then fail('temporary',true,'invalid_response') end
        if not seen[name] then names[#names+1]=name;seen[name]=true;bytes=bytes+#name+3 end
        if bytes>60000 then fail('temporary',false,'pagination_limit') end
    end
    rows=rows+#items
    if rows>total then fail('temporary',true,'pagination_changed') end
    if mode=='check' or rows==total then table.sort(names);output(report('',false,'',names));return end
    if #items==0 then fail('temporary',true,'pagination_changed') end
end
fail('temporary',false,'pagination_limit')
