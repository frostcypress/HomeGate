-- Private Huawei signed adapter; record mode is independently gated outside.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local common=assert(loadfile(dir..'/aliyun-reader.lua'))('library')
local function hex(s)return (s:gsub('.',function(c)return string.format('%02x',c:byte()) end)) end
local host='dns.cn-north-4.myhuaweicloud.com'
local origin='https://dns.cn-north-4.myhuaweicloud.com'
local function endpoint(s)
    if s=='https://'..host or s=='https://'..host..'/' then return host end
end
local function authorization(id,key,domain,query,date,digest,method,path,payload)
    method=method or 'GET';path=path or '/v2/zones';payload=payload or ''
    local function hmac(k,text)
        if #k>64 then k=digest(k) end
        return digest(common.pad(k,92)..digest(common.pad(k,54)..text))
    end
    local names='content-type;host;x-domain-id;x-sdk-date'
    local headers='content-type:application/json\nhost:'..host..'\nx-domain-id:'..domain..'\nx-sdk-date:'..date..'\n'
    local canonical=method..'\n'..path:gsub('/?$','/')..'\n'..query..'\n'..headers..'\n'..names..'\n'..hex(digest(payload))
    local text='SDK-HMAC-SHA256\n'..date..'\n'..hex(digest(canonical))
    return 'SDK-HMAC-SHA256 Access='..id..', SignedHeaders='..names..', Signature='..hex(hmac(key,text))
end
if ...=='library' then return {authorization=authorization,endpoint=endpoint} end
local account,revision,mode,job=arg[2],arg[3],arg[4],arg[5]
if type(account)~='string' or #account<1 or #account>64 or not account:match('^[a-zA-Z0-9_-]+$') or
    type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 then os.exit(1) end
local records=assert(loadfile(dir..'/huaweicloud-records.lua'))()
local reconcile=assert(loadfile(dir..'/huaweicloud-reconcile-plan.lua'))()
local state={attempted=false,affected=0}
local codes={credentials_missing=true,invalid_credentials=true,unsupported_endpoint=true,invalid_response=true,response_limit=true,
    pagination_limit=true,pagination_changed=true,provider_rejected=true,signing_unavailable=true,
    ['APIGW.0301']=true,['APIGW.0308']=true,['DNS.0003']=true}
for code in pairs(records.codes) do codes[code]=true end
local kinds={['']=true,invalid_zone=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true}
local function report(kind,retry,code,names)
    if mode=='reconcile' then return reconcile.report(account,revision,kind,code,'incomplete') end
    if mode=='records' then if state.attempted then retry=false end;return records.report(account,revision,kind,retry,code,'failed',state.attempted and 'unknown' or 'none',state.affected) end
    local out=string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"huaweicloud","account":"%s","configuration_revision":%s,',tostring(kind==''),account,revision)
    if mode=='check' then out=out..'"credentials_valid":'..tostring(kind=='')..',' end
    out=out..string.format('"check_scope":"%s","error_kind":"%s","retryable":%s,"provider_code":"%s"',mode=='zones' and 'zone-list' or 'zone-read',kind,tostring(retry),code or '')
    if mode=='zones' then
        local list={};for _,name in ipairs(names or {}) do list[#list+1]='"'..name..'"' end
        out=out..',"zones":['..table.concat(list,',')..']'
    end
    return out..'}\n'
end
if arg[1]=='result' or arg[1]=='reconcile-result' then
    local rc=mode;mode=job
    if (rc~='0' and rc~='1') or (mode~='check' and mode~='zones' and mode~='records' and mode~='reconcile') or arg[6] then os.exit(1) end
    local raw=io.stdin:read(65537) or '';local doc=shared.parse(raw)
    if mode=='reconcile' then
        if arg[1]~='reconcile-result' then os.exit(1) end
        local checked=reconcile.validate(raw,doc,account,revision,rc,kinds,codes)
        if not checked then os.exit(1) end;io.write(checked);return
    end
    if arg[1]~='result' then os.exit(1) end
    if mode=='records' then
        local f=io.open('/proc/self/fd/9','rb');local marker=f and (f:read(14) or '')
        if not f or not f:close() then os.exit(1) end
        local checked=records.validate(raw,doc,account,revision,rc,marker,kinds,codes)
        if not checked then os.exit(1) end;io.write(checked);return
    end
    if not doc or #raw>65536 or doc.ok~=(rc=='0') or not kinds[doc.error_kind] or type(doc.retryable)~='boolean' or
        type(doc.provider_code)~='string' or (doc.provider_code~='' and not codes[doc.provider_code]) then os.exit(1) end
    local names={}
    if mode=='zones' then
        if type(doc.zones)~='table' or (#doc.zones>0 and doc.error_kind~='') then os.exit(1) end
        for i,name in ipairs(doc.zones) do if common.domain(name)~=name or (i>1 and name<=names[i-1]) then os.exit(1) end;names[i]=name end
    end
    local expected=report(doc.error_kind,doc.retryable,doc.provider_code,names)
    if raw~=expected then os.exit(1) end;io.write(expected);return
end
if arg[1]~='run' or (mode~='check' and mode~='zones' and mode~='records' and mode~='reconcile' and mode~='records-durable') or type(job)~='string' or #job>9 or not job:match('^[1-9]%d*$') or tonumber(job)<2 or arg[6] then os.exit(1) end
local durable=mode=='records-durable';if durable then mode='records' end
local function output(body)local f=io.open('/proc/self/fd/3','wb');if not f or not f:write(body) or not f:close() then os.exit(1) end end
local function fail(kind,retry,code)output(report(kind,retry,code));os.exit(1) end
local function write(fd,data)
    local path='/proc/self/fd/'..fd
    if mode=='records' and (fd==5 or fd==6 or fd==7) then path='/var/run/homegate/.dns-check-'..job..'/'..(fd==5 and 'input' or fd==6 and 'context' or 'attempt') end
    local f=io.open(path,'wb');if not f or not f:write(data) or not f:close() then fail('temporary',false,'signing_unavailable') end
end
local function sha256(raw)
    write(8,raw)
    local rc=os.execute('/usr/bin/openssl dgst -sha256 -binary < /proc/self/fd/8 > /proc/self/fd/9 3>&- 4>&- 5>&- 6>&- 7>&- 8<&- 9>&- 2>/dev/null')
    if rc~=0 then fail('temporary',false,'signing_unavailable') end
    local f=io.open('/proc/self/fd/9','rb');local out=f and f:read(33)
    if not f or not f:close() or not out or #out~=32 then fail('temporary',false,'signing_unavailable') end;return out
end
local backup=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,backup)
if not snapshot or snapshot.revision~=tonumber(revision) then fail('invalid_request',false) end
local selected;for _,s in ipairs(snapshot.configuration) do if s.kind=='dns_account' and s.name==account then selected=s end end
if not selected then fail('not_found',false) end
if selected.values.provider~='huaweicloud' then fail('unsupported',false) end
local prefix='huaweicloud.'..account..'.'
local id,secret,domain,url=snapshot.credentials[prefix..'key_id'],snapshot.credentials[prefix..'secret'],snapshot.credentials[prefix..'account_id'],snapshot.credentials[prefix..'endpoint']
for _,v in ipairs({id or '',secret or '',domain or ''}) do if type(v)~='string' or v:match('^%s*$') then fail('authentication',false,'credentials_missing') end end
if #id>4096 or #secret>4096 or not id:match('^[a-zA-Z0-9_-]+$') or #domain~=32 or domain:find('[^0-9a-f]') then fail('authentication',false,'invalid_credentials') end
if not endpoint(url) then fail('unsupported',false,'unsupported_endpoint') end
local work='/var/run/homegate/.dns-check-'..job
local function fetch(method,path,params,data)
    local valid=method=='GET' and path=='/v2/zones'
    if mode=='records' or mode=='reconcile' then
        valid=valid or ((method=='GET' or method=='POST') and path:match('^/v2/zones/[a-zA-Z0-9_-]+/recordsets$')) or ((method=='GET' or method=='PUT' or method=='DELETE') and path:match('^/v2/zones/[a-zA-Z0-9_-]+/recordsets/[a-zA-Z0-9_-]+$'))
    end
    if mode=='reconcile' and method~='GET' then valid=false end
    if not valid then fail('invalid_request',false,'invalid_operation') end
    local query=common.canonical(params);local payload=data and backup.json(data) or ''
    if #payload>32768 then fail('temporary',false,'state_limit') end
    local date=os.date('!%Y%m%dT%H%M%SZ');if type(date)~='string' or not date:match('^%d%d%d%d%d%d%d%dT%d%d%d%d%d%dZ$') then fail('temporary',false,'signing_unavailable') end
    local auth=authorization(id,secret,domain,query,date,sha256,method,path,payload)
    local request='url = "'..origin..path..(query~='' and '?'..query or '')..'"\nrequest = "'..method..'"\nheader = "Host: '..host..'"\nheader = "Content-Type: application/json"\nheader = "X-Domain-ID: '..domain..'"\nheader = "X-Sdk-Date: '..date..'"\nheader = "Authorization: '..auth..'"\n'
    if data then request=request..'data = "'..payload:gsub('\\','\\\\'):gsub('"','\\"')..'"\n' end
    if #request>65536 then fail('temporary',false,'state_limit') end;write(4,request)
    local command="rc=0; /usr/bin/curl --disable --config '"..work.."/request' --proto '=https' --proto-redir '=https' --proxy '' --noproxy '*' --connect-timeout 3 --max-time 10 --cacert /etc/ssl/certs/ca-certificates.crt --silent --write-out '\\nHGHTTP:%{http_code}\\n' 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- 2>/dev/null || rc=$?; printf '\\nHGTRANSPORT:%s\\n' \"$rc\""
    local pipe=io.popen(command,'r');if not pipe then fail('network_unavailable',true) end
    local raw=pipe:read(65537) or '';pipe:close();if #raw>65536 then fail('temporary',true,'response_limit') end
    local body,status,transport=raw:match('^(.*)\nHGHTTP:(%d%d%d)\n\nHGTRANSPORT:(%d+)\n$')
    if not body or #transport>3 then fail('temporary',true,'invalid_response') end
    if transport~='0' then fail(transport=='28' and 'timeout' or 'network_unavailable',true) end
    local doc,types,shape=shared.parse(body);status=tonumber(status)
    if status<200 or status>=300 or (doc and doc.code~=nil) then
        local code=doc and doc.code;local kind,retry='invalid_request',false
        if status==429 then kind,retry='rate_limit',true
        elseif status>=500 then kind,retry='temporary',true
        elseif status==401 or status==403 then kind='authentication' end
        fail(kind,retry,codes[code] and code or 'provider_rejected')
    end
    if not doc or not types or (mode~='records' and mode~='reconcile' and (types.zones~='array' or types.metadata~='object' or not shape.children.zones or not shape.children.metadata)) then fail('temporary',true,'invalid_response') end
    return doc,shape
end
if mode=='records' or mode=='reconcile' then
    local function read(fd,limit)
        local f=io.open('/proc/self/fd/'..fd,'rb');if not f then fail('temporary',false,'state_limit') end
        local raw=f:read(limit+1) or '';if not f:close() or #raw>limit then fail('invalid_request',false,'invalid_operation') end;return raw
    end
    local function checkpoint()
        if durable then
            local helper="'"..(dir..'/homegate-dns-receipt.sh'):gsub("'","'\\''").."'"
            local rc=os.execute('ash '..helper..' --huaweicloud-internal checkpoint '..account..' '..revision..' '..job..' 3>&- 4>&- 5>&- 8>&- 9>&- >/dev/null 2>&1')
            if rc~=0 then fail('temporary',false,'invalid_receipt') end
        end
    end
    output(records.run(snapshot,account,revision,{parse=shared.parse,context_parse=require('luci.jsonc').parse,reconcile=reconcile,reconciling=mode=='reconcile',checkpoint=checkpoint,encode=backup.json,plan=assert(loadfile(dir..'/cloudflare-record-plan.lua'))(),read=read,write=write,fetch=fetch,fail=fail,state=state}));return
end
local function integer(n,a,b)return type(n)=='number' and n==math.floor(n) and n>=a and n<=b end
local per=mode=='zones' and 100 or 1
local total,rows,bytes,names,seen,ids=nil,0,0,{},{},{}
for page=1,1000 do
    local doc,shape=fetch('GET','/v2/zones',{type='public',offset=tostring((page-1)*per),limit=tostring(per)});local count=doc.metadata.total_count;local items=doc.zones
    if not integer(count,0,100000) or type(items)~='table' or #items>per then fail('temporary',true,'invalid_response') end
    if total and total~=count then fail('temporary',true,'pagination_changed') end;total=count
    for k,item in pairs(items) do
        if not integer(k,1,#items) or type(item)~='table' or type(item.id)~='string' or #item.id<1 or #item.id>128 or item.id:find('[^a-zA-Z0-9_-]') or item.zone_type~='public' then fail('temporary',true,'invalid_response') end
        if ids[item.id] then fail('temporary',true,'pagination_changed') end;ids[item.id]=true
        local name=common.domain(item.name);if not name then fail('temporary',true,'invalid_response') end
        if not seen[name] then seen[name]=true;names[#names+1]=name;bytes=bytes+#name+3;if bytes>60000 then fail('temporary',true,'response_limit') end end
    end
    rows=rows+#items
    if rows>total or (#items==0 and rows<total) then fail('temporary',true,'pagination_changed') end
    if mode=='check' then output(report('',false));return end
    if rows==total then table.sort(names);output(report('',false,'',names));return end
    if #items<per then fail('temporary',true,'pagination_changed') end
end
fail('temporary',true,'pagination_limit')
