-- Data-only bounded page ledger and canonical public zone names. No HTTP/file paths from input.
local json=require('luci.jsonc')
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local account,revision=arg[2],arg[3]
if type(account)~='string' or #account<1 or #account>64 or not account:match('^[a-zA-Z0-9_-]+$') or
    type(revision)~='string' or not revision:match('^[1-9]%d*$') or tonumber(revision)>32 or arg[5] then os.exit(1) end
local function integer(n,low,high) return type(n)=='number' and n==math.floor(n) and n>=low and n<=high end
local function name(s)
    if type(s)~='string' or #s>255 then return nil end
    s=s:match('^%s*(.-)%s*$'):lower():gsub('%.$','')
    if #s<1 or #s>253 or s:find('[^a-z0-9.-]') or s:find('..',1,true) or s:sub(1,1)=='.' or s:sub(-1)=='.' then return nil end
    for label in s:gmatch('[^.]+') do
        if #label>63 or label:sub(1,1)=='-' or label:sub(-1)=='-' then return nil end
    end
    return s
end
local function report(kind,retry,code,zones)
    local names={};for _,s in ipairs(zones or {}) do names[#names+1]='"'..s..'"' end
    return string.format('{"api_version":1,"prototype":true,"ok":%s,"phase":"dns-provider","provider":"cloudflare","account":"%s","configuration_revision":%s,"check_scope":"zone-list","error_kind":"%s","retryable":%s,"provider_code":"%s","zones":[%s]}',tostring(kind==''),account,revision,kind,tostring(retry),code or '',table.concat(names,','))..'\n'
end
local function output(body)
    local f=io.open('/proc/self/fd/3','wb');if not f or not f:write(body) or not f:close() then os.exit(1) end
end
local function fail(kind,retry,code) output(report(kind,retry,code));os.exit(1) end
local function invalid(code) fail('temporary',true,code or 'invalid_response') end
local function read(fd,limit)
    local f=io.open('/proc/self/fd/'..fd,'rb');if not f then os.exit(1) end
    local body=f:read(limit+1) or '';if not f:close() or #body>limit then os.exit(1) end;return body
end
local function ledger(page)
    local body=read(5,100)
    if body=='' and page==1 then return -1,-1,0 end
    local nextpage,pages,count,rows=body:match('^HGCFLIST1:(%d+):(-?%d+):(-?%d+):(%d+)\n$')
    if not nextpage or tonumber(nextpage)~=page or not integer(tonumber(pages),-1,1000) or
        not integer(tonumber(count),-1,50000) or not integer(tonumber(rows),0,50000) then os.exit(1) end
    return tonumber(pages),tonumber(count),tonumber(rows)
end
if arg[1]=='page' then
    local page=tonumber(arg[4]);if not integer(page,1,1000) or tostring(page)~=arg[4] then os.exit(1) end
    local pages,count,rows=ledger(page)
    local doc,types=shared.envelope(io.stdin:read(65537),fail)
    if type(doc.result)~='table' or types.result~='array' or #doc.result>50 then invalid() end
    local lines={};local ids={}
    for k,v in pairs(doc.result) do
        if not integer(k,1,#doc.result) or type(v)~='table' or type(v.id)~='string' or #v.id~=32 or v.id:find('[^0-9a-f]') or ids[v.id] then invalid() end
        local zone=name(v.name);if not zone then invalid() end;ids[v.id]=true;lines[k]=v.id..':'..zone..'\n'
    end
    local info=doc.result_info
    if info~=nil then
        if type(info)~='table' or types.result_info~='object' then invalid() end
        for key,expected in pairs({page=page,per_page=50,count=#lines}) do
            if info[key]~=nil and info[key]~=expected then invalid() end
        end
        if info.total_pages~=nil then
            if not integer(info.total_pages,0,1000) then invalid('pagination_limit') end
            if pages~=-1 and pages~=info.total_pages then invalid('pagination_changed') end;pages=info.total_pages
        elseif pages~=-1 then invalid('pagination_changed') end
        if info.total_count~=nil then
            if not integer(info.total_count,0,50000) then invalid('pagination_limit') end
            if count~=-1 and count~=info.total_count then invalid('pagination_changed') end;count=info.total_count
        elseif count~=-1 then invalid('pagination_changed') end
    elseif pages~=-1 or count~=-1 then invalid('pagination_changed') end
    rows=rows+#lines;if rows>50000 or (count~=-1 and rows>count) then invalid('pagination_limit') end
    local done
    if pages==-1 then done=#lines<50
    elseif pages==0 then if page~=1 or #lines~=0 then invalid() end;done=true
    else if page>pages or (#lines==0 and page<pages) then invalid() end;done=page==pages end
    if done and count~=-1 and rows~=count then invalid('pagination_changed') end
    if not done and page==1000 then invalid('pagination_limit') end
    -- Only validated names/IDs are appended; provider metadata never persists.
    local f=io.open('/proc/self/fd/4','ab');if not f or not f:write(table.concat(lines)) or not f:close() then os.exit(1) end
    f=io.open('/proc/self/fd/5','wb')
    if not f or not f:write(string.format('HGCFLIST1:%d:%d:%d:%d\n',page+1,pages,count,rows)) or not f:close() then os.exit(1) end
    io.write(done and 'HGDNSDONE1\n' or 'HGDNSNEXT1\n')
elseif arg[1]=='finish' and not arg[4] then
    local raw=read(4,14350000);local ids,seen,zones={},{},{};local rows,bytes=0,0
    for line in raw:gmatch('[^\n]+\n') do
        local id,s=line:match('^([0-9a-f]+):([^\n]+)\n$')
        if not id or #id~=32 or ids[id] or name(s)~=s then invalid() end
        ids[id]=true;rows=rows+1;bytes=bytes+#line;if rows>50000 then invalid('pagination_limit') end
        if not seen[s] then seen[s]=true;zones[#zones+1]=s end
    end
    if bytes~=#raw then invalid() end
    local state=read(5,100);local n=tonumber(state:match(':([0-9]+)\n$'))
    if n~=rows then invalid() end
    table.sort(zones);output(report('',false,'',zones))
elseif arg[1]=='result' then
    if arg[4]~='0' and arg[4]~='1' then os.exit(1) end
    local raw=io.stdin:read(14350513)
    if not raw or #raw>14350512 or raw:find('%z') then os.exit(1) end
    -- Native parse plus exact canonical re-encoding rejects extra documents/keys.
    local doc=json.parse(raw);if type(doc)~='table' or doc.ok~=(arg[4]=='0') then os.exit(1) end
    local kinds={['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true}
    if not kinds[doc.error_kind] or type(doc.retryable)~='boolean' or type(doc.provider_code)~='string' or #doc.provider_code>32 or not doc.provider_code:match('^[a-zA-Z0-9_-]*$') or type(doc.zones)~='table' or #doc.zones>50000 then os.exit(1) end
    local last='';for k,s in pairs(doc.zones) do if not integer(k,1,#doc.zones) or name(s)~=s then os.exit(1) end end
    for _,s in ipairs(doc.zones) do if s<=last then os.exit(1) end;last=s end
    if doc.error_kind~='' and #doc.zones~=0 then os.exit(1) end
    local expected=report(doc.error_kind,doc.retryable,doc.provider_code,doc.zones)
    if raw~=expected then os.exit(1) end;io.write(expected)
else os.exit(1) end
