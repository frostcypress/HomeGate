-- Read-only, bounded process/control metadata. Never emits cmdline or secrets.
local function fail() os.exit(1) end
local function number(s,max)
    if type(s)~="string" or not s:match("^[1-9]%d*$") or #s>9 then fail() end
    local n=tonumber(s); if not n or n>max then fail() end; return n
end
local function read(path,limit,empty_allowed,vanishing)
    local f=io.open(path,"rb"); if not f then return nil end
    local s=f:read(limit+1); local ok=f:close()
    if s==nil and vanishing and ok then return nil end
    if not s and empty_allowed then s="" end
    if not s or #s>limit or not ok then fail() end
    return s
end
local function inspect(pid,token)
    number(pid,999999999)
    local body=read("/proc/"..pid.."/stat",8192,false,true); if not body then return nil end
    local tail=body:match("^%d+ %(.+%) (.+)$"); if not tail then fail() end
    local a={}; for v in tail:gmatch("%S+") do a[#a+1]=v end
    if #a<20 or not a[1]:match("^[A-Z]$") then fail() end
    for _,i in ipairs({2,3,4,20}) do if not a[i]:match("^%d+$") then fail() end end
    local hit="0"
    if token~="none" then
        if #token~=32 or token:find("[^0-9a-f]") then fail() end
        -- Exited tasks have an empty cmdline; Lua numeric reads return nil
        -- at EOF. Their stat identity still suffices to report Z/X safely.
        local cmdline=""
        if a[1]~="Z" and a[1]~="X" then cmdline=read("/proc/"..pid.."/cmdline",8192,true) or "" end
        for value in cmdline:gmatch("([^%z]+)%z") do if value==token then hit="1" end end
    end
    return {a[1],a[2],a[3],a[4],a[20],hit}
end
if arg[1]=="info" and arg[2] and arg[3] and not arg[4] then
    local a=inspect(arg[2],arg[3]); if a then io.write(table.concat(a,":"),"\n") end
elseif arg[1]=="group" and arg[2] and arg[3] and not arg[4] then
    number(arg[2],999999999); if arg[3]~="0" then number(arg[3],999999999) end
    -- Fixed command, no caller-controlled shell text or paths.
    local p=io.popen('printf "%s\\n" /proc/[0-9]*; printf "\\nHGPROC-EXIT:%s\\n" "$?"',"r"); if not p then fail() end
    local raw=p:read(65569); local ok=p:close()
    if not raw or #raw>65568 or not ok then fail() end
    local listing,status=raw:match('^(.*)\nHGPROC%-EXIT:(%d+)\n$')
    if not listing or #listing>65536 or status~='0' then fail() end
    -- Command substitution may retain an ash parent while this probe runs.
    -- Exclude only this inspection ancestry; it is not a business worker.
    local ignored={}
    local self_stat=read("/proc/self/stat",8192)
    local ancestor=self_stat and self_stat:match("^(%d+) ")
    if not ancestor then fail() end
    for i=1,32 do
        ignored[ancestor]=true
        local a=inspect(ancestor,"none")
        if not a or a[2]=="0" then break end
        ancestor=a[2]
        if i==32 then fail() end
    end
    local count=0; local scanned=0
    for entry in listing:gmatch("[^\n]+") do
        local pid=entry:match("^/proc/([1-9]%d*)$"); if not pid then fail() end
        do
            scanned=scanned+1; if scanned>4096 then fail() end
            local a=inspect(pid,"none")
            if a and not ignored[pid] and pid~=arg[3] and a[3]==arg[2] and a[4]==arg[2] and a[1]~="Z" and a[1]~="X" then count=count+1 end
        end
    end
    if scanned==0 then fail() end
    io.write(count,"\n")
elseif arg[1]=="now" and not arg[2] then
    local body=read("/proc/uptime",128); local s=body and body:match("^(%d+)%.")
    if not s or #s>9 then fail() end; io.write(s,"\n")
elseif arg[1]=="revision" and not arg[2] then
    local body=io.stdin:read(1025)
    local s=body and body:match('^{"api_version":1,"prototype":true,"ok":true,"revision":(%d+),"scope":"internal%-worker%-context"}\n$')
    if not s then fail() end; number(s,32); io.write(s,"\n")
elseif arg[1]=="ticket" and not arg[2] then
    local body=io.stdin:read(1025)
    if not body or #body>1024 then fail() end
    local token=body:match('^{"api_version":1,"prototype":true,"ok":true,"revision":%d+,"restoration_pending":true,"restore_handle":"([0-9a-f]+)","business_restored":false}\n$')
    if token and #token==32 then io.write(token,"\n")
    elseif body:match('^{"api_version":1,"prototype":true,"ok":true,"revision":%d+,"application_pending":false,"worker_acknowledged":true}\n$') then io.write("completed\n")
    else fail() end
elseif arg[1]=="receipt" and arg[2] and arg[3] and arg[4] and not arg[5] then
    number(arg[3],32); if arg[4]~="apply" and arg[4]~="restore" then fail() end
    if not arg[2]:match("^/tmp/homegate%-config%-prototype%-") then fail() end
    local body=read(arg[2].."/runtime",256)
    local dir=arg[0]:match("^(.*)/[^/]+$"); if not dir then fail() end
    local codec=assert(loadfile(dir.."/../../luci/lua/luasrc/model/homegate/backup.lua"))()
    local public=read(arg[2].."/gen-"..arg[3].."/public.conf",262144)
    local doc=public and codec.parse(public); if not doc then fail() end
    local port
    for _,s in ipairs(doc) do if s.kind=="homegate" then port=s.values.https_port end end
    if not port or body~="homegate-worker-receipt:1\nrevision="..arg[3].."\nrole="..arg[4].."\nhttps_port="..port.."\n" then fail() end
else fail() end
