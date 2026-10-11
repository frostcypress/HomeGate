-- Bounded public UCI backup codec. No shell, filesystem or UCI write access.
-- This module deliberately cannot publish a restore candidate.
local M = {}
local TYPES = {"homegate", "dns_account", "ddns_rule", "certificate", "web_rule", "wol_host"}
local FIELDS = {
    homegate = {"enabled", "log_level", "log_max_lines", "access_enabled", "access_allow", "access_deny", "access_region", "wol_interface", "last_wol_host", "ddns_interval", "https_port", "http_port", "proxy_https_port", "proxy_http_port", "auto_firewall", "acme_email", "acme_directory", "renew_days", "version"},
    dns_account = {"name", "provider"},
    ddns_rule = {"enabled", "name", "account", "zone", "host", "type", "source", "interface", "ttl"},
    certificate = {"enabled", "name", "source", "account", "zone", "domains", "email", "renew_days", "ca", "environment"},
    web_rule = {"enabled", "domain", "https", "certificate"},
    wol_host = {"name", "mac"}
}
local DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
local STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
local DEFAULTS = {
    homegate = {enabled="0", log_level="info", log_max_lines="1024", access_enabled="0", access_allow="", access_deny="", access_region="", wol_interface="br-lan", last_wol_host="", ddns_interval="300", https_port="443", http_port="0", proxy_https_port="10443", proxy_http_port="10080", auto_firewall="1", acme_email="", acme_directory=DIRECTORY, renew_days="30", version=""},
    dns_account = {name=""},
    ddns_rule = {enabled="0", name="", account="", zone="", host="@", type="AAAA", source="auto", interface="", ttl="600"},
    certificate = {enabled="0", name="", source="acme", account="", zone="", email="", renew_days="30", ca="letsencrypt", environment="production"},
    web_rule = {enabled="0", domain="", https="1", certificate=""},
    wol_host = {name="", mac=""}
}
local KEYS = {}
for kind, fields in pairs(FIELDS) do
    KEYS[kind] = {}
    for _, key in ipairs(fields) do KEYS[kind][key] = true end
end
local function id(v) return type(v)=="string" and #v>0 and #v<=64 and v:match("^[a-zA-Z0-9_%-]+$") ~= nil end
local function utf8(s)
    local p = 1
    while p <= #s do
        local b = s:byte(p)
        local n, lo, hi = 1, 128, 191
        if b < 128 then
            if b < 32 or b == 127 then return false end
        elseif b >= 194 and b <= 223 then n=2
        elseif b >= 224 and b <= 239 then
            n=3; if b==224 then lo=160 elseif b==237 then hi=159 end
        elseif b >= 240 and b <= 244 then
            n=4; if b==240 then lo=144 elseif b==244 then hi=143 end
        else return false end
        if p+n-1>#s then return false end
        for j=1,n-1 do
            local c=s:byte(p+j)
            if c<(j==1 and lo or 128) or c>(j==1 and hi or 191) then return false end
        end
        p=p+n
    end
    return true
end
local function integer(v, low, high)
    if not v:match("^[0-9]+$") or #v>9 then return nil end
    local n=tonumber(v)
    if n<low or n>high then return nil end
    return string.format("%.0f",n)
end
local function domain(v, wildcard, empty)
    if v=="" and empty then return "" end
    v=v:lower():gsub("%.$","")
    local base=v
    if wildcard and v:sub(1,2)=="*." then base=v:sub(3) end
    if #base==0 or #base>253 or base:sub(1,1)=="." or base:sub(-1)=="." or base:find("..",1,true) then return nil end
    for label in base:gmatch("[^.]+") do
        if #label>63 or not (label:match("^[a-z0-9]$") or label:match("^[a-z0-9][a-z0-9%-]*[a-z0-9]$")) then return nil end
    end
    return v
end
local function ipv4(v)
    local a,b,c,d=v:match("^([0-9]+)%.([0-9]+)%.([0-9]+)%.([0-9]+)$")
    if not a then return false end
    for _, part in ipairs({a,b,c,d}) do
        if #part>3 or tonumber(part)>255 or (#part>1 and part:sub(1,1)=="0") then return false end
    end
    return true
end
local function ipv6(v)
    if not v:find(":",1,true) or v:find("[^a-fA-F0-9:%.]") then return false end
    local ip4=v:match("([^:]+%.[^:]+)$")
    if ip4 then if not ipv4(ip4) then return false end; v=v:sub(1,#v-#ip4).."0:0" end
    if v:find(":::" ,1,true) then return false end
    local compression=v:find("::",1,true)
    if compression and v:find("::",compression+2,true) then return false end
    if not compression and (v:sub(1,1)==":" or v:sub(-1)==":") then return false end
    local count=0
    for part in v:gmatch("[^:]+") do if #part>4 then return false end; count=count+1 end
    return (compression and count<8) or (not compression and count==8)
end
local function networks(v)
    if #v>4096 then return nil end
    local count=0
    for part in v:gmatch("[^,; ]+") do
        count=count+1; if count>256 then return nil end
        local address,prefix=part:match("^(.-)/([0-9]+)$")
        address=address or part
        local four=ipv4(address)
        if not four and not ipv6(address) then return nil end
        if prefix and not integer(prefix,0,four and 32 or 128) then return nil end
    end
    return v
end
local function enum(v, values)
    for _, wanted in ipairs(values) do if v==wanted then return v end end
end
local function scalar(kind, key, v)
    if type(v)~="string" or #v>4096 or not utf8(v) then return nil end
    if key=="enabled" or key=="access_enabled" or key=="auto_firewall" or key=="https" then return enum(v,{"0","1"}) end
    if key=="log_level" then return enum(v,{"debug","info","warn","error"}) end
    if key=="log_max_lines" then return integer(v,64,20000) end
    if key=="ddns_interval" then return integer(v,60,999999999) end
    if key=="renew_days" then return integer(v,1,3650) end
    if key=="ttl" then return integer(v,1,214748364) end
    if key:match("_port$") then return integer(v,0,65535) end
    if key=="provider" then return enum(v,{"aliyun","cloudflare","dnspod","huaweicloud"}) end
    if key=="source" then return enum(v,kind=="certificate" and {"acme","local"} or {"auto","interface","url"}) end
    if key=="type" then return enum(v,{"A","AAAA"}) end
    if key=="ca" then return enum(v,{"letsencrypt"}) end
    if key=="environment" then return enum(v,{"production","staging"}) end
    if key=="acme_directory" then return enum(v,{DIRECTORY,STAGING}) end
    if key=="access_region" then return enum(v,{"","CN"}) end
    if key=="access_allow" or key=="access_deny" then return networks(v) end
    if key=="account" or key=="certificate" or key=="last_wol_host" then return v=="" and "" or (id(v) and v or nil) end
    if key=="interface" or key=="wol_interface" then
        return (#v<=32 and (v=="" or v:match("^[a-zA-Z0-9_%.:%-]+$"))) and v or nil
    end
    if key=="zone" then return domain(v,false,kind=="certificate") end
    if key=="domain" then return domain(v,false,false) end
    if key=="host" then return v=="@" and "@" or domain(v,false,false) end
    if key=="mac" then
        local hex=v:gsub(":",""):gsub("%-",""):upper()
        if #hex~=12 or hex:find("[^0-9A-F]") or hex=="000000000000" or tonumber(hex:sub(1,2),16)%2==1 then return nil end
        return hex:gsub("(..)","%1:"):sub(1,-2)
    end
    if key=="email" or key=="acme_email" then
        if v=="" then return "" end
        return (#v<=254 and v:match("^[a-zA-Z0-9_.+%-]+@[a-zA-Z0-9.%-]+$") and domain(v:match("@(.+)$"),false,false)) and v or nil
    end
    if key=="version" then return (#v<=64 and (v=="" or v:match("^[a-zA-Z0-9_.+%-]+$"))) and v or nil end
    return #v<=255 and v or nil
end
local function domains(value)
    local input=type(value)=="table" and value or {}
    if type(value)=="string" then for v in value:gmatch("[^, ]+") do input[#input+1]=v end end
    local out,seen={},{}
    for _,v in ipairs(input) do
        if type(v)~="string" then return nil end
        local normalized=domain(v,true,false)
        if not normalized or seen[normalized] or #out>=32 then return nil end
        seen[normalized]=true; out[#out+1]=normalized
    end
    if #out==0 then return nil end
    table.sort(out); return out
end
-- Tokens are data, never Lua/shell expressions. Support normal UCI quoting,
-- including concatenated single-quote escapes emitted by the legacy exporter.
local function tokens(line)
    local out,p={},1
    while p<=#line do
        while line:sub(p,p):match("[ \t]") do p=p+1 end
        if p>#line or line:sub(p,p)=="#" then break end
        local parts,quote={},nil
        while p<=#line do
            local c=line:sub(p,p)
            if quote then
                if c==quote then quote=nil
                elseif c=="\\" and quote=='"' then
                    p=p+1; if p>#line then return nil end; parts[#parts+1]=line:sub(p,p)
                else parts[#parts+1]=c end
            elseif c=="'" or c=='"' then quote=c
            elseif c=="\\" then
                p=p+1; if p>#line then return nil end; parts[#parts+1]=line:sub(p,p)
            elseif c==" " or c=="\t" then break
            else parts[#parts+1]=c end
            p=p+1
        end
        if quote then return nil end
        out[#out+1]=table.concat(parts); if #out>3 then return nil end
    end
    return out
end
local function normalize(doc)
    local names,counts={},{}
    for _,s in ipairs(doc) do
        names[s.name]=s; counts[s.kind]=(counts[s.kind] or 0)+1
        if counts[s.kind]>(s.kind=="homegate" and 1 or 32) then return nil,"Too many configuration sections" end
        for _,key in ipairs(FIELDS[s.kind]) do
            local v=s.values[key]
            if v==nil then v=DEFAULTS[s.kind][key] end
            if key=="domains" then v=domains(v)
            elseif v~=nil then v=scalar(s.kind,key,v) end
            if v==nil then return nil,"Invalid or missing configuration field" end
            s.values[key]=v
        end
        -- An omitted credential/URL must never silently activate a restored rule.
        if s.values.enabled then s.values.enabled="0" end
        if s.kind=="homegate" then s.values.access_enabled="0" end
    end
    if not names.main or names.main.kind~="homegate" then return nil,"HomeGate main section is required" end
    local function reference(v,kind) return v=="" or (names[v] and names[v].kind==kind) end
    local function in_zone(v,zone) local d=v:gsub("^%*%.",""); return d==zone or d:sub(-(#zone+1))=="."..zone end
    local web_domains,wol_macs={},{}
    for _,s in ipairs(doc) do
        local v=s.values
        if (s.kind=="ddns_rule" or (s.kind=="certificate" and v.source=="acme")) and (v.account=="" or not reference(v.account,"dns_account")) then return nil,"DNS account reference is missing or invalid" end
        if s.kind=="certificate" and v.source=="acme" then
            if v.zone=="" then return nil,"Certificate zone is required" end
            for _,d in ipairs(v.domains) do if not in_zone(d,v.zone) then return nil,"Certificate domain is outside its zone" end end
        end
        if s.kind=="certificate" and v.source=="local" and (v.account~="" or v.zone~="") then return nil,"Local certificate has DNS account fields" end
        if s.kind=="ddns_rule" and v.host~="@" and not in_zone(v.host,v.zone) then return nil,"DDNS host is outside its zone" end
        if s.kind=="web_rule" then
            if not reference(v.certificate,"certificate") then return nil,"Certificate reference is invalid" end
            if web_domains[v.domain] then return nil,"Duplicate service domain" end; web_domains[v.domain]=true
            if v.certificate~="" then
                local covers=false
                for _,d in ipairs(names[v.certificate].values.domains) do
                    if d==v.domain or (d:sub(1,2)=="*." and v.domain:match("^[^.]+%.(.+)$")==d:sub(3)) then covers=true end
                end
                if not covers then return nil,"Certificate does not cover service domain" end
            end
        end
        if s.kind=="wol_host" then if wol_macs[v.mac] then return nil,"Duplicate wake host MAC" end; wol_macs[v.mac]=true end
        if s.kind=="homegate" and not reference(v.last_wol_host,"wol_host") then return nil,"Wake host reference is invalid" end
    end
    return doc
end
function M.parse(body)
    if type(body)~="string" or #body==0 then return nil,"Select a HomeGate configuration file" end
    if #body>262144 then return nil,"Configuration file is too large" end
    body=body:gsub("\r\n","\n")
    if body:find("[%z\1-\8\11-\31\127]") then return nil,"Invalid configuration framing" end
    local doc,names,meta={}, {}, {}
    local current,line_number=nil,0
    for line in (body.."\n"):gmatch("(.-)\n") do
        line_number=line_number+1
        if line_number>8192 or #line>4096 then return nil,"Configuration line limit exceeded" end
        local key,value=line:match("^# ([a-z0-9%-]+): (.-)$")
        if key and (key=="homegate-backup-format" or key=="plugin" or key=="schema" or key=="secrets") then
            if current or meta[key] then return nil,"Duplicate or misplaced backup metadata" end
            meta[key]=value
        else
            local t=tokens(line)
            if not t then return nil,"Invalid configuration syntax" end
            if #t>0 then
                if #t~=3 then return nil,"Named sections and three-token directives are required" end
                if t[1]=="config" then
                    if not FIELDS[t[2]] or not id(t[3]) or names[t[3]] or (t[2]=="homegate" and t[3]~="main") then return nil,"Invalid or duplicate configuration section" end
                    if #doc>=128 then return nil,"Too many configuration sections" end
                    current={kind=t[2],name=t[3],values={}}; doc[#doc+1]=current; names[t[3]]=true
                elseif t[1]=="option" or t[1]=="list" then
                    if not current then return nil,"Option has no configuration section" end
                    local field=t[2]
                    if not KEYS[current.kind][field] then return nil,"Unknown or private configuration field" end
                    if t[1]=="list" then
                        if current.kind~="certificate" or field~="domains" or (current.values[field] and type(current.values[field])~="table") then return nil,"Invalid configuration list" end
                        current.values[field]=current.values[field] or {}
                        if #current.values[field]>=32 then return nil,"Too many certificate domains" end
                        current.values[field][#current.values[field]+1]=t[3]
                    else
                        if current.values[field]~=nil then return nil,"Duplicate configuration field" end
                        current.values[field]=t[3]
                    end
                else return nil,"Unsupported configuration directive" end
            end
        end
    end
    if meta["homegate-backup-format"]=="2" then
        if meta.plugin~="homegate" or meta.schema~="public-uci-v1" or meta.secrets~="omitted" then return nil,"Wrong plugin or unsupported backup schema" end
    elseif meta["homegate-backup-format"]=="1" then
        if meta.secrets~="omitted" or meta.plugin or meta.schema then return nil,"Invalid legacy public backup metadata" end
    else return nil,"Unsupported HomeGate backup format" end
    return normalize(doc)
end
local function quote(v) return "'"..v:gsub("'","'\\''").."'" end
local function ordered(doc)
    local out={}
    for _,kind in ipairs(TYPES) do
        local group={}; for _,s in ipairs(doc) do if s.kind==kind then group[#group+1]=s end end
        table.sort(group,function(a,b) return a.name<b.name end)
        for _,s in ipairs(group) do out[#out+1]=s end
    end
    return out
end
local function serialize(doc)
    local out={"# homegate-backup-format: 2", "# plugin: homegate", "# schema: public-uci-v1", "# secrets: omitted"}
    for _,s in ipairs(ordered(doc)) do
        out[#out+1]=""; out[#out+1]="config "..s.kind.." "..quote(s.name)
        for _,key in ipairs(FIELDS[s.kind]) do
            local value=s.values[key]
            if type(value)=="table" then for _,v in ipairs(value) do out[#out+1]="\tlist "..key.." "..quote(v) end
            else out[#out+1]="\toption "..key.." "..quote(value) end
        end
    end
    return table.concat(out,"\n").."\n"
end
-- Project existing state through the same whitelist before any public diff.
-- Malformed public values are replaced rather than exposing unvalidated data.
local function snapshot(cur)
    local doc,seen={},{}
    local overflow=false
    local invalid=false
    for _,kind in ipairs(TYPES) do
        cur:foreach("homegate",kind,function(raw)
            if not id(raw[".name"]) or seen[raw[".name"]] or (kind=="homegate" and raw[".name"]~="main") then invalid=true; return end
            if #doc>=128 then overflow=true; return end
            seen[raw[".name"]]=true
            local s={kind=kind,name=raw[".name"],values={}}
            for _,key in ipairs(FIELDS[kind]) do
                local v=raw[key]; if v==nil then v=DEFAULTS[kind][key] end
                if key=="domains" then v=domains(v) elseif v~=nil then v=scalar(kind,key,v) end
                s.values[key]=v or "[omitted]"
            end
            doc[#doc+1]=s
        end)
    end
    if overflow then return nil,"Current configuration exceeds the public section limit" end
    if invalid then return nil,"Current public configuration contains invalid sections" end
    return ordered(doc)
end
function M.export(cur)
    local current=snapshot(cur)
    if not current then return nil,"Current public configuration cannot be exported safely" end
    local body=serialize(current)
    local doc,err=M.parse(body)
    if not doc then return nil,"Current public configuration cannot be exported safely" end
    return serialize(doc)
end
function M.preview(cur,body)
    local proposed,err=M.parse(body)
    if not proposed then return nil,err end
    local before,baseline_error=snapshot(cur)
    if not before then return nil,baseline_error end
    local old,new={},{}
    for _,s in ipairs(before) do old[s.name]=s end
    for _,s in ipairs(proposed) do new[s.name]=s end
    local changes={}
    local function add(s,key,a,b)
        if type(a)=="table" then a=table.concat(a,", ") end
        if type(b)=="table" then b=table.concat(b,", ") end
        if a~=b then changes[#changes+1]={section=s.name,kind=s.kind,field=key,before=a or "",after=b or ""} end
    end
    for _,s in ipairs(before) do if not new[s.name] or new[s.name].kind~=s.kind then add(s,".section","Present","Absent") end end
    for _,s in ipairs(ordered(proposed)) do
        local previous=old[s.name]; if previous and previous.kind~=s.kind then previous=nil end
        if not previous then add(s,".section","Absent","Present") end
        for _,key in ipairs(FIELDS[s.kind]) do add(s,key,previous and previous.values[key] or "",s.values[key]) end
    end
    return {api_version=1,ok=true,phase="config-preview",schema="public-uci-v1",can_commit=false,section_count=#proposed,changes=changes,
        warnings={"Preview only. Configuration remains unchanged.","Services and access control are disabled in the restore candidate.","Credentials, source URLs, upstream URLs and certificate files must be restored separately."}}
end
-- Small bounded JSON encoder for both native Lua LuCI and the reference bridge.
-- No dependency on a stringify method absent from the current Go bridge.
function M.json(value)
    local function string_json(s)
        return '"'..s:gsub('[%z\1-\31\\"]',function(c) return string.format('\\u%04x',c:byte()) end)..'"'
    end
    local function encode(v)
        if type(v)=="string" then return string_json(v) end
        if type(v)=="number" or type(v)=="boolean" then return tostring(v) end
        if type(v)~="table" then return "null" end
        local out={}
        if #v>0 or next(v)==nil then for _,item in ipairs(v) do out[#out+1]=encode(item) end; return "["..table.concat(out,",").."]" end
        local keys={}; for key in pairs(v) do keys[#keys+1]=key end; table.sort(keys)
        for _,key in ipairs(keys) do out[#out+1]=string_json(key)..":"..encode(v[key]) end
        return "{"..table.concat(out,",").."}"
    end
    return encode(value)
end
return M
