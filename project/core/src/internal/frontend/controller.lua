package.preload["luci.model.homegate.backup"] = function()
-- Bounded public UCI backup codec. No shell, filesystem or UCI write access.
-- This module deliberately cannot publish a restore candidate.
local M = {}
local TYPES = {"homegate", "dns_account", "ddns_rule", "certificate", "web_rule", "wol_host"}
local FIELDS = {
    homegate = {"enabled", "log_level", "log_max_lines", "access_enabled", "access_allow", "access_deny", "access_region", "wol_interface", "last_wol_host", "ddns_interval", "https_port", "http_port", "proxy_https_port", "proxy_http_port", "auto_firewall", "acme_email", "acme_directory", "renew_days", "version"},
    dns_account = {"name", "provider"},
    ddns_rule = {"enabled", "name", "account", "zone", "host", "type", "source", "interface", "ttl"},
    certificate = {"enabled", "name", "source", "account", "zone", "domains", "email", "renew_days", "ca", "environment"},
    web_rule = {"enabled", "domain", "https", "certificate", "certificate_mode", "certificate_managed"},
    wol_host = {"name", "mac"}
}
local DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
local STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
local DEFAULTS = {
    homegate = {enabled="0", log_level="info", log_max_lines="1024", access_enabled="0", access_allow="", access_deny="", access_region="", wol_interface="br-lan", last_wol_host="", ddns_interval="300", https_port="443", http_port="0", proxy_https_port="10443", proxy_http_port="10080", auto_firewall="1", acme_email="", acme_directory=DIRECTORY, renew_days="30", version=""},
    dns_account = {name=""},
    ddns_rule = {enabled="0", name="", account="", zone="", host="@", type="AAAA", source="auto", interface="", ttl="600"},
    certificate = {enabled="0", name="", source="acme", account="", zone="", email="", renew_days="30", ca="letsencrypt", environment="production"},
    web_rule = {enabled="0", domain="", https="1", certificate="", certificate_mode="auto", certificate_managed="0"},
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
    if key=="enabled" or key=="access_enabled" or key=="auto_firewall" or key=="https" or key=="certificate_managed" then return enum(v,{"0","1"}) end
    if key=="certificate_mode" then return enum(v,{"auto","local"}) end
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
local PRIVATE = {dns_account={id="key_id",secret="secret",account_id="account_id",endpoint="endpoint"},
    ddns_rule={url="url"},web_rule={target="target"}}
local function parse(body, legacy)
    if type(body)~="string" or #body==0 then return nil,"Select a HomeGate configuration file" end
    if #body>262144 then return nil,"Configuration file is too large" end
    body=body:gsub("\r\n","\n")
    if body:find("[%z\1-\8\11-\31\127]") then return nil,"Invalid configuration framing" end
    local doc,names,meta={}, {}, {}
    local private, package_seen={},false
    local current,line_number=nil,0
    for line in (body.."\n"):gmatch("(.-)\n") do
        line_number=line_number+1
        if line_number>8192 or #line>4096 then return nil,"Configuration line limit exceeded" end
        local key,value=line:match("^# ([a-z0-9%-]+): (.-)$")
        if key and (key=="homegate-backup-format" or key=="plugin" or key=="schema" or key=="secrets") then
            if legacy then return nil,"Backup metadata is not a legacy configuration" end
            if current or meta[key] then return nil,"Duplicate or misplaced backup metadata" end
            meta[key]=value
        else
            local t=tokens(line)
            if not t then return nil,"Invalid configuration syntax" end
            if #t>0 then
                if legacy and t[1]=="package" then
                    if #t~=2 or t[2]~="homegate" or current or package_seen then return nil,"Invalid legacy package" end
                    package_seen=true
                elseif #t~=3 then return nil,"Named sections and three-token directives are required"
                elseif t[1]=="config" then
                    if not FIELDS[t[2]] or not id(t[3]) or names[t[3]] or (t[2]=="homegate" and t[3]~="main") then return nil,"Invalid or duplicate configuration section" end
                    if #doc>=128 then return nil,"Too many configuration sections" end
                    current={kind=t[2],name=t[3],values={}}; doc[#doc+1]=current; names[t[3]]=true
                elseif t[1]=="option" or t[1]=="list" then
                    if not current then return nil,"Option has no configuration section" end
                    local field=t[2]
                    if legacy and current.kind=="certificate" and field=="domain" then field="domains" end
                    local slot=legacy and PRIVATE[current.kind] and PRIVATE[current.kind][field]
                    if slot then
                        if t[1]~="option" or current.values[field]~=nil or private[current.name..":"..slot]~=nil then return nil,"Duplicate or invalid private field" end
                        if #t[3]>4096 or not utf8(t[3]) then return nil,"Invalid private field" end
                        private[current.name..":"..slot]={section=current,slot=slot,value=t[3]}
                    elseif not KEYS[current.kind][field] then return nil,"Unknown or private configuration field"
                    elseif t[1]=="list" then
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
    if legacy then
        for _,s in ipairs(doc) do
            if s.kind=="ddns_rule" then
                local zone,host=s.values.zone,s.values.host
                if host=="" then s.values.host="@"; host="@" end
                if zone and host and host~="" and host~="@" and host~=zone and host:sub(-(#zone+1))~="."..zone then s.values.host=host.."."..zone end
            end
        end
        local normalized,err=normalize(doc)
        if not normalized then return nil,err end
        local slots={}
        for _,p in pairs(private) do
            if p.value~="" then
                local s=p.section
                local namespace=s.kind=="dns_account" and s.values.provider or (s.kind=="ddns_rule" and "ddns" or "web")
                slots[namespace.."."..s.name.."."..p.slot]=p.value
            end
        end
        return normalized,slots
    elseif meta["homegate-backup-format"]=="2" then
        if meta.plugin~="homegate" or meta.schema~="public-uci-v1" or meta.secrets~="omitted" then return nil,"Wrong plugin or unsupported backup schema" end
    elseif meta["homegate-backup-format"]=="1" then
        if meta.secrets~="omitted" or meta.plugin or meta.schema then return nil,"Invalid legacy public backup metadata" end
    else return nil,"Unsupported HomeGate backup format" end
    return normalize(doc)
end
function M.parse(body) return parse(body,false) end
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
-- Canonical public bytes used by the isolated transaction store as well as
-- LuCI. Reparse the generated document so expansion cannot bypass file limits.
function M.canonical(body)
    local doc,err=M.parse(body)
    if not doc then return nil,err end
    local result=serialize(doc)
    local checked,limit_error=M.parse(result)
    if not checked then return nil,limit_error end
    return result
end
-- Internal migration preparation only. Never called by a Web route or public
-- backup importer. Private values stay in the caller's restricted file store.
function M.migration(body)
    local doc,slots=parse(body,true)
    if not doc then return nil,"Legacy configuration cannot be migrated safely" end
    local result=serialize(doc)
    if not M.parse(result) then return nil,"Legacy configuration exceeds public limits" end
    return result,slots
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

end
module("luci.controller.homegate", package.seeall)

local PROD_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
local STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
local CERT_ENV_PRODUCTION = "production"
local CERT_ENV_STAGING = "staging"
local DEFAULT_CA = "letsencrypt"

local function core_catalog(command, field)
    local out = require("luci.sys").exec("/usr/bin/homegate " .. command .. " 2>/dev/null") or ""
    local ok_json, jsonc = pcall(require, "luci.jsonc")
    if not ok_json or not jsonc then return {} end
    local report = jsonc.parse(out)
    if type(report) ~= "table" or report.ok ~= true or type(report[field]) ~= "table" then return {} end
    return report[field]
end

local function dns_provider_catalog()
    return core_catalog("dns-provider-catalog", "providers")
end

local function acme_ca_catalog()
    return core_catalog("acme-ca-catalog", "cas")
end

local ACCESS_REGIONS = {
    { key = "CN", label = "China / Mainland" }
}
local ACCESS_REGION_KEYS = {}
for _, region in ipairs(ACCESS_REGIONS) do ACCESS_REGION_KEYS[region.key] = true end

function index()
    local root = entry({"admin", "services", "homegate"},
        alias("admin", "services", "homegate", "overview"), _("HomeGate"), 56)
    root.dependent = true
    entry({"admin", "services", "homegate", "overview"}, call("action_overview"), _("Overview"), 10).leaf = true
    entry({"admin", "services", "homegate", "settings"}, alias("admin", "services", "homegate", "settings", "basic"), _("Settings"), 20)
    entry({"admin", "services", "homegate", "settings", "basic"}, call("action_basic"), _("Basic Settings"), 10).leaf = true
    entry({"admin", "services", "homegate", "settings", "public"}, call("action_public"), _("Public Services"), 20).leaf = true
    entry({"admin", "services", "homegate", "settings", "wol"}, call("action_wol"), _("Wake-on-LAN"), 30).leaf = true
    entry({"admin", "services", "homegate", "maintenance"}, call("action_maintenance"), _("Maintenance"), 30).leaf = true
    -- Keep old read routes for the RPC bridge and saved bookmarks, without menu titles.
    entry({"admin", "services", "homegate", "basic"}, call("action_basic"), nil).leaf = true
    entry({"admin", "services", "homegate", "public"}, call("action_public"), nil).leaf = true
    entry({"admin", "services", "homegate", "wol"}, call("action_wol"), nil).leaf = true

    entry({"admin", "services", "homegate", "basic_apply"},
        post("action_basic_apply")).leaf = true
    entry({"admin", "services", "homegate", "public_apply"},
        post("action_public_apply")).leaf = true
    entry({"admin", "services", "homegate", "public_account_apply"},
        post("action_public_account_apply")).leaf = true
    entry({"admin", "services", "homegate", "certificate_apply"},
        post("action_public_certificate_apply")).leaf = true
    entry({"admin", "services", "homegate", "public_action"},
        post("action_public_action")).leaf = true
    entry({"admin", "services", "homegate", "access_update"},
        post("action_access_update")).leaf = true
    entry({"admin", "services", "homegate", "access_clear_all"},
        post("action_access_clear_all")).leaf = true
    entry({"admin", "services", "homegate", "access_clear_entry"},
        post("action_access_clear_entry")).leaf = true
    entry({"admin", "services", "homegate", "access_clear_denied"},
        post("action_access_clear_denied")).leaf = true
    entry({"admin", "services", "homegate", "access_delete_all"},
        post("action_access_delete_all")).leaf = true
    entry({"admin", "services", "homegate", "access_delete_entry"},
        post("action_access_delete_entry")).leaf = true
    entry({"admin", "services", "homegate", "access_delete_rule"},
        post("action_access_delete_rule")).leaf = true
    entry({"admin", "services", "homegate", "wol_apply"},
        post("action_wol_apply")).leaf = true
    entry({"admin", "services", "homegate", "wol_action"},
        post("action_wol_action")).leaf = true
    entry({"admin", "services", "homegate", "maintenance_apply"},
        post("action_maintenance_apply")).leaf = true
    entry({"admin", "services", "homegate", "log_clear"},
        post("action_log_clear")).leaf = true
    entry({"admin", "services", "homegate", "config_export"},
        post("action_config_export")).leaf = true
    entry({"admin", "services", "homegate", "config_import"},
        post("action_config_import")).leaf = true
    entry({"admin", "services", "homegate", "config_reset"},
        post("action_config_reset")).leaf = true
    entry({"admin", "services", "homegate", "diagnostic_download"},
        post("action_diagnostic_download")).leaf = true

    -- Compatibility aliases for bookmarks from earlier 0.5.x UI candidates.
    entry({"admin", "services", "homegate", "domain"},
        call("action_legacy_public_redirect"), nil).leaf = true
    entry({"admin", "services", "homegate", "web"},
        call("action_legacy_public_redirect"), nil).leaf = true

    local api = entry({"admin", "services", "homegate", "api"}, firstchild(), nil)
    api.dependent = false
    api.leaf = false
    entry({"admin", "services", "homegate", "api", "status"}, call("api_status")).leaf = true
    entry({"admin", "services", "homegate", "api", "version"}, call("api_version")).leaf = true
    entry({"admin", "services", "homegate", "api", "network"}, call("api_network")).leaf = true
    entry({"admin", "services", "homegate", "api", "ddns"}, call("api_ddns")).leaf = true
    entry({"admin", "services", "homegate", "api", "dns_zones"}, call("api_dns_zones")).leaf = true
    entry({"admin", "services", "homegate", "api", "certs"}, call("api_certs")).leaf = true
    entry({"admin", "services", "homegate", "api", "proxy"}, call("api_proxy")).leaf = true
    entry({"admin", "services", "homegate", "api", "firewall"}, call("api_firewall")).leaf = true
    entry({"admin", "services", "homegate", "api", "wol"}, call("api_wol")).leaf = true
    entry({"admin", "services", "homegate", "api", "logs"}, call("api_logs")).leaf = true
    entry({"admin", "services", "homegate", "api", "log_events"}, call("api_log_events")).leaf = true
    entry({"admin", "services", "homegate", "api", "access_recent"}, call("api_access_recent")).leaf = true
end

local function http()
    return require "luci.http"
end

local function dispatcher()
    return require "luci.dispatcher"
end

local function uci_cursor()
    return require("luci.model.uci").cursor()
end

local function sys()
    return require "luci.sys"
end

local function lan_interface_inventory()
    local entries, seen, bridges = {}, {}, {}
    local function add(name, parent, kind)
        name = tostring(name or ""):match("^%s*(.-)%s*$") or ""
        parent = tostring(parent or ""):match("^%s*(.-)%s*$") or ""
        if name == "" or not name:match("^[%w%._:%-]+$") or seen[name] then return end
        seen[name] = true
        entries[#entries + 1] = {name = name, parent = parent, kind = kind or "ethernet"}
        if kind == "bridge" then bridges[#bridges + 1] = name end
    end

    -- Enumerate bridge-scoped interfaces only, so detached WAN/IPTV/loopback
    -- devices are not mixed into the WOL selector.  Classify members from
    -- sysfs capabilities instead of interface-name prefixes: QSDK commonly
    -- uses ath*, mac80211 may use wlan*/phy*-ap*, and other vendors use yet
    -- different names.
    local raw = sys().exec([[for b in /sys/class/net/*; do
        [ -d "$b/bridge" ] || continue
        bn="${b##*/}"
        echo "B|$bn"
        for m in "$b"/brif/*; do
            [ -e "$m" ] || continue
            mn="${m##*/}"
            if [ -d "/sys/class/net/$mn/wireless" ] || \
               [ -e "/sys/class/net/$mn/phy80211" ] || \
               grep -q '^DEVTYPE=wlan$' "/sys/class/net/$mn/uevent" 2>/dev/null || \
               { command -v iwinfo >/dev/null 2>&1 && iwinfo "$mn" info >/dev/null 2>&1; } || \
               { command -v iwconfig >/dev/null 2>&1 && iwconfig "$mn" 2>/dev/null | grep -q 'IEEE 802.11'; }; then
                kind="wifi"
            else
                kind="ethernet"
            fi
            echo "M|$bn|$mn|$kind"
        done
    done 2>/dev/null]]) or ""
    for line in raw:gmatch("[^\r\n]+") do
        local bridge = line:match("^B|([^|]+)$")
        if bridge then
            add(bridge, "", "bridge")
        else
            local parent, member, kind = line:match("^M|([^|]+)|([^|]+)|([^|]+)$")
            if parent and member then add(member, parent, kind == "wifi" and "wifi" or "ethernet") end
        end
    end
    if #entries == 0 then add("br-lan", "", "bridge") end

    local rank = {bridge = 1, ethernet = 2, wifi = 3}
    table.sort(entries, function(a, b)
        if a.name == "br-lan" then return b.name ~= "br-lan" end
        if b.name == "br-lan" then return false end
        local ar, br = rank[a.kind] or 9, rank[b.kind] or 9
        if ar ~= br then return ar < br end
        if a.parent ~= b.parent then return a.parent < b.parent end
        return a.name < b.name
    end)
    table.sort(bridges, function(a, b)
        if a == "br-lan" then return b ~= "br-lan" end
        if b == "br-lan" then return false end
        return a < b
    end)
    return entries, seen, bridges
end

local function wol_interfaces(current)
    local entries, seen = lan_interface_inventory()
    current = tostring(current or ""):match("^%s*(.-)%s*$") or ""
    local selected = seen[current] and current or (entries[1] and entries[1].name) or "br-lan"
    return entries, selected
end

local function is_lan_interface(ifname)
    ifname = tostring(ifname or "")
    if ifname == "" or not ifname:match("^[%w%._:%-]+$") then return false end
    local _, seen = lan_interface_inventory()
    return seen[ifname] == true
end

local function trim(v)
    if v == nil then return "" end
    return tostring(v):match("^%s*(.-)%s*$") or ""
end

local function bool_value(v)
    v = trim(v):lower()
    return v == "1" or v == "true" or v == "yes" or v == "on"
end

local function checked(name)
    return http().formvalue(name) ~= nil
end

local function safe_id(v)
    v = trim(v)
    if v ~= "" and v:match("^[%w_%-]+$") then return v end
    return ""
end

local function catalog_entry(entries, name)
    name = trim(name):lower()
    for _, row in ipairs(entries or {}) do
        if trim(row.name):lower() == name then return row end
        for _, alias in ipairs(row.aliases or {}) do
            if trim(alias):lower() == name then return row end
        end
    end
    return nil
end

local function provider_definition(provider, catalog)
    return catalog_entry(catalog or dns_provider_catalog(), provider)
end

local function provider_name(provider, catalog)
    local def = provider_definition(provider, catalog)
    return def and trim(def.name):lower() or ""
end

local function provider_display_name(provider, catalog)
    local def = provider_definition(provider, catalog)
    if not def then return trim(provider) ~= "" and trim(provider) or "DNS" end
    local label = trim(def.display_name)
    return label ~= "" and label or trim(def.name)
end

local function dns_account_raw(cur, id)
    id = safe_id(id)
    if id == "" then return nil end
    local s = cur:get_all("homegate", id)
    if not s or s[".type"] ~= "dns_account" then return nil end
    return {
        id = trim(s.id),
        key_id = trim(s.id),
        secret = trim(s.secret),
        account_id = trim(s.account_id),
        endpoint = trim(s.endpoint),
        provider = trim(s.provider):lower(),
        name = trim(s.name),
        section_id = id
    }
end

local function dns_account_values_from_form(h)
    return {
        provider = trim(h.formvalue("provider")):lower(),
        key_id = trim(h.formvalue("key_id")),
        secret = trim(h.formvalue("secret")),
        account_id = trim(h.formvalue("provider_account_id")),
        endpoint = trim(h.formvalue("endpoint"))
    }
end

local function credential_value(values, name)
    if name == "key_id" then return trim(values.key_id) end
    if name == "secret" then return trim(values.secret) end
    if name == "account_id" then return trim(values.account_id) end
    if name == "endpoint" then return trim(values.endpoint) end
    return ""
end

local function validate_dns_account_values(values, existing, catalog)
    values.provider = provider_name(values.provider ~= "" and values.provider or "aliyun", catalog)
    if values.provider == "" then return nil, "Unsupported DNS provider" end
    local def = provider_definition(values.provider, catalog)
    if not def then return nil, "Unsupported DNS provider" end
    for _, field in ipairs(def.credentials or {}) do
        if field.required then
            local value = credential_value(values, trim(field.name))
            if trim(field.name) == "secret" and value == "" and existing then
                value = trim(existing.secret)
            end
            if value == "" then
                local label = trim(field.label)
                if label == "" then label = trim(field.name) end
                return nil, label .. " is required"
            end
        end
    end
    return def, nil
end

local function ca_definition(ca, catalog)
    ca = trim(ca):lower()
    if ca == "" then ca = DEFAULT_CA end
    for _, row in ipairs(catalog or acme_ca_catalog()) do
        if trim(row.name):lower() == ca then return row end
    end
    return nil
end

local function normalize_ca_selection(ca, environment, catalog)
    ca = trim(ca):lower()
    if ca == "" then ca = DEFAULT_CA end
    local def = ca_definition(ca, catalog)
    if not def then return nil, nil, nil, "Unsupported certificate authority" end
    environment = trim(environment):lower()
    if environment == "" then environment = CERT_ENV_PRODUCTION end
    if environment ~= CERT_ENV_PRODUCTION and environment ~= CERT_ENV_STAGING then
        return nil, nil, nil, "Invalid certificate environment"
    end
    if type(def.directories) ~= "table" or trim(def.directories[environment]) == "" then
        return nil, nil, nil, "Certificate authority does not support the selected environment"
    end
    return ca, environment, def, nil
end

local function parse_int(name, default, minv, maxv)
    local raw = trim(http().formvalue(name))
    if raw == "" then return default end
    local n = tonumber(raw)
    if not n or n ~= math.floor(n) or n < minv or n > maxv then
        return nil, "Invalid numeric value"
    end
    return n
end

local function csrf_token()
    local d = dispatcher()
    return d.context and (d.context.authtoken or d.context.authsession) or ""
end

local function page_url(page, params)
    local base = dispatcher().build_url("admin", "services", "homegate", page)
    if not params then return base end
    local parts = {}
    local h = http()
    for k, v in pairs(params) do
        if v ~= nil and tostring(v) ~= "" then
            parts[#parts + 1] = h.urlencode(tostring(k)) .. "=" .. h.urlencode(tostring(v))
        end
    end
    table.sort(parts)
    if #parts > 0 then return base .. "?" .. table.concat(parts, "&") end
    return base
end

local function redirect_page(page, notice, err, extra)
    local params = {}
    for k, v in pairs(extra or {}) do params[k] = v end
    params.notice = notice
    params.error = err
    http().redirect(page_url(page, params))
end

local function render(name, data)
    data = data or {}
    data.token = csrf_token()
    data.notice = trim(http().formvalue("notice"))
    data.error_message = trim(http().formvalue("error"))
    require("luci.template").render("homegate/" .. name, data)
end

local function get_sections(cur, stype)
    local out = {}
    cur:foreach("homegate", stype, function(s)
        local row = {}
        for k, v in pairs(s) do row[k] = v end
        if stype == "dns_account" then
            row.key_id = row.id
            row.secret = nil
        end
        row.id = s[".name"]
        out[#out + 1] = row
    end)
    table.sort(out, function(a, b)
        local ak = trim(a.name ~= "" and a.name or a.domain ~= "" and a.domain or a.id)
        local bk = trim(b.name ~= "" and b.name or b.domain ~= "" and b.domain or b.id)
        return ak < bk
    end)
    return out
end

local function get_section(cur, id, expected_type)
    id = safe_id(id)
    if id == "" then return nil end
    local s = cur:get_all("homegate", id)
    if not s or (expected_type and s[".type"] ~= expected_type) then return nil end
    if expected_type == "dns_account" then
        s.key_id = s.id
        s.secret = nil
    end
    s.id = id
    return s
end

local function random_id(cur, prefix)
    for _ = 1, 4 do
        local f = io.open("/proc/sys/kernel/random/uuid", "r")
        local raw = f and f:read("*l") or ""
        if f then f:close() end
        raw = trim(raw):gsub("[^%x]", "")
        if #raw >= 12 then
            local id = prefix .. "_" .. raw:sub(1, 12)
            if not cur:get_all("homegate", id) then return id end
        end
    end
    local fallback = prefix .. "_" .. tostring(os.time()) .. tostring(math.random(1000, 9999))
    return fallback:gsub("[^%w_%-]", "")
end


local function upsert_section(cur, stype, id, values)
    local current = cur:get_all("homegate", id)
    if current then
        if current[".type"] ~= stype then return false, "UCI section type mismatch" end
        for k, v in pairs(values or {}) do
            cur:set("homegate", id, k, v)
        end
        return true
    end
    local created, err = cur:section("homegate", stype, id, values or {})
    if not created then return false, err or "Unable to create UCI section" end
    return true
end

local function commit(cur)
    if cur:commit("homegate") == false then
        return false, "UCI commit failed"
    end
    return true
end

local function apply_homegate()
    local rc = sys().call("/etc/init.d/homegate reload >/dev/null 2>&1")
    if rc ~= 0 then return false, "HomeGate reload failed" end
    return true
end

local function finish_save(cur, page, mode)
    local ok, err = commit(cur)
    if not ok then return redirect_page(page, nil, err) end
    if mode == "apply" then
        local applied, apply_err = apply_homegate()
        if not applied then return redirect_page(page, nil, apply_err) end
        return redirect_page(page, "Saved and applied")
    end
    return redirect_page(page, "Saved")
end

local function normalize_mac(v)
    local hex = trim(v):gsub("[:-]", ""):upper()
    if #hex ~= 12 or not hex:match("^%x+$") then return nil end
    return table.concat({
        hex:sub(1, 2), hex:sub(3, 4), hex:sub(5, 6),
        hex:sub(7, 8), hex:sub(9, 10), hex:sub(11, 12)
    }, ":")
end

local function wol_client_candidates(cur)
    local _, allowed = lan_interface_inventory()
    local names, ips, live, local_macs = {}, {}, {}, {}

    local function valid_unicast(mac)
        mac = normalize_mac(mac or "")
        if not mac then return nil end
        local first = tonumber(mac:sub(1, 2), 16) or 0
        if first % 2 == 1 or mac == "00:00:00:00:00:00" or mac == "FF:FF:FF:FF:FF:FF" then return nil end
        return mac
    end

    -- Do not offer the router's own interface addresses as wake targets.
    local own = sys().exec("cat /sys/class/net/*/address 2>/dev/null") or ""
    for raw in own:gmatch("[^\r\n]+") do
        local mac = valid_unicast(raw)
        if mac then local_macs[mac] = true end
    end

    local function remember(mac_raw, dev, ip)
        local mac = valid_unicast(mac_raw)
        dev = trim(dev)
        if not mac or local_macs[mac] or not allowed[dev] then return end
        live[mac] = true
        ip = trim(ip)
        if ip ~= "" and not ips[mac] then ips[mac] = ip end
    end

    -- IPv4 ARP cache is widely available even on older QWRT builds.
    local arp = io.open("/proc/net/arp", "r")
    if arp then
        for line in arp:lines() do
            local ip, hwtype, flags, mac, mask, dev = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
            if ip and flags and flags ~= "0x0" then remember(mac, dev, ip) end
        end
        arp:close()
    end

    -- Supplement with IPv4/IPv6 neighbour entries, excluding failed probes.
    local neigh = sys().exec("ip neigh show 2>/dev/null") or ""
    for line in neigh:gmatch("[^\r\n]+") do
        if not line:match("%sFAILED%s*$") and not line:match("%sINCOMPLETE%s*$") then
            local ip = line:match("^(%S+)") or ""
            local dev = line:match("%sdev%s+(%S+)") or ""
            local mac = line:match("%slladdr%s+(%S+)") or ""
            remember(mac, dev, ip)
        end
    end

    -- The bridge FDB can reveal currently learned L2 clients even before an
    -- ARP/ND entry exists. Ignore permanent/self entries belonging to the router.
    local fdb = sys().exec("bridge fdb show 2>/dev/null") or ""
    for line in fdb:gmatch("[^\r\n]+") do
        if not line:match("%spermanent%s") and not line:match("%sself%s") then
            local mac = line:match("^(%S+)") or ""
            local dev = line:match("%sdev%s+(%S+)") or ""
            remember(mac, dev, "")
        end
    end

    -- Dynamic DHCP lease names provide the best human-readable labels.
    local lease = io.open("/tmp/dhcp.leases", "r")
    if lease then
        for line in lease:lines() do
            local _, raw_mac, ip, hostname = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
            local mac = normalize_mac(raw_mac or "")
            hostname = trim(hostname)
            if mac then
                if hostname ~= "" and hostname ~= "*" then names[mac] = hostname end
                if trim(ip) ~= "" and not ips[mac] then ips[mac] = trim(ip) end
            end
        end
        lease:close()
    end

    -- Static DHCP host entries override lease names when configured.
    cur:foreach("dhcp", "host", function(s)
        local hostname = trim(s.name or s.hostname)
        local macs = s.mac
        if type(macs) ~= "table" then macs = {macs} end
        for _, raw_mac in ipairs(macs) do
            local mac = normalize_mac(raw_mac or "")
            if mac and hostname ~= "" then names[mac] = hostname end
        end
    end)

    local out = {}
    for mac in pairs(live) do
        local name = trim(names[mac])
        local ip = trim(ips[mac])
        local suffix = name ~= "" and name or ip
        out[#out + 1] = {
            mac = mac,
            name = name,
            ip = ip,
            label = suffix ~= "" and (mac .. " (" .. suffix .. ")") or mac
        }
    end
    table.sort(out, function(a, b)
        local an, bn = a.name ~= "", b.name ~= ""
        if an ~= bn then return an end
        return a.label:lower() < b.label:lower()
    end)
    return out
end

local function detected_name_for_mac(cur, mac)
    mac = normalize_mac(mac or "")
    if not mac then return "" end
    for _, row in ipairs(wol_client_candidates(cur)) do
        if row.mac == mac then return trim(row.name) end
    end
    return ""
end

local function full_domain(zone, host)
    zone = trim(zone):lower():gsub("%.$", "")
    host = trim(host):lower():gsub("%.$", "")
    if host == "" or host == "@" then return zone end
    if host == zone or host:sub(-(#zone + 1)) == "." .. zone then return host end
    return host .. "." .. zone
end

local function certificate_source(c)
    local source = trim(c and c.source or ""):lower()
    if source == "local" then return "local" end
    return "acme"
end

local function certificate_ca(c)
    local ca = trim(c and c.ca or ""):lower()
    if ca == "" then return DEFAULT_CA end
    return ca
end

local function certificate_environment(c)
    local environment = trim(c and c.environment or ""):lower()
    if environment == CERT_ENV_STAGING then return CERT_ENV_STAGING end
    -- Certificates created before 1.1.0 are Let's Encrypt production by
    -- definition. Never inherit the legacy global main.acme_directory value.
    return CERT_ENV_PRODUCTION
end

local function certificate_environment_from_form(value)
    value = trim(value):lower()
    if value == CERT_ENV_PRODUCTION or value == PROD_DIRECTORY then return CERT_ENV_PRODUCTION end
    if value == CERT_ENV_STAGING or value == STAGING_DIRECTORY then return CERT_ENV_STAGING end
    return nil
end

local function certificate_acme_matches(c, ca, environment)
    if certificate_source(c) ~= "acme" then return false end
    ca = trim(ca):lower()
    if ca == "" then ca = DEFAULT_CA end
    environment = certificate_environment_from_form(environment) or CERT_ENV_PRODUCTION
    return certificate_ca(c) == ca and certificate_environment(c) == environment
end

local function certificate_domains(c)
    local out = {}
    if not c then return out end
    local raw = c.domains or c.domain
    if type(raw) == "table" then
        for _, d in ipairs(raw) do
            d = trim(d):lower():gsub("%.$", "")
            if d ~= "" then out[#out + 1] = d end
        end
    else
        for d in trim(raw):gmatch("[^,%s]+") do
            d = trim(d):lower():gsub("%.$", "")
            if d ~= "" then out[#out + 1] = d end
        end
    end
    return out
end

local function valid_dns_name(name)
    name = trim(name):lower():gsub("%.$", "")
    if name == "" or #name > 253 or name:sub(1, 1) == "." or name:sub(-1) == "." then return false end
    for label in name:gmatch("[^%.]+") do
        if #label > 63 then return false end
        if not label:match("^[a-z0-9]$") and not label:match("^[a-z0-9][a-z0-9%-]*[a-z0-9]$") then
            return false
        end
    end
    return not name:find("%.%.", 1, false)
end

local function parse_certificate_domains(raw)
    local out, seen = {}, {}
    for value in trim(raw):gmatch("[^,%s]+") do
        local pattern = trim(value):lower():gsub("%.$", "")
        if pattern ~= "" then
            local base = pattern
            if pattern:sub(1, 2) == "*." then
                base = pattern:sub(3)
            elseif pattern:find("*", 1, true) then
                return nil, "Wildcard is only supported as the left-most *. label"
            end
            if not valid_dns_name(base) then
                return nil, "Invalid certificate domain: " .. pattern
            end
            if not seen[pattern] then
                seen[pattern] = true
                out[#out + 1] = pattern
            end
        end
    end
    if #out == 0 then return nil, "At least one certificate domain is required" end
    table.sort(out)
    return out
end

local function certificate_pattern_in_zone(pattern, zone)
    pattern = trim(pattern):lower():gsub("%.$", "")
    zone = trim(zone):lower():gsub("%.$", "")
    if pattern:sub(1, 2) == "*." then pattern = pattern:sub(3) end
    if pattern == zone then return true end
    return #pattern > #zone and pattern:sub(-(#zone + 1)) == "." .. zone
end

local function same_certificate_domains(a, b)
    local aa, bb = {}, {}
    for _, d in ipairs(a or {}) do aa[#aa + 1] = trim(d):lower():gsub("%.$", "") end
    for _, d in ipairs(b or {}) do bb[#bb + 1] = trim(d):lower():gsub("%.$", "") end
    table.sort(aa); table.sort(bb)
    if #aa ~= #bb then return false end
    for i = 1, #aa do if aa[i] ~= bb[i] then return false end end
    return true
end

local function certificate_files_exist(id)
    id = safe_id(id)
    if id == "" then return false end
    local ok, fs = pcall(require, "nixio.fs")
    return ok and fs and fs.stat("/etc/homegate/certs/" .. id .. "/fullchain.pem") ~= nil
end

local function certificate_covers(c, domain)
    domain = trim(domain):lower():gsub("%.$", "")
    if domain == "" then return false end
    for _, pattern in ipairs(certificate_domains(c)) do
        if pattern == domain then return true end
        if pattern:sub(1, 2) == "*." then
            local suffix = pattern:sub(2)
            if domain:sub(-#suffix) == suffix then
                local label = domain:sub(1, #domain - #suffix)
                if label ~= "" and not label:find("%.") then return true end
            end
        end
    end
    return false
end

local function local_certificate_core_import(home_dir, id, cert_pem, key_pem)
    cert_pem, key_pem = tostring(cert_pem or ""), tostring(key_pem or "")
    if cert_pem == "" or key_pem == "" then return nil, "Certificate and private key files are required" end
    if #cert_pem > 524288 or #key_pem > 524288 then return nil, "Certificate or private key file is too large" end
    id = safe_id(id)
    if id == "" then return nil, "Invalid local certificate id" end
    local ok_fs, fs = pcall(require, "nixio.fs")
    if not ok_fs or not fs then return nil, "Filesystem support is unavailable" end
    local suffix = tostring(os.time()) .. tostring(math.random(100000, 999999))
    local cert_path = "/tmp/homegate-local-cert-" .. suffix .. ".pem"
    local key_path = "/tmp/homegate-local-key-" .. suffix .. ".pem"
    local function cleanup()
        os.remove(cert_path)
        os.remove(key_path)
        if home_dir and home_dir ~= "" and home_dir:match("^/tmp/homegate%-local%-validate%-%d+$") then
            sys().call("rm -rf " .. home_dir .. " >/dev/null 2>&1")
        end
    end
    local cf = io.open(cert_path, "w")
    if not cf then return nil, "Unable to create temporary certificate file" end
    cf:write(cert_pem); cf:close(); fs.chmod(cert_path, 384)
    local kf = io.open(key_path, "w")
    if not kf then os.remove(cert_path); return nil, "Unable to create temporary private key file" end
    kf:write(key_pem); kf:close(); fs.chmod(key_path, 384)
    local prefix = ""
    if home_dir and home_dir ~= "" then prefix = "HOMEGATE_HOME_DIR=" .. home_dir .. " " end
    local out = sys().exec(prefix .. "/usr/bin/homegate cert-import " .. id .. " " .. cert_path .. " " .. key_path .. " 2>/dev/null") or ""
    cleanup()
    local ok_json, jsonc = pcall(require, "luci.jsonc")
    if not ok_json or not jsonc then return nil, "JSON support is unavailable" end
    local report = jsonc.parse(out)
    if type(report) ~= "table" or report.ok ~= true or type(report.domains) ~= "table" or #report.domains == 0 then
        local err = type(report) == "table" and trim(report.error) or ""
        return nil, err ~= "" and err or "Local certificate validation failed"
    end
    local domains = {}
    for _, d in ipairs(report.domains) do domains[#domains + 1] = trim(d):lower():gsub("%.$", "") end
    table.sort(domains)
    return {domains = domains, expires = trim(report.expires), id = id}, nil
end

local function validate_local_certificate(cert_pem, key_pem)
    local suffix = tostring(os.time()) .. tostring(math.random(100000, 999999))
    local home_dir = "/tmp/homegate-local-validate-" .. suffix
    return local_certificate_core_import(home_dir, "cert_validate", cert_pem, key_pem)
end

local function install_local_certificate(id, cert_pem, key_pem)
    return local_certificate_core_import(nil, id, cert_pem, key_pem)
end

local function cleanup_local_certificate_files(id)
    id = safe_id(id)
    if id ~= "" then sys().call("rm -rf /etc/homegate/certs/" .. id .. " >/dev/null 2>&1") end
end

local function certificate_exact_covers(c, domain)
    domain = trim(domain):lower():gsub("%.$", "")
    if domain == "" then return false end
    for _, pattern in ipairs(certificate_domains(c)) do
        if pattern == domain then return true end
    end
    return false
end

local function package_field(pkg, field)
    local allowed = {
        homegate = true,
        ["luci-app-homegate"] = true,
        ["luci-i18n-homegate-zh-cn"] = true
    }
    if not allowed[pkg] then return "-" end
    local raw = sys().exec("opkg status " .. pkg .. " 2>/dev/null") or ""
    local value = raw:match("\n" .. field .. ":%s*([^\r\n]+)") or raw:match("^" .. field .. ":%s*([^\r\n]+)")
    return trim(value) ~= "" and trim(value) or "-"
end

local function package_info()
    local core_version = package_field("homegate", "Version")
    -- Show the exact installed build, including the maintenance release suffix.
    local product_version = core_version
    return {
        product = product_version,
        core = core_version,
        luci = package_field("luci-app-homegate", "Version"),
        i18n = package_field("luci-i18n-homegate-zh-cn", "Version"),
        arch = package_field("homegate", "Architecture")
    }
end

local function find_account_by_identity(cur, values, catalog)
    local def = provider_definition(values.provider, catalog)
    if not def then return nil end
    local identity = {}
    for _, field in ipairs(def.credentials or {}) do
        local name = trim(field.name)
        if field.required and field.secret ~= true then
            local value = credential_value(values, name)
            if value == "" then return nil end
            identity[#identity + 1] = {name = name, value = value}
        end
    end
    -- Token-only providers intentionally have no non-secret identity. Never
    -- compare or expose the secret merely to deduplicate accounts.
    if #identity == 0 then return nil end
    local found = nil
    cur:foreach("homegate", "dns_account", function(s)
        if found then return end
        local provider = provider_name(trim(s.provider) ~= "" and s.provider or "aliyun", catalog)
        if provider ~= trim(def.name):lower() then return end
        for _, item in ipairs(identity) do
            local actual = ""
            if item.name == "key_id" then actual = trim(s.id)
            elseif item.name == "account_id" then actual = trim(s.account_id)
            elseif item.name == "endpoint" then actual = trim(s.endpoint)
            end
            if actual ~= item.value then return end
        end
        found = s[".name"]
    end)
    return found
end

local function find_certificate_for_domain(cur, domain, wanted_source, wanted_environment, wanted_ca)
    local exact, wildcard = nil, nil
    cur:foreach("homegate", "certificate", function(s)
        if exact then return end
        if wanted_source and certificate_source(s) ~= wanted_source then return end
        if wanted_source == "acme" and (wanted_environment or wanted_ca) then
            if not certificate_acme_matches(s, wanted_ca or DEFAULT_CA, wanted_environment or CERT_ENV_PRODUCTION) then return end
        end
        local row = {}
        for k, v in pairs(s) do row[k] = v end
        row.id = s[".name"]
        if certificate_covers(row, domain) then
            local is_exact = false
            for _, d in ipairs(certificate_domains(row)) do
                if d == trim(domain):lower():gsub("%.$", "") then is_exact = true break end
            end
            if is_exact then exact = row else wildcard = wildcard or row end
        end
    end)
    return exact or wildcard
end

-- Automatic HTTPS is service-centric in the LuCI UI, but certificates remain
-- independent Core resources.  New automatic services use the nearest useful
-- shared scope: parent + one-label wildcard.  Example:
--   vault.chenos.cn     -> chenos.cn, *.chenos.cn
--   api.home.chenos.cn  -> home.chenos.cn, *.home.chenos.cn
-- Existing explicit certificate references are preserved by action_public_apply;
-- this helper is only used when a service needs a new/reusable automatic asset.
local function automatic_certificate_scope(zone, domain)
    zone = trim(zone):lower():gsub("%.$", "")
    domain = trim(domain):lower():gsub("%.$", "")
    if zone == "" or domain == "" then return nil, nil end
    local base = nil
    if domain == zone then
        base = zone
    elseif #domain > #zone and domain:sub(-(#zone + 1)) == "." .. zone then
        base = domain:match("^[^%.]+%.(.+)$")
    end
    if not base or base == "" or not certificate_pattern_in_zone(base, zone) then return nil, nil end
    return base, {base, "*." .. base}
end

local function certificate_has_pattern(c, wanted)
    wanted = trim(wanted):lower():gsub("%.$", "")
    for _, pattern in ipairs(certificate_domains(c)) do
        if pattern == wanted then return true end
    end
    return false
end

local function enabled_certificate_pattern_owner(cur, wanted, exclude_id)
    wanted = trim(wanted):lower():gsub("%.$", "")
    exclude_id = safe_id(exclude_id)
    local found = nil
    cur:foreach("homegate", "certificate", function(s)
        if found or not bool_value(s.enabled) or s[".name"] == exclude_id then return end
        local row = {}
        for k, v in pairs(s) do row[k] = v end
        row.id = s[".name"]
        if certificate_has_pattern(row, wanted) then found = row end
    end)
    return found
end

local function find_automatic_shared_certificate(cur, zone, domain, environment, ca)
    local base, wanted = automatic_certificate_scope(zone, domain)
    if not base then return nil end
    environment = certificate_environment_from_form(environment) or CERT_ENV_PRODUCTION
    ca = trim(ca):lower(); if ca == "" then ca = DEFAULT_CA end
    local exact_set, wildcard = nil, nil
    cur:foreach("homegate", "certificate", function(s)
        if exact_set or not bool_value(s.enabled) or not certificate_acme_matches(s, ca, environment) then return end
        local row = {}
        for k, v in pairs(s) do row[k] = v end
        row.id = s[".name"]
        if certificate_covers(row, domain) then
            if same_certificate_domains(certificate_domains(row), wanted) then
                exact_set = row
            elseif certificate_has_pattern(row, "*." .. base) then
                wildcard = wildcard or row
            end
        end
    end)
    return exact_set or wildcard
end

local function automatic_certificate_create_domains(cur, zone, domain, environment, ca)
    local base = automatic_certificate_scope(zone, domain)
    if not base then return nil end
    environment = certificate_environment_from_form(environment) or CERT_ENV_PRODUCTION
    ca = trim(ca):lower(); if ca == "" then ca = DEFAULT_CA end
    local wildcard = "*." .. base
    local base_owner = enabled_certificate_pattern_owner(cur, base, "")
    local wildcard_owner = enabled_certificate_pattern_owner(cur, wildcard, "")

    -- Certificate identities remain globally unique. Automatic mode may reuse
    -- an ACME owner only when the CA identity matches as well as the domain.
    local required_owner = domain == base and base_owner or wildcard_owner
    if required_owner then
        if certificate_acme_matches(required_owner, ca, environment) and certificate_covers(required_owner, domain) then
            return nil, required_owner
        end
        return nil, nil, required_owner
    end

    local domains = {}
    if not base_owner then domains[#domains + 1] = base end
    if not wildcard_owner then domains[#domains + 1] = wildcard end
    if #domains == 0 then return nil, nil end
    local proposed = {domains = table.concat(domains, ",")}
    if not certificate_covers(proposed, domain) then return nil, nil end
    return domains, nil
end

local function certificate_use_count(cur, id)
    id = safe_id(id)
    if id == "" then return 0 end
    local count = 0
    cur:foreach("homegate", "web_rule", function(s)
        if safe_id(s.certificate) == id then count = count + 1 end
    end)
    return count
end

local function account_use_count(cur, id)
    id = safe_id(id)
    if id == "" then return 0 end
    local count = 0
    cur:foreach("homegate", "ddns_rule", function(s)
        if safe_id(s.account) == id then count = count + 1 end
    end)
    cur:foreach("homegate", "certificate", function(s)
        if safe_id(s.account) == id then count = count + 1 end
    end)
    return count
end

local function mask_account_id(value)
    value = trim(value)
    if value == "" then return "-" end
    if #value <= 8 then return value end
    return value:sub(1, 4) .. "****" .. value:sub(-4)
end

local function account_choice_label(account, catalog)
    if not account then return "-" end
    local provider = provider_name(account.provider ~= "" and account.provider or "aliyun", catalog)
    if provider == "" then provider = trim(account.provider) end
    local display = provider_display_name(provider, catalog)
    local def = provider_definition(provider, catalog)
    local identity = ""
    if def then
        for _, field in ipairs(def.credentials or {}) do
            if field.secret ~= true then
                identity = credential_value(account, trim(field.name))
                if identity ~= "" then break end
            end
        end
    end
    if identity == "" then return display .. " · saved" end
    return display .. " · " .. mask_account_id(identity)
end

local function dns_account_choices(cur, catalog)
    catalog = catalog or dns_provider_catalog()
    local out = {}
    cur:foreach("homegate", "dns_account", function(s)
        local provider = provider_name(trim(s.provider) ~= "" and s.provider or "aliyun", catalog)
        local def = provider_definition(provider, catalog)
        if def then
            local account = {
                provider = provider,
                key_id = trim(s.id),
                account_id = trim(s.account_id),
                endpoint = trim(s.endpoint)
            }
            out[#out + 1] = {
                id = s[".name"],
                provider = provider,
                display_name = provider_display_name(provider, catalog),
                key_id = account.key_id,
                provider_account_id = account.account_id,
                endpoint = account.endpoint,
                key_masked = mask_account_id(account.key_id),
                label = account_choice_label(account, catalog),
                secret_saved = trim(cur:get("homegate", s[".name"], "secret")) ~= "",
                use_count = account_use_count(cur, s[".name"])
            }
        end
    end)
    table.sort(out, function(a, b)
        return trim(a.label):lower() < trim(b.label):lower()
    end)
    return out
end

local function certificate_choices(cur, provider_catalog)
    provider_catalog = provider_catalog or dns_provider_catalog()
    local main = cur:get_all("homegate", "main") or {}
    local default_renew = tonumber(main.renew_days or "30") or 30
    local out = {}
    cur:foreach("homegate", "certificate", function(s)
        local row = {}
        for k, v in pairs(s) do row[k] = v end
        row.id = s[".name"]
        row.source = certificate_source(row)
        row.ca = certificate_ca(row)
        row.environment = certificate_environment(row)
        row.domain_list = certificate_domains(row)
        row.domain_text = table.concat(row.domain_list, ", ")
        row.renew_days = tostring(tonumber(row.renew_days or "") or default_renew)
        row.use_count = certificate_use_count(cur, row.id)
        local account = dns_account_raw(cur, safe_id(row.account))
        row.account_label = account_choice_label(account, provider_catalog)
        out[#out + 1] = row
    end)
    table.sort(out, function(a, b)
        local ad = trim(a.domain_text ~= "" and a.domain_text or a.name or a.id)
        local bd = trim(b.domain_text ~= "" and b.domain_text or b.name or b.id)
        return ad:lower() < bd:lower()
    end)
    return out
end

local function public_services(cur)
    local ddns_by_domain, ddns_used, cert_by_id, rows, ddns_group_counts = {}, {}, {}, {}, {}
    local provider_catalog = dns_provider_catalog()
    local main = cur:get_all("homegate", "main") or {}
    local default_renew = tonumber(main.renew_days or "30") or 30
    local cert_use = {}
    cur:foreach("homegate", "web_rule", function(s)
        local cid = safe_id(s.certificate)
        if cid ~= "" then cert_use[cid] = (cert_use[cid] or 0) + 1 end
    end)
    cur:foreach("homegate", "ddns_rule", function(s)
        local d = trim(s.name)
        if d == "" then d = full_domain(s.zone, s.host) end
        d = d:lower():gsub("%.$", "")
        if d ~= "" then
            ddns_by_domain[d] = ddns_by_domain[d] or {}
            ddns_by_domain[d][#ddns_by_domain[d] + 1] = s[".name"]
        end
        local account_id = safe_id(s.account)
        local zone = trim(s.zone):lower():gsub("%.$", "")
        if account_id ~= "" and zone ~= "" then
            local key = account_id .. "|" .. zone
            ddns_group_counts[key] = (ddns_group_counts[key] or 0) + 1
        end
    end)
    cur:foreach("homegate", "certificate", function(s)
        local row = {}
        for k, v in pairs(s) do row[k] = v end
        row.id = s[".name"]
        cert_by_id[row.id] = row
    end)

    local function first_ddns(domain)
        local list = ddns_by_domain[domain] or {}
        for _, id in ipairs(list) do
            if not ddns_used[id] then ddns_used[id] = true return get_section(cur, id, "ddns_rule") end
        end
        return nil
    end

    local function make_row(domain, web, ddns)
        local account = ddns and get_section(cur, ddns.account, "dns_account") or nil
        local cert = nil
        if web and safe_id(web.certificate) ~= "" then cert = cert_by_id[safe_id(web.certificate)] end
        if not cert then cert = find_certificate_for_domain(cur, domain) end
        local zone = ddns and trim(ddns.zone) or (cert and trim(cert.zone) or "")
        local host = ddns and trim(ddns.host) or ""
        local cert_source = cert and certificate_source(cert) or "acme"
        local cert_mode = cert_source == "local" and "local" or "auto"
        local cert_managed = false
        if web then
            local explicit_managed = trim(web.certificate_managed)
            if explicit_managed ~= "" then
                cert_managed = bool_value(explicit_managed)
            elseif cert and (cert_use[cert.id] or 0) <= 1 and certificate_exact_covers(cert, domain) then
                -- Adopt legacy exact, single-service certificates into the new
                -- automatic-management UI so their renewal threshold remains
                -- editable. Wildcard/shared certificates stay reusable assets.
                cert_managed = true
            end
        end
        local delete_confirm = false
        if cert and (cert_use[cert.id] or 0) <= 1 then delete_confirm = true end
        if ddns then
            local group_key = safe_id(ddns.account) .. "|" .. trim(ddns.zone):lower():gsub("%.$", "")
            if (ddns_group_counts[group_key] or 0) <= 1 then delete_confirm = true end
        end
        rows[#rows + 1] = {
            id = web and web.id or (ddns and ddns.id or ""),
            web_id = web and web.id or "",
            ddns_id = ddns and ddns.id or "",
            account_id = ddns and safe_id(ddns.account) or "",
            cert_id = cert and cert.id or "",
            cert_mode = cert_mode,
            cert_source = cert_source,
            cert_ca = cert and certificate_ca(cert) or DEFAULT_CA,
            cert_environment = cert and certificate_environment(cert) or CERT_ENV_PRODUCTION,
            cert_managed = cert_managed,
            cert_renew_days = cert and tostring(tonumber(cert.renew_days or "") or default_renew) or tostring(default_renew),
            cert_shared = cert and (cert_use[cert.id] or 0) > 1 or false,
            delete_confirm = delete_confirm,
            enabled = web and (bool_value(web.enabled) and "1" or "0") or (ddns and (bool_value(ddns.enabled) and "1" or "0") or "0"),
            domain = domain,
            target = web and trim(web.target) or "",
            https = web and (bool_value(web.https) and "1" or "0") or "1",
            provider = account and provider_name(trim(account.provider) ~= "" and account.provider or "aliyun", provider_catalog) or "aliyun",
            key_id = account and trim(account.key_id) or "",
            provider_account_id = account and trim(account.account_id) or "",
            endpoint = account and trim(account.endpoint) or "",
            secret_saved = ddns and trim(ddns.account) ~= "" and trim(cur:get("homegate", ddns.account, "secret")) ~= "" or false,
            zone = zone,
            host = host,
            ttl = ddns and trim(ddns.ttl) or "600"
        }
    end

    cur:foreach("homegate", "web_rule", function(s)
        local web = {}
        for k, v in pairs(s) do web[k] = v end
        web.id = s[".name"]
        local domain = trim(web.domain):lower():gsub("%.$", "")
        make_row(domain, web, first_ddns(domain))
    end)
    cur:foreach("homegate", "ddns_rule", function(s)
        local id = s[".name"]
        if not ddns_used[id] then
            local ddns = get_section(cur, id, "ddns_rule")
            local domain = trim(ddns.name)
            if domain == "" then domain = full_domain(ddns.zone, ddns.host) end
            make_row(domain:lower():gsub("%.$", ""), nil, ddns)
            ddns_used[id] = true
        end
    end)
    table.sort(rows, function(a, b) return trim(a.domain) < trim(b.domain) end)
    return rows
end

local function account_in_use(cur, id)
    return account_use_count(cur, id) > 0
end

local function certificate_in_use(cur, id)
    return certificate_use_count(cur, id) > 0
end

local function run_core_json(command)
    local out = sys().exec("/usr/bin/homegate " .. command .. " 2>/dev/null") or ""
    local h = http()
    h.prepare_content("application/json")
    if trim(out) == "" then
        h.write('{"api_version":1,"ok":false,"error":"empty HomeGate response"}\n')
    else
        h.write(out)
    end
end

local function action_core(command)
    return sys().call("/usr/bin/homegate " .. command .. " >/dev/null 2>&1") == 0
end

local function access_region_supported(key)
    key = trim(key):upper()
    return key == "" or ACCESS_REGION_KEYS[key] == true
end

local function access_region_cache_updated(key)
    key = trim(key):upper()
    if key == "" or not ACCESS_REGION_KEYS[key] then return "" end
    local ok, fs = pcall(require, "nixio.fs")
    if not ok or not fs then return "" end
    local st = fs.stat("/etc/homegate/access/regions/" .. key .. ".cidr")
    local mtime = st and tonumber(st.mtime) or nil
    if not mtime or mtime <= 0 then return "" end
    return os.date("%Y/%m/%d", mtime)
end

local function access_region_choices()
    local out = {}
    for _, region in ipairs(ACCESS_REGIONS) do
        out[#out + 1] = {
            key = region.key,
            label = region.label,
            updated = access_region_cache_updated(region.key)
        }
    end
    return out
end

local function validate_access_allow(raw)
    raw = trim(raw)
    if #raw > 4096 then return false end
    if raw == "" then return true end
    local suffix = tostring(os.time()) .. tostring(math.random(1000, 9999))
    local path = "/tmp/homegate-access-validate-" .. suffix
    local f = io.open(path, "w")
    if not f then return false end
    f:write(raw)
    f:close()
    local rc = sys().call("/usr/bin/homegate access-validate-file " .. path .. " >/dev/null 2>&1")
    os.remove(path)
    return rc == 0
end

local function safe_access_source_ip(v)
    v = trim(v)
    if v == "" or #v > 64 or not v:match("^[%x%.:]+$") then return "" end
    return v
end

local function safe_access_source_host(v)
    v = trim(v):lower():gsub("%.$", "")
    if v == "" or #v > 253 or not v:match("^[%w%.%-]+$") then return "" end
    return v
end

local function access_rule_tokens(raw)
    local out, seen = {}, {}
    raw = tostring(raw or "")
    for token in raw:gmatch("[^,%s;]+") do
        token = trim(token)
        local key = token:lower()
        if token ~= "" and not seen[key] then
            seen[key] = true
            out[#out + 1] = token
        end
    end
    return out
end

local function access_exact_token(ip)
    ip = trim(ip)
    if ip == "" then return "" end
    return ip:find(":", 1, true) and (ip .. "/128") or (ip .. "/32")
end

local function access_token_matches_ip(token, ip)
    token, ip = trim(token):lower(), trim(ip):lower()
    if token == "" or ip == "" then return false end
    return token == ip or token == access_exact_token(ip):lower()
end

local function remove_access_ip(raw, ip)
    local kept = {}
    for _, token in ipairs(access_rule_tokens(raw)) do
        if not access_token_matches_ip(token, ip) then kept[#kept + 1] = token end
    end
    return table.concat(kept, ", ")
end

local function remove_access_token(raw, wanted)
    wanted = trim(wanted):lower()
    local kept = {}
    for _, token in ipairs(access_rule_tokens(raw)) do
        if token:lower() ~= wanted then kept[#kept + 1] = token end
    end
    return table.concat(kept, ", ")
end

function action_overview()
    local cur = uci_cursor()
    local jsonc = require("luci.jsonc")
    local report = jsonc.parse(sys().exec("/usr/bin/homegate status 2>/dev/null") or "") or {}
    render("overview", { packages = package_info(), status = report,
        public_count = #public_services(cur), wol_count = #get_sections(cur, "wol_host") })
end

function action_basic()
    local cur = uci_cursor()
    local main = cur:get_all("homegate", "main") or {}
    render("basic", {
        main = main,
        packages = package_info(),
        public_count = #public_services(cur),
        wol_count = #get_sections(cur, "wol_host")
    })
end

function action_basic_apply()
    local cur = uci_cursor()
    if not cur:get_all("homegate", "main") then
        cur:section("homegate", "homegate", "main", {})
    end

    local ddns_interval, err = parse_int("ddns_interval", 300, 60, 86400)
    if not ddns_interval then return redirect_page("basic", nil, err) end
    local https_port; https_port, err = parse_int("https_port", 443, 1, 65535)
    if not https_port then return redirect_page("basic", nil, err) end
    local proxy_https_port; proxy_https_port, err = parse_int("proxy_https_port", 10443, 1, 65535)
    if not proxy_https_port then return redirect_page("basic", nil, err) end
    cur:set("homegate", "main", "enabled", checked("enabled") and "1" or "0")
    cur:set("homegate", "main", "ddns_interval", tostring(ddns_interval))
    cur:set("homegate", "main", "https_port", tostring(https_port))
    cur:set("homegate", "main", "proxy_https_port", tostring(proxy_https_port))
    cur:set("homegate", "main", "auto_firewall", checked("auto_firewall") and "1" or "0")

    return finish_save(cur, "basic", trim(http().formvalue("mode")))
end

function action_legacy_public_redirect()
    http().redirect(page_url("public"))
end

function action_public()
    local cur = uci_cursor()
    local main = cur:get_all("homegate", "main") or {}
    local retired_access_region = trim(main.access_region):upper():match("^CN%-") ~= nil
    if retired_access_region then main.access_region = "" end
    local provider_catalog = dns_provider_catalog()
    local ca_catalog = acme_ca_catalog()
    render("public", {
        main = main,
        services = public_services(cur),
        dns_accounts = dns_account_choices(cur, provider_catalog),
        certificates = certificate_choices(cur, provider_catalog),
        dns_provider_catalog = provider_catalog,
        acme_ca_catalog = ca_catalog,
        access_regions = access_region_choices(),
        retired_access_region = retired_access_region and main.access_enabled == "1",
        default_renew_days = tostring(tonumber(main.renew_days or "30") or 30),
        acme_directory = (trim(main.acme_directory) == STAGING_DIRECTORY) and STAGING_DIRECTORY or PROD_DIRECTORY,
        resume_public = trim(http().formvalue("resume_public")),
        resume_account = safe_id(http().formvalue("resume_account"))
    })
end

function action_public_account_apply()
    local cur = uci_cursor()
    local h = http()
    local catalog = dns_provider_catalog()
    local values = dns_account_values_from_form(h)
    if values.provider == "" then values.provider = "aliyun" end
    values.provider = provider_name(values.provider, catalog)
    if values.provider == "" then return redirect_page("public", nil, "Unsupported DNS provider") end

    local id = find_account_by_identity(cur, values, catalog) or ""
    local existing = id ~= "" and dns_account_raw(cur, id) or nil
    local def, err = validate_dns_account_values(values, existing, catalog)
    if not def then return redirect_page("public", nil, err) end
    if id == "" then id = random_id(cur, "dns") end

    local account_name = existing and trim(existing.name) or ""
    if account_name == "" then account_name = provider_display_name(values.provider, catalog) end
    local ok
    ok, err = upsert_section(cur, "dns_account", id, {
        name = account_name,
        provider = values.provider,
        id = values.key_id,
        account_id = values.account_id,
        endpoint = values.endpoint
    })
    if not ok then cur:revert("homegate"); return redirect_page("public", nil, err) end
    if values.secret ~= "" then cur:set("homegate", id, "secret", values.secret) end
    if not cur:commit("homegate") then cur:revert("homegate"); return redirect_page("public", nil, "Failed to save DNS account") end
    -- Saving credentials is an immediate helper action inside Add/Edit Public
    -- Service. Resume the same workflow instead of forcing the user to reopen it.
    return redirect_page("public", "DNS account saved; primary domains can now be detected", nil, {
        resume_public = "add", resume_account = id
    })
end

function action_public_certificate_apply()
    local cur = uci_cursor()
    local h = http()
    local provider_catalog = dns_provider_catalog()
    local ca_catalog = acme_ca_catalog()
    local id = safe_id(h.formvalue("certificate_id"))
    local existing = id ~= "" and get_section(cur, id, "certificate") or nil
    if id ~= "" and not existing then return redirect_page("public", nil, "Certificate not found") end

    local enabled = bool_value(h.formvalue("enabled"))
    local name = trim(h.formvalue("name"))
    local zone = trim(h.formvalue("zone")):lower():gsub("%.$", "")
    if not valid_dns_name(zone) then return redirect_page("public", nil, "Invalid certificate zone") end

    local domains, err = parse_certificate_domains(h.formvalue("domains"))
    if not domains then return redirect_page("public", nil, err) end
    for _, pattern in ipairs(domains) do
        if not certificate_pattern_in_zone(pattern, zone) then
            return redirect_page("public", nil, "Certificate domain is outside the configured DNS zone: " .. pattern)
        end
    end

    local renew_days = tonumber(trim(h.formvalue("renew_days")))
    if not renew_days or renew_days ~= math.floor(renew_days) or renew_days < 1 or renew_days > 3650 then
        return redirect_page("public", nil, "Invalid certificate renewal threshold")
    end

    local ca, environment
    ca, environment, _, err = normalize_ca_selection(
        h.formvalue("certificate_ca"),
        h.formvalue("certificate_environment") or h.formvalue("acme_directory"),
        ca_catalog)
    if not ca then return redirect_page("public", nil, err) end

    local account_raw = trim(h.formvalue("account_id"))
    local account_id = account_raw == "__new__" and "" or safe_id(account_raw)
    local account = account_id ~= "" and dns_account_raw(cur, account_id) or nil
    if account_id ~= "" and not account then return redirect_page("public", nil, "DNS account not found") end
    if account then
        local def; def, err = validate_dns_account_values(account, account, provider_catalog)
        if not def then return redirect_page("public", nil, err) end
    else
        local values = dns_account_values_from_form(h)
        if values.provider == "" then values.provider = "aliyun" end
        values.provider = provider_name(values.provider, provider_catalog)
        account_id = find_account_by_identity(cur, values, provider_catalog) or ""
        account = account_id ~= "" and dns_account_raw(cur, account_id) or nil
        local def; def, err = validate_dns_account_values(values, account, provider_catalog)
        if not def then return redirect_page("public", nil, err) end
        if account_id == "" then account_id = random_id(cur, "dns") end
        if not account then
            local ok
            ok, err = upsert_section(cur, "dns_account", account_id, {
                name = provider_display_name(values.provider, provider_catalog),
                provider = values.provider,
                id = values.key_id,
                account_id = values.account_id,
                endpoint = values.endpoint
            })
            if not ok then cur:revert("homegate"); return redirect_page("public", nil, err) end
            if values.secret ~= "" then cur:set("homegate", account_id, "secret", values.secret) end
        end
    end

    if id == "" then id = random_id(cur, "cert") end
    if name == "" then name = table.concat(domains, ", ") end

    if existing and certificate_files_exist(id) and not same_certificate_domains(certificate_domains(existing), domains) then
        cur:revert("homegate")
        return redirect_page("public", nil, "Issued certificate domains cannot be changed; create a new certificate instead")
    end

    local proposed = {domains = table.concat(domains, ",")}
    if not enabled and certificate_use_count(cur, id) > 0 then
        cur:revert("homegate")
        return redirect_page("public", nil, "Certificate is still in use and cannot be disabled")
    end
    local coverage_error = nil
    cur:foreach("homegate", "web_rule", function(s)
        if not coverage_error and safe_id(s.certificate) == id and not certificate_covers(proposed, trim(s.domain)) then
            coverage_error = "Certificate no longer covers Web service domain: " .. trim(s.domain)
        end
    end)
    if coverage_error then cur:revert("homegate"); return redirect_page("public", nil, coverage_error) end

    if enabled then
        local wanted = {}
        for _, pattern in ipairs(domains) do wanted[pattern] = true end
        local duplicate = nil
        cur:foreach("homegate", "certificate", function(s)
            if duplicate or s[".name"] == id or not bool_value(s.enabled) then return end
            for _, pattern in ipairs(certificate_domains(s)) do
                if wanted[pattern] then
                    duplicate = "Certificate domain " .. pattern .. " is already declared by " .. s[".name"]
                    return
                end
            end
        end)
        if duplicate then cur:revert("homegate"); return redirect_page("public", nil, duplicate) end
    end

    local ok
    ok, err = upsert_section(cur, "certificate", id, {
        enabled = enabled and "1" or "0",
        name = name,
        source = "acme",
        account = account_id,
        zone = zone,
        domains = table.concat(domains, ","),
        email = existing and trim(existing.email) or "",
        renew_days = tostring(renew_days),
        ca = ca,
        environment = environment
    })
    if not ok then cur:revert("homegate"); return redirect_page("public", nil, err) end

    return finish_save(cur, "public", "apply")
end

local cleanup_certificate_files
local ddns_group_count
local delete_orphan_zone_certificates

function action_public_apply()
    local cur = uci_cursor()
    local h = http()
    local mode = trim(h.formvalue("mode"))
    local installed_local = {}
    local function fail(message)
        cur:revert("homegate")
        for _, id in ipairs(installed_local) do cleanup_local_certificate_files(id) end
        return redirect_page("public", nil, message)
    end

    local count = tonumber(trim(h.formvalue("public_service_count")))
    if not count or count ~= math.floor(count) or count < 0 or count > 128 then
        return fail("Invalid public service list")
    end

    -- Validate uploaded local certificate pairs before touching UCI. The Core
    -- performs key matching, validity and SAN extraction in an isolated /tmp
    -- HOMEGATE_HOME_DIR; private-key contents never enter stdout or logs.
    local local_uploads = {}
    for i = 1, count do
        local prefix = "public_service_" .. i .. "_"
        local cert_mode = trim(h.formvalue(prefix .. "cert_mode")):lower()
        if cert_mode == "local" then
            local cert_pem = tostring(h.formvalue(prefix .. "local_cert_pem") or "")
            local key_pem = tostring(h.formvalue(prefix .. "local_key_pem") or "")
            if (cert_pem == "") ~= (key_pem == "") then
                return fail("Certificate and private key files must be uploaded together")
            end
            if cert_pem ~= "" then
                local info, err = validate_local_certificate(cert_pem, key_pem)
                if not info then return fail(err) end
                local_uploads[i] = {info = info, cert_pem = cert_pem, key_pem = key_pem}
            end
        end
    end

    local access_scope = trim(h.formvalue("access_scope")):upper()
    local access_allow = trim(h.formvalue("access_allow"))
    local access_deny = trim(h.formvalue("access_deny"))
    local access_enabled, access_region = false, ""
    if access_scope == "__MANUAL__" then
        access_enabled = true
    elseif access_scope ~= "" then
        if not access_region_supported(access_scope) then return fail("Unsupported allowed region") end
        access_enabled = true
        access_region = access_scope
    end
    if #access_allow > 4096 or not validate_access_allow(access_allow) then return fail("Invalid allowed IP or network") end
    if #access_deny > 4096 or not validate_access_allow(access_deny) then return fail("Invalid denied IP or network") end

    local original_web, original_ddns = {}, {}
    local original_web_rows, original_ddns_rows = {}, {}
    local original_web_cert, original_web_cert_managed = {}, {}
    local original_local_certs = {}
    cur:foreach("homegate", "web_rule", function(s)
        local id = s[".name"]
        original_web[id] = true
        original_web_rows[id] = { id = id, certificate = safe_id(s.certificate), domain = trim(s.domain) }
        original_web_cert[id] = safe_id(s.certificate)
        local explicit_managed = trim(s.certificate_managed)
        if explicit_managed ~= "" then
            original_web_cert_managed[id] = bool_value(explicit_managed)
        else
            local cert = original_web_cert[id] ~= "" and get_section(cur, original_web_cert[id], "certificate") or nil
            original_web_cert_managed[id] = cert ~= nil and certificate_use_count(cur, original_web_cert[id]) <= 1 and certificate_exact_covers(cert, trim(s.domain))
        end
    end)
    cur:foreach("homegate", "ddns_rule", function(s)
        local id = s[".name"]
        original_ddns[id] = true
        original_ddns_rows[id] = { id = id, account = safe_id(s.account), zone = trim(s.zone):lower():gsub("%.$", "") }
    end)
    cur:foreach("homegate", "certificate", function(s)
        if certificate_source(s) == "local" then original_local_certs[s[".name"]] = true end
    end)

    local kept_web, kept_ddns, seen_domains = {}, {}, {}
    local main = cur:get_all("homegate", "main") or {}
    local default_renew = tonumber(main.renew_days or "30") or 30
    local provider_catalog = dns_provider_catalog()
    local ca_catalog = acme_ca_catalog()
    local pending_local = {}

    for i = 1, count do
        local prefix = "public_service_" .. i .. "_"
        local web_id = safe_id(h.formvalue(prefix .. "web_id"))
        local ddns_id = safe_id(h.formvalue(prefix .. "ddns_id"))
        local account_id = safe_id(h.formvalue(prefix .. "account_id"))
        local cert_id = safe_id(h.formvalue(prefix .. "cert_id"))
        local enabled = bool_value(h.formvalue(prefix .. "enabled"))
        local provider = trim(h.formvalue(prefix .. "provider")):lower()
        if provider == "" then provider = "aliyun" end
        provider = provider_name(provider, provider_catalog)
        if provider == "" then return fail("Unsupported DNS provider") end
        local key_id = trim(h.formvalue(prefix .. "key_id"))
        local secret = trim(h.formvalue(prefix .. "secret"))
        local provider_account_id = trim(h.formvalue(prefix .. "provider_account_id"))
        local endpoint = trim(h.formvalue(prefix .. "endpoint"))
        local zone = trim(h.formvalue(prefix .. "zone")):lower():gsub("%.$", "")
        local host = trim(h.formvalue(prefix .. "host")):lower():gsub("%.$", "")
        local domain = trim(h.formvalue(prefix .. "domain")):lower():gsub("%.$", "")
        local target = trim(h.formvalue(prefix .. "target"))
        local https = bool_value(h.formvalue(prefix .. "https"))
        local cert_mode = trim(h.formvalue(prefix .. "cert_mode")):lower()
        if cert_mode ~= "local" then cert_mode = "auto" end
        local cert_ca, cert_environment, _, cert_ca_err = normalize_ca_selection(
            h.formvalue(prefix .. "cert_ca"),
            h.formvalue(prefix .. "cert_environment"),
            ca_catalog)
        if cert_mode == "auto" and not cert_ca then return fail(cert_ca_err) end
        if cert_mode ~= "auto" then
            cert_ca, cert_environment = DEFAULT_CA, CERT_ENV_PRODUCTION
        end
        local cert_renew_days = tonumber(trim(h.formvalue(prefix .. "cert_renew_days"))) or default_renew
        if cert_renew_days ~= math.floor(cert_renew_days) or cert_renew_days < 1 or cert_renew_days > 3650 then return fail("Invalid certificate renewal threshold") end
        local ttl = tonumber(trim(h.formvalue(prefix .. "ttl"))) or 600
        if ttl ~= math.floor(ttl) or ttl < 1 or ttl > 86400 then return fail("Invalid DDNS TTL") end

        if zone ~= "" then
            if zone:find("[%s/]") or host:find("[%s/]") then return fail("Public service domain contains invalid characters") end
            domain = full_domain(zone, host)
        end
        if domain == "" or domain:find("[%s/]") then return fail("Valid public service domain is required") end
        if seen_domains[domain] then return fail("Duplicate public service domain") end
        seen_domains[domain] = true

        local account = account_id ~= "" and dns_account_raw(cur, account_id) or nil
        if zone ~= "" then
            if account_id ~= "" then
                -- Existing DNS accounts are shared resources. Public-service
                -- Save only validates and references them; it never rewrites
                -- stored credentials from row form data.
                if not account then return fail("DNS account not found") end
                provider = provider_name(account.provider ~= "" and account.provider or "aliyun", provider_catalog)
                if provider == "" then return fail("Unsupported DNS provider") end
                local def, account_err = validate_dns_account_values(account, account, provider_catalog)
                if not def then return fail(account_err) end
                key_id = account.key_id
                provider_account_id = account.account_id
                endpoint = account.endpoint
            else
                -- Backward-compatible fallback for old POST payloads. Current
                -- LuCI saves credentials through public_account_apply first.
                local values = {
                    provider = provider,
                    key_id = key_id,
                    secret = secret,
                    account_id = provider_account_id,
                    endpoint = endpoint
                }
                account_id = find_account_by_identity(cur, values, provider_catalog) or ""
                account = account_id ~= "" and dns_account_raw(cur, account_id) or nil
                local def, account_err = validate_dns_account_values(values, account, provider_catalog)
                if not def then return fail(account_err) end
                if not account then
                    account_id = random_id(cur, "dns")
                    local ok, create_err = upsert_section(cur, "dns_account", account_id, {
                        name = provider_display_name(provider, provider_catalog),
                        provider = provider,
                        id = key_id,
                        account_id = provider_account_id,
                        endpoint = endpoint
                    })
                    if not ok then return fail(create_err) end
                    if secret ~= "" then cur:set("homegate", account_id, "secret", secret) end
                    account = dns_account_raw(cur, account_id)
                end
            end

            if ddns_id ~= "" and not get_section(cur, ddns_id, "ddns_rule") then return fail("DDNS rule not found") end
            if ddns_id == "" then ddns_id = random_id(cur, "ddns") end
            ok, err = upsert_section(cur, "ddns_rule", ddns_id, {
                enabled = enabled and "1" or "0", name = domain, account = account_id,
                zone = zone, host = (host == "" and "@" or host), type = "AAAA", source = "auto", ttl = tostring(ttl)
            })
            if not ok then return fail(err) end
            kept_ddns[ddns_id] = true
        elseif ddns_id ~= "" then
            kept_ddns[ddns_id] = true
        end

        if target ~= "" then
            if not target:match("^https?://[^%s]+$") then return fail("Target must start with http:// or https://") end
            if web_id ~= "" and not get_section(cur, web_id, "web_rule") then return fail("Web rule not found") end
            if web_id == "" then web_id = random_id(cur, "web") end

            local selected_cert = nil
            local certificate_managed = false
            if https then
                if cert_mode == "local" then
                    local upload = local_uploads[i]
                    if upload then
                        local proposed = {domains = table.concat(upload.info.domains, ",")}
                        if not certificate_covers(proposed, domain) then return fail("Uploaded certificate does not cover this service domain") end
                        -- Replacing a single-use local certificate is safe to stage
                        -- as a new resource: the old resource becomes orphaned after
                        -- this Web rule moves and is deleted only after commit. This
                        -- keeps file rollback simple because the old pair is never
                        -- overwritten before the UCI transaction succeeds. Shared
                        -- local certificates are not excluded: duplicate identities
                        -- would otherwise leave the runtime certificate index ambiguous.
                        local duplicate_exclude = ""
                        if cert_id ~= "" then
                            local previous = get_section(cur, cert_id, "certificate")
                            if previous and certificate_source(previous) == "local" and certificate_use_count(cur, cert_id) <= 1 then
                                duplicate_exclude = cert_id
                            end
                        end
                        for _, pattern in ipairs(upload.info.domains) do
                            local owner = enabled_certificate_pattern_owner(cur, pattern, duplicate_exclude)
                            if owner then return fail("Uploaded certificate identity is already provided by another certificate: " .. pattern) end
                        end
                        cert_id = random_id(cur, "cert_local")
                        local ok, err = upsert_section(cur, "certificate", cert_id, {
                            enabled = "1", name = table.concat(upload.info.domains, ", "), source = "local",
                            account = "", zone = "", domains = table.concat(upload.info.domains, ","), email = "", renew_days = tostring(default_renew)
                        })
                        if not ok then return fail(err) end
                        pending_local[#pending_local + 1] = {id = cert_id, cert_pem = upload.cert_pem, key_pem = upload.key_pem}
                        selected_cert = get_section(cur, cert_id, "certificate")
                    else
                        if cert_id ~= "" then
                            local c = get_section(cur, cert_id, "certificate")
                            if c and certificate_source(c) == "local" and certificate_covers(c, domain) then selected_cert = c end
                        end
                        if not selected_cert then selected_cert = find_certificate_for_domain(cur, domain, "local") end
                        if not selected_cert then return fail("Upload a local certificate and private key for this service") end
                        cert_id = selected_cert.id
                    end
                else
                    local original_cert = web_id ~= "" and original_web_cert[web_id] or ""
                    local identity_changed = false
                    local current_cert = nil
                    if cert_id ~= "" then
                        local c = get_section(cur, cert_id, "certificate")
                        if c and certificate_source(c) == "acme" and certificate_covers(c, domain) then
                            if certificate_acme_matches(c, cert_ca, cert_environment) then
                                selected_cert = c
                            elseif certificate_use_count(cur, cert_id) <= 1 and original_cert == cert_id then
                                -- A single-service ACME resource may change CA in
                                -- place. Shared resources must never be silently
                                -- retargeted for all consumers.
                                selected_cert = c
                                current_cert = c
                                identity_changed = true
                            else
                                return fail("Shared automatic certificate authority cannot be changed from one service")
                            end
                        end
                    end
                    if not selected_cert then
                        selected_cert = find_automatic_shared_certificate(cur, zone, domain, cert_environment, cert_ca)
                    end
                    if not selected_cert then
                        if zone == "" or account_id == "" then return fail("DNS configuration is required for automatic HTTPS certificate") end
                        local auto_domains, reuse, conflict = automatic_certificate_create_domains(cur, zone, domain, cert_environment, cert_ca)
                        if conflict then
                            return fail("Automatic certificate conflicts with an existing certificate identity")
                        elseif reuse then
                            selected_cert = reuse
                        elseif auto_domains then
                            cert_id = random_id(cur, "cert")
                            local auto_base = automatic_certificate_scope(zone, domain)
                            local ok, create_err = upsert_section(cur, "certificate", cert_id, {
                                enabled = "1", name = auto_base or domain, source = "acme", account = account_id,
                                zone = zone, domains = table.concat(auto_domains, ","), email = "", renew_days = tostring(cert_renew_days),
                                ca = cert_ca, environment = cert_environment
                            })
                            if not ok then return fail(create_err) end
                            certificate_managed = false
                        else
                            selected_cert = find_certificate_for_domain(cur, domain, "acme", cert_environment, cert_ca)
                            if not selected_cert then return fail("Unable to create or reuse automatic HTTPS certificate") end
                        end
                    end
                    if selected_cert then
                        cert_id = selected_cert.id
                        if identity_changed then
                            cur:set("homegate", cert_id, "ca", cert_ca)
                            cur:set("homegate", cert_id, "environment", cert_environment)
                            cur:set("homegate", cert_id, "account", account_id)
                            cur:set("homegate", cert_id, "zone", zone)
                        end
                        if not bool_value(selected_cert.enabled) then cur:set("homegate", cert_id, "enabled", "1") end
                        certificate_managed = original_cert == cert_id and original_web_cert_managed[web_id] == true
                        if certificate_use_count(cur, cert_id) <= 1 then
                            cur:set("homegate", cert_id, "renew_days", tostring(cert_renew_days))
                        end
                    end
                end
            else
                cert_id = ""
                cert_mode = "auto"
                certificate_managed = false
            end

            local ok, err = upsert_section(cur, "web_rule", web_id, {
                enabled = enabled and "1" or "0", domain = domain, target = target, https = https and "1" or "0",
                certificate = cert_id, certificate_mode = cert_mode, certificate_managed = certificate_managed and "1" or "0"
            })
            if not ok then return fail(err) end
            kept_web[web_id] = true
        elseif web_id ~= "" then
            return fail("LAN target is required for an existing Web service")
        end
    end

    local removed_web, removed_ddns = {}, {}
    for id in pairs(original_web) do if not kept_web[id] then removed_web[#removed_web + 1] = id end end
    for id in pairs(original_ddns) do if not kept_ddns[id] then removed_ddns[#removed_ddns + 1] = id end end
    table.sort(removed_web)
    table.sort(removed_ddns)

    -- Public-service deletion is an ordinary configuration change. The UI stages
    -- it and the externally visible provider cleanup is executed only by
    -- Save & Apply. Plain Save is intentionally rejected for a destructive staged
    -- deletion so a remote DNS record can never be orphaned from its local rule.
    if (#removed_web > 0 or #removed_ddns > 0) and mode ~= "apply" then
        return fail("Public service deletion requires Save & Apply")
    end
    for _, id in ipairs(removed_ddns) do
        if not action_core("ddns-delete " .. id) then return fail("Unable to delete public DNS record") end
    end

    local deleted_cert_ids, deleted_cert_seen, candidate_accounts, candidate_zones = {}, {}, {}, {}
    local function remember_cert(id)
        id = safe_id(id)
        if id ~= "" and not deleted_cert_seen[id] then
            deleted_cert_seen[id] = true
            deleted_cert_ids[#deleted_cert_ids + 1] = id
        end
    end
    for _, id in ipairs(removed_web) do cur:delete("homegate", id) end
    for _, id in ipairs(removed_ddns) do
        local row = original_ddns_rows[id] or {}
        if row.account and row.account ~= "" then
            candidate_accounts[row.account] = true
            if row.zone and row.zone ~= "" then candidate_zones[row.account .. "\0" .. row.zone] = {account = row.account, zone = row.zone} end
        end
        cur:delete("homegate", id)
    end

    -- A certificate disappears only after its final Web reference disappears.
    -- When the last service in an account+zone group is gone, clean any older
    -- orphan certificate from that same group as well. DNS accounts are removed
    -- only after no HomeGate resource references them anymore.
    for _, id in ipairs(removed_web) do
        local cert_id = safe_id((original_web_rows[id] or {}).certificate)
        if cert_id ~= "" and certificate_use_count(cur, cert_id) == 0 and get_section(cur, cert_id, "certificate") then
            cur:delete("homegate", cert_id)
            remember_cert(cert_id)
        end
    end
    for _, pair in pairs(candidate_zones) do
        if ddns_group_count(cur, pair.account, pair.zone, "") == 0 then
            local before = #deleted_cert_ids
            delete_orphan_zone_certificates(cur, pair.account, pair.zone, deleted_cert_ids)
            for i = before + 1, #deleted_cert_ids do deleted_cert_seen[deleted_cert_ids[i]] = true end
        end
    end
    for account_id in pairs(candidate_accounts) do
        if account_use_count(cur, account_id) == 0 then cur:delete("homegate", account_id) end
    end

    -- Local uploads have no standalone management table. Editing a service away
    -- from an old local certificate also removes that now-unreferenced pair.
    for id in pairs(original_local_certs) do
        if certificate_use_count(cur, id) == 0 and get_section(cur, id, "certificate") then
            cur:delete("homegate", id)
            remember_cert(id)
        end
    end

    if access_enabled and access_region ~= "" and not action_core("access-update " .. access_region) then return fail("Unable to update access region data") end
    cur:set("homegate", "main", "access_enabled", access_enabled and "1" or "0")
    cur:set("homegate", "main", "access_allow", access_allow)
    cur:set("homegate", "main", "access_deny", access_deny)
    cur:set("homegate", "main", "access_region", access_region)

    for _, pending in ipairs(pending_local) do
        local info, err = install_local_certificate(pending.id, pending.cert_pem, pending.key_pem)
        if not info then
            cleanup_local_certificate_files(pending.id)
            return fail(err)
        end
        installed_local[#installed_local + 1] = pending.id
    end

    local committed, commit_err = commit(cur)
    if not committed then return fail(commit_err) end
    for _, id in ipairs(deleted_cert_ids) do cleanup_certificate_files(id) end

    if mode == "apply" then
        local applied, apply_err = apply_homegate()
        if not applied then return redirect_page("public", nil, apply_err) end
        return redirect_page("public", "Saved and applied")
    end
    return redirect_page("public", "Saved")
end

cleanup_certificate_files = function(id)
    id = safe_id(id)
    if id == "" then return end
    sys().call("rm -rf /etc/homegate/certs/" .. id .. " >/dev/null 2>&1")
    sys().call("rm -f /var/run/homegate/acme-renew/" .. id .. ".json >/dev/null 2>&1")
end

ddns_group_count = function(cur, account_id, zone, exclude_id)
    account_id, zone, exclude_id = safe_id(account_id), trim(zone):lower():gsub("%.$", ""), safe_id(exclude_id)
    local count = 0
    cur:foreach("homegate", "ddns_rule", function(s)
        if s[".name"] ~= exclude_id and safe_id(s.account) == account_id and trim(s.zone):lower():gsub("%.$", "") == zone then
            count = count + 1
        end
    end)
    return count
end

local function service_delete_needs_confirmation(cur, web, ddns)
    local cert_id = web and safe_id(web.certificate) or ""
    if cert_id ~= "" and certificate_use_count(cur, cert_id) <= 1 then return true end
    if ddns then
        local account_id, zone = safe_id(ddns.account), trim(ddns.zone):lower():gsub("%.$", "")
        if account_id ~= "" and zone ~= "" and ddns_group_count(cur, account_id, zone, ddns[".name"]) == 0 then return true end
    end
    return false
end

delete_orphan_zone_certificates = function(cur, account_id, zone, deleted_ids)
    account_id, zone = safe_id(account_id), trim(zone):lower():gsub("%.$", "")
    if account_id == "" or zone == "" then return end
    local ids = {}
    cur:foreach("homegate", "certificate", function(s)
        if safe_id(s.account) == account_id and trim(s.zone):lower():gsub("%.$", "") == zone and certificate_use_count(cur, s[".name"]) == 0 then
            ids[#ids + 1] = s[".name"]
        end
    end)
    for _, id in ipairs(ids) do
        cur:delete("homegate", id)
        deleted_ids[#deleted_ids + 1] = id
    end
end

function action_public_action()
    local op = trim(http().formvalue("op"))
    if op == "service_delete" then
        local cur = uci_cursor()
        local web_id = safe_id(http().formvalue("web_id"))
        local ddns_id = safe_id(http().formvalue("ddns_id"))
        local web = web_id ~= "" and get_section(cur, web_id, "web_rule") or nil
        local ddns = ddns_id ~= "" and get_section(cur, ddns_id, "ddns_rule") or nil
        if not web and not ddns then return redirect_page("public", nil, "Public service not found") end
        if web_id ~= "" and not web then return redirect_page("public", nil, "Web rule not found") end
        if ddns_id ~= "" and not ddns then return redirect_page("public", nil, "DDNS rule not found") end

        local needs_confirm = service_delete_needs_confirmation(cur, web, ddns)
        if needs_confirm and trim(http().formvalue("confirmed")) ~= "1" then
            return redirect_page("public", nil, "Public service deletion requires confirmation")
        end

        -- Remove the externally managed DNS record before dropping its local
        -- rule. Provider deletion is exact to this hostname and record type.
        if ddns and not action_core("ddns-delete " .. ddns_id) then
            return redirect_page("public", nil, "Unable to delete public DNS record")
        end

        local account_id = ddns and safe_id(ddns.account) or ""
        local zone = ddns and trim(ddns.zone):lower():gsub("%.$", "") or ""
        local cert_id = web and safe_id(web.certificate) or ""
        if account_id == "" and cert_id ~= "" then
            local cert = get_section(cur, cert_id, "certificate")
            if cert then
                account_id = safe_id(cert.account)
                zone = trim(cert.zone):lower():gsub("%.$", "")
            end
        end

        if web then cur:delete("homegate", web_id) end
        if ddns then cur:delete("homegate", ddns_id) end

        local deleted_cert_ids = {}
        if cert_id ~= "" and certificate_use_count(cur, cert_id) == 0 then
            cur:delete("homegate", cert_id)
            deleted_cert_ids[#deleted_cert_ids + 1] = cert_id
        end

        -- Once the final service in one account+zone group disappears, clean
        -- old orphan certificates from that same group as well. This replaces
        -- the standalone certificate-delete UI without touching other zones.
        if account_id ~= "" and zone ~= "" and ddns_group_count(cur, account_id, zone, "") == 0 then
            delete_orphan_zone_certificates(cur, account_id, zone, deleted_cert_ids)
        end
        if account_id ~= "" and account_use_count(cur, account_id) == 0 then
            cur:delete("homegate", account_id)
        end

        local ok, err = commit(cur)
        if not ok then return redirect_page("public", nil, err or "Unable to delete public service") end
        local cleaned = {}
        for _, cid in ipairs(deleted_cert_ids) do
            if not cleaned[cid] then cleanup_certificate_files(cid); cleaned[cid] = true end
        end
        local applied, apply_err = apply_homegate()
        if not applied then return redirect_page("public", nil, apply_err) end
        return redirect_page("public", "Public service deleted")
    end

    local id = safe_id(http().formvalue("id"))
    if id == "" then return redirect_page("public", nil, "Invalid item ID") end
    if op == "ddns_sync" then
        local rule = get_section(uci_cursor(), id, "ddns_rule")
        if not rule then return redirect_page("public", nil, "DDNS rule not found") end
        if trim(rule.enabled) ~= "1" then return redirect_page("public", nil, "Public service is disabled; DDNS sync was not performed") end
        if action_core("ddns-sync " .. id) then return redirect_page("public", "DDNS sync completed") end
        return redirect_page("public", nil, "DDNS sync failed; check HomeGate logs")
    elseif op == "cert_renew" then
        if not get_section(uci_cursor(), id, "certificate") then return redirect_page("public", nil, "Certificate not found") end
        if action_core("cert-renew " .. id) then return redirect_page("public", "Certificate renewal completed") end
        return redirect_page("public", nil, "Certificate renewal failed; check HomeGate logs")
    elseif op == "account_delete" then
        local cur = uci_cursor()
        if not get_section(cur, id, "dns_account") then return redirect_page("public", nil, "DNS account not found") end
        if account_in_use(cur, id) then return redirect_page("public", nil, "DNS account is still in use") end
        cur:delete("homegate", id)
        local ok, err = commit(cur)
        if not ok then return redirect_page("public", nil, err or "Unable to delete DNS account") end
        return redirect_page("public", "DNS account deleted")
    elseif op == "cert_delete" then
        local cur = uci_cursor()
        if not get_section(cur, id, "certificate") then return redirect_page("public", nil, "Certificate not found") end
        if certificate_in_use(cur, id) then return redirect_page("public", nil, "Certificate is still in use") end
        cur:delete("homegate", id)
        local ok, err = commit(cur)
        if not ok then return redirect_page("public", nil, err or "Unable to delete certificate") end
        -- Certificate deletion is independent from DNS-account deletion.  Remove
        -- only this certificate's owned files and leave its DNS account intact.
        sys().call("rm -rf /etc/homegate/certs/" .. id .. " >/dev/null 2>&1")
        sys().call("rm -f /var/run/homegate/acme-renew/" .. id .. ".json >/dev/null 2>&1")
        local applied, apply_err = apply_homegate()
        if not applied then return redirect_page("public", nil, apply_err) end
        return redirect_page("public", "Certificate deleted")
    end
    return redirect_page("public", nil, "Unsupported action")
end

function action_wol()
    local cur = uci_cursor()
    local main = cur:get_all("homegate", "main") or {}
    local interfaces, selected = wol_interfaces(main.wol_interface or "br-lan")
    render("wol", {
        main = main,
        hosts = get_sections(cur, "wol_host"),
        wol_interfaces = interfaces,
        wol_selected_interface = selected,
        wol_clients = wol_client_candidates(cur)
    })
end

function action_wol_apply()
    local cur = uci_cursor()
    local h = http()
    if not cur:get_all("homegate", "main") then cur:section("homegate", "homegate", "main", {}) end
    local ifname = trim(h.formvalue("wol_interface"))
    if ifname == "" or not ifname:match("^[%w%._:%-]+$") then return redirect_page("wol", nil, "Invalid WOL interface") end
    if not is_lan_interface(ifname) then return redirect_page("wol", nil, "WOL interface must belong to the LAN") end

    local count_raw = h.formvalue("wol_host_count")
    local rows, original = nil, {}
    if count_raw ~= nil then
        local count = tonumber(trim(count_raw))
        if not count or count ~= math.floor(count) or count < 0 or count > 128 then
            return redirect_page("wol", nil, "Invalid WOL host list")
        end
        rows = {}
        cur:foreach("homegate", "wol_host", function(s) original[s[".name"]] = true end)
        local seen_ids, seen_macs = {}, {}
        for i = 1, count do
            local id = safe_id(h.formvalue("wol_host_id_" .. i))
            if id ~= "" and not get_section(cur, id, "wol_host") then return redirect_page("wol", nil, "WOL host not found") end
            if id ~= "" and seen_ids[id] then return redirect_page("wol", nil, "Duplicate WOL host") end
            if id ~= "" then seen_ids[id] = true end
            local mac = normalize_mac(h.formvalue("wol_host_mac_" .. i))
            if not mac then return redirect_page("wol", nil, "Valid MAC address is required") end
            if seen_macs[mac] then return redirect_page("wol", nil, "Duplicate MAC address") end
            seen_macs[mac] = true
            local name = trim(h.formvalue("wol_host_name_" .. i))
            if name == "" then name = detected_name_for_mac(cur, mac) end
            if name == "" then name = mac end
            rows[#rows + 1] = {id = id, name = name, mac = mac}
        end
    end

    cur:set("homegate", "main", "wol_interface", ifname)
    if rows then
        local kept = {}
        for _, row in ipairs(rows) do
            local id = row.id
            if id == "" then id = random_id(cur, "wol") end
            local ok, err = upsert_section(cur, "wol_host", id, {name = row.name, mac = row.mac})
            if not ok then cur:revert("homegate"); return redirect_page("wol", nil, err) end
            kept[id] = true
        end
        for id in pairs(original) do
            if not kept[id] then cur:delete("homegate", id) end
        end
        local last = safe_id(cur:get("homegate", "main", "last_wol_host"))
        if last ~= "" and not kept[last] then cur:set("homegate", "main", "last_wol_host", "") end
    end
    return finish_save(cur, "wol", trim(h.formvalue("mode")))
end

function action_wol_action()
    local cur = uci_cursor()
    local op = trim(http().formvalue("op"))
    local id = safe_id(http().formvalue("id"))
    if op == "wake" then
        local host = get_section(cur, id, "wol_host")
        if not host then return redirect_page("wol", nil, "WOL host not found") end
        cur:set("homegate", "main", "last_wol_host", id)
        cur:commit("homegate")
        if action_core("wol " .. id) then return redirect_page("wol", "Wake packet sent") end
        return redirect_page("wol", nil, "Wake-on-LAN failed; check HomeGate logs")
    elseif op == "delete" then
        local host = get_section(cur, id, "wol_host")
        if not host then return redirect_page("wol", nil, "WOL host not found") end
        cur:delete("homegate", id)
        if cur:get("homegate", "main", "last_wol_host") == id then cur:set("homegate", "main", "last_wol_host", "") end
        local ok, err = commit(cur)
        if not ok then return redirect_page("wol", nil, err) end
        return redirect_page("wol", "Host deleted")
    end
    return redirect_page("wol", nil, "Unsupported action")
end

function action_access_update()
    local region = trim(http().formvalue("region")):upper()
    if region == "" or not access_region_supported(region) then
        return redirect_page("public", nil, "Unsupported allowed region")
    end
    if not action_core("access-refresh " .. region) then
        return redirect_page("public", nil, "Unable to update access region data")
    end
    local cur = uci_cursor()
    if cur:get("homegate", "main", "access_enabled") == "1" and trim(cur:get("homegate", "main", "access_region")):upper() == region then
        local ok, err = apply_homegate()
        if not ok then return redirect_page("public", nil, err) end
    end
    return redirect_page("public", "Access region data updated")
end

function action_access_clear_all()
    if not action_core("access-clear-all") then
        return redirect_page("public", nil, "Unable to clear access records")
    end
    -- The daemon owns a bounded in-memory recorder. Reload after changing the
    -- runtime file so cleared rows cannot reappear from the old in-memory copy.
    local ok, err = apply_homegate()
    if not ok then return redirect_page("public", nil, err) end
    return redirect_page("public", "Access records cleared")
end

function action_access_clear_entry()
    local ip = safe_access_source_ip(http().formvalue("ip"))
    local host = safe_access_source_host(http().formvalue("host"))
    if ip == "" or host == "" then
        return redirect_page("public", nil, "Invalid access record")
    end
    if not action_core("access-clear-entry " .. ip .. " " .. host) then
        return redirect_page("public", nil, "Unable to clear access record")
    end
    local ok, err = apply_homegate()
    if not ok then return redirect_page("public", nil, err) end
    return redirect_page("public", "Access record cleared")
end

function action_access_clear_denied()
    if not action_core("access-clear-denied") then
        return redirect_page("public", nil, "Unable to clear denied recent access")
    end
    -- The daemon keeps a bounded in-memory recorder. Reload it from the freshly
    -- filtered runtime file so cleared denied entries cannot reappear.
    local ok, err = apply_homegate()
    if not ok then return redirect_page("public", nil, err) end
    return redirect_page("public", "Denied recent access cleared")
end

function action_access_delete_entry()
    local ip = safe_access_source_ip(http().formvalue("ip"))
    local host = safe_access_source_host(http().formvalue("host"))
    if ip == "" or host == "" then return redirect_page("public", nil, "Invalid access record") end

    local cur = uci_cursor()
    if not cur:get_all("homegate", "main") then cur:section("homegate", "homegate", "main", {}) end
    local allow = remove_access_ip(cur:get("homegate", "main", "access_allow") or "", ip)
    local deny = remove_access_ip(cur:get("homegate", "main", "access_deny") or "", ip)
    cur:set("homegate", "main", "access_allow", allow)
    cur:set("homegate", "main", "access_deny", deny)

    if not action_core("access-clear-entry " .. ip .. " " .. host) then
        cur:revert("homegate")
        return redirect_page("public", nil, "Unable to delete access entry")
    end
    local ok, err = commit(cur)
    if not ok then return redirect_page("public", nil, err or "Unable to delete access entry") end
    local applied, apply_err = apply_homegate()
    if not applied then return redirect_page("public", nil, apply_err) end
    return redirect_page("public", "Access entry deleted")
end

function action_access_delete_rule()
    local kind = trim(http().formvalue("kind")):lower()
    local token = trim(http().formvalue("token"))
    if (kind ~= "allow" and kind ~= "deny") or token == "" or #token > 256 then
        return redirect_page("public", nil, "Invalid access rule")
    end
    local cur = uci_cursor()
    if not cur:get_all("homegate", "main") then cur:section("homegate", "homegate", "main", {}) end
    local option = kind == "deny" and "access_deny" or "access_allow"
    local updated = remove_access_token(cur:get("homegate", "main", option) or "", token)
    if not validate_access_allow(updated) then return redirect_page("public", nil, "Invalid access rule") end
    cur:set("homegate", "main", option, updated)
    local ok, err = commit(cur)
    if not ok then return redirect_page("public", nil, err or "Unable to delete access rule") end
    local applied, apply_err = apply_homegate()
    if not applied then return redirect_page("public", nil, apply_err) end
    return redirect_page("public", "Access rule deleted")
end

function action_access_delete_all()
    local cur = uci_cursor()
    if not cur:get_all("homegate", "main") then cur:section("homegate", "homegate", "main", {}) end
    cur:set("homegate", "main", "access_allow", "")
    cur:set("homegate", "main", "access_deny", "")
    if not action_core("access-clear-all") then
        cur:revert("homegate")
        return redirect_page("public", nil, "Unable to delete all access entries")
    end
    local ok, err = commit(cur)
    if not ok then return redirect_page("public", nil, err or "Unable to delete all access entries") end
    local applied, apply_err = apply_homegate()
    if not applied then return redirect_page("public", nil, apply_err) end
    return redirect_page("public", "All access entries deleted")
end

function action_maintenance()
    local cur = uci_cursor()
    render("maintenance", {
        main = cur:get_all("homegate", "main") or {},
        packages = package_info()
    })
end

function action_maintenance_apply()
    local cur = uci_cursor()
    local h = http()
    if not cur:get_all("homegate", "main") then cur:section("homegate", "homegate", "main", {}) end
    local log_max_lines, err = parse_int("log_max_lines", 1024, 64, 20000)
    if not log_max_lines then return redirect_page("maintenance", nil, err) end
    local level = trim(h.formvalue("log_level")):lower()
    if level ~= "debug" and level ~= "info" and level ~= "warn" and level ~= "error" then level = "info" end

    cur:set("homegate", "main", "log_level", level)
    cur:set("homegate", "main", "log_max_lines", tostring(log_max_lines))
    cur:delete("homegate", "main", "log_capture_errors")
    return finish_save(cur, "maintenance", trim(h.formvalue("mode")))
end

function action_log_clear()
    local f = io.open("/var/log/homegate.log", "w")
    if not f then return redirect_page("maintenance", nil, "Unable to clear HomeGate log") end
    f:close()
    return redirect_page("maintenance", "Log cleared")
end

local function attachment(name, content_type)
    local h = http()
    h.header("Content-Disposition", 'attachment; filename="' .. name .. '"')
    h.prepare_content(content_type or "application/octet-stream")
end

-- Only the public backup codec can consume uploaded bytes. It cannot write UCI.
local function backup_codec()
    return require "luci.model.homegate.backup"
end

function action_config_export()
    local body, err = backup_codec().export(uci_cursor())
    if not body then return redirect_page("maintenance", nil, err) end
    attachment("homegate-config-backup.conf", "text/plain; charset=UTF-8")
    http().write(body)
end

function action_config_import()
    -- The legacy POST route now validates and previews only. Neither a crafted
    -- mode nor a browser confirmation can reach the old direct overwrite path.
    local codec = backup_codec()
    local result, err = codec.preview(uci_cursor(), http().formvalue("config_payload"))
    http().prepare_content("application/json")
    http().write(codec.json(result or {api_version=1,ok=false,phase="config-preview",error=err}) .. "\n")
end

local function reset_homegate_config(cur)
    -- Keep reset deterministic on older LuCI/UCI bindings: enumerate the
    -- section types HomeGate owns instead of relying on foreach(..., nil).
    local names, seen = {}, {}
    local types = {"homegate", "dns_account", "ddns_rule", "certificate", "web_rule", "wol_host"}
    for _, stype in ipairs(types) do
        cur:foreach("homegate", stype, function(s)
            local name = s[".name"]
            if name and not seen[name] then
                seen[name] = true
                names[#names + 1] = name
            end
        end)
    end
    for _, name in ipairs(names) do cur:delete("homegate", name) end
    local ok = cur:section("homegate", "homegate", "main", {
        enabled = "1",
        log_level = "info",
        log_max_lines = "1024",
        access_enabled = "0",
        access_allow = "",
        access_deny = "",
        access_region = "",
        wol_interface = "br-lan",
        last_wol_host = "",
        ddns_interval = "300",
        https_port = "443",
        http_port = "0",
        proxy_https_port = "10443",
        proxy_http_port = "10080",
        auto_firewall = "1",
        acme_email = "",
        acme_directory = PROD_DIRECTORY,
        renew_days = "30",
        version = (function()
            local v = package_info().product
            return (v ~= "" and v ~= "-") and v or "dev"
        end)()
    })
    return ok ~= false
end

function action_config_reset()
    local cur = uci_cursor()
    if not reset_homegate_config(cur) then return redirect_page("maintenance", nil, "Unable to restore default configuration") end
    local ok, err = commit(cur)
    if not ok then return redirect_page("maintenance", nil, err) end
    local applied, apply_err = apply_homegate()
    if not applied then return redirect_page("maintenance", nil, apply_err) end
    return redirect_page("maintenance", "Default configuration restored")
end

local function diagnostic_config(cur)
    local out = {"[configuration]"}
    local main = cur:get_all("homegate", "main") or {}
    local keys = {}
    for k in pairs(main) do if k:sub(1, 1) ~= "." then keys[#keys + 1] = k end end
    table.sort(keys)
    for _, k in ipairs(keys) do out[#out + 1] = "main." .. k .. "=" .. tostring(main[k]) end
    local types = {"dns_account", "ddns_rule", "certificate", "web_rule", "wol_host"}
    for _, stype in ipairs(types) do
        cur:foreach("homegate", stype, function(s)
            local id = s[".name"] or "?"
            out[#out + 1] = stype .. "." .. id
            local skeys = {}
            for k in pairs(s) do if k:sub(1, 1) ~= "." then skeys[#skeys + 1] = k end end
            table.sort(skeys)
            for _, k in ipairs(skeys) do
                local v = s[k]
                if stype == "dns_account" and (k == "id" or k == "secret") then v = "[redacted]" end
                if type(v) == "table" then v = table.concat(v, ",") end
                out[#out + 1] = "  " .. k .. "=" .. tostring(v or "")
            end
        end)
    end
    return table.concat(out, "\n")
end

function action_diagnostic_download()
    local cur = uci_cursor()
    local p = package_info()
    local parts = {
        "HomeGate diagnostic report",
        "generated=" .. os.date("!%Y-%m-%dT%H:%M:%SZ"),
        "core_package=" .. p.core,
        "luci_package=" .. p.luci,
        "i18n_package=" .. p.i18n,
        "architecture=" .. p.arch,
        "",
        "[homegate status]", trim(sys().exec("/usr/bin/homegate status 2>/dev/null") or ""),
        "", "[network]", trim(sys().exec("/usr/bin/homegate network-resolve 2>/dev/null") or ""),
        "", "[ddns]", trim(sys().exec("/usr/bin/homegate ddns-status 2>/dev/null") or ""),
        "", "[certificates]", trim(sys().exec("/usr/bin/homegate cert-status 2>/dev/null") or ""),
        "", "[proxy]", trim(sys().exec("/usr/bin/homegate proxy-status 2>/dev/null") or ""),
        "", "[access]", trim(sys().exec("/usr/bin/homegate access-status 2>/dev/null") or ""),
        "", "[firewall]", trim(sys().exec("/usr/bin/homegate firewall-status 2>/dev/null") or ""),
        "", "[wol]", trim(sys().exec("/usr/bin/homegate wol-status 2>/dev/null") or ""),
        "", diagnostic_config(cur),
        "", "[recent log]"
    }
    local log = sys().exec("tail -n 300 /var/log/homegate.log 2>/dev/null") or ""
    parts[#parts + 1] = trim(log)
    attachment("homegate-diagnostic.txt", "text/plain; charset=UTF-8")
    http().write(table.concat(parts, "\n") .. "\n")
end

function api_status() run_core_json("status") end
function api_version() run_core_json("version") end
function api_network() run_core_json("network-resolve") end
function api_ddns() run_core_json("ddns-status") end
function api_dns_zones()
    local id = safe_id(http().formvalue("account"))
    if id == "" then
        http().prepare_content("application/json")
        http().write('{"api_version":1,"ok":false,"phase":"dns-provider","zones":[],"error":"DNS account is required"}\n')
        return
    end
    run_core_json("dns-zones " .. id)
end
function api_certs() run_core_json("cert-status") end
function api_proxy() run_core_json("proxy-status") end
function api_firewall() run_core_json("firewall-status") end
function api_wol() run_core_json("wol-status") end

function api_access_recent() run_core_json("access-recent") end

function api_log_events()
    local max_lines = tonumber(uci_cursor():get("homegate", "main", "log_max_lines") or "1024") or 1024
    if max_lines < 64 then max_lines = 64 elseif max_lines > 20000 then max_lines = 20000 end
    run_core_json("log-events " .. tostring(math.floor(max_lines)))
end

function api_logs()
    local max_lines = tonumber(uci_cursor():get("homegate", "main", "log_max_lines") or "1024") or 1024
    if max_lines < 64 then max_lines = 64 elseif max_lines > 20000 then max_lines = 20000 end
    local lines = {}
    local count, next_slot = 0, 1
    local f = io.open("/var/log/homegate.log", "r")
    if f then
        for line in f:lines() do
            lines[next_slot] = line
            next_slot = next_slot % max_lines + 1
            count = math.min(count + 1, max_lines)
        end
        f:close()
    end
    if count == max_lines and next_slot ~= 1 then
        local ordered = {}
        for i = 0, count - 1 do
            ordered[i + 1] = lines[(next_slot + i - 1) % max_lines + 1]
        end
        lines = ordered
    end
    http().prepare_content("text/plain; charset=UTF-8")
    http().write(table.concat(lines, "\n"))
    if #lines > 0 then http().write("\n") end
end
