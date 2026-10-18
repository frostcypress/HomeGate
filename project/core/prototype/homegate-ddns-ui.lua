-- Fixed request/result codecs for the separate, disabled native UI transport.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local backup=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local auth=assert(loadfile(dir..'/ddns-authority.lua'))()
local id=assert(loadfile(dir..'/ddns-plan.lua'))().id
local policy=assert(loadfile(dir..'/ddns-ui-policy.lua'))()
if arg[1]=='request' then
 if arg[2] then os.exit(1) end
 local f=io.open('/proc/self/fd/3','rb');if not f then os.exit(1) end
 local raw=f:read(4097) or '';local closed=f:close();if not closed or #raw>4096 then os.exit(1) end
 local d=shared.parse(raw);local action,payload=policy.request(d,auth.selection,id)
 if not action then os.exit(1) end;io.write(action..':'..payload..'\n');return
end
if arg[1]~='response' or not arg[2] or not arg[3] or arg[4] then os.exit(1) end
local raw=io.stdin:read(65537) or '';local d=shared.parse(raw)
if #raw>65536 or not policy.response(arg[2],arg[3],d,raw,auth.selection,id,backup.json,assert(loadfile(dir..'/ddns-schedule.lua'))(),assert(loadfile(dir..'/ddns-job.lua'))()) then os.exit(1) end
local effect=arg[2]=='submit' and 'unknown' or 'none'
io.write('{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-ui","operation":"'..arg[2]..'","effect":"'..effect..'","write_ready":false,"report":'..raw:gsub('%s+$','')..'}\n')
