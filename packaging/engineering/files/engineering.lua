-- No filesystem writes, external actions or implicit reads of user configuration.
local base=arg[0]:match('^(.*)/[^/]+$')
if not base then os.exit(7) end
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local function line(name)
    local f=io.open(base..'/'..name,'rb');if not f then return nil end
    local value=f:read(65);if not f:close() or not value or #value>64 then return nil end;return value
end
local version,release=line('VERSION'),line('RELEASE')
if not version or not version:match('^%d+%.%d+%.%d+\n$') or not release or not release:match('^[1-9]%d*\n$') then os.exit(7) end
local report={api_version=1,engineering=true,ok=true,version=version:sub(1,-2)..'-r'..release:sub(1,-2),
    scope='isolated-ddns-contract-engineering',effect='none',write_ready=false,production_ready=false,
    configuration_changed=false,daemon_started=false}
if arg[2] or (arg[1]~='version' and arg[1]~='check-stdin') then os.exit(2) end
if arg[1]=='version' then
    report.phase='engineering-version'
else
    local validator=assert(loadfile(base..'/project/core/prototype/configuration-validation.lua'))()
    local ip=assert(loadfile(base..'/project/core/prototype/cloudflare-record-plan.lua'))()
    local raw=io.stdin:read(262145) or ''
    local candidate=#raw<=262144 and codec.private_configuration(raw)
    local counts
    if candidate then counts=validator.validate(candidate,candidate,codec.json,ip) end
    report.phase='engineering-configuration-check';report.ok=counts~=nil
    report.configuration_valid=report.ok;report.source_bound=false
    report.error_kind=counts and '' or 'invalid_configuration'
    report.sections=counts or {}
end
io.write(codec.json(report)..'\n')
if not report.ok then os.exit(1) end
