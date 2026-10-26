-- Read-only catalog compatibility; no account/configuration/worker access.
local dir=arg[0]:match('^(.*)/[^/]+$')
if not dir or arg[2] or (arg[1]~='dns-provider-catalog' and arg[1]~='acme-ca-catalog') then os.exit(1) end
local function source_line(name)
    local f=io.open(dir..'/../../../'..name,'rb')
    if not f then return nil end
    local raw=f:read(65)
    if not f:close() or not raw or #raw>64 then return nil end
    return raw
end
local version,release=source_line('VERSION'),source_line('RELEASE')
if not version or not version:match('^%d+%.%d+%.%d+\n$') or
    not release or not release:match('^[1-9]%d*\n$') then os.exit(1) end
version=version:sub(1,-2)..'-r'..release:sub(1,-2)
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local function capabilities()
    return {credentials_validation=true,ddns=true,dns01=true,zone_discovery=true}
end
local report={api_version=1,ok=true,version=version,prototype=true,write_ready=false,effect='none'}
if arg[1]=='dns-provider-catalog' then
    report.phase='dns-provider'
    report.providers={
        {name='aliyun',display_name='Aliyun DNS',aliases={'alidns'},capabilities=capabilities(),credentials={
            {name='key_id',label='AccessKey ID',secret=false,required=true},
            {name='secret',label='AccessKey Secret',secret=true,required=true}}},
        {name='cloudflare',display_name='Cloudflare',aliases={'cf'},capabilities=capabilities(),credentials={
            {name='secret',label='API Token',secret=true,required=true}}},
        {name='dnspod',display_name='Tencent DNSPod',aliases={'tencent','tencentcloud'},capabilities=capabilities(),credentials={
            {name='key_id',label='SecretId',secret=false,required=true},
            {name='secret',label='SecretKey',secret=true,required=true}}},
        {name='huaweicloud',display_name='Huawei Cloud DNS',aliases={'huawei','hwcloud'},capabilities=capabilities(),credentials={
            {name='key_id',label='Access Key ID',secret=false,required=true},
            {name='secret',label='Secret Access Key',secret=true,required=true},
            {name='account_id',label='Account ID',secret=false,required=true},
            {name='endpoint',label='DNS API Endpoint',secret=false,required=true,placeholder='https://dns.<region>.myhuaweicloud.com'}}}
    }
else
    report.phase='acme-ca'
    report.cas={{name='letsencrypt',display_name="Let's Encrypt",directories={
        production='https://acme-v02.api.letsencrypt.org/directory',
        staging='https://acme-staging-v02.api.letsencrypt.org/directory'}}}
end
local output=codec.json(report)..'\n'
if #output>8192 then os.exit(1) end
io.write(output)
