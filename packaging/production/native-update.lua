local fs = require('nixio.fs')
local nx = require('nixio')
local json = require('luci.jsonc')
require('nixio.util')

local M = {}
local base = assert(arg[0]:match('^(.*)/[^/]+$'))
local proto = base .. '/project/core/prototype'
local cache_root = '/tmp/homegate-update-check'
local interval = 86400
local retry_interval = 900
local response_limit = 262144
local notes_limit = 16384
local cache_limit = 6 * notes_limit + 24576
local default_source = 'https://github.com/frostcypress/HomeGate/releases'
M.source_path = '/etc/homegate/plugin-update-url'

local function private_dir(path)
    local info = fs.lstat(path)
    return info and info.type == 'dir' and info.uid == 0 and info.modedec == 700
end

local function private_file(path, max)
    local info = fs.lstat(path)
    return info and info.type == 'reg' and info.uid == 0 and info.modedec == 600 and
        info.nlink == 1 and info.size <= max and info
end

function M.read_source()
    if not fs.lstat(M.source_path) then return '' end
    if not private_dir('/etc/homegate') then return end
    local state = private_file(M.source_path, 2049)
    if not state or state.size < 1 then return end
    local raw = fs.readfile(M.source_path, 2049)
    return raw and #raw == state.size and raw:match('^([^\r\n%z]*)\n$') or nil
end

function M.valid_source(value)
    if type(value) ~= 'string' or #value > 2048 then return false end
    local validation = assert(loadfile(proto .. '/configuration-validation.lua'))()
    local ip = assert(loadfile(proto .. '/cloudflare-record-plan.lua'))()
    return validation.target(value, ip)
end

local function release_version(value)
    if type(value) ~= 'string' or #value > 64 then return end
    local a, b, c, r = value:match('^v?(%d+)%.(%d+)%.(%d+)%-r(%d+)$')
    if not a then a, b, c = value:match('^v?(%d+)%.(%d+)%.(%d+)$') end
    if not a then return end
    local parts = {a, b, c, r or '0'}
    for i, part in ipairs(parts) do
        if #part > 9 then return end
        parts[i] = tonumber(part)
    end
    return parts, string.format('%d.%d.%d-r%d', unpack(parts))
end

local function is_newer(remote, installed)
    for i, value in ipairs(remote) do
        if value ~= installed[i] then return value > installed[i] end
    end
    return false
end

function M.next_release(current, target)
    local a, normalized = release_version(current)
    local b, next_version = release_version(target)
    if not a or not b or normalized ~= current or next_version ~= target then return false end
    return a[1] == b[1] and a[2] == b[2] and a[3] == b[3] and b[4] == a[4] + 1
end

local function release_assets(release, revision)
    local expected = {['manifest.json']=true, ['manifest.sig']=true,
                      ['homegate-r' .. revision .. '-offline-three.tar']=true}
    local assets = {}
    if type(release.assets) ~= 'table' then return end
    for _, asset in ipairs(release.assets) do
        if type(asset) == 'table' and expected[asset.name] then
            if assets[asset.name] or not M.valid_source(asset.browser_download_url) then return end
            assets[asset.name] = asset.browser_download_url
        end
    end
    for name in pairs(expected) do if not assets[name] then return end end
    return assets
end

local function endpoint(source)
    local owner, repo, suffix = source:match('^https://github%.com/([%w_.-]+)/([%w_.-]+)(.*)$')
    if owner and (suffix == '' or suffix == '/' or suffix == '/releases' or
                  suffix == '/releases/' or suffix == '/releases/latest') then
        return 'https://api.github.com/repos/' .. owner .. '/' .. repo .. '/releases/latest'
    end
    return source
end

local function write_private(path, raw)
    local fd = nx.open(path, nx.open_flags('wronly', 'creat', 'excl'), '600')
    if not fd then return false end
    local size = fd:writeall(raw)
    local closed = fd:close()
    if size == #raw and closed then return true end
    fs.unlink(path)
    return false
end

local function fetch(url)
    local request = cache_root .. '/request'
    fs.unlink(request) -- only the holder of the check lock writes this file
    local config = 'url = "' .. url:gsub('"', '\\"') .. '"\n'
    if not write_private(request, config) then return nil, 'cache' end
    local curl = "/usr/bin/curl --disable --silent --noproxy '*' --proto '=http,https' --globoff " ..
        "--connect-timeout 4 --max-time 8 --max-filesize " .. response_limit ..
        " --header 'Accept: application/vnd.github+json' --user-agent HomeGate-Update " ..
        "--write-out '\\nHGHTTP:%{http_code}\\n' --config - < " .. request ..
        " 2>/dev/null; printf '\\nHGEXIT:%s\\n' \"$?\""
    local file = io.popen(curl, 'r')
    local raw = file and file:read(response_limit + 64)
    if file then file:close() end
    fs.unlink(request)
    local output, exit
    if raw then output, exit = raw:match('^(.*)\nHGEXIT:(%d+)\n$') end
    if exit == '28' then return nil, 'timeout' end
    if exit ~= '0' then return nil, 'transport' end
    local body, status = output:match('^(.*)\nHGHTTP:(%d%d%d)\n$')
    if not body or #body > response_limit then return nil, 'transport' end
    return body, status
end

local function collect(source, parse)
    local url = endpoint(source)
    local body, status = fetch(url)
    if not body then return {state='error', reason=status} end
    if status == '404' and url:match('^https://api%.github%.com/repos/[%w_.-]+/[%w_.-]+/releases/latest$') then
        return {state='unpublished'}
    end
    if status ~= '200' then return {state='error', reason='http', http_status=tonumber(status)} end
    local release = parse(body)
    local parts, version
    if release then parts, version = release_version(release.tag_name) end
    if not parts or release.draft ~= false or release.prerelease ~= false then
        return {state='error', reason='metadata'}
    end
    local notes = type(release.body) == 'string' and release.body or ''
    local truncated = #notes > notes_limit
    if truncated then
        local last = notes_limit
        while notes:byte(last + 1) >= 128 and notes:byte(last + 1) < 192 do last = last - 1 end
        notes = notes:sub(1, last)
    end
    local assets = release_assets(release, parts[4])
    local id = assets and fs.readfile('/proc/sys/kernel/random/uuid', 38)
    local offer = id and id:gsub('[-\n]', '')
    if not offer or #offer ~= 32 or offer:find('[^0-9a-f]') then assets, offer = nil, nil end
    return {state='release', version=version, notes=notes, truncated=truncated,
            tag=release.tag_name, assets=assets, offer=offer}
end

local function cached(path, source, now)
    if not private_file(path, cache_limit) then return end
    local raw = fs.readfile(path, cache_limit + 1)
    local entry = raw and json.parse(raw)
    if type(entry) ~= 'table' or entry.format ~= 2 or entry.source ~= source or type(entry.checked_at) ~= 'number' or
        entry.checked_at > now or now - entry.checked_at >=
        (entry.state == 'error' and retry_interval or interval) then return end
    if entry.state == 'release' and not release_version(entry.version) then return end
    if entry.state == 'release' or entry.state == 'unpublished' or entry.state == 'error' then return entry end
end

local function store(path, entry)
    local next_path = path .. '.next'
    if not write_private(next_path, json.stringify(entry)) then return false end
    if fs.rename(next_path, path) then return true end
    fs.unlink(next_path)
    return false
end

local function get_entry(source, parse)
    local now = os.time()
    if not fs.lstat(cache_root) then fs.mkdir(cache_root, '700') end
    if not private_dir(cache_root) then
        return {state='error', reason='cache'}
    end
    local path = cache_root .. '/result.json'
    local entry = cached(path, source, now)
    if entry then return entry end
    local lock_path = cache_root .. '/check.lock'
    if not fs.lstat(lock_path) then
        local created = nx.open(lock_path, nx.open_flags('wronly', 'creat', 'excl'), '600')
        if created then created:close() end
    end
    if not private_file(lock_path, 0) then return {state='error', reason='cache'} end
    local lock = nx.open(lock_path, nx.open_flags('rdwr'))
    if not lock then return {state='error', reason='cache'} end
    if not lock:lock('tlock') then
        lock:close()
        return {state='checking'}
    end
    entry = cached(path, source, now)
    if not entry then
        entry = collect(source, parse)
        entry.format, entry.source, entry.checked_at = 2, source, os.time()
        -- A killed check can leave an uncommitted sibling. The lease owns it.
        fs.unlink(path .. '.next')
        if not store(path, entry) then entry = {state='error', reason='cache'} end
    end
    lock:close()
    return entry
end

function M.installed()
    local version = fs.readfile(base .. '/VERSION', 64)
    local release = fs.readfile(base .. '/RELEASE', 64)
    local semver = version and version:match('^(%d+%.%d+%.%d+)\n$')
    local revision = release and release:match('^([1-9]%d*)\n$')
    if semver and revision then return release_version(semver .. '-r' .. revision) end
end

function M.trust_key()
    local path = base .. '/update-public.pem'
    local info = fs.lstat(path)
    if info and info.type == 'reg' and info.uid == 0 and info.nlink == 1 and
       (info.modedec == 644 or info.modedec == 600) and info.size > 0 and info.size <= 4096 then return path end
end

function M.status()
    local current, current_version = M.installed()
    if not current then return {ok=true,state='error',reason='installed'} end
    local source = M.read_source()
    if source == '' then source = default_source end
    if not M.valid_source(source) then return {ok=true,state='error',reason='source'} end
    local entry = get_entry(source, assert(loadfile(base .. '/strict-web-json.lua'))())
    local output = {ok=true,state=entry.state,current=current_version,checked_at=entry.checked_at,
                    reason=entry.reason,http_status=entry.http_status}
    if entry.state == 'release' then
        output.latest = entry.version
        output.state = is_newer(release_version(entry.version), current) and 'available' or 'latest'
        if output.state == 'available' then
            output.notes, output.truncated = entry.notes, entry.truncated
            if not M.next_release(current_version, entry.version) then output.install_blocked='version'
            elseif not M.trust_key() then output.install_blocked='trust'
            elseif not entry.assets then output.install_blocked='assets'
            else output.offer = entry.offer end
        end
    end
    return output, entry
end

function M.asset_url(entry, name)
    local source = endpoint(entry.source)
    local value = entry.assets[name]
    if not M.valid_source(value) then return end
    local owner, repo = source:match('^https://api%.github%.com/repos/([%w_.-]+)/([%w_.-]+)/releases/latest$')
    if owner and entry.tag:match('^[v%d][%d%.r%-]+$') then
        local path = 'https://github.com/' .. owner .. '/' .. repo .. '/releases/download/' .. entry.tag .. '/' .. name
        if value == path then return value, true end
        return
    end
    local origin = source:match('^(https?://[^/?]+)')
    if origin and value:match('^(https?://[^/?]+)') == origin then return value, false end
end

if ... == 'library' then return M end
if arg[1] ~= 'schedule' or arg[2] or nx.getuid() ~= 0 then os.exit(2) end
nx.nanosleep(15)
while true do
    M.status()
    nx.nanosleep(retry_interval)
end
