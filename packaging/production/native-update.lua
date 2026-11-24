local fs = require('nixio.fs')
local nx = require('nixio')
local json = require('luci.jsonc')
require('nixio.util')

local M = {}
local mode, library_base = ...
local base = (mode == 'library' and library_base) or assert(arg[0]:match('^(.*)/[^/]+$'))
local proto = base .. '/project/core/prototype'
local cache_root = '/tmp/homegate-update-check'
local last_check_day = '/etc/homegate/update-check-day'
local interval = 86400
local response_limit = 262144
local notes_limit = 16384
local cache_limit = 6 * notes_limit + 24576
local default_source = 'https://github.com/frostcypress/HomeGate/releases'
local archive_limit = 32 * 1024 * 1024
M.source_path = '/etc/homegate/plugin-update-url'

local function quote(value) return "'" .. value:gsub("'", "'\\''") .. "'" end

function M.digest(value)
    return type(value) == 'string' and #value == 64 and not value:find('[^0-9a-f]')
end

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

function M.upgrade_path(current, target, minimum)
    if minimum == nil then minimum = current end
    local a, normalized = release_version(current)
    local b, next_version = release_version(target)
    local floor, floor_version = release_version(minimum)
    if not a or not b or not floor or normalized ~= current or next_version ~= target or
       floor_version ~= minimum or floor[4] < 1 then return false end
    for i = 1, 3 do
        if a[i] ~= b[i] or floor[i] ~= b[i] then return false end
    end
    return floor[4] <= a[4] and a[4] < b[4]
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
    if type(entry) ~= 'table' or entry.format ~= 4 or entry.source ~= source or type(entry.checked_at) ~= 'number' or
        entry.checked_at > now then return end
    if entry.state == 'release' and (now - entry.checked_at >= interval or not release_version(entry.version)) then return end
    if entry.state == 'release' or entry.state == 'unpublished' or entry.state == 'error' then return entry end
end

local function replace_private(path, raw)
    local next_path = path .. '.next'
    fs.unlink(next_path)
    if not write_private(next_path, raw) then return false end
    if fs.rename(next_path, path) then return true end
    fs.unlink(next_path)
    return false
end

local function claim_day(day)
    if not private_dir('/etc/homegate') then return false end
    if fs.lstat(last_check_day) then
        if not private_file(last_check_day, 9) then return false end
        local raw = fs.readfile(last_check_day, 9)
        local previous = raw and raw:match('^(%d%d%d%d%d%d%d%d)\n$')
        if not previous or previous >= day then return false end
    end
    return replace_private(last_check_day, day .. '\n')
end

local function current_source()
    local source = M.read_source()
    if source == '' then source = default_source end
    if M.valid_source(source) then return source end
end

function M.check(day)
    local source = current_source()
    if not source then return false, 'source' end
    if not fs.lstat(cache_root) then fs.mkdir(cache_root, '700') end
    if not private_dir(cache_root) then return false, 'cache' end
    local lock_path = cache_root .. '/check.lock'
    if not fs.lstat(lock_path) then
        local created = nx.open(lock_path, nx.open_flags('wronly', 'creat', 'excl'), '600')
        if created then created:close() end
    end
    if not private_file(lock_path, 0) then return false, 'cache' end
    local lock = nx.open(lock_path, nx.open_flags('rdwr'))
    if not lock then return false, 'cache' end
    if not lock:lock('tlock') then lock:close(); return false, 'busy' end
    -- Only the automatic check records its attempt for the day.
    if day and not claim_day(day) then lock:close(); return false end
    local parse = assert(loadfile(base .. '/strict-web-json.lua'))()
    local entry = collect(source, parse)
    entry.format, entry.source = 4, source
    local current = M.installed()
    if entry.state == 'release' and entry.assets and current and is_newer(release_version(entry.version), current) then
        entry.manifest, entry.install_blocked = M.signed_release(entry, cache_root, parse)
    end
    entry.checked_at = os.time()
    local saved = replace_private(cache_root .. '/result.json', json.stringify(entry))
    lock:close()
    return saved, not saved and 'cache' or nil
end

local function check_at_two()
    local tz = fs.readfile('/etc/TZ', 256)
    nx.setenv('TZ', tz and tz:match('^([^%c]+)%s*$') or nil)
    local now = os.time()
    local clock = os.date('*t', now)
    if clock.hour == 2 and clock.min == 0 then M.check(os.date('%Y%m%d', now)) end
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
    local source = current_source()
    if not source then return {ok=true,state='error',reason='source'} end
    if fs.lstat(cache_root) and not private_dir(cache_root) then return {ok=true,state='error',reason='cache'} end
    local entry = cached(cache_root .. '/result.json', source, os.time())
    if not entry then return {ok=true,state='scheduled',current=current_version} end
    local output = {ok=true,state=entry.state,current=current_version,checked_at=entry.checked_at,
                    reason=entry.reason,http_status=entry.http_status}
    if entry.state == 'release' then
        output.latest = entry.version
        output.state = is_newer(release_version(entry.version), current) and 'available' or 'latest'
        if output.state == 'available' then
            output.notes, output.truncated = entry.notes, entry.truncated
            if not M.trust_key() then output.install_blocked='trust'
            elseif not entry.assets then output.install_blocked='assets'
            elseif type(entry.manifest) ~= 'table' or not M.upgrade_path(entry.manifest.minimum, entry.version) then
                output.install_blocked=entry.install_blocked or 'manifest'
            elseif not M.upgrade_path(current_version, entry.version, entry.manifest.minimum) then
                output.install_blocked='version'
                output.minimum_version=entry.manifest.minimum
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

function M.capture(command, limit)
    local pipe = io.popen(command .. " 2>/dev/null; printf '\\nHGEXIT:%s\\n' \"$?\"", 'r')
    if not pipe then return end
    local raw = pipe:read(limit + 32)
    pipe:close()
    local text, code
    if raw then text, code = raw:match('^(.*)\nHGEXIT:(%d+)\n$') end
    if code == '0' and #text <= limit then return text end
end

function M.download(entry, name, path, limit, timeout)
    local url, github = M.asset_url(entry, name)
    if not url then return false end
    local network = github and "--location --max-redirs 3 --proto '=https' --proto-redir '=https'" or
        "--proto '=http,https'"
    local request = path .. '.request'
    fs.unlink(request)
    local config = 'url = "' .. url:gsub('"', '\\"') .. '"\n'
    if not write_private(request, config) then return false end
    local cmd = "/usr/bin/curl --disable --silent --noproxy '*' --globoff " .. network ..
        " --connect-timeout 5 --max-time " .. (timeout or 90) .. " --max-filesize " .. limit ..
        " --output " .. quote(path) .. " --write-out '%{http_code}' --config - < " .. quote(request)
    local status = M.capture("(umask 077 && ulimit -f " .. math.ceil(limit / 512) .. " && " .. cmd .. ")", 3)
    fs.unlink(request)
    local info = private_file(path, limit)
    return status == '200' and info and info.size > 0 and info
end

function M.signed_release(entry, dir, parse)
    local key = M.trust_key()
    if not key then return nil, 'trust' end
    local manifest, signature = dir .. '/manifest.json', dir .. '/manifest.sig'
    fs.unlink(manifest)
    fs.unlink(signature)
    local signed, reason
    if not M.download(entry, 'manifest.json', manifest, 16384, 8) or
       not M.download(entry, 'manifest.sig', signature, 1024, 8) then
        reason = 'download'
    else
        signed, reason = M.verify_manifest(dir, parse, entry.version)
    end
    fs.unlink(manifest)
    fs.unlink(signature)
    return signed, reason
end

function M.verify_manifest(dir, parse, expected)
    local key = M.trust_key()
    if not key then return nil, 'trust' end
    local manifest, signature = dir .. '/manifest.json', dir .. '/manifest.sig'
    if not private_file(manifest, 16384) or not private_file(signature, 1024) then return nil, 'archive' end
    if os.execute('openssl dgst -sha256 -verify ' .. quote(key) .. ' -signature ' .. quote(signature) .. ' ' ..
                  quote(manifest) .. ' >/dev/null 2>&1') ~= 0 then return nil, 'signature' end
    local raw = fs.readfile(manifest, 16385)
    local signed = raw and parse(raw)
    local target, version
    if type(signed) == 'table' then target, version = release_version(signed.version) end
    if not target or version ~= signed.version or expected and version ~= expected then return nil, 'manifest' end
    local previous = string.format('%d.%d.%d-r%d', target[1], target[2], target[3], target[4] - 1)
    local artifact = 'homegate-r' .. target[4] .. '-offline-three.tar'
    if signed.from_version ~= previous or signed.artifact ~= artifact or not M.digest(signed.sha256) or type(signed.size) ~= 'number' or
       signed.size < 1 or signed.size > archive_limit or signed.size ~= math.floor(signed.size) or
       type(signed.architecture) ~= 'string' or #signed.architecture > 64 or signed.architecture == 'all' or
       not signed.architecture:match('^[a-z0-9_%-]+$') then return nil, 'manifest' end
    local minimum = signed.minimum_version
    if minimum == nil then minimum = previous end
    if not M.upgrade_path(minimum, version) then return nil, 'manifest' end
    return {minimum=minimum, declared_minimum=signed.minimum_version, architecture=signed.architecture,
            artifact=artifact, sha256=signed.sha256, size=signed.size, version=version}
end

if mode == 'library' then return M end
if arg[1] ~= 'schedule' or arg[2] or nx.getuid() ~= 0 then os.exit(2) end
while true do
    check_at_two()
    local pending = fs.lstat('/tmp/homegate-offline-update/release.tar') or fs.lstat('/tmp/homegate-offline-update/upload.tar')
    if pending and os.time() - pending.mtime > 900 then
        assert(loadfile(base .. '/native-online-update.lua'))('library', base).expire_staging()
    end
    nx.nanosleep(15)
end
