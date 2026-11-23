local fs = require('nixio.fs')
local nx = require('nixio')
local json = require('luci.jsonc')
require('nixio.util')

local base = assert(arg[0]:match('^(.*)/[^/]+$'))
local update = assert(loadfile(base .. '/native-update.lua'))('library')
local parse = assert(loadfile(base .. '/strict-web-json.lua'))()
local M = {}
local root = '/etc/homegate'
local receipt = root .. '/online-update.json'
local lock_path = root .. '/online-update.lock'
local archive_limit = 32 * 1024 * 1024
local states = {queued=true,downloading=true,installing=true,failed=true,recovery=true,success=true}
local function quote(value) return "'" .. value:gsub("'", "'\\''") .. "'" end
local function id(value)
    return type(value) == 'string' and #value == 32 and not value:find('[^0-9a-f]')
end
local function digest(value)
    return type(value) == 'string' and #value == 64 and not value:find('[^0-9a-f]')
end
local function private(path, limit)
    local info = fs.lstat(path)
    return info and info.type == 'reg' and info.uid == 0 and info.modedec == 600 and
        info.nlink == 1 and info.size <= limit and info
end
local function write(path, value)
    local fd = nx.open(path, nx.open_flags('wronly', 'creat', 'excl'), '600')
    if not fd then return false end
    local n = fd:writeall(value)
    local closed = fd:close()
    return n == #value and closed
end
local function lock()
    local directory = fs.lstat(root)
    if not directory or directory.type ~= 'dir' or directory.uid ~= 0 or directory.modedec ~= 700 then return end
    if not fs.lstat(lock_path) then
        local fd = nx.open(lock_path, nx.open_flags('wronly', 'creat', 'excl'), '600')
        if fd then fd:close() end
    end
    if not private(lock_path, 0) then return end
    local fd = nx.open(lock_path, nx.open_flags('rdwr'))
    if fd and fd:lock('tlock') then return fd end
    if fd then fd:close() end
end
local function read()
    if not fs.lstat(receipt) then return end
    if not private(receipt, 4096) then return false end
    local raw = fs.readfile(receipt, 4097)
    local value = raw and parse(raw)
    if value and id(value.job) and id(value.offer) and update.next_release(value.current, value.target) and
        type(value.updated_at) == 'number' and states[value.state] then return value end
    return false
end
local function store(job, state, reason)
    job.state, job.reason, job.updated_at = state, reason, os.time()
    local tmp = receipt .. '.next'
    fs.unlink(tmp)
    return write(tmp, json.stringify(job)) and os.execute('fsync ' .. quote(tmp)) == 0 and
           fs.rename(tmp, receipt) and os.execute('fsync ' .. quote(root)) == 0
end

local function verified_after_recovery(job)
    local _, installed = update.installed()
    if installed ~= job.target then return false end
    local from = job.current:match('%-r(%d+)$')
    local target = job.target:match('%-r(%d+)$')
    local checkpoint = '/etc/.homegate-r' .. from .. '-before-r' .. target
    local directory = fs.lstat(checkpoint)
    return directory and directory.type == 'dir' and directory.uid == 0 and
        directory.modedec == 700 and private(checkpoint .. '/upgrade-log-verified', 0)
end

function M.status()
    local job = read()
    if job == nil then return {ok=true,state='idle'} end
    if not job then return {ok=true,state='recovery',reason='receipt'} end
    local state, reason = job.state, job.reason
    if state == 'installing' or state == 'downloading' or state == 'queued' and os.time() - job.updated_at > 30 then
        local lease = lock()
        if lease then
            -- Re-read after obtaining the lease in case the installer just completed.
            job = read()
            lease:close()
            if not job then return {ok=true,state='recovery',reason='receipt'} end
            state, reason = job.state, job.reason
            if state == 'installing' then state, reason = 'recovery', 'interrupted'
            elseif state == 'downloading' or state == 'queued' and os.time() - job.updated_at > 30 then
                state, reason = 'failed', 'interrupted'
            end
        end
    end
    if state == 'recovery' and verified_after_recovery(job) then
        state, reason = 'success', nil
    elseif state == 'success' then
        -- An offline upgrade can leave a verified receipt for an older installation.
        local _, installed = update.installed()
        if installed ~= job.target then return {ok=true,state='idle'} end
    end
    return {ok=true,state=state,reason=reason,target=job.target,job=job.job}
end

function M.prepare(form, job)
    if not id(job) or not id(form.update_offer) or type(form.update_target) ~= 'string' then return false, 'offer' end
    local lease = lock()
    if not lease then return false, 'busy' end
    local previous = read()
    local result, reason
    if previous == false or previous and (previous.state == 'installing' or previous.state == 'recovery') and
        not verified_after_recovery(previous) then
        result, reason = false, 'recovery'
    elseif previous and previous.state == 'queued' and os.time() - previous.updated_at <= 30 then
        result, reason = false, 'busy'
    else
        local current = update.status()
        if current.offer == form.update_offer and current.latest == form.update_target then
            result = store({job=job,offer=current.offer,current=current.current,target=current.latest}, 'queued')
            if not result then reason = 'receipt' end
        else
            result, reason = false, 'offer'
        end
    end
    lease:close()
    return result, reason
end

local function capture(command, limit)
    local pipe = io.popen(command .. " 2>/dev/null; printf '\\nHGEXIT:%s\\n' \"$?\"", 'r')
    if not pipe then return end
    local raw = pipe:read(limit + 32)
    pipe:close()
    local text, code
    if raw then text, code = raw:match('^(.*)\nHGEXIT:(%d+)\n$') end
    if code == '0' and #text <= limit then return text end
end

local function download(entry, name, path, limit)
    local url, github = update.asset_url(entry, name)
    if not url then return false end
    local network = github and "--location --max-redirs 3 --proto '=https' --proto-redir '=https'" or
        "--proto '=http,https'"
    local request = path .. '.request'
    local config = 'url = "' .. url:gsub('"', '\\"') .. '"\n'
    if not write(request, config) then return false end
    local cmd = "(/usr/bin/curl --disable --silent --noproxy '*' --globoff " .. network ..
        " --connect-timeout 5 --max-time 90 --max-filesize " .. limit ..
        " --output " .. quote(path) .. " --write-out '%{http_code}' --config - < " .. quote(request) .. ")"
    local status = capture("(ulimit -f " .. math.ceil(limit / 512) .. " && " .. cmd .. ")", 3)
    fs.unlink(request)
    local info = private(path, limit)
    return status == '200' and info and info.size > 0 and info
end

local function hash(path)
    local text = capture('sha256sum ' .. quote(path), 256)
    return text and text:match('^([0-9a-f]+)  ')
end
local function extract(archive, dir, folder, files)
    local listing = capture('tar -tf ' .. quote(archive), 4096)
    if not listing then return false end
    local count, seen = 0, {}
    for line in listing:gmatch('[^\n]+') do
        if line ~= folder .. '/' and line ~= folder then
            local path, name = line:match('^([^/]+)/([^/]+)$')
            if path ~= folder or not files[name] or seen[name] then return false end
            count, seen[name] = count + 1, true
        end
    end
    local expected = 0
    for _ in pairs(files) do expected = expected + 1 end
    if count ~= expected then return false end
    for name in pairs(files) do
        local output = dir .. '/' .. name
        local cmd = 'tar -xOf ' .. quote(archive) .. ' ' .. quote(folder .. '/' .. name) .. ' > ' .. quote(output)
        local info
        if os.execute(cmd .. ' 2>/dev/null') == 0 then info = private(output, archive_limit) end
        if not info or info.size == 0 then return false end
    end
    return true
end

local function install(job, entry, dir, files)
    local version, rev = job.target, job.target:match('%-r(%d+)$')
    local folder = 'homegate-r' .. rev .. '-offline-three'
    local arch = capture('opkg status homegate-core', 16384)
    arch = arch and arch:match('\nArchitecture: ([a-z0-9_%-]+)\n')
    if not arch or arch == 'all' or #arch > 64 then return false, 'architecture' end
    local key = update.trust_key()
    if not key then return false, 'trust' end
    local manifest, signature, archive = dir .. '/manifest.json', dir .. '/manifest.sig', dir .. '/release.tar'
    if not download(entry, 'manifest.json', manifest, 16384) or not download(entry, 'manifest.sig', signature, 1024) then
        return false, 'download'
    end
    if os.execute('openssl dgst -sha256 -verify ' .. quote(key) .. ' -signature ' .. quote(signature) .. ' ' ..
                  quote(manifest) .. ' >/dev/null 2>&1') ~= 0 then return false, 'signature' end
    local signed = parse(fs.readfile(manifest, 16385))
    if not signed or signed.version ~= version or signed.from_version ~= job.current or
       signed.architecture ~= arch or signed.artifact ~= folder .. '.tar' or not digest(signed.sha256) or
       type(signed.size) ~= 'number' or signed.size < 1 or signed.size > archive_limit or
       signed.size ~= math.floor(signed.size) then return false, 'manifest' end
    local architectures = capture('opkg print-architecture', 8192)
    if not architectures then return false, 'architecture' end
    local compatible = false
    for value in architectures:gmatch('arch ([a-z0-9_%-]+) %d+\n') do
        if value == arch then compatible = true; break end
    end
    if not compatible then return false, 'architecture' end
    local downloaded = download(entry, signed.artifact, archive, signed.size)
    if not downloaded or downloaded.size ~= signed.size then return false, 'download' end
    if hash(archive) ~= signed.sha256 then return false, 'checksum' end
    local core = 'homegate-core_' .. version .. '_' .. arch .. '.ipk'
    local web = 'luci-app-homegate_' .. version .. '_all.ipk'
    local language = 'luci-i18n-homegate-zh-cn_' .. version .. '_all.ipk'
    for _, name in ipairs({core, web, language, 'install.sh', 'upgrade-log.sh', 'SOURCE.json', 'SHA256SUMS', 'installed-SHA256SUMS'}) do
        files[name] = true
    end
    if not extract(archive, dir, folder, files) then return false, 'archive' end
    local source_file = dir .. '/SOURCE.json'
    if not private(source_file, 65536) then return false, 'archive' end
    local source = parse(fs.readfile(source_file, 65537))
    if not source or source.version ~= version or source.architecture ~= arch or type(source.sha256) ~= 'table' then
        return false, 'archive'
    end
    for _, name in ipairs({core, web, language}) do
        if not digest(source.sha256[name]) or hash(dir .. '/' .. name) ~= source.sha256[name] then return false, 'checksum' end
    end
    local _, installed = update.installed()
    local status = update.status()
    if installed ~= job.current or status.offer ~= job.offer then return false, 'offer' end
    if not store(job, 'installing') then return false, 'receipt' end
    local log = dir .. '/install.log'
    local code = os.execute('/bin/ash ' .. quote(dir .. '/install.sh') .. ' --migrate > ' .. quote(log) .. ' 2>&1')
    local actual = fs.readfile(log, 65536) or ''
    _, installed = update.installed()
    if code == 0 and installed == version and ('\n' .. actual):find('\nhomegate_offline_verified=true\n', 1, true) then
        return true
    end
    return false, actual:match('homegate_offline_failed=([a-z_]+)') or 'installer'
end

local function run(id_value)
    local lease = lock()
    if not lease then return end
    local job = read()
    if not job or job.job ~= id_value or job.state ~= 'queued' then lease:close(); return end
    local status, entry = update.status()
    if status.offer ~= job.offer or status.current ~= job.current or status.latest ~= job.target then
        store(job, 'failed', 'offer'); lease:close(); return
    end
    local dir = '/tmp/homegate-online-' .. id_value
    if not fs.mkdir(dir, '700') then store(job, 'failed', 'cache'); lease:close(); return end
    local files = {}
    if store(job, 'downloading') then
        local ok, succeeded, reason = pcall(install, job, entry, dir, files)
        if ok and succeeded then store(job, 'success')
        else store(job, job.state == 'installing' and 'recovery' or 'failed', ok and reason or 'installer') end
    end
    for name in pairs(files) do fs.unlink(dir .. '/' .. name) end
    for _, name in ipairs({'manifest.json','manifest.sig','release.tar','install.log'}) do
        fs.unlink(dir .. '/' .. name)
        fs.unlink(dir .. '/' .. name .. '.request')
    end
    fs.rmdir(dir)
    lease:close()
end

if ... == 'library' then return M end
if nx.getuid() ~= 0 then os.exit(2) end
if arg[1] == 'web-write' and not arg[2] then
    local state = M.status().state
    os.exit((state == 'queued' or state == 'downloading' or state == 'installing') and 4 or 0)
end
if arg[1] ~= 'run' or not id(arg[2]) or arg[3] then os.exit(2) end
run(arg[2])
