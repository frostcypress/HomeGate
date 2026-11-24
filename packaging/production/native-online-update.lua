local fs = require('nixio.fs')
local nx = require('nixio')
local json = require('luci.jsonc')
require('nixio.util')

local mode, library_base = ...
local base = (mode == 'library' and library_base) or assert(arg[0]:match('^(.*)/[^/]+$'))
local update = assert(loadfile(base .. '/native-update.lua'))('library', base)
local parse = assert(loadfile(base .. '/strict-web-json.lua'))()
local M = {}
local root = '/etc/homegate'
local receipt = root .. '/online-update.json'
local lock_path = root .. '/online-update.lock'
local archive_limit = 32 * 1024 * 1024
local stage_dir = '/tmp/homegate-offline-update'
local stage_archive = stage_dir .. '/upload.tar'
local stage_payload = stage_dir .. '/release.tar'
local stage_ticket = stage_dir .. '/ticket.json'
M.upload_limit = archive_limit + 65536
local states = {queued=true,downloading=true,installing=true,failed=true,recovery=true,success=true}
local function quote(value) return "'" .. value:gsub("'", "'\\''") .. "'" end
local function id(value)
    return type(value) == 'string' and #value == 32 and not value:find('[^0-9a-f]')
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
    if value and id(value.job) and id(value.offer) and update.upgrade_path(value.current, value.target) and
        type(value.updated_at) == 'number' and states[value.state] and
        (value.offline == nil or value.offline == true) then return value end
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

local function queue_blocker()
    local previous = read()
    if previous == false or previous and (previous.state == 'installing' or previous.state == 'recovery') and
        not verified_after_recovery(previous) then return 'recovery' end
    if previous and previous.state == 'queued' and os.time() - previous.updated_at <= 30 then return 'busy' end
end

function M.prepare(form, job)
    if not id(job) or not id(form.update_offer) or type(form.update_target) ~= 'string' then return false, 'offer' end
    local lease = lock()
    if not lease then return false, 'busy' end
    local result, reason = false, queue_blocker()
    if not reason then
        local current
        if form.update_mode == 'offline' then current = M.staged()
        elseif not form.update_mode then current = update.status() end
        if current and current.offer == form.update_offer and current.latest == form.update_target then
            result = store({job=job,offer=current.offer,current=current.current,target=current.latest,
                            offline=form.update_mode == 'offline' or nil}, 'queued')
            if not result then reason = 'receipt' end
        else
            result, reason = false, 'offer'
        end
    end
    lease:close()
    return result, reason
end

local function hash(path)
    local text = update.capture('sha256sum ' .. quote(path), 256)
    return text and text:match('^([0-9a-f]+)  ')
end

local function installed_architecture()
    local arch = update.capture('opkg status homegate-core', 16384)
    arch = arch and arch:match('\nArchitecture: ([a-z0-9_%-]+)\n')
    if not arch or arch == 'all' or #arch > 64 then return end
    local architectures = update.capture('opkg print-architecture', 8192)
    if not architectures then return end
    for value in architectures:gmatch('arch ([a-z0-9_%-]+) %d+\n') do
        if value == arch then return arch end
    end
end

local function stage_directory(create)
    if create and not fs.lstat(stage_dir) then fs.mkdir(stage_dir, '700') end
    local info = fs.lstat(stage_dir)
    return info and info.type == 'dir' and info.uid == 0 and info.modedec == 700
end

local function clear_stage()
    for _, name in ipairs({'upload.tar','release.tar','ticket.json','manifest.json','manifest.sig'}) do
        fs.unlink(stage_dir .. '/' .. name)
    end
end

function M.staged()
    if not stage_directory() or not private(stage_ticket, 4096) or not private(stage_payload, archive_limit) then return end
    local value = parse(fs.readfile(stage_ticket, 4097) or '')
    local _, current = update.installed()
    if value and id(value.offer) and value.current == current and type(value.expires) == 'number' and
       value.expires >= os.time() and update.upgrade_path(current, value.latest) then return value end
end

function M.expire_staging()
    local lease = lock()
    if not lease then return end
    local upload = stage_directory() and (private(stage_payload, archive_limit) or private(stage_archive, M.upload_limit))
    if upload and os.time() - upload.mtime > 900 and not M.staged() then clear_stage() end
    lease:close()
end

local function member_command(archive, name)
    return 'tar -xOf ' .. quote(archive) .. ' ' .. quote(name)
end

local function extract_member(archive, name, output, limit)
    local cmd = member_command(archive, name)
    local code = os.execute('(umask 077; ulimit -f ' .. math.ceil(limit / 512) .. ' && ' ..
        cmd .. ' > ' .. quote(output) .. ') 2>/dev/null')
    return code == 0 and private(output, limit)
end

local function offline_manifest(archive, dir, expected)
    local header = fs.readfile(archive, 512)
    if not header or header:sub(258, 263) ~= 'ustar\0' then return nil, 'archive' end
    local listing = update.capture('tar -tf ' .. quote(archive), 1024)
    if not listing then return nil, 'archive' end
    local entries, count = {}, 0
    for name in listing:gmatch('[^\n]+') do
        if entries[name] then return nil, 'archive' end
        entries[name], count = true, count + 1
    end
    if count ~= 3 or not entries['manifest.json'] or not entries['manifest.sig'] or
       not extract_member(archive, 'manifest.json', dir .. '/manifest.json', 16384) or
       not extract_member(archive, 'manifest.sig', dir .. '/manifest.sig', 1024) then return nil, 'archive' end
    local signed, reason = update.verify_manifest(dir, parse, expected)
    if not signed then return nil, reason end
    if not entries[signed.artifact] then return nil, 'archive' end
    return signed
end

local function stage_verified_upload()
    local signed, reason = offline_manifest(stage_archive, stage_dir)
    if not signed then return nil, reason end
    local _, current = update.installed()
    if not update.upgrade_path(current, signed.version, signed.minimum) then return nil, 'version' end
    if signed.architecture ~= installed_architecture() then return nil, 'architecture' end
    local payload = extract_member(stage_archive, signed.artifact, stage_payload, signed.size)
    if not payload or payload.size ~= signed.size or hash(stage_payload) ~= signed.sha256 then return nil, 'checksum' end
    local uuid = fs.readfile('/proc/sys/kernel/random/uuid', 38)
    local offer = uuid and uuid:gsub('[-\n]', '')
    if not id(offer) or not write(stage_ticket, json.stringify({offer=offer, current=current,
        latest=signed.version, expires=os.time() + 900})) then return nil, 'cache' end
    return {ok=true,offer=offer,current=current,latest=signed.version}
end

function M.stage(size, receive)
    local lease = lock()
    if not lease then return {ok=false,update_reason='busy'} end
    local blocked = queue_blocker()
    if blocked then lease:close(); return {ok=false,update_reason=blocked} end
    if not stage_directory(true) then lease:close(); return {ok=false,update_reason='cache'} end
    clear_stage()
    local fd = nx.open(stage_archive, nx.open_flags('wronly', 'creat', 'excl'), '600')
    if not fd then lease:close(); return {ok=false,update_reason='cache'} end
    local ok, complete = pcall(receive, fd)
    local closed = fd:close()
    local info = ok and complete and closed and private(stage_archive, M.upload_limit)
    local result, reason
    if info and info.size == size then result, reason = stage_verified_upload() end
    fs.unlink(stage_archive)
    if not result then clear_stage() end
    lease:close()
    return result or {ok=false,update_reason=reason or 'archive'}
end
local function extract(archive, dir, folder, files)
    local listing = update.capture('tar -tf ' .. quote(archive), 4096)
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
    local arch = installed_architecture()
    if not arch then return false, 'architecture' end
    local signed, reason
    if job.offline then signed, reason = update.verify_manifest(stage_dir, parse, version)
    else signed, reason = update.signed_release(entry, dir, parse) end
    if not signed then return false, reason end
    if not update.upgrade_path(job.current, version, signed.minimum) then return false, 'version' end
    if signed.architecture ~= arch then return false, 'architecture' end
    local archive = dir .. '/release.tar'
    if job.offline then
        local payload = private(stage_payload, signed.size)
        if not payload or payload.size ~= signed.size or not fs.rename(stage_payload, archive) then return false, 'archive' end
    else
        local offered = entry.manifest
        if signed.sha256 ~= offered.sha256 or signed.size ~= offered.size or
           signed.architecture ~= offered.architecture or signed.minimum ~= offered.minimum or
           signed.declared_minimum ~= offered.declared_minimum then return false, 'offer' end
        local downloaded = update.download(entry, signed.artifact, archive, signed.size)
        if not downloaded or downloaded.size ~= signed.size then return false, 'download' end
    end
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
    if not source or source.version ~= version or source.architecture ~= arch or
       source.minimum_version ~= signed.declared_minimum or type(source.sha256) ~= 'table' then
        return false, 'archive'
    end
    for _, name in ipairs({core, web, language}) do
        if not update.digest(source.sha256[name]) or hash(dir .. '/' .. name) ~= source.sha256[name] then return false, 'checksum' end
    end
    local _, installed = update.installed()
    if installed ~= job.current or not job.offline and update.status().offer ~= job.offer then return false, 'offer' end
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
    local status, entry
    if job.offline then status = M.staged() else status, entry = update.status() end
    if not status or status.offer ~= job.offer or status.current ~= job.current or status.latest ~= job.target then
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
    if job.offline then clear_stage() end
    for name in pairs(files) do fs.unlink(dir .. '/' .. name) end
    for _, name in ipairs({'manifest.json','manifest.sig','release.tar','install.log'}) do
        fs.unlink(dir .. '/' .. name)
        fs.unlink(dir .. '/' .. name .. '.request')
    end
    fs.rmdir(dir)
    lease:close()
end

if mode == 'library' then return M end
if nx.getuid() ~= 0 then os.exit(2) end
if arg[1] == 'web-write' and not arg[2] then
    local state = M.status().state
    os.exit((state == 'queued' or state == 'downloading' or state == 'installing') and 4 or 0)
end
if arg[1] ~= 'run' or not id(arg[2]) or arg[3] then os.exit(2) end
run(arg[2])
