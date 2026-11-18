-- Store manual rules separately so editing them does not replace the service
-- revision used by the coordinator, certificate worker, and DDNS scheduler.
local fs = require('nixio.fs')
local nx = require('nixio')
require('nixio.util')
local json = require('luci.jsonc')
local root = '/etc/homegate'
local path = root .. '/access-rules.json'
local pending = path .. '.next'
local M = {}
local ip = assert(loadfile('/usr/libexec/homegate/project/core/prototype/cloudflare-record-plan.lua'))()

function M.rule_key(token)
    local value = token:lower()
    local address, bits = value:match('^([^/]+)/(%d+)$')
    if address then
        local exact = address:find(':',1,true) and '128' or '32'
        if bits ~= exact then return value end
        value = address
    end
    return value:find(':',1,true) and ip.ipv6(value) or value
end

local function baseline(value)
    return type(value) == 'string' and #value <= 4096
end

local function rule_list(value, limit)
    return type(value) == 'string' and #value <= (limit or 4096) and not value:find('[^%x:.,;/%s]')
end

local function valid_stamp(value)
    return type(value) == 'string' and #value == 32 and not value:find('[^%da-f]')
end

local function metadata(name)
    local entry = fs.lstat(name)
    if entry then
        assert(entry.type == 'reg' and entry.uid == 0 and entry.modedec == 600
            and entry.nlink == 1 and entry.size <= 32768, 'unsafe access rule file')
    end
    return entry
end

local function rule_origins(allow, deny, origins)
    local out, selected = {}, {custom={},observed={}}
    for token in (allow .. ',' .. deny):gmatch('[^,%s;]+') do
        local key = M.rule_key(token)
        local origin = origins[key]
        if selected[origin] and not out[key] then
            out[key] = origin
            table.insert(selected[origin],token)
        end
    end
    return out,selected
end

function M.read(base_allow, base_deny)
    if not metadata(path) then return nil end
    local data = assert(json.parse(assert(fs.readfile(path, 32769))))
    assert(rule_list(data.allow) and rule_list(data.deny) and valid_stamp(data.stamp)
        and baseline(data.base_allow) and baseline(data.base_deny), 'invalid access rule file')
    if data.base_allow == base_allow and data.base_deny == base_deny then
        local origins = {}
        for _, origin in ipairs({'custom','observed'}) do
            local raw = data[origin] or ''
            assert(rule_list(raw,8192), 'invalid rule origins')
            for token in raw:gmatch('[^,%s;]+') do origins[M.rule_key(token)] = origin end
        end
        data.origins = rule_origins(data.allow, data.deny, origins)
        return data
    end
end

function M.write(base_allow, base_deny, allow, deny, origins)
    local directory = assert(fs.lstat(root))
    assert(directory.type == 'dir' and directory.uid == 0 and directory.modedec == 700)
    assert(baseline(base_allow) and baseline(base_deny) and rule_list(allow) and rule_list(deny))
    local stamp = assert(fs.readfile('/proc/sys/kernel/random/uuid', 38)):gsub('[%s-]', '')
    assert(valid_stamp(stamp))
    local _, selected = rule_origins(allow, deny, origins or {})
    local data = assert(json.stringify({base_allow=base_allow,base_deny=base_deny,allow=allow,deny=deny,stamp=stamp,
        custom=table.concat(selected.custom,','),observed=table.concat(selected.observed,',')}))
    assert(#data <= 32768, 'access rule file exceeds limit')
    metadata(path)
    if metadata(pending) then assert(fs.unlink(pending)) end
    local fd = assert(nx.open(pending, nx.open_flags('wronly','creat','excl'), '600'))
    local written = fd:writeall(data)
    assert(fd:close() and written == #data)
    assert(os.execute('fsync /etc/homegate/access-rules.json.next') == 0)
    assert(fs.rename(pending, path))
    assert(os.execute('fsync /etc/homegate') == 0)
end

function M.clear()
    local active, staged = metadata(path), metadata(pending)
    if active or staged then
        if staged then assert(fs.unlink(pending)) end
        if active then assert(fs.unlink(path)) end
        assert(os.execute('fsync /etc/homegate') == 0)
    end
end

return M
