-- Native LuCI handoff to the fixed Shell writer. Never lock with nixio lockf:
-- it does not serialize against the existing Linux flock writers.
local M = {}
local native_dispatch_enabled = false
M.routes = {
    basic_apply="action_basic_apply", public_apply="action_public_apply",
    public_account_apply="action_public_account_apply", certificate_apply="action_public_certificate_apply",
    public_action="action_public_action", access_update="action_access_update",
    access_clear_all="action_access_clear_all", access_clear_entry="action_access_clear_entry",
    access_clear_denied="action_access_clear_denied", access_delete_all="action_access_delete_all",
    access_delete_entry="action_access_delete_entry", access_delete_rule="action_access_delete_rule",
    wol_apply="action_wol_apply", wol_action="action_wol_action",
    maintenance_apply="action_maintenance_apply", log_clear="action_log_clear",
    config_reset="action_config_reset"
}

local function refused()
    local h = require("luci.http")
    h.status(503, "Service Unavailable")
    h.prepare_content("application/json")
    h.write('{"api_version":1,"ok":false,"error":"Native writer coordination is not ready"}\n')
end

local function request(route)
    local h = require("luci.http")
    local form = h.formvalue() or {}
    if type(form) ~= "table" then return nil end
    local fields, total = {}, 0
    for key, value in pairs(form) do
        if type(key) ~= "string" or #key > 96 or not key:match("^[%w_]+$") or
            type(value) ~= "string" or value:find("%z") then return nil end
        total = total + 1
        if total > 4096 then return nil end
        fields[key] = value
    end
    local body = require("luci.jsonc").stringify({route=route, form=fields})
    if type(body) ~= "string" or #body > 2097152 then return nil end
    return body
end

local function dispatch(route)
    local body = request(route)
    if not body then return refused() end
    local nx, fs = require("nixio"), require("nixio.fs")
    require("nixio.util")
    local uuid = io.open("/proc/sys/kernel/random/uuid", "r")
    if not uuid then return refused() end
    local id = uuid:read(38); uuid:close()
    if type(id) ~= "string" or not id:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x\n$") then return refused() end
    id = id:gsub("[-\n]", ""):lower()
    local dir = "/tmp/homegate-luci-" .. id
    local path = dir .. "/request"
    if not fs.mkdir(dir, "700") then return refused() end -- exclusive 0700
    local result, fd
    local ok = pcall(function()
        fd = nx.open(path, nx.open_flags("wronly", "creat", "excl"), "600")
        if not fd then error("private request") end
        local written = fd:writeall(body)
        local closed = fd:close()
        fd = nil
        if written ~= #body or not closed then error("private request") end
        -- Only an internally generated lowercase hex path enters the command.
        local out = require("luci.sys").exec("/usr/libexec/homegate/frontend-write '" .. path .. "' 2>/dev/null")
        if type(out) ~= "string" or #out > 65536 then error("response") end
        result = require("luci.jsonc").parse(out)
    end)
    if fd then pcall(function() fd:close() end) end
    fs.unlink(path); fs.rmdir(dir)
    if not ok or type(result) ~= "table" or result.dispatched ~= true or type(result.ok) ~= "boolean" or
        type(result.redirect) ~= "string" or #result.redirect > 4096 or
        not result.redirect:match("^/cgi%-bin/luci/admin/services/homegate/") or
        result.redirect:find("[\r\n%z]") then return refused() end
    local page, query = result.redirect:match("^/cgi%-bin/luci/admin/services/homegate/([%w_]+)(.*)$")
    if not ({basic=true,public=true,wol=true,maintenance=true})[page] or
        (query ~= "" and query:sub(1,1) ~= "?") then return refused() end
    return require("luci.http").redirect(result.redirect)
end

function M.run(route, handler)
    if not M.routes[route] or type(handler) ~= "function" then return refused() end
    -- No parameter or environment override. Persistent barriers, supervisor and
    -- recovery are prerequisites before this source can be enabled/installed.
    if not native_dispatch_enabled then return refused() end
    return dispatch(route)
end

return M
