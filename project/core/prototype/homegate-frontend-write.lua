-- Locked native controller runner. Not a web endpoint or a general Lua runner.
local jsonc = require("luci.jsonc")
local function fail()
    io.write('{"api_version":1,"ok":false,"error":"Native writer request refused"}\n')
    os.exit(2)
end
if #arg ~= 1 then fail() end
local f = io.open(arg[1], "rb")
if not f then fail() end
local raw = f:read(2097153); local closed = f:close()
if not closed or type(raw) ~= "string" or #raw == 0 or #raw > 2097152 then fail() end
-- Older jsonc bindings use C strings and can silently truncate decoded NUL.
-- Inspect actual escape tokens before decoding; escaped backslashes are text.
if raw:find("%z") then fail() end
local offset = 1
while offset <= #raw do
    if raw:sub(offset,offset) == "\\" then
        if raw:sub(offset+1,offset+5) == "u0000" then fail() end
        offset = offset + 2
    else
        offset = offset + 1
    end
end
-- The official incremental parser rejects a second document/trailing content.
local parser = jsonc.new()
local parsed, request
for i=1,#raw do
    local byte = raw:sub(i,i)
    if parsed then
        if not byte:match("%s") then fail() end
    else
        local done = parser:parse(byte)
        if done == nil then fail() end
        if done then parsed=true; request=parser:get() end
    end
end
if not parsed or type(request) ~= "table" or type(request.route) ~= "string" or type(request.form) ~= "table" then fail() end
for key in pairs(request) do if key ~= "route" and key ~= "form" then fail() end end
local writer = require("luci.model.homegate.writer")
local handler = writer.routes[request.route]
if not handler then fail() end
local count = 0
for key,value in pairs(request.form) do
    count=count+1
    if count > 4096 or type(key) ~= "string" or #key > 96 or not key:match("^[%w_]+$") or
        type(value) ~= "string" or value:find("%z") then fail() end
end
-- Only this locked runner and the existing Go transaction host bypass the
-- transport layer. No request field or environment variable selects bypass.
package.loaded["luci.model.homegate.writer"] = {run=function(route, fn)
    if route ~= request.route or type(fn) ~= "function" then error("route") end
    return fn()
end}
local redirect
local http = require("luci.http")
local original_form = http.formvalue
http.formvalue = function(key) if key == nil then return request.form end; return request.form[key] end
http.redirect = function(value)
    if type(value) ~= "string" or #value > 4096 or value:find("[\r\n%z]") or
        not value:match("^/cgi%-bin/luci/admin/services/homegate/[%w_]+[?]?") then error("redirect") end
    local page,query=value:match("^/cgi%-bin/luci/admin/services/homegate/([%w_]+)(.*)$")
    if not ({basic=true,public=true,wol=true,maintenance=true})[page] or
        (query ~= "" and query:sub(1,1) ~= "?") then error("redirect") end
    redirect=value
end
-- Mutating routes return a bounded redirect. Their raw output is never relayed.
http.write = function() error("unexpected response") end
http.header = function() error("unexpected response") end
http.prepare_content = function() error("unexpected response") end
local sys = require("luci.sys")
local original_exec, original_call = sys.exec, sys.call
-- Close in the launcher shell itself, before it forks a command/subshell.
-- A redirection on parentheses alone leaves the waiting shell holding FD6.
sys.exec = function(command) return original_exec("exec 6>&-; (" .. command .. ")") end
sys.call = function(command) return original_call("exec 6>&-; (" .. command .. ")") end
local ok = pcall(function()
    require("luci.controller.homegate")[handler]()
end)
http.formvalue = original_form
if not ok or not redirect then fail() end
io.write(jsonc.stringify({api_version=1,dispatched=true,
    ok=not redirect:find("[?&]error="),redirect=redirect}) .. "\n")
