-- Internal business reader. Never serialize this result to a public response.
-- The caller supplies the shared codec and an inherited private pipe stream.
local M={limit=1114112}
local error_message="Invalid private configuration snapshot"
function M.parse(body,codec)
    local function reject() return nil,error_message end
    if type(body)~="string" or #body>M.limit or not codec then return reject() end
    local pos=1
    local function bytes(size)
        if pos+size-1>#body then error(error_message) end
        local value=body:sub(pos,pos+size-1); pos=pos+size; return value
    end
    local function number(max)
        local finish=body:find("\n",pos,true)
        if not finish or finish-pos>7 then error(error_message) end
        local value=body:sub(pos,finish-1); pos=finish+1
        if not value:match("^%d+$") or (#value>1 and value:sub(1,1)=="0") then error(error_message) end
        local n=tonumber(value)
        if not n or n>max then error(error_message) end
        return n
    end
    local ok,result=pcall(function()
        if bytes(11)~="HGPRIVATE1\n" then error(error_message) end
        local revision=number(32)
        if revision<1 then error(error_message) end
        local size=number(262144); local count=number(192)
        local public=bytes(size)
        local doc=codec.parse(public)
        if not doc or codec.canonical(public)~=public then error(error_message) end
        local permitted={}
        for _,s in ipairs(doc) do
            if s.kind=="dns_account" then
                for _,slot in ipairs({"key_id","secret","account_id","endpoint"}) do
                    permitted[s.values.provider.."."..s.name.."."..slot]=true
                end
            elseif s.kind=="ddns_rule" then permitted["ddns."..s.name..".url"]=true
            elseif s.kind=="web_rule" then permitted["web."..s.name..".target"]=true end
        end
        local credentials={}; local previous=""
        for i=1,count do
            local name_size=number(96); local value_size=number(4096)
            if name_size<1 or value_size<1 then error(error_message) end
            local name=bytes(name_size); local value=bytes(value_size)
            if not permitted[name] or name<=previous then error(error_message) end
            previous=name; credentials[name]=value
        end
        if bytes(4)~="END\n" or pos~=#body+1 then error(error_message) end
        return {revision=revision,configuration=doc,credentials=credentials}
    end)
    if not ok then return reject() end
    return result
end
function M.read(stream,codec)
    local ok,body=pcall(function() return stream:read(M.limit+1) end)
    if not ok then return nil,error_message end
    return M.parse(body,codec)
end
return M
