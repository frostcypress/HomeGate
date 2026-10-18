-- Bounded private original receipts. No authority, network or filesystem actions.
local M={}
local formats={cloudflare='HGCFRetire1',aliyun='HGALIRetire1',dnspod='HGDNPRetire1',huaweicloud='HGHWRetire1'}
local function id(v)return type(v)=='string' and #v>0 and #v<=64 and v:match('^[a-zA-Z0-9_-]+$') end
local function hex(v)return type(v)=='string' and #v==64 and v:match('^[0-9a-f]+$') end
local function keys(d,allowed,n)
    if type(d)~='table' then return false end
    local count=0;for k in pairs(d) do if not allowed[k] then return false end;count=count+1 end;return count==n
end
local header={schema=true,identity=true,generation=true,grant=true,revision=true,boot=true,batch=true,previous=true,rows=true}
local fields={rule=true,provider=true,account=true,job=true,receipt=true,result=true,hashes=true,state=true,retired=true}
function M.proof(row,identity,raw)
    if type(raw)~='string' or #raw>2048 or raw:find('\r') then return false end
    local f={};for s in raw:gmatch('([^\n]*)\n') do f[#f+1]=s end
    if #f~=14 or table.concat(f,'\n')..'\n'~=raw or f[1]~=formats[row.provider] or f[2]~='homegate' or f[3]~=identity or f[4]~=row.account or f[5]~=row.job or not hex(f[6]) or not hex(f[14]) then return false end
    for i=1,7 do if f[i+6]~=row.hashes[i] then return false end end
    return true
end
function M.valid(d,json,parse,sync)
    if not keys(d,header,9) or d.schema~='HGDDNSBATCHRESULT1' or not hex(d.identity) or not hex(d.generation) or not hex(d.grant) or
        type(d.revision)~='number' or d.revision<1 or d.revision>32 or d.revision~=math.floor(d.revision) or type(d.boot)~='string' or #d.boot~=36 or not d.boot:match('^[0-9a-f-]+$') or
        type(d.batch)~='string' or #d.batch>30 or not d.batch:match('^[1-9]%d*:[1-9]%d*$') or (d.previous~='none' and not hex(d.previous)) or type(d.rows)~='table' or #d.rows<1 or #d.rows>32 then return false end
    local seen={}
    for index,row in ipairs(d.rows) do
        if not keys(row,fields,9) or not id(row.rule) or seen[row.rule] or not formats[row.provider] or not id(row.account) or type(row.job)~='string' or #row.job>9 or not row.job:match('^[1-9]%d*$') or tonumber(row.job)<2 or
            type(row.receipt)~='string' or #row.receipt>4096 or type(row.result)~='string' or #row.result>4096 or type(row.hashes)~='table' or #row.hashes~=7 or
            (row.state~='recorded' and row.state~='closed') or (row.state=='recorded' and (index~=#d.rows or row.retired~='')) then return false end
        seen[row.rule]=true
        for i,v in ipairs(row.hashes) do if (i>=2 and i<=5 and v=='-') then else if not hex(v) then return false end end end
        local hc=0;for k in pairs(row.hashes) do if type(k)~='number' or k<1 or k>7 or k~=math.floor(k) then return false end;hc=hc+1 end;if hc~=7 then return false end
        if (row.hashes[2]=='-')~=(row.hashes[3]=='-') or (row.hashes[4]=='-')~=(row.hashes[5]=='-') or (row.hashes[2]=='-' and row.hashes[4]=='-') then return false end
        local result,effect=sync.result(row.receipt,parse(row.receipt),row.provider,row.account,tostring(d.revision),row.rule,'0')
        if not result or result~=row.result or effect~='confirmed' then return false end
        if row.state=='closed' and not M.proof(row,d.identity,row.retired) then return false end
    end
    -- Reject sparse/object-shaped arrays, even with valid prefix members.
    local n=0;for k in pairs(d.rows) do if type(k)~='number' or k<1 or k>#d.rows or k~=math.floor(k) then return false end;n=n+1 end
    return n==#d.rows
end
function M.transition(old,next,previous,json)
    if next.previous~=previous then return false end
    if not old then return previous=='none' and #next.rows==1 and next.rows[1].state=='recorded' end
    for _,k in ipairs({'schema','identity','generation','grant','revision','boot','batch'}) do if old[k]~=next[k] then return false end end
    local n=#old.rows
    if #next.rows==n+1 then
        for i=1,n do if old.rows[i].state~='closed' or json(old.rows[i])~=json(next.rows[i]) then return false end end
        return next.rows[n+1].state=='recorded'
    elseif #next.rows==n and old.rows[n].state=='recorded' and next.rows[n].state=='closed' then
        for i=1,n-1 do if json(old.rows[i])~=json(next.rows[i]) then return false end end
        for k,v in pairs(old.rows[n]) do if k~='state' and k~='retired' and json(v)~=json(next.rows[n][k]) then return false end end
        return true
    end
    return false
end
return M
