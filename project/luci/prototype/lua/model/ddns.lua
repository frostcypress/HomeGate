-- Separate candidate transport. Not installed by the production LuCI recipe.
local M={}
local native_ddns_ui_enabled=false
local root='/usr/libexec/homegate'
local function unavailable(action)
 return {api_version=1,prototype=true,ok=false,phase='ddns-ui',effect=action=='submit' and 'unknown' or 'none',write_ready=false,error='DDNS UI request refused'}
end
function M.call(action,form)
 if not native_ddns_ui_enabled then return unavailable(action) end
 local h=require('luci.http');form=form or {}
 if type(form)~='table' then return unavailable(action) end
 local write=action~='status' and action~='jobs'
 if write then
  local c=require('luci.dispatcher').context or {};local token=c.authtoken
  if h.getenv('REQUEST_METHOD')~='POST' or type(token)~='string' or token=='' or form.token~=token then return unavailable(action) end
 elseif h.getenv('REQUEST_METHOD')~='GET' then return unavailable(action) end
 local request={action=action}
 for k,v in pairs(form) do
  if k~='token' then
   if (k~='selection' and k~='confirmation' and k~='consent' and k~='job' and k~='rule') or type(v)~='string' then return unavailable(action) end
   request[k]=v
  end
 end
 local policy=assert(loadfile(root..'/ddns-ui-policy.lua'))()
 local select=assert(loadfile(root..'/ddns-authority.lua'))().selection
 local id=assert(loadfile(root..'/ddns-plan.lua'))().id
 local op,payload=policy.request(request,select,id);if not op then return unavailable(action) end
 local codec=require('luci.model.homegate.backup');local json=require('luci.jsonc')
 local body=codec.json(request)..'\n';if #body>4096 then return unavailable(action) end
 local fs,nx=require('nixio.fs'),require('nixio');require('nixio.util')
 local uuid=io.open('/proc/sys/kernel/random/uuid','r');if not uuid then return unavailable(action) end
 local nonce=uuid:read(38);uuid:close()
 if type(nonce)~='string' or not nonce:match('^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x\n$') then return unavailable(action) end
 local dir='/tmp/homegate-ddns-ui-'..nonce:gsub('[-\n]',''):lower();local path=dir..'/request'
 if not fs.mkdir(dir,448) then return unavailable(action) end
 local fd,result
 local ok=pcall(function()
  fd=nx.open(path,nx.open_flags('wronly','creat','excl'),384);if not fd then error('request') end
  local n=fd:writeall(body);local closed=fd:close();fd=nil;if n~=#body or not closed then error('request') end
  local out=require('luci.sys').exec(root.."/ddns-ui '"..path.."' 2>/dev/null")
  if type(out)~='string' or #out>65536 then error('response') end
  result=json.parse(out);if type(result)~='table' then error('response') end
  local allowed={api_version=true,prototype=true,ok=true,phase=true,operation=true,effect=true,write_ready=true,report=true};local n=0
  for k in pairs(result) do if not allowed[k] then error('response') end;n=n+1 end
  if n~=8 or result.api_version~=1 or result.prototype~=true or result.ok~=true or result.phase~='ddns-ui' or result.operation~=op or result.effect~=(op=='submit' and 'unknown' or 'none') or result.write_ready~=false or
   not policy.response(op,payload,result.report,nil,select,id,codec.json,assert(loadfile(root..'/ddns-schedule.lua'))(),assert(loadfile(root..'/ddns-job.lua'))()) then error('response') end
 end)
 if fd then pcall(function()fd:close()end) end
 fs.unlink(path);fs.rmdir(dir)
 if not ok then return unavailable(action) end;return result
end
return M
