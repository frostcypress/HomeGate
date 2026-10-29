local M={}
local writes={preview_access=true,access_update=true,access_refresh=true,access_clear=true,access_clear_denied=true,access_stop=true,access_reap=true,preview_web_rule=true,web_target_put=true,proxy_start=true,proxy_stop=true,proxy_reap=true,acme_schedule_start=true,acme_schedule_stop=true,acme_schedule_reap=true,acme_issue=true,acme_renew=true,acme_stop=true,acme_cleanup=true,preview_acme_certificate=true,cert_import=true,cert_resume=true,cert_cancel=true,preview_local_certificate=true,recover=true,production_copy_preview=true,production_copy_commit=true,lifecycle_enable=true,lifecycle_disable=true,provider_status=true,zones=true,delete_rule=true,prepare=true,cancel=true,activate_preview=true,preview_account=true,preview_rule=true,secret_put=true,apply=true,finish=true,schedule_serve=true,schedule_start=true,schedule_stop=true,schedule_reap=true}
local function refused()return {api_version=1,engineering=true,ok=false,effect='none',write_ready=false,error='Configuration request refused'}end
function M.call(action,form)
 local h=require('luci.http');local c=require('luci.dispatcher').context or {}
 if action~='access_status' and action~='access_recent' and action~='proxy_status' and action~='read' and action~='schedule_status' and action~='lifecycle_status' and action~='cert_status' and action~='acme_status' and action~='acme_schedule_status' and not writes[action] then return refused() end
 if type(form)~='table' then return refused() end
 if writes[action] then
  if h.getenv('REQUEST_METHOD')~='POST' or type(c.authtoken)~='string' or c.authtoken=='' or form.token~=c.authtoken then return refused() end
 elseif h.getenv('REQUEST_METHOD')~='GET' then return refused() end
 local request={action=action};local count=0
 for k,v in pairs(form)do
  if k~='token' then
   if not ({allow=true,deny=true,region=true,domain=true,https=true,certificate=true,selection=true,policy=true,id=true,name=true,provider=true,account=true,zone=true,host=true,source=true,interface=true,slot=true,value=true,consent=true,confirmation=true,certificate_pem=true,private_key_pem=true,domains=true,job=true,email=true,environment=true})[k] or
      type(v)~='string' or v:find('%z') or #v>(k=='certificate_pem' and 65536 or k=='private_key_pem' and 16384 or k=='domains' and 8192 or (k=='value' or k=='allow' or k=='deny') and 4096 or 512) then return refused() end
   request[k]=v;count=count+1;if count>10 then return refused() end
  end
 end
 local json=require('luci.jsonc');local body=json.stringify(request)
 if type(body)~='string' or #body>(action=='cert_import' and 114688 or 32768) then return refused() end
 local fs,nx=require('nixio.fs'),require('nixio');require('nixio.util')
 local f=io.open('/proc/sys/kernel/random/uuid','r');if not f then return refused() end
 local nonce=f:read(38);f:close()
 if type(nonce)~='string' or not nonce:match('^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x\n$') then return refused() end
 local dir='/tmp/homegate-engineering-web-'..nonce:gsub('[-\n]',''):lower();local path=dir..'/request'
 if not fs.mkdir(dir,'700') then return refused() end
 local fd,result
 local ok=pcall(function()
  fd=nx.open(path,nx.open_flags('wronly','creat','excl'),'600');if not fd then error('request') end
  local n=fd:writeall(body);local closed=fd:close();fd=nil;if n~=#body or not closed then error('request') end
  local raw=require('luci.sys').exec("/usr/libexec/homegate-engineering/config-web.sh '"..path.."' 2>/dev/null")
  if type(raw)~='string' or #raw>524288 then error('response') end
  result=json.parse(raw)
  if type(result)~='table' or result.api_version~=1 or result.engineering~=true or type(result.ok)~='boolean' or (result.effect~='none' and result.effect~='confirmed' and result.effect~='unknown') or result.write_ready~=false then error('response') end
 end)
 if fd then pcall(function()fd:close()end)end
 fs.unlink(path);fs.rmdir(dir)
 if not ok then return refused() end;return result
end
return M
