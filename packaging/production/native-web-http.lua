local M={};local nx=require('nixio');local fs=require('nixio.fs');local json=require('luci.jsonc')
require('nixio.util')
local h=require('luci.http');local sys=require('luci.sys')
local function refused()return {ok=false,error='Web task unavailable; inspect retained tasks'}end
local function valid(id)return type(id)=='string' and #id==32 and id:match('^[0-9a-f]+$')end
local function invoke(command,form)
 local path,fd;local ok,value=pcall(function()
  local u=assert(io.open('/proc/sys/kernel/random/uuid','rb'));local id=u:read(38);u:close();id=id:gsub('[-\n]',''):lower();assert(valid(id))
  path='/tmp/homegate-web-'..id;assert(fs.mkdir(path,'700'))
  fd=assert(nx.open(path..'/request',nx.open_flags('wronly','creat','excl'),'600'))
  local raw='{"route":'..json.stringify(form.route)..',"write":'..tostring(form.write)..',"form":'..(next(form.form) and json.stringify(form.form) or '{}')..'}';assert(fd:writeall(raw)==#raw);assert(fd:close());fd=nil
  raw=sys.exec('/usr/bin/homegate '..command.." '"..path.."/request' 2>/dev/null")
  assert(type(raw)=='string' and #raw<=2097152);local d=json.parse(raw);assert(type(d)=='table' and type(d.ok)=='boolean');return d
 end)
 if fd then fd:close()end
 if path then fs.unlink(path..'/request');fs.rmdir(path)end
 return ok and value or refused()
end
local function reply(d)
 if not d.ok then h.status(503,'Service Unavailable')end
 h.prepare_content('application/json');h.write(json.stringify(d)..'\n')
end
local function job(command,id)
 if not valid(id)then return refused()end
 local raw=sys.exec('/usr/bin/homegate '..command.." '"..id.."' 2>/dev/null")
 if type(raw)~='string' or #raw>2097152 then return refused()end
 local d=json.parse(raw);return type(d)=='table' and type(d.ok)=='boolean' and d or refused()
end
function M.status(id)reply(job('web-job-status',id))end
function M.ack(id)
 local c=require('luci.dispatcher').context or {};if h.getenv('REQUEST_METHOD')~='POST' or not c.authtoken or c.authtoken=='' or h.formvalue('token')~=c.authtoken then reply(refused());return end
 reply(job('web-job-ack',id))
end
function M.dispatch(route,write)
 if write then local c=require('luci.dispatcher').context or {};if h.getenv('REQUEST_METHOD')~='POST' or not c.authtoken or c.authtoken=='' or h.formvalue('token')~=c.authtoken then reply(refused());return end end
 local size=tonumber(h.getenv('CONTENT_LENGTH') or '0')
 if not size or size<0 or size>2097152 then h.status(413,'Request Entity Too Large');return end
 local form=h.formvalue() or {};local clean={};local count=0
 for k,v in pairs(form)do
  count=count+1;if count>4096 or type(k)~='string' or not k:match('^[a-zA-Z0-9_]+$') or #k>96 or type(v)~='string' or v:find('%z')then reply(refused());return end
  if k~='token'then clean[k]=v end
 end
 local d=invoke(write and 'web-submit' or 'web-read',{route=route,form=clean,write=write})
 if not d.ok then reply(d);return end
 if write then
  if not valid(d.job) or d.pending~=true then reply(refused());return end
  if (h.getenv('HTTP_ACCEPT') or ''):find('application/json',1,true)then reply(d);return end
  local dispatcher=require('luci.dispatcher');local c=dispatcher.context or {}
  require('luci.template').render('homegate_legacy/pending',{job=d.job,token=c.authtoken or ''});return
 end
 if d.redirect then h.redirect(d.redirect);return end
 if d.template then
  if type(d.template)~='string' or not ({['homegate/overview']=true,['homegate/basic']=true,['homegate/public']=true,['homegate/wol']=true,['homegate/maintenance']=true})[d.template]then reply(refused());return end
  local data=d.data or {};data.token=(require('luci.dispatcher').context or {}).authtoken or ''
  require('luci.template').render(d.template:gsub('^homegate/','homegate_legacy/'),data);return
 end
 for k,v in pairs(d.headers or {})do if k=='Content-Type'then h.prepare_content(v)elseif k=='Content-Disposition'then h.header(k,v)end end
 h.write(d.body or '')
end
return M
