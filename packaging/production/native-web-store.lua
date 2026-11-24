-- Fixed private request/result store; no task is deleted while its owner lives.
local base=assert(arg[0]:match('^(.*)/[^/]+$'));local fs=require('nixio.fs');local nx=require('nixio');local json=require('luci.jsonc')
require('nixio.util')
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local strict=assert(loadfile(base..'/strict-web-json.lua'))()
local rf=assert(io.open(base..'/legacy-routes.json','rb'));local routes=json.parse(rf:read('*a'));rf:close()
local root='/tmp/homegate-frontend-jobs'
local pending_paths={public='/etc/homegate/public-add-pending',wol='/etc/homegate/wol-add-pending'}
local function fail()io.write('{"api_version":1,"ok":false,"error":"Web request unavailable or retained task requires attention"}\n');os.exit(1)end
local function id(s)return type(s)=='string' and #s==32 and s:match('^[0-9a-f]+$')end
local function dir(p)local s=fs.lstat(p);return s and s.type=='dir' and s.uid==0 and s.modedec==700 end
local function read(p,n)
 local a=fs.lstat(p);if not a or a.type~='reg' or a.uid~=0 or a.nlink~=1 or a.modedec~=600 or a.size>n then fail()end
 local f=io.open(p,'rb');if not f then fail()end;local raw=f:read(n+1) or '';f:close();local b=fs.lstat(p)
 if not b or a.dev~=b.dev or a.ino~=b.ino or a.size~=b.size or #raw>n then fail()end;return raw
end
local function write(p,raw)
 local fd=nx.open(p,nx.open_flags('wronly','creat','excl'),'600');if not fd then fail()end
 local n=fd:writeall(raw);local ok=fd:close();if n~=#raw or not ok then fail()end
end
local function pending_add(kind)
 local pending_add_path=assert(pending_paths[kind])
 if not fs.lstat(pending_add_path) then return nil end
 if not dir('/etc/homegate') then fail() end
 local value=read(pending_add_path,65):match('^([A-Za-z0-9_-]+)\n$')
 if not value then fail() end
 return value
end
local function mark_pending_add(kind,value)
 local pending_add_path=assert(pending_paths[kind])
 if not dir('/etc/homegate') or type(value)~='string' or #value>64 or not value:match('^[A-Za-z0-9_-]+$') then fail() end
 pending_add(kind)
 local nextpath=pending_add_path..'.next'
 if fs.lstat(nextpath) then read(nextpath,65);assert(fs.unlink(nextpath)) end
 write(nextpath,value..'\n')
 assert(os.execute('fsync '..nextpath)==0 and fs.rename(nextpath,pending_add_path))
 assert(os.execute('fsync /etc/homegate')==0)
end
local public_view_path='/etc/homegate/public-applied.json'
local function valid_public_view(view)
 if type(view)~='table' or type(view.enabled)~='table' or #view.enabled>16 or
    (view.scope~='' and view.scope~='CN' and view.scope~='__manual__') then return false end
 for _,name in ipairs(view.enabled) do
  if type(name)~='string' or #name>64 or not name:match('^[A-Za-z0-9_-]+$') then return false end
 end
 return true
end
local function public_view(document)
 local view={enabled={},scope=''}
 for _,row in ipairs(document) do
  local v=row.values
  if row.name=='main' and v.access_enabled=='1' then
   view.scope=v.access_region=='CN' and 'CN' or '__manual__'
  elseif row.kind=='web_rule' and v.retained~='1' and v.enabled=='1' then
   view.enabled[#view.enabled+1]=row.name
  end
 end
 return view
end
local function read_public_view()
 if not fs.lstat(public_view_path) then return nil end
 if not dir('/etc/homegate') then fail() end
 local view=json.parse(read(public_view_path,4096))
 if not valid_public_view(view) then fail() end
 return view
end
local function write_public_view(view)
 if not valid_public_view(view) or not dir('/etc/homegate') then fail() end
 read_public_view()
 local nextpath=public_view_path..'.next'
 if fs.lstat(nextpath) then read(nextpath,4096);assert(fs.unlink(nextpath)) end
 write(nextpath,codec.json(view)..'\n')
 assert(os.execute('fsync '..nextpath)==0 and fs.rename(nextpath,public_view_path))
 assert(os.execute('fsync /etc/homegate')==0)
end
local function validate(d,types,writeflag)
 if type(d)~='table' or type(d.route)~='string' or not routes[d.route] or type(d.form)~='table' or types.form~='object' or d.write~=nil and type(d.write)~='boolean'then return nil end
 for k in pairs(d)do if k~='route' and k~='form' and k~='write'then return nil end end
 local count=0;for k,v in pairs(d.form)do count=count+1;if count>4096 or type(k)~='string' or #k>96 or not k:match('^[a-zA-Z0-9_]+$') or type(v)~='string' or v:find('%z')then return nil end end
 d.write=writeflag
 if routes[d.route].write and not writeflag or writeflag and not routes[d.route].write then return nil end
 return d
end
local function request(path,writeflag)
 local raw=read(path,2097152);local d,types=strict(raw)
 d=validate(d,types,writeflag);if not d then fail()end
 return d,raw
end
local function web_operation(d)
 local route,form=d.route,d.form
 local apply=form.mode=='apply'
 if route=='basic_apply' then
  if not apply then return 'save_service' end
  return form.enabled~=nil and 'enable_service' or 'disable_service'
 elseif route=='public_apply' then return apply and 'apply_public' or 'save_public'
 elseif route=='public_account_apply' then return 'save_dns_account'
 elseif route=='public_action' then
  local actions={ddns_sync=true,cert_renew=true,service_delete=true,account_delete=true,cert_delete=true}
  return actions[form.op] and form.op or 'public_action'
 elseif route=='access_save_rule' then
  if form.old_rule_token and form.old_rule_token~='' and form.old_rule_token~=form.rule_token then return 'edit_access' end
  return form.kind=='deny' and 'deny_access' or 'allow_access'
 elseif route=='wol_action' then return form.op=='wake' and 'wake_host' or 'wol_action'
 elseif route=='maintenance_apply' then return apply and 'apply_maintenance' or 'save_maintenance'
 elseif route=='config_import' then return form.mode=='restore' and 'config_import' or nil
 end
 return ({access_update=route,access_delete_rule=route,access_delete_entry=route,access_delete_all=route,
  wol_apply=route,config_reset=route,certificate_apply=route})[route]
end
if ...=='library'then return {read=read,write=write,dir=dir,id=id,request=request,validate=validate,routes=routes,strict=strict,encode=codec.json,root=root,fail=fail,web_operation=web_operation,pending_add=pending_add,mark_pending_add=mark_pending_add,public_view=public_view,read_public_view=read_public_view,write_public_view=write_public_view}end
local mode=arg[1]
if mode=='validate-request'then request(arg[2],true);return
elseif mode=='release-pending-add'then
 local token=arg[2];if not id(token) then fail() end
 local result=strict(read(root..'/'..token..'/result.next',2097152))
 if result and result.ok and type(result.add_applied_revision)=='number' then
  local current=read('/etc/homegate/transactions/current',16)
  if tonumber(current)==result.add_applied_revision then
   if result.public_applied then write_public_view(result.public_applied) end
   for kind,path in pairs(pending_paths)do
    if (result.add_applied_page=='all' or result.add_applied_page==kind) and pending_add(kind) then
     assert(fs.unlink(path));assert(os.execute('fsync /etc/homegate')==0)
    end
   end
  end
 end
 return
elseif mode=='log-args'then
 local token=arg[2];if not id(token) or not dir(root) or not dir(root..'/'..token)then fail()end
 local path=root..'/'..token
 local operation=web_operation(request(path..'/request',true));if not operation then return end
 local d=strict(read(path..'/result',2097152))
 if type(d)~='table' or type(d.ok)~='boolean' then fail()end
 local outcome
 if not d.ok then outcome=d.runtime_restored and 'restored' or d.uncertain and (d.configuration_saved and 'saved_unknown' or 'unknown') or d.configuration_saved and 'saved_failed' or
  (d.failure_stage=='homegate-disabled' or d.failure_stage=='editor-stale' or d.failure_stage=='public-pending-add' or d.failure_stage=='wol-pending-add') and 'not_executed' or 'failed'
 elseif operation=='disable_service' then outcome='disabled'
 elseif operation=='config_reset' then outcome='ok'
 elseif d.homegate_disabled then outcome='saved_disabled'
 elseif d.certificate_state then outcome='certificate_'..d.certificate_state
 elseif d.runtime_applied then
  local access=operation:match('access$') or operation:match('^access_delete')
  outcome=operation=='access_update' and 'region_running' or access and 'proxy_applied' or 'running'
 elseif d.runtime_stopped_for_save then outcome='saved_stopped'
 elseif operation=='access_update' then outcome=({published='region_published',cached='region_cached',limited='region_limited'})[d.access_region_state]
 end
 if type(outcome)~='string' or not outcome:match('^[a-z_]+$') then outcome='ok' end
 local reason=d.runtime_failure_reason or d.failure_stage
 if type(reason)~='string' or #reason>64 or not reason:match('^[a-z_%-]+$') then reason='none' end
 local subject=type(d.log_subject)=='string' and #d.log_subject<=320 and d.log_subject:gsub('[%z\1-\31\127]',' ') or ''
 io.write(operation,':',outcome,':',reason,'\n',subject,'\n');return
elseif mode=='start-options' or mode=='start-restore' or mode=='runtime-result'then
 local token=arg[2];if not id(token) or not dir(root) or not dir(root..'/'..token)then fail()end
 local path=root..'/'..token..'/result.next';local d=strict(read(path,2097152));if not d or type(d.ok)~='boolean' or d.api_version~=1 then fail()end
 if mode=='start-options'then
  if d.runtime_start and (d.ok or d.runtime_start.restore==true) then local r=d.runtime_start.revision;if type(r)~='number' or r<1 or r>999999999 or r%1~=0 then fail()end;io.write(r,'\n')end;return
 end
 if mode=='start-restore'then
  io.write(d.runtime_start and d.runtime_start.restore==true and 'true\n' or 'false\n');return
 end
 local raw=io.stdin:read(32769);local status=raw and #raw<=32768 and strict(raw)
 local revision=d.runtime_start and d.runtime_start.revision
 local restoring=d.runtime_start and d.runtime_start.restore==true
 local verified=false
 if arg[3]=='true'then
  verified=status and status.ok==true and status.configuration_revision==revision and status.service and status.service.configured==true and status.service.enabled==true and status.service.running==true and status.service.healthy==true or false
 end
 d.runtime_start=nil;d.runtime_applied=verified and not restoring
 local messages={pending='已保存并应用；证书正在后台签发。',unknown='已保存并应用；证书签发结果待核对。',
  retry='已保存并应用；证书签发失败，将稍后重试。',rate_limited='已保存并应用；证书机构限流，正在等待重试。'}
 if verified and messages[status.certificate_state] then
  d.certificate_state=status.certificate_state
  local encoded=messages[d.certificate_state]:gsub('([^a-zA-Z0-9_.~-])',function(c)return string.format('%%%02X',c:byte())end)
  if d.redirect then d.redirect=d.redirect:gsub('([?&]notice=)[^&]*',function(prefix)return prefix..encoded end) end
 end
 if restoring then
  d.runtime_restored=verified
  if verified then d.error=d.error..'原有服务已恢复运行。'
  else d.uncertain=true;d.error=d.error..'原有服务尚未确认恢复，请检查运行状态。' end
 elseif not verified then
  local stages={['runtime-admission']=true,['runtime-start']=true,['boot-enable']=true}
  if not stages[arg[4]] then fail()end
  d.ok=false;d.uncertain=true;d.redirect=nil;d.failure_stage=arg[4]
  d.init_start_exit=tonumber(arg[5]);d.receipt_exit=tonumber(arg[6])
  d.error=arg[4]=='boot-enable' and '服务已运行，但开机自启尚未确认。请核对任务状态后再操作。'
   or '配置已保存，但服务尚未验证运行。请核对任务状态后再操作。'
  if d.access_region_updated and arg[4]~='boot-enable' then
   d.error='地区数据已更新，但服务尚未验证运行。请核对任务状态。'
  end
  if d.receipt_exit==1 and status and status.api_version==1 and status.native==true and status.ok==false and status.configuration_revision==revision and status.cleanup_confirmed==true then
   d.runtime_failure_reason=status.reason
   local message=({firewall_apply_failed='IPv6 防火墙配置失败，HomeGate 未启动。',proxy_start_failed='HTTPS 代理未能启动，请查看代理状态。'})[status.reason]
   if message then
    d.uncertain=false
    d.error=(d.access_region_updated and '地区数据已更新。' or '配置已保存。')..message
   end
  end
 end
 assert(fs.unlink(path));write(path,codec.json(d)..'\n');return
elseif mode=='purge'then
 if not dir(root)then fail()end
 local jobs={};for n in fs.dir(root)do if n~='.' and n~='..' and n~='.allocation.lock'then
  if not id(n) or not dir(root..'/'..n)then fail()end
  local path=root..'/'..n;local d=strict(read(path..'/result',2097152));if not d or type(d.ok)~='boolean' or d.api_version~=1 or d.uncertain then fail()end
  for item in fs.dir(path)do if item~='.' and item~='..' and item~='result' and item~='owner.lock'then fail()end end
  read(path..'/owner.lock',1);jobs[#jobs+1]=path
 end end
 for _,path in ipairs(jobs)do assert(fs.unlink(path..'/result'));assert(fs.unlink(path..'/owner.lock'));assert(fs.rmdir(path))end
 read(root..'/.allocation.lock',1);assert(fs.unlink(root..'/.allocation.lock'));assert(fs.rmdir(root));io.write('{"ok":true}\n');return
elseif mode=='submit'then
 local d=request(arg[2],true);if not dir(root)then fail()end
 local count=0;for n in fs.dir(root)do if id(n)then if not dir(root..'/'..n)then fail()end;count=count+1 end end
 if count>=8 then fail()end
 local f=assert(io.open('/proc/sys/kernel/random/uuid','rb'));local token=f:read(38);f:close();token=token:gsub('[-\n]',''):lower();if not id(token)then fail()end
 local path=root..'/'..token;if not fs.mkdir(path,'700')then fail()end
 local form=next(d.form) and codec.json(d.form) or '{}'
 write(path..'/request','{"route":'..codec.json(d.route)..',"write":true,"form":'..form..'}\n');io.write(token,'\n');return
elseif mode=='status' or mode=='ack'then
 local token=arg[2];if not id(token) or not dir(root) or not dir(root..'/'..token)then fail()end
 local path=root..'/'..token;local live=arg[3]=='true'
 if not fs.lstat(path..'/result')then
  if mode=='ack'then fail()end
  local phase=live and fs.lstat(path..'/starting')
  local starting=phase and phase.type=='reg' and phase.uid==0 and phase.nlink==1 and phase.modedec==600 and phase.size==0
  local function marker(name)
   local a=live and fs.lstat(path..'/'..name)
   return a and a.type=='reg' and a.uid==0 and a.nlink==1 and a.modedec==600 and a.size==0
  end
  local applying=marker('applying-stop') and 'stop' or marker('applying-start') and 'start' or nil
  io.write(codec.json({ok=true,job=token,pending=true,owner_running=live,configuration_saved=(applying or starting) and true or nil,applying_service=applying or nil,recovery_required=not live and fs.lstat(path..'/owner.lock')~=nil}),'\n');return
 end
 local result=strict(read(path..'/result',2097152));if type(result)~='table' or type(result.ok)~='boolean' or result.api_version~=1 then fail()end
 if live then io.write(codec.json({ok=true,job=token,pending=true}),'\n');return end
 if mode=='ack'then
  if result.uncertain then fail()end
  for n in fs.dir(path)do if n~='.' and n~='..' and n~='result' and n~='owner.lock'then fail()end end
  for _,name in ipairs({'result','owner.lock'})do if fs.lstat(path..'/'..name)then read(path..'/'..name,2097152);assert(fs.unlink(path..'/'..name))end end
  assert(fs.rmdir(path))
 end
 io.write(codec.json({ok=true,job=token,pending=false,result=result}),'\n');return
elseif mode=='error'then io.write(codec.json({api_version=1,ok=false,error='Web task interrupted; inspect retained operation before retry',uncertain=true}),'\n');return
elseif mode=='not-started'then
 local reasons={['runtime-directory']='运行目录不可用，操作未执行。', ['runtime-lock']='操作锁不可用，操作未执行。',busy='其它操作尚未结束，本次操作未执行。', ['package-state']='软件包正在变更，操作未执行。',preflight='操作准备失败，本次操作未执行。'}
 local reason=reasons[arg[2]] and arg[2] or 'preflight'
 io.write(codec.json({api_version=1,ok=false,started=false,error_code=reason,error=reasons[reason]}),'\n');return end
fail()
