-- Execute the frozen controller with a virtual UCI cursor and fixed host API.
-- No request selects Lua code, a shell command, a filesystem root or a writer.
local function run(fixture)
local base=assert(arg[0]:match('^(.*)/[^/]+$'));local proto=base..'/project/core/prototype'
local lib=assert(loadfile(base..'/native-web-store.lua'))('library')
local fs=require('nixio.fs');local json=require('luci.jsonc');local nx=require('nixio')
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local original_io,original_os=io,os
local write=fixture and fixture.write or arg[1]=='write'
local request,work
if fixture then
 local d,types=lib.strict(fixture.request)
 request=lib.validate(d,types or {},write)
 if not request then return {api_version=1,ok=false,error='Invalid request'}end
 work='/offline-memory'
else request=lib.request(arg[2],write);work=arg[2]:match('^(.*)/[^/]+$')end
local result={api_version=1,ok=false,headers={}};local bytes=0;local private={};local documents={};local files={};local revision
local needs_config_write=write and not ({config_export=true,diagnostic_download=true,log_clear=true,update_url_save=true})[request.route]
if request.route=='config_import' and request.form.mode~='restore'then needs_config_write=false end
local effect_started=false
local failure_stage
local pending_imports={}
local stopped_for_save=false
local dns_delete_confirmed=false
local prepared_region
local access_rule_routes={access_save_rule=true,access_delete_all=true,access_delete_entry=true,access_delete_rule=true}
local access_store=not fixture and assert(loadfile(base..'/native-access.lua'))()
local access_baseline,access_overlay
local access_origins={}
local function quote(s)return "'"..tostring(s):gsub("'","'\\''").."'"end
local function capture(command,limit)
 if fixture then return fixture.shell(command)end
 local f=assert(original_io.popen(command.." 2>/dev/null; printf '\\nHGWEBEXIT:%s\\n' \"$?\"",'r'))
 local raw=f:read((limit or 2097152)+65) or '';f:close()
 local body,code=raw:match('^(.*)\nHGWEBEXIT:(%d+)\n$');if not body or #body>(limit or 2097152)then error('bounded command response')end
 return body,tonumber(code)
end
local function call(argv,input,limit)
 local args={};for _,v in ipairs(argv)do args[#args+1]=quote(v)end
 local path=work..'/call-input';local command=table.concat(args,' ')
 if input then lib.write(path,input);command=command..' < '..quote(path)end
 local raw,code=capture(command,limit);if input then assert(fs.unlink(path))end
 return raw,code
end
local function core(args,input)
 if fixture then return fixture.shell('/usr/bin/homegate '..table.concat(args,' '))end
 -- Public read routes consume the compatible CLI reports. The virtual file
 -- adapter alone needs the typed single-certificate maintenance report.
 local entry=write and base..'/native-cli-internal.sh' or '/usr/bin/homegate'
 if not write and args[1]=='cert-status' and #args==2 then entry=base..'/native-cli-core.sh'end
 local argv={'ash',entry}
 for _,v in ipairs(args)do argv[#argv+1]=v end;return call(argv,input)
end
local function decoded(args,input)
 local raw,code=core(args,input);return json.parse(raw),code
end
local update_url_path='/etc/homegate/plugin-update-url'
local function read_update_url()
 local state=fs.lstat(update_url_path)
 if not state then return '' end
 if not lib.dir('/etc/homegate') or state.type~='reg' or state.uid~=0 or state.nlink~=1 or
    state.modedec~=600 or state.size<1 or state.size>2049 then return nil end
 local raw=fs.readfile(update_url_path,2049)
 return raw and #raw==state.size and raw:match('^([^\r\n%z]*)\n$') or nil
end
local function save_update_url(value)
 if type(value)~='string' or #value>2048 then return '请输入有效的 HTTP 或 HTTPS 更新地址。' end
 if value~='' then
  local validation=assert(loadfile(proto..'/configuration-validation.lua'))()
  local ip=assert(loadfile(proto..'/cloudflare-record-plan.lua'))()
  if not validation.target(value,ip) then return '请输入有效的 HTTP 或 HTTPS 更新地址。' end
 end
 local current=read_update_url()
 if current==nil or not lib.dir('/etc/homegate') then return '无法保存插件更新地址。' end
 if value~=current then
  local job=work:match('/([0-9a-f]+)$')
  if not lib.id(job) then return '无法保存插件更新地址。' end
  local staged=update_url_path..'.'..job
  lib.write(staged,value..'\n')
  local _,code=call({'fsync',staged},nil,64)
  if code~=0 or not fs.rename(staged,update_url_path) then
   fs.unlink(staged)
   return '无法保存插件更新地址。'
  end
  local _,synced=call({'fsync','/etc/homegate'},nil,64)
  if synced~=0 then return '更新地址保存结果待确认，请刷新页面核对。' end
 end
 result.plugin_update_url=value
end
local function uptime()
 local f=original_io.open('/proc/uptime','rb')
 if not f then return nil end
 local raw=f:read(128) or '';f:close()
 return tonumber(raw:match('^(%d+%.%d+) '))
end
local function validate_pair(cert,key)
 local job=work:match('/([0-9a-f]+)$');if not write or not job or #job~=32 then return '',1 end
 local raw,rc=call({'ash',base..'/native-web-cert-preview.sh',job},codec.json({certificate_pem=cert,private_key_pem=key}))
 if rc~=0 then result.failure_stage='certificate-validation';result.exit_code=rc end;return raw,rc
end
local function copy(v)if type(v)~='table'then return v end;local d={};for k,x in pairs(v)do d[k]=copy(x)end;return d end
local function read_editor_state()
 local raw,code=capture('ash '..quote(proto..'/homegate-config-prototype.sh')..' --persistent editor-state-read 3>&1 >/dev/null')
 local state=code==0 and lib.strict(raw)
 if type(state)=='table' and type(state.configuration)=='table' and type(state.revision)=='number'then return state end
end
local function read_configuration_source()
 local f=original_io.open('/etc/config/homegate','rb');local source=f and f:read(262145);if f then f:close()end
 return source
end
local function load_document(pkg)
 if documents[pkg]then return documents[pkg]end
 if fixture then documents[pkg]=copy(fixture.documents[pkg] or {});return documents[pkg]end
 if pkg~='homegate'then
  local doc={};if pkg=='network' or pkg=='dhcp'then
   pcall(function()local count=0;require('luci.model.uci').cursor():foreach(pkg,nil,function(s)
    count=count+1;if count>512 then error('inventory limit')end
    local values={};for k,v in pairs(s)do if k:sub(1,1)~='.'then values[k]=copy(v)end end
    doc[#doc+1]={name=s['.name'],kind=s['.type'],values=values}
   end)end)
  end
  documents[pkg]=doc;return doc
 end
 local state=read_editor_state()
 if not state and needs_config_write then
  local store='/etc/homegate/transactions'
  local prepare='prepare'
  -- A reboot can remove the shared lock while leaving an adopted store intact.
  if lib.dir(store) and not fs.lstat(store..'/bootstrap-pending')
     and not fs.lstat('/var/run/homegate/frontend.lock') then
   prepare='prepare-resume'
  else
   local factory=assert(original_io.open(base..'/factory.config','rb'));local expected=factory:read(262145);factory:close()
   if read_configuration_source()~=expected then error('Source adoption required in configuration maintenance')end
  end
  failure_stage='configuration-prepare'
  local _,rc=core({prepare})
  if rc~=0 then error('Configuration initialization unavailable') end
  state=read_editor_state()
  if not state then error('Prepared configuration could not be read') end
  failure_stage=nil
 end
 if state then revision=state.revision;documents[pkg]=state.configuration
 else
  local source=read_configuration_source()
  local d=source and #source<=262144 and codec.private_configuration(source)
  documents[pkg]=d and d.configuration or {}
  if d then for _,s in ipairs(documents[pkg])do
   local v=s.values;local flags=d.switches[s.name] or {};if flags.enabled then v.enabled=flags.enabled end;if flags.access_enabled then v.access_enabled=flags.access_enabled end
   for _,key in ipairs(s.kind=='dns_account' and {'key_id','secret','account_id','endpoint'} or s.kind=='ddns_rule' and {'url'} or s.kind=='web_rule' and {'target'} or {})do
    local prefix=s.kind=='dns_account' and v.provider or s.kind=='ddns_rule' and 'ddns' or 'web';local value=d.credentials[prefix..'.'..s.name..'.'..key];if value then v[key=='key_id' and 'id' or key]=value end
   end
  end end
 end
 for _,s in ipairs(documents[pkg])do
  if s.name=='main' and s.kind=='homegate'then
   access_baseline={s.values.access_allow or '',s.values.access_deny or ''}
   access_overlay=access_store.read(unpack(access_baseline))
   if access_overlay then
    s.values.access_allow,s.values.access_deny=access_overlay.allow,access_overlay.deny
    access_origins=access_overlay.origins
   end
  elseif s.kind=='dns_account'then for _,k in ipairs({'id','secret','account_id','endpoint'})do local v=s.values[k];if v and v~=''then private[#private+1]=v end end
  elseif s.kind=='ddns_rule' and s.values.url then private[#private+1]=s.values.url
  elseif s.kind=='web_rule' and s.values.target then
   local credentials=s.values.target:match('^https?://([^/@]+)@');if credentials then private[#private+1]=credentials end
  end
 end
 return documents[pkg]
end
local function find(pkg,name)
 for _,s in ipairs(load_document(pkg))do if s.name==name then return s end end
end
local verified_management={}
local function management_domains(selected)
 local raw,code=call({'lua',proto..'/homegate-network.lua','overview-wan'},nil,8192)
 local wan=code==0 and json.parse(raw)
 if type(wan)~='table' or wan.ok~=true then return nil end
 local management=assert(loadfile(base..'/native-management.lua'))()
 local observe=assert(loadfile(base..'/native-certificates.lua'))('observe')
 return management.domains(load_document('homegate'),wan.public_ipv6,observe,selected)
end
local function masked(s)
 s=s:gsub('(https?://)[^/@%s]+@','%1[redacted]@')
 for _,v in ipairs(private)do if #v>=4 then s=s:gsub(v:gsub('([^%w])','%%%1'),'[redacted]')end end
 return s
end
local function public(v,key)
 if type(v)=='string'then if key=='secret' or key=='private_key_pem' or key=='key_id' or key=='provider_account_id' or key=='endpoint'then return ''end;return masked(v)end
 if type(v)~='table'then return v end;local d={};for k,x in pairs(v)do d[k]=public(x,k)end;return d
end
local function text(doc)
 local rows={}
 for _,s in ipairs(doc)do
  rows[#rows+1]='config '..s.kind..' '..quote(s.name)
  local keys={};for k in pairs(s.values)do if k:sub(1,1)~='.'then keys[#keys+1]=k end end;table.sort(keys)
  for _,k in ipairs(keys)do local value=s.values[k]
   if type(value)=='table'then for _,v in ipairs(value)do rows[#rows+1]=' list '..k..' '..quote(v)end
   elseif type(value)=='string'then rows[#rows+1]=' option '..k..' '..quote(value)else error('configuration value')end
  end
 end
 return table.concat(rows,'\n')..'\n'
end
local changed=false
local cursor={}
function cursor:get_all(pkg,name)
 local s=find(pkg,name);if not s then return nil end
 local row=copy(s.values);row['.name']=s.name;row['.type']=s.kind
 if pkg=='homegate' and name=='main' and request.route=='public' then
  local origins={observed={},custom={}}
  for ip,origin in pairs(access_origins)do table.insert(origins[origin],ip)end
  row['.access_observed']=table.concat(origins.observed,',')
  row['.access_custom']=table.concat(origins.custom,',')
 end
 return row
end
function cursor:get(pkg,name,key)local s=find(pkg,name);if s then if key then return s.values[key]end;return s.kind end end
function cursor:foreach(pkg,kind,cb)
 for i,s in ipairs(copy(load_document(pkg)))do if not kind or s.kind==kind then local row=copy(s.values);row['.name']=s.name;row['.type']=s.kind;row['.index']=i-1;cb(row)end end
end
function cursor:set(pkg,name,key,value)
 if not write or pkg~='homegate' or type(key)~='string' or not key:match('^[a-zA-Z0-9_]+$')then return false end
 local s=find(pkg,name);if not s then return false end
 if type(value)=='string' and type(s.values[key])=='string' and value==masked(s.values[key])then value=s.values[key]end
 if type(value)=='string' and value==s.values[key] then return true end
 s.values[key]=copy(value);changed=true;return true
end
function cursor:section(pkg,kind,name,values)
 if not write or pkg~='homegate' or find(pkg,name) or not name:match('^[a-zA-Z0-9_-]+$')then return false end
 local doc=load_document(pkg);doc[#doc+1]={name=name,kind=kind,values=copy(values or {})};changed=true;return name
end
function cursor:delete(pkg,name,key)
 if not write or pkg~='homegate'then return false end
 local s=find(pkg,name);if not s then return true end
 if key then
  if s.values[key]==nil then return true end
  s.values[key]=nil
 else local out={};for _,v in ipairs(load_document(pkg))do if v.name~=name then out[#out+1]=v end end;documents[pkg]=out end
 changed=true;return true
end
function cursor:revert(pkg)documents[pkg]=nil;changed=false;return true end
local function wait_ms(ms)
 local _,rc=call({'lua',proto..'/worker-process.lua','pause',tostring(ms)},nil,32)
 if rc~=0 then _,rc=call({'sleep','1'},nil,32) end
 return rc==0
end
local function service_owner()
 local owner,rc=call({'ash',base..'/native-service.sh','owner-state'})
 if rc==0 and (owner=='true\n' or owner=='false\n') then return owner=='true\n' end
end
local function log_web_progress(outcome)
 local operation=not fixture and lib.web_operation(request)
 if operation then pcall(call,{'ash',base..'/native-log.sh','web',operation,outcome,'none'},nil,32) end
end
local function stop_and_wait()
 if not fixture and service_owner()==true then log_web_progress('stopping') end
 local _,rc=core({'service-stop','--confirm'})
 if rc~=0 then return rc,'runtime-stop' end
 local started=uptime()
 local short_retries=3
 repeat
  _,rc=core({'service-quiescent'})
  if rc==0 then return 0 end
  local now=uptime()
  if not started or not now or now-started>=20 then break end
  if not wait_ms(short_retries>0 and 300 or 1000) then break end
  short_retries=short_retries-1
 until false
 return rc,'runtime-quiescent'
end
local function disable_intent()
 local started=uptime()
 repeat
  local raw,code=core({'lifecycle-disable','--confirm'})
  local now=uptime()
  if code~=4 or not started or not now or now-started>=6 or not wait_ms(300) then return raw,code end
 until false
end
local function stop_for_save()
 if stopped_for_save then return true end
 local owner=service_owner()
 if owner==nil then result.failure_stage='runtime-quiescent';return false end
 if owner then
  local rc,stage=stop_and_wait()
  if rc~=0 then result.failure_stage=stage;result.exit_code=rc;return false end
  stopped_for_save=true;result.runtime_stopped_for_save=true
 end
 return true
end
local editor_contention={
 ['Shared writer is busy']='shared-writer',
 ['Worker supervisor is busy']='worker-supervisor',
 ['Configuration busy']='configuration',
 ['Proxy must be quiescent before configuration changes']='proxy-quiescence',
}
local editor_errors={
 ['Editor candidate invalid']='invalid',
 ['Editor input size']='invalid',
 ['Editor baseline changed']='stale',
 ['Prototype history capacity reached']='history',
 ['Configuration history is retained by active references']='history',
 ['Invalid history reference']='history',
 ['Unable to allocate generation']='storage',
 ['Unable to allocate credential directory']='storage',
 ['Unable to synchronize candidate files']='storage',
 ['Unable to synchronize candidate directories']='storage',
}
local function reject_editor(stage,report,code,blocker)
 local kind=type(report)=='table' and editor_errors[report.error] or nil
 result.failure_stage=blocker=='ddns-sync' and 'editor-ddns-busy' or blocker and 'editor-busy' or
    ((kind=='history' or kind=='storage' or kind=='stale') and 'editor-'..kind or stage)
 if blocker then result.editor_stage=stage;result.editor_blocker=blocker end
 result.exit_code=code
end
local function ddns_in_progress()
 local status,rc=decoded({'schedule-status'})
 return rc==0 and type(status)=='table' and status.ok==true and status.phase=='ddns-schedule'
    and status.continuous==true and status.running==true and status.status=='running'
    and type(status.ticks)=='number' and status.ticks>0
end
local function editor(action,body)
 local started=uptime()
 local deadline=started and started+20
 local waiting_for_ddns=false
 local attempt=0
 while true do
  local raw,code=call({'ash',proto..'/homegate-config-prototype.sh','--persistent',action,tostring(revision)},body)
  local report=json.parse(raw)
  -- Only these errors occur before candidate generation or publication.
  -- Let an admitted background batch settle before asking the owner to stop.
  local blocker=code==4 and type(report)=='table' and editor_contention[report.error]
  if not blocker then return report,code end
  local now=uptime()
  if not deadline or not now then return report,code,blocker end
  if now>=deadline then
   if waiting_for_ddns or action~='editor-check' or (blocker~='shared-writer' and blocker~='worker-supervisor')
      or not ddns_in_progress() then
    return report,code,waiting_for_ddns and ddns_in_progress() and 'ddns-sync' or blocker
   end
   -- The running coordinator can publish readiness before its first batch
   -- drains. Keep the old service live and leave time to stop and publish.
   local job_deadline=tonumber(lib.read(work..'/deadline',16))
   if not job_deadline then return report,code,blocker end
   deadline=math.min(started+90,job_deadline-60)
   if now>=deadline then return report,code,'ddns-sync' end
   waiting_for_ddns=true
  end
  attempt=attempt+1
  if not wait_ms(attempt<=3 and 300 or 1000) then return report,code,blocker end
 end
end
local function restore_before_publish()
 if not stopped_for_save or dns_delete_confirmed or result.uncertain then return end
 local status,code=decoded({'config-status'})
 if code==0 and status and status.ok==true and status.revision==revision and
    status.preview_present==false and status.application_pending==false and
    status.persistent_fence_pending==false and status.workers_pending==false then
  -- The start broker must still verify the exact previous source and plan.
  result.runtime_start={revision=revision,restore=true}
 end
end
function cursor:commit(pkg)
 if not write or pkg~='homegate'then return false end
 if not changed then result.configuration_saved=true;return true end
 if fixture then
  fixture.commits=fixture.commits+1
  if fixture.fail_commit then return false end
  fixture.documents[pkg]=copy(documents[pkg]);changed=false;return true
 end
 if access_rule_routes[request.route] then
  local main=find(pkg,'main')
  if not main or not revision or not access_baseline then return false end
  effect_started=true
  if request.route=='access_save_rule' then
   local key=access_store.rule_key(request.form.rule_token)
   if key and not access_origins[key] then
    access_origins[key]=request.form.rule_origin=='observed' and 'observed' or 'custom'
   end
  end
  access_store.write(access_baseline[1],access_baseline[2],main.values.access_allow or '',main.values.access_deny or '',access_origins)
  access_origins=assert(access_store.read(unpack(access_baseline))).origins
  changed=false;result.configuration_saved=true;return true
 end
 local body=text(load_document(pkg))
 local checked,checked_code,blocker=editor('editor-check',body)
 if checked_code~=0 or not checked or checked.ok~=true or checked.revision~=revision then
  reject_editor('editor-check',checked,checked_code,blocker)
  restore_before_publish()
  return false
 end
 -- A write needs to know whether a coordinator owns the service. The full
 -- health report reads configuration twice and can be busy during a job.
 if not stop_for_save() then return false end
 effect_started=true
 if request.route=='config_reset' then
  local cleanup,cleanup_code=call({'ash',base..'/native-dns-cleanup.sh','--confirm',tostring(revision)})
  if cleanup_code~=0 then
   result.failure_stage='reset-dns-cleanup';result.exit_code=cleanup_code;result.uncertain=true
   return false
  end
  dns_delete_confirmed=cleanup~=''
 end
 local preview,code,preview_blocker=editor('editor-preview',body)
 if code~=0 or type(preview)~='table' or type(preview.confirmation)~='string'then
  reject_editor('editor-preview',preview,code,preview_blocker)
  restore_before_publish()
  return false
 end
 local d,rc=decoded({'config-commit',preview.confirmation});if rc~=0 or not d or not d.ok then result.failure_stage='editor-publish';result.exit_code=rc;return false end
 result.configuration_saved=true
 if request.route=='config_reset' or request.route=='config_import' then
  access_store.clear()
 elseif access_overlay then
  local main=find(pkg,'main')
  local allow,deny=main.values.access_allow or '',main.values.access_deny or ''
  if next(access_origins) then access_store.write(allow,deny,allow,deny,access_origins)
  else access_store.clear() end
 end
 for id,pair in pairs(pending_imports)do
  local material,code=decoded({'cert-import-stdin',id},codec.json(pair))
  if code~=0 or not material or not material.ok then result.failure_stage='certificate-publication';result.uncertain=true;return false end
 end
 pending_imports={}
 changed=false;revision=d.configuration_revision or d.revision or revision+2;return true
end
local stage_messages={
 ['reset-dns-cleanup']='云端解析清理未完成，本地设置和 DNS 凭据已保留。请核对 DNS 账户及任务状态后重试。',
 ['runtime-stop']='现有服务未能停止，请检查运行状态。',
 ['runtime-quiescent']='上一次服务操作尚未结束，请稍后再试。',
 ['editor-check']='配置未通过保存前检查，请刷新页面核对当前配置。',
 ['editor-busy']='配置正被另一项任务使用，请稍后再试。',
 ['editor-ddns-busy']='后台 DNS 同步仍在进行，配置尚未保存。同步结束后请重试。',
 ['editor-history']='无法为这次修改保留配置历史，请检查插件维护中的配置状态。',
 ['editor-storage']='无法写入配置，请检查路由器存储空间。',
 ['editor-stale']='配置已被其他操作更新，请刷新页面后重试。',
 ['editor-preview']='配置校验未通过，请刷新页面核对当前配置。',
 ['editor-publish']='配置提交未完成，请到插件维护检查恢复状态。',
 ['legacy-certificate-adoption']='已有证书无法接管，请检查证书和私钥。',
 ['certificate-publication']='证书更新未完成，请检查证书状态。',
 ['runtime-enable']='服务启用检查未通过，请检查配置和恢复状态。',
 ['runtime-disable']='服务停用检查未通过，请检查当前运行状态。',
 ['runtime-boot-disable']='服务已停止，开机自启停用未确认。',
 ['ddns-authorization']='DDNS 规则授权未完成，请检查规则和账号。',
 ['runtime-plan']='服务启动计划未能保存，请检查已启用的公网规则、证书和访问策略。',
 ['runtime-binding']='无法确认启动时要使用的配置版本。',
 ['access-region-retained']='地区数据更新失败，已保留上次验证通过的数据。',
 ['access-region-download']='无法下载或验证地区数据，请检查路由器联网后重试。',
 ['access-region-unavailable']='地区数据任务未能完成，请稍后查看或重试。',
 ['access-region-transport']='无法从 APNIC 或镜像下载地区数据。',
 ['access-region-invalid_data']='下载的地区数据未通过校验。',
 ['access-region-publish']='地区数据未能写入路由器缓存。',
 ['access-region-timeout']='获取地区数据超时。',
 ['access-region-worker_exit']='地区数据更新进程提前退出。',
 ['access-record-clear']='无法确认访问记录已清除，请刷新记录后重试。',
 ['reset-access-cache']='默认配置已保存，地区数据清理未确认，请重试恢复默认配置。',
 ['reset-access-records']='默认配置已保存，访问记录清理未确认，请重试恢复默认配置。',
 ['access-live-reload']='访问规则已保存，代理加载尚未确认。',
 ['dns-busy']='后台正在处理 DNS 或证书任务，请稍后再试。',
 ['ddns-delete']='远端 DNS 记录未能删除，公网服务条目已保留。',
 ['ddns-delete-unknown']='远端 DNS 删除结果待核对，公网服务条目已保留。请先检查任务状态。',
 ['ddns-sync']='DDNS 同步未完成，请检查 DNS 账户和插件日志。',
 ['ddns-backoff']='DNS 服务暂时无法更新，请等待下一次自动同步。',
 ['ddns-unknown']='DDNS 更新结果待核对，请检查插件日志。',
 ['acme-admission']='续期未能启动，请检查插件日志和证书任务。',
 ['acme-failed']='证书续期失败，请检查插件日志。',
 ['acme-unknown']='证书续期结果待核对，请检查插件日志。',
}
local function refused_stage(stage, code)
 result.failure_stage=stage;result.exit_code=code
 return '',code~=0 and code or 1
end
local function prepare_region(action,region)
 local d,rc=decoded({action,region})
 if rc~=0 or not d or not d.ok then
  local stage='access-region-unavailable'
  if d and ({transport=true,invalid_data=true,publish=true,timeout=true,worker_exit=true})[d.error_kind] then
   stage='access-region-'..d.error_kind
  elseif d and d.cache_retained then stage='access-region-retained'
  elseif d and d.native_state=='failed' then stage='access-region-download' end
  if d and d.cache_retained then result.access_region_retained=true end
  return refused_stage(stage,rc)
 end
 prepared_region=region
 if action=='access-refresh' then
  result.access_region_state=d.native_state
  result.access_region_updated=d.cache_updated_local
 end
 return '',0
end
local function dns_action(args)
 local until_time=uptime()
 if until_time then until_time=until_time+12 end
 while true do
  local raw,rc=call(args)
  local now=uptime()
  -- Exit 8 is reserved for pre-admission lock contention, before any write.
  if rc~=8 or not until_time or not now or now>=until_time then return raw,rc end
  wait_ms(500)
 end
end
local function mark_service_apply(operation)
 if fixture or request.route~='basic_apply' then return end
 -- The write owner is still holding its lock. Publish only after the
 -- configuration commit returned and before any service action starts.
 lib.write(work..'/applying-'..operation,'')
end
local function words(command)
 command=command:gsub('%s+>%s*/dev/null%s+2>&1$',''):gsub('%s+2>/dev/null$','')
 local out,part,quotechar,active={},'',nil,false;local i=1
 while i<=#command do local c=command:sub(i,i)
  if quotechar then
   if c==quotechar then quotechar=nil elseif c=='\\' and quotechar=='"'then i=i+1;part=part..command:sub(i,i)else part=part..c end
  elseif c=='"' or c=="'"then quotechar=c;active=true
  elseif c:match('%s')then if active then out[#out+1]=part;part='';active=false end
  elseif c:find('[;&|<>$`()]')then return nil
  elseif c=='\\'then i=i+1;part=part..command:sub(i,i);active=true
  else part=part..c;active=true end;i=i+1
 end
 if quotechar then return nil end;if active then out[#out+1]=part end;return out
end
local function virtual_file(path,mode)
 if fixture then return nil end
 local writable=mode and (mode:find('w',1,true) or mode:find('a',1,true))
 if writable then
  if not write or not(path:match('^/tmp/homegate%-local%-cert%-%d+%.pem$') or path:match('^/tmp/homegate%-local%-key%-%d+%.pem$') or path:match('^/tmp/homegate%-access%-validate%-%d+$') or path=='/var/log/homegate.log')then return nil end
  files[path]=mode:find('a',1,true) and files[path] or ''
 elseif not files[path] or path=='/proc/sys/kernel/random/uuid'then
  if path=='/var/log/homegate.log'then local d=decoded({'log-events'});local rows={};for _,v in ipairs(d and d.events or {})do rows[#rows+1]=v.raw end;files[path]=table.concat(rows,'\n')
  elseif path=='/proc/sys/kernel/random/uuid' or path=='/proc/net/arp' or path=='/tmp/dhcp.leases'then
   local f=original_io.open(path,'rb');if not f then return nil end;files[path]=f:read(262145) or '';f:close();if #files[path]>262144 then return nil end
  else return nil end
 end
 local f={};local pos=1
 function f:read(spec)
  local raw=files[path] or '';if pos>#raw then return nil end
  if type(spec)=='number'then local r=raw:sub(pos,pos+spec-1);pos=pos+#r;return r end
  if spec=='*a'then local r=raw:sub(pos);pos=#raw+1;return r end
  local n=raw:find('\n',pos,true);local r=raw:sub(pos,n and n-1 or #raw);pos=n and n+1 or #raw+1;return r
 end
 function f:lines()return function()return self:read('*l')end end
 function f:write(...)
  if not writable then return nil end;local raw=table.concat({...});if #(files[path] or '')+#raw>1048576 then error('private file limit')end;files[path]=(files[path] or '')..raw;return self
 end
 function f:close()
  if writable and path=='/var/log/homegate.log'then
   local _,rc=call({'ash',base..'/native-log.sh','clear'},nil,32)
   if rc~=0 then error('log clear')end
  end;return true
 end
 return f
end
local function shell(command)
 if command=='sha256sum /etc/config/homegate 2>/dev/null'then
  if fixture then return fixture.shell(command)end
  find('homegate','main')
  if access_overlay then return capture('cat /etc/config/homegate /etc/homegate/access-rules.json | sha256sum',256) end
  return capture('sha256sum /etc/config/homegate',256)
 end
 if fixture then return fixture.shell(command)end
 local isolated=command:match('^HOMEGATE_HOME_DIR=/tmp/homegate%-local%-validate%-%d+ (.+)$')
 if isolated then
  local a=words(isolated);if not write or not a or a[1]~='/usr/bin/homegate' or a[2]~='cert-import' or #a~=5 then return '',1 end
  local cert,key=files[a[4]],files[a[5]];if not cert or not key then return '',1 end
  return validate_pair(cert,key)
 end
 local argv=words(command)
 if argv and argv[1]=='/usr/bin/homegate'then
  table.remove(argv,1);local action=argv[1]
  if not write and not ({version=true,status=true,check=true,['network-resolve']=true,['ddns-status']=true,['cert-status']=true,['proxy-status']=true,['access-status']=true,['access-recent']=true,['firewall-status']=true,['wol-status']=true,['log-events']=true,['dns-zones']=true,['dns-provider-catalog']=true,['acme-ca-catalog']=true})[action]then return '',1 end
  if action=='access-validate-file'then
   local body=files[argv[2]];if not body then return '',1 end
   local raw,rc=call({'lua',base..'/native-adapters.lua','access-stdin'},body);return raw,rc
  end
  if action=='cert-import'then
   local cert,key=files[argv[3]],files[argv[4]];if not cert or not key then return '',1 end
   local raw,rc=validate_pair(cert,key);local d=json.parse(raw)
   if rc~=0 or not d or not d.ok then return raw,1 end
   pending_imports[argv[2]]={certificate_pem=cert,private_key_pem=key};return raw,0
  end
  if action=='dns-zones'then
   local raw,rc=call({'ash',base..'/native-cli-core.sh',action,argv[2]})
   if rc==4 then
    return codec.json({api_version=1,ok=false,phase='dns-provider',error_kind='busy',retryable=true,zones={}}),rc
   end
   return raw,rc
  end
  if action=='access-update' or action=='access-refresh'then
   if not write or #argv~=2 then return '',1 end
   return prepare_region(action,argv[2])
  end
  if action=='access-clear-all' or action=='access-clear-denied' or action=='access-clear-entry'then
   local raw,rc=core(argv)
   if rc~=0 then return refused_stage('access-record-clear',rc) end
   result.access_records_cleared=true
   return raw,rc
  end
  if action=='ddns-sync'then
   if not write or #argv~=2 then return '',1 end
   effect_started=true
   local raw,rc=dns_action({'ash',proto..'/homegate-ddns-batch.sh','sync','--confirm-rule',argv[2]})
   local d=json.parse(raw)
   if rc==0 and d and d.ok then return raw,0 end
   local row=d and d.rules and d.rules[1]
   if d and (d.effect=='unknown' or d.effect=='confirmed') then
    result.uncertain=true;return refused_stage('ddns-unknown',rc)
   end
   return refused_stage(rc==8 and 'dns-busy' or row and row.status=='retry_wait' and 'ddns-backoff' or 'ddns-sync',rc)
  end
  if action=='ddns-delete'then
   if not write or #argv~=2 then return '',1 end
   if not stop_for_save() then return '',1 end
   effect_started=true
   local raw,rc
   if fixture then raw,rc=core(argv)
   else raw,rc=call({'ash',proto..'/homegate-ddns-read.sh','--runtime-delete-close',argv[2],'--confirm'}) end
   local d=json.parse(raw)
   if rc==0 and d and d.ok then dns_delete_confirmed=true;return raw,0 end
   if dns_delete_confirmed or not d or d.effect~='none' or d.reconciliation_required then
    result.uncertain=true
    return refused_stage('ddns-delete-unknown',rc)
   end
   -- The previous revision is still published and no remote write occurred.
   -- Dispatch its sealed plan back through the same bounded Web start flow.
   if stopped_for_save and revision then result.runtime_start={revision=revision,restore=true} end
   return refused_stage('ddns-delete',rc)
  end
  if action=='cert-renew'then
   if not write or #argv~=2 then return '',1 end
   local job=work:match('/([0-9a-f]+)$');if not job or #job~=32 then return '',1 end
   local deadline=tonumber(lib.read(work..'/deadline',16));if not deadline then return '',1 end
   effect_started=true;result.native_job=job
   local raw,rc=dns_action({'ash',proto..'/homegate-acme-job.sh','issue-live',argv[2],job,'--confirm'})
   local d=json.parse(raw)
   if rc~=0 or not d or not d.ok then return refused_stage(rc==8 and 'dns-busy' or 'acme-admission',rc) end
   while true do
    local status,code=decoded({'acme-job',job})
    if code~=0 or not status then result.uncertain=true;return refused_stage('acme-unknown',code) end
    if status.pending==false then
     local success=status.ok and status.cleanup_required==false and (status.state=='issued' or status.state=='skipped')
     if success then return codec.json(status),0 end
     if status.cleanup_required or status.state=='unknown'then result.uncertain=true end
     return refused_stage(result.uncertain and 'acme-unknown' or 'acme-failed',code)
    end
    local now,nrc=call({'lua',proto..'/worker-process.lua','now'},nil,32)
    if nrc~=0 or not tonumber(now) or tonumber(now)>=deadline-15 then
     core({'acme-stop',job,'--confirm'});result.uncertain=true;return refused_stage('acme-unknown',1)
    end
    wait_ms(200)
   end
  end
  return core(argv)
 elseif argv and argv[1]=='/etc/init.d/homegate'then
  if not write or #argv~=2 or not({reload=true,start=true,stop=true,enable=true,disable=true})[argv[2]]then return '',1 end
  if argv[2]=='reload'then
   local main=find('homegate','main')
   if not main then return '',1 end
   if access_rule_routes[request.route] then
    if not fs.lstat('/var/run/homegate/proxy') then return '',0 end
    local owner=service_owner()
    if owner==false then return '',0 end
    if not owner then return refused_stage('access-live-reload',7)end
    local started=uptime()
    repeat
     local raw,rc=call({'ash',proto..'/homegate-proxy.sh','access-reload'})
     if rc==0 then result.runtime_applied=true;return '',0 end
     local now=uptime()
     if rc~=4 or not started or not now or now-started>=1 or not wait_ms(100) then
      local status=json.parse(raw)
      result.reload_step=type(status)=='table' and status.step or nil
      return refused_stage('access-live-reload',rc)
     end
    until false
   end
   if request.route=='access_update' then
    if result.access_region_state~='published' then return '',0 end
    local owner=stopped_for_save or service_owner()
    if owner==nil then return refused_stage('runtime-quiescent',7) end
    if not owner then return '',0 end
   end
   if main.values.enabled~='1'then
    mark_service_apply('stop')
    local rc,stage=stop_and_wait();if rc~=0 then return refused_stage(stage,rc) end
    local raw,code=disable_intent();if code~=0 then return refused_stage('runtime-disable',code) end
    local _,boot_code=capture('exec 8>&-; /etc/init.d/homegate disable')
    if boot_code~=0 then return refused_stage('runtime-boot-disable',boot_code) end
    if request.route=='config_reset' then
     local records,clear_code=decoded({'access-clear-all'})
     if clear_code~=0 or not records or records.ok~=true or type(records.entries)~='table' or next(records.entries) then
      return refused_stage('reset-access-records',clear_code~=0 and clear_code or 7)
     end
     local _,cache_code=call({'ash',proto..'/homegate-access-region.sh','clear-cache','--confirm'})
     if cache_code~=0 then return refused_stage('reset-access-cache',cache_code) end
    end
    return raw,code
   end
   mark_service_apply('start')
   local region=main.values.access_enabled=='1' and main.values.access_region
   if region and region~='' and region~=prepared_region then
    local raw,rc=prepare_region('access-update',region)
    if rc~=0 then return raw,rc end
   end
   if not stopped_for_save then
    local rc,stage=stop_and_wait()
    if rc~=0 then return refused_stage(stage,rc) end
   end
   local ddns,certs,web={},{},{}
   for _,s in ipairs(load_document('homegate'))do
    if s.kind=='certificate' and fs.lstat('/etc/homegate/certs/'..s.name..'/fullchain.pem') and not fs.lstat('/etc/homegate/certs/'..s.name..'/current')then
     local _,rc=core({'cert-adopt',s.name,'--confirm'});if rc~=0 then return refused_stage('legacy-certificate-adoption',rc) end
    end
    if s.values.enabled=='1'then
     if s.kind=='ddns_rule'then ddns[#ddns+1]=s.name
     elseif s.kind=='web_rule'then web[#web+1]=s.name
     elseif s.kind=='certificate' and s.values.source=='acme'then certs[#certs+1]=s.name end
    end
   end
   for _,list in ipairs({ddns,certs,web})do table.sort(list)end
   local _,enabled=core({'lifecycle-enable','--confirm'});if enabled~=0 then return refused_stage('runtime-enable',enabled) end
   local grant,rc
   if #ddns==1 then grant,rc=decoded({'grant-preview',ddns[1]})
   elseif #ddns>1 then local raw;raw,rc=call({'ash',proto..'/homegate-ddns-authority.sh','preview-rules',table.concat(ddns,',')});grant=json.parse(raw)end
   if #ddns>0 then
    if rc~=0 or not grant or not grant.confirmation then return refused_stage('ddns-authorization',rc) end
    local _,code=core({'grant-commit',grant.confirmation});if code~=0 then return refused_stage('ddns-authorization',code) end
   elseif fs.lstat('/etc/homegate/transactions/ddns-authority')then local _,code=core({'grant-revoke','--confirm'});if code~=0 then return refused_stage('ddns-authorization',code) end end
   local function selection(v)return #v>0 and table.concat(v,',') or '-'end
   local _,plan=core({'service-plan-set',selection(ddns),selection(certs),selection(web),main.values.access_enabled=='1' and 'allow' or 'open','--confirm'});if plan~=0 then return refused_stage('runtime-plan',plan) end
   local current=tonumber(lib.read('/etc/homegate/transactions/current',16));if not current then return refused_stage('runtime-binding',7) end
   result.runtime_start={revision=current};return '',0
  end
  return capture('exec 8>&-; '..quote(argv[1])..' '..quote(argv[2]))
 elseif argv and argv[1]=='opkg' and argv[2]=='status' and #argv==3 then
  local name=argv[3]=='homegate' and 'homegate-core' or argv[3]
  if not ({['homegate-core']=true,['luci-app-homegate']=true,['luci-i18n-homegate-zh-cn']=true})[name]then return '',1 end
  local path='/usr/lib/opkg/info/'..name..'.control';local a=fs.lstat(path);if not a or a.type~='reg' or a.uid~=0 or a.size>65536 then return '',1 end
  local f=assert(original_io.open(path,'rb'));local raw=f:read(65537);f:close();return raw,0
 elseif command:match('^for b in /sys/class/net/%*; do')then
  local rows={};local listing=fs.dir('/sys/class/net');if not listing then return '',0 end;for name in listing do
   if name:match('^[a-zA-Z0-9_.:-]+$') and fs.stat('/sys/class/net/'..name..'/bridge')then
    rows[#rows+1]='B|'..name
    local p='/sys/class/net/'..name..'/brif';if fs.stat(p)then for member in fs.dir(p)do if member:match('^[a-zA-Z0-9_.:-]+$')then local wifi=fs.stat('/sys/class/net/'..member..'/wireless') or fs.stat('/sys/class/net/'..member..'/phy80211');rows[#rows+1]='M|'..name..'|'..member..'|'..(wifi and 'wifi' or 'ethernet')end end end
   end
  end;return table.concat(rows,'\n'),0
 elseif command=='cat /sys/class/net/*/address 2>/dev/null' or command=='ip neigh show 2>/dev/null' or command=='bridge fdb show 2>/dev/null'then return capture(command,262144)
 elseif command=='tail -n 300 /var/log/homegate.log 2>/dev/null'then local f=virtual_file('/var/log/homegate.log','r');return f and f:read('*a') or '',0
 elseif command:match('^rm %-f /var/run/homegate/acme%-renew/[a-zA-Z0-9_-]+%.json')then return '',0
 elseif command:match('^rm %-rf /etc/homegate/certs/[a-zA-Z0-9_-]+ >')then
  local id=command:match('^rm %-rf /etc/homegate/certs/([a-zA-Z0-9_-]+) >')
  if not id then return '',1 end
  local raw,code=core({'cert-purge',id,'--confirm'});if code~=0 then result.material_retained=true end;return raw,code
 end
 return '',1
end
local modules={}
modules['luci.model.uci']={cursor=function()return cursor end}
modules['luci.model.homegate.backup']=codec
if not fixture then
 modules['luci.model.homegate.management']={certificate=function(domain)return verified_management[domain]end}
end
modules['luci.model.homegate.writer']={run=function(route,fn)if not write or route~=request.route then error('writer route')end;if fixture then fixture.begins=fixture.begins+1 end;return fn()end}
modules['luci.jsonc']={parse=json.parse,stringify=codec.json}
modules['luci.sys']={exec=function(c)local raw=shell(c);return raw end,call=function(c)local _,rc=shell(c);return rc end}
modules['luci.dispatcher']={context={authtoken='rpc'},build_url=function(...)return '/cgi-bin/luci/'..table.concat({...},'/')end}
modules['luci.http']={formvalue=function(k)if k then return request.form[k]end;return request.form end,
 urlencode=function(v)return tostring(v):gsub('[^a-zA-Z0-9_.~-]',function(c)return string.format('%%%02X',c:byte())end)end,
 redirect=function(v)
  if type(v)~='string' or #v>4096 or v:find('[\r\n%z]') or not v:match('^/cgi%-bin/luci/admin/services/homegate/[%w_/]+[?]?')then error('redirect')end
  local validation_error=v:match('[?&]error=([^&]*)')
  result.redirect=v;if result.material_retained then result.error='证书材料已保留，尚未完成清理。请先在维护中核对，不要重复操作。';result.redirect=nil
  elseif validation_error then
   result.error=stage_messages[result.failure_stage] or '操作未完成，请检查当前配置及未完成的操作。'
   if request.route=='config_reset' and result.configuration_saved and
       not result.error:find('^默认配置已保存') then
    result.error='默认配置已保存。'..result.error
   end
   if dns_delete_confirmed and not result.configuration_saved then
    result.uncertain=true
    result.error=result.error..'远端 DNS 已处理，公网服务配置还未保存，请核对当前状态。'
   end
   if result.access_region_retained and result.failure_stage~='access-region-retained' then
    result.error=result.error..'已保留可用的地区缓存。'
   end
   if access_rule_routes[request.route] and not result.failure_stage then
    if v:find('error=Invalid%20access%20rule',1,true) then result.error='请输入有效的 IP 地址或网段。'
    elseif v:find('error=Access%20rule%20changed',1,true) then result.error='规则已被修改，请核对列表后再操作。' end
   end
   if request.route=='wol_apply' and not result.failure_stage then
    if validation_error=='Duplicate%20MAC%20address' then
     result.error='MAC 地址不能重复。请删除重复的主机条目后再保存。'
     result.failure_stage='wol-duplicate-mac'
    elseif validation_error=='WOL%20host%20MAC%20cannot%20be%20changed' then
     result.error='已有主机的 MAC 地址不能修改。要更换地址，请删除该条目后重新添加。'
     result.failure_stage='wol-fixed-mac'
    end
   end
   if request.route=='public_apply' and not result.failure_stage then
    local errors={
     ['External%20port%20must%20be%20between%201%20and%2065535']='公网端口须为 1–65535 的整数。',
     ['External%20port%20conflicts%20with%20a%20reserved%20service%20port']='公网端口与服务保留端口冲突。',
     ['External%20port%20cannot%20serve%20both%20HTTP%20and%20HTTPS']='同一个公网端口不能同时用于 HTTP 和 HTTPS。',
     ['Public%20services%20require%20a%20custom%20port%20other%20than%2080%20or%20443']='请填写自定义公网端口。80 和 443 由本机管理页使用。',
     ['Invalid%20management%20domain']='请输入有效的管理域名。',
     ['Management%20domain%20required%20for%20WAN%20access']='允许外网访问前，请填写管理域名。',
     ['Automatic%20firewall%20is%20required%20for%20management%20domain']='使用管理域名需要启用 HomeGate 自动防火墙。',
     ['Management%20domain%20requires%20a%20matching%20production%20certificate']='请选择已有有效证书覆盖的管理域名。',
     ['Duplicate%20public%20service%20domain%20and%20external%20port']='同一域名和公网端口只能添加一次。',
     ['Services%20for%20one%20domain%20must%20share%20DNS%20settings']='同一域名的多个端口必须共用 DNS 设置。'
    }
    result.error=errors[validation_error] or result.error
   end
  end
  if result.redirect and not result.error and stopped_for_save and not result.runtime_start then
   local notice=modules['luci.http'].urlencode('配置已保存，任务已停止；应用后重新启动。');result.redirect=result.redirect:gsub('([?&]notice=)[^&]*',function(prefix)return prefix..notice end)
  end
 end,
 prepare_content=function(v)result.headers['Content-Type']=v end,
 header=function(k,v)if k~='Content-Disposition' or #v>256 or v:find('[\r\n%z]')then error('header')end;result.headers[k]=v end,
 write=function(v)if type(v)~='string'then error('response')end;bytes=bytes+#v;if bytes>2097152 then error('response limit')end;result.body=(result.body or '')..v end}
modules['luci.template']={render=function(name,data)
 if not name:match('^homegate/[a-z]+$')then error('template')end
 if name=='homegate/overview' and not fixture then
  local raw,rc=call({'ash',base..'/native-service.sh','overview-status'},nil,8192)
  local info=rc==0 and json.parse(raw)
  local running=info and info.ok and info.service and info.service.running
  data.runtime_enabled=type(running)=='boolean' and (running and '1' or '0') or 'unknown'
 end
 if name=='homegate/maintenance' and not fixture then
  local store='/etc/homegate/transactions'
  data.configuration_recovery_needed=fs.lstat(store..'/application')~=nil
  local pointer=fs.lstat(store..'/current')
  local current=pointer and pointer.type=='reg' and pointer.uid==0 and pointer.nlink==1 and
   pointer.modedec==600 and pointer.size<=10 and fs.readfile(store..'/current',10)
  local generation=current and current:match('^([1-9]%d*)\n$')
  local path=generation and store..'/gen-'..generation
  data.configuration_migration_needed=(not pointer or path and not fs.lstat(path..'/source.conf')) and
   read_configuration_source()~=assert(fs.readfile(base..'/factory.config')) or false
  data.configuration_migration_copied=path and fs.lstat(path..'/legacy.conf')~=nil or false
 end
 result.template=name;result.data=public(data)
 if name=='homegate/maintenance' and not fixture then result.data.plugin_update_url=read_update_url() end
end}
modules['nixio.fs']={chmod=function(path)if files[path]then return true end;return false end,stat=function(path)
 if fixture then return nil end
 local cid=path:match('^/etc/homegate/certs/([a-zA-Z0-9_-]+)/fullchain%.pem$') or path:match('^/etc/homegate/certs/([a-zA-Z0-9_-]+)/privkey%.pem$')
 if cid then local d=decoded({'cert-status',cid});return d and d.exists and {mtime=0,size=0} or nil end
 if path=='/etc/homegate/access/regions/CN.cidr'then
  local p='/etc/homegate/access/CN.cidr';local a=fs.lstat(p)
  if not a or a.type~='reg' or a.uid~=0 or a.modedec~=600 or a.nlink~=1 then return nil end
  local f=original_io.open(p,'rb');if not f then return nil end
  local header=(f:read(96) or ''):match('^([^\n]+)\n');f:close()
  if not header then return nil end
  local stamp=header:match('^HGREGION1|(%d+)|%d+|%d+$') or header:match('^HGREGION1|(%d+)|%d+|%d+|%d+|[12]$')
  if not stamp then return nil end
  local date,rc=call({'lua',proto..'/homegate-access.lua','display-time',stamp},nil,32)
  return rc==0 and {mtime=tonumber(stamp),updated=date:gsub('\n$','')} or nil
 end
 return nil
end}
local env={_M=nil,module=function()end,package={seeall=true},require=function(name)if not modules[name]then error('module unavailable')end;return modules[name]end,
 io={open=virtual_file},os={time=os.time,date=os.date,remove=function(p)if files[p]then files[p]=nil;return true end;return false end},math=math,string=string,table=table,tonumber=tonumber,tostring=tostring,type=type,pairs=pairs,ipairs=ipairs,next=next,assert=assert,error=error,pcall=pcall,select=select,unpack=unpack,_=function(s)return s end}
env._M=env
local ok,err=pcall(function()
 if request.route=='update_url_save' and not fixture then
  result.error=save_update_url(request.form.plugin_update_url)
  result.ok=result.error==nil
  return
 end
 if request.route=='diagnostic_download' and not fixture then
  local collect=assert(loadfile(base..'/native-diagnostics.lua'))()
  result.body=collect(core,call,load_document('homegate'),lib,work)
  result.headers['Content-Type']='text/plain; charset=UTF-8'
  result.headers['Content-Disposition']='attachment; filename="homegate-diagnostic.txt"'
  result.ok=true
  return
 end
 if request.route=='api/overview_status' or request.route=='api/overview_ipv6' then
  local command=request.route=='api/overview_status' and {'ash',base..'/native-service.sh','overview-status'}
   or {'lua',proto..'/homegate-network.lua','overview-wan'}
  local raw,code=call(command,nil,8192)
  local data=code==0 and json.parse(raw)
  result.body=type(data)=='table' and raw or '{"ok":false}'
  result.headers['Content-Type']='application/json'
  result.ok=true
  return
 end
 if request.route=='api/management_domains' and not fixture then
  local domains=management_domains()
  local names={}
  for name in pairs(domains or {})do names[#names+1]=name end
  table.sort(names)
  result.body=codec.json({ok=domains~=nil,domains=names})
  result.headers['Content-Type']='application/json'
  result.ok=true
  return
 end
 if request.route=='api/certs' and not fixture then
  local doc=load_document('homegate')
  local certificates={}
  if revision then
   local observe=assert(loadfile(base..'/native-certificates.lua'))('observe')
   for _,section in ipairs(doc)do
    if section.kind=='certificate'then
     local ok,status=pcall(observe,section.name,section.values)
     if ok then certificates[#certificates+1]=status end
    end
   end
  end
  local info=decoded({'version'})
  result.body=codec.json({api_version=1,ok=revision~=nil,phase='acme',version=info and info.version,
   certificates=certificates,effect='none',write_ready=false})
  result.headers['Content-Type']='application/json'
  result.ok=true
  return
 end
 if request.route=='public_apply' then
  local count=tonumber(request.form.public_service_count)
  if count and count>=0 and count<=128 and count==math.floor(count) then
   local validation=assert(loadfile(proto..'/configuration-validation.lua'))()
   local ip=assert(loadfile(proto..'/cloudflare-record-plan.lua'))()
   local listening,owned
   local main=find('homegate','main')
   local management=assert(loadfile(base..'/native-management.lua'))()
   local management_context
   if not fixture then
    management_context=management.read()
    local submitted=request.form.management_domain
    local domain=submitted and codec.management_domain(submitted:match('^%s*(.-)%s*$'))
    local current=main and main.values or {}
    local enabling=request.form.management_wan=='1' and current.management_wan~='1'
    if domain and domain~='' and (domain~=current.management_domain or enabling) then
     if not management_context or not management_context.backend then
      result.error='无法确认本机 LuCI 的监听地址。请检查路由器管理服务。';return
     end
     verified_management=management_domains(domain) or {}
     if not verified_management[domain] then
      result.error='管理域名暂不可用。请确认 AAAA 记录指向本机公网 IPv6，且有有效证书。';return
     end
    end
   end
   for i=1,count do
    local prefix='public_service_'..i..'_'
    local target=(request.form[prefix..'target'] or ''):match('^%s*(.-)%s*$')
    if target~='' and not validation.target(target,ip) then
     result.error='内网网址无效，请检查 HTTP/HTTPS 地址和端口（1–65535）。'
     return
    end
    if not fixture and target~='' then
     local allowed,reason=management.ordinary_target(management_context,target)
     if not allowed then
      result.error=reason=='local_management' and '本机 LuCI 请通过「路由管理」设置。' or '无法核对内网网址。'
      return
     end
    end
    local port=tonumber(request.form[prefix..'external_port'])
    local https=request.form[prefix..'https']=='1'
    local default=main and tonumber(main.values[https and 'https_port' or 'http_port'])
    if not fixture and target~='' and port and port%1==0 and port>0 and port<=65535 and port~=80 and port~=443 and port~=default then
     if not listening then
      listening={}
      for _,path in ipairs({'/proc/net/tcp','/proc/net/tcp6'})do
       local file=assert(io.open(path,'rb'));local raw=file:read(1048577) or '';file:close()
       if #raw>1048576 then error('TCP listener table limit')end
       validation.listening_ports(raw,listening)
      end
      owned=assert(loadfile(base..'/native-public-listeners.lua'))()()
     end
     if listening[port] and not owned[port] then
      result.error='公网端口 '..port..' 已被路由器上的其他服务占用。';return
     end
    end
   end
  end
 end
 if not fixture and request.route=='access_save_rule' and request.form.old_rule_token and request.form.rule_token then
  find('homegate','main')
  local old=access_store.rule_key(request.form.old_rule_token)
  if access_origins[old]=='observed' and old~=access_store.rule_key(request.form.rule_token) then
   result.error='访问记录的来源 IP 不可修改。'
   return
  end
 end
 local fn=assert(loadfile(base..'/legacy-controller.lua'));setfenv(fn,env);fn()
 local handler=env[lib.routes[request.route].handler];if type(handler)~='function'then error('route handler')end;handler()
 if access_rule_routes[request.route] and access_overlay and not result.error and not result.configuration_saved then
  local _,rc=shell('/etc/init.d/homegate reload')
  if rc~=0 then result.error=stage_messages[result.failure_stage] end
 end
 result.ok=result.error==nil
 if access_rule_routes[request.route] then
  local main=find('homegate','main')
  if main and (not changed or result.configuration_saved) then
   result.access_rules={allow=main.values.access_allow or '',deny=main.values.access_deny or '',origins=access_origins}
  end
 end
end)
if not ok then
 local message='Native Web operation unavailable; inspect current configuration and retained tasks'
 if failure_stage=='configuration-prepare' then
  message='配置写入准备失败，本次配置未提交。'
 elseif request.route=='config_reset' then
  message=effect_started and '恢复结果待核对，请检查当前配置和任务状态。' or '恢复默认配置失败，本次配置未提交。'
 end
 result={api_version=1,ok=false,error=message,failure_stage=failure_stage,error_site=tostring(err):match('%.lua:(%d+):'),uncertain=effect_started or nil,configuration_saved=result.configuration_saved}
end
if result.body then result.body=masked(result.body)end
if result.redirect then result.redirect=masked(result.redirect)end
if result.headers and next(result.headers)==nil then result.headers=nil end
if fixture then return result end
if write and result.runtime_start then log_web_progress(result.runtime_start.restore and 'restoring' or 'starting') end
io.write(codec.json(result),'\n')
end
-- Only the fixed installed selftest invokes this library with a memory host.
-- Ordinary CLI/HTTP requests cannot select or serialize a fixture capability.
if ...=='library'then return run end
run()
