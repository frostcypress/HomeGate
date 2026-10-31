-- Fixed private request/result store; no task is deleted while its owner lives.
local base=assert(arg[0]:match('^(.*)/[^/]+$'));local fs=require('nixio.fs');local nx=require('nixio');local json=require('luci.jsonc')
require('nixio.util')
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local strict=assert(loadfile(base..'/strict-web-json.lua'))()
local rf=assert(io.open(base..'/legacy-routes.json','rb'));local routes=json.parse(rf:read('*a'));rf:close()
local root='/tmp/homegate-frontend-jobs'
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
if ...=='library'then return {read=read,write=write,dir=dir,id=id,request=request,validate=validate,routes=routes,strict=strict,encode=codec.json,root=root,fail=fail}end
local mode=arg[1]
if mode=='validate-request'then request(arg[2],true);return
elseif mode=='start-options' or mode=='runtime-result'then
 local token=arg[2];if not id(token) or not dir(root) or not dir(root..'/'..token)then fail()end
 local path=root..'/'..token..'/result.next';local d=strict(read(path,2097152));if not d or type(d.ok)~='boolean' or d.api_version~=1 then fail()end
 if mode=='start-options'then
  if d.ok and d.runtime_start then local r=d.runtime_start.revision;if type(r)~='number' or r<1 or r>32 or r%1~=0 then fail()end;io.write(r,'\n')end;return
 end
 local verified=false
 if arg[3]=='true'then
  local raw=io.stdin:read(32769);local status=raw and #raw<=32768 and strict(raw)
  verified=status and status.ok==true and status.configuration_revision==d.runtime_start.revision and status.service and status.service.configured==true and status.service.enabled==true and status.service.running==true and status.service.healthy==true or false
 end
 d.runtime_start=nil;d.runtime_applied=verified
 if not verified then d.ok=false;d.uncertain=true;d.redirect=nil;d.error='配置已保存，但服务尚未验证运行。请核对任务状态后再操作。'end
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
 if not fs.lstat(path..'/result')then if mode=='ack'then fail()end;io.write(codec.json({ok=true,job=token,pending=true,owner_running=live,recovery_required=not live and fs.lstat(path..'/owner.lock')~=nil}),'\n');return end
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
elseif mode=='not-started'then io.write(codec.json({api_version=1,ok=false,error='Writer unavailable; operation was not started'}),'\n');return end
fail()
