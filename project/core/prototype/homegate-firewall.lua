-- Fixed ip6tables command contract. All external operations are supervised.
local dir=assert(arg[0]:match('^(.*)/[^/]+$'))
local json=require('luci.jsonc');local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local network=assert(loadfile(dir..'/wan6-plan.lua'))();local ipplan=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local root='/var/run/homegate/firewall';local proxy='/var/run/homegate/proxy';local mode,token=arg[1],arg[2]
local function read(p,optional)
 local f=io.open(p,'rb');if not f then if optional then return nil end;error('read')end
 local s=f:read(32769) or '';f:close();if #s>=32768 then error('size')end;return s
end
local function doc(p,optional)local s=read(p,optional);if not s then return nil end;local d=json.parse(s);if type(d)~='table'then error('JSON')end;return d end
local function save(name,d)
 local f=assert(io.open(root..'/'..name..'.next','wb'));assert(f:write(codec.json(d)..'\n'));assert(f:close());assert(os.rename(root..'/'..name..'.next',root..'/'..name..'.json'))
end
local function admission(optional)
 local d=doc(root..'/desired.json',optional);if not d then return nil end
 if type(d.enabled)~='boolean' or type(d.reconcile)~='boolean' or type(d.token)~='string' or #d.token~=32 or not d.token:match('^[0-9a-f]+$')then error('admission')end;return d
end
if mode=='armed' or mode=='watch-armed'then local ok,d=pcall(admission,false);if not ok then os.exit(7)end;os.exit(d.enabled and (mode=='armed' or d.reconcile) and 0 or 3)end
if mode=='live'then local raw=io.stdin:read(32769);local d=#raw<32768 and json.parse(raw);os.exit(type(d)=='table' and d.ok==true and d.running==true and d.state=='running' and d.phase=='proxy' and 0 or 7)end
if mode=='reply'then local ok,d=pcall(doc,root..'/reply');if not ok or d.api_version~=1 or d.engineering~=true or d.phase~='firewall' or type(d.ok)~='boolean'then os.exit(7)end;io.write(codec.json(d)..'\n');return end
if mode=='clean-reply'then local ok,d=pcall(doc,root..'/reply');os.exit(ok and d.ok==true and d.known==true and d.active==false and d.state=='inactive' and 0 or 7)end
local function quote(s)return "'"..s:gsub("'","'\\''").."'"end
local function command(argv)
 local args={};for _,s in ipairs(argv)do args[#args+1]=quote(s)end
 local rc=os.execute(table.concat(args,' ')..' > '..quote(root..'/out')..' 2> '..quote(root..'/err'))
 return rc==0,read(root..'/out'),read(root..'/err'),rc
end
local function call(table_name,args)
 local argv={'/usr/sbin/ip6tables','-w','1','-t',table_name};for _,s in ipairs(args)do argv[#argv+1]=s end
 return command(argv)
end
local function absent(err,rc)
 return (rc==1 or rc==256) and err:find('No chain/target/match by that name',1,true) and not err:lower():find('permission',1,true)
end
local function lines(s)local a={};for l in s:gmatch('[^\n]+')do a[#a+1]=l end;return a end
local function normalize(s)return s:gsub(' %-m tcp','')end
local function observe()
 local result={}
 for _,item in ipairs({{'nat','PREROUTING','HG_ENG_NAT'},{'filter','INPUT','HG_ENG_INPUT'}})do
  -- A reference can originate in any chain, including a goto. Read the
  -- complete bounded table before deleting our exact parent jumps/chains.
  local tab,parent,chain=unpack(item);local ok,out=call(tab,{'-S'});if not ok then error('backend')end
  local hooks,foreign=0,0
  for _,l in ipairs(lines(out))do
   if l=='-A '..parent..' -j '..chain then hooks=hooks+1
   elseif l:find(' %-[jg] '..chain..'%f[%s%z]')then foreign=foreign+1 end
  end
  if hooks>32 then error('hook_limit')end
  local exists,raw,err,rc=call(tab,{'-S',chain});if not exists and not absent(err,rc)then error('backend')end
  local rules={}
  if exists then
   for _,l in ipairs(lines(raw))do
    if l~='-N '..chain then if l:sub(1,#chain+4)~='-A '..chain..' ' then error('chain')end;rules[#rules+1]=normalize(l)end
   end
  end
  result[tab]={exists=exists,hooks=hooks,foreign=foreign,rules=rules}
 end
 return result
end
local function empty(d)return not d.nat.exists and not d.filter.exists and d.nat.hooks==0 and d.filter.hooks==0 and d.nat.foreign==0 and d.filter.foreign==0 end
local function must(tab,args)if not call(tab,args)then error('command')end end
local function cleanup()
 local d=observe()
 -- Inspect both tables before any mutation. A conditional or otherwise
 -- foreign reference is not one of our exact owned parent jumps.
 if d.nat.foreign>0 or d.filter.foreign>0 then error('foreign_reference')end
 for _,item in ipairs({{'nat','PREROUTING','HG_ENG_NAT'},{'filter','INPUT','HG_ENG_INPUT'}})do
  local tab,parent,chain=unpack(item)
  for _=1,d[tab].hooks do must(tab,{'-D',parent,'-j',chain})end
  if d[tab].exists then must(tab,{'-F',chain});must(tab,{'-X',chain})end
 end
 if not empty(observe())then error('cleanup')end
end
local function equal(a,b)if #a~=#b then return false end;for n,l in ipairs(a)do if l~=b[n]then return false end end;return true end
local function matched(observed,d)
 return observed.nat.exists and observed.filter.exists and observed.nat.hooks==1 and observed.filter.hooks==1 and observed.nat.foreign==0 and observed.filter.foreign==0 and equal(observed.nat.rules,d.nat) and equal(observed.filter.rules,d.filter)
end
local failure
local function report(ok,known,active,state,desired,quiet)
 local d={api_version=1,engineering=true,ok=ok,phase='firewall',known=known,active=active,state=state,managed=desired and desired.enabled or false,automatic_reconcile=desired and desired.enabled and desired.reconcile or false,backend='ip6tables',family='IPv6',effect=known and (mode=='status' and 'none' or 'confirmed') or 'unknown',write_ready=false}
 if desired then d.wan_device=desired.wan end
 if desired and desired.failure and not failure then d.error_kind=desired.failure;d.retryable=desired.failure=='wan_unavailable'end
 if not ok and failure then d.error_kind=failure;d.retryable=failure=='wan_unavailable'end
 save('report',d);if not quiet then io.write(codec.json(d)..'\n')end;return d
end
local function port(n,optional)if optional and n==0 then return 0 end;if type(n)~='number' or n%1~=0 or n<1 or n>65535 then error('port')end;return n end
local function plan()
 if type(token)~='string' or #token~=32 or not token:match('^[0-9a-f]+$') then error('token')end
 local p=doc(proxy..'/plan.json');if p.auto_firewall~=true then error('disabled')end
 if type(p.routes)~='table' or #p.routes<1 or #p.routes>16 then error('routes')end
 local has_http,has_https=false,false
 for _,r in ipairs(p.routes)do if r.https==true then has_https=true elseif r.https==false then has_http=true else error('route')end end
 local commands={addresses={'ip','-6','-o','addr','show','scope','global'},routes={'ip','-6','route','show','default'},wan6={'ubus','call','network.interface.wan6','status'}}
 local wan=network.sample(function(name)local ok,out=command(assert(commands[name]));return out,ok end,json.parse,ipplan)
 if not wan or not network.device(wan.device)then error('wan_unavailable')end
 local out={enabled=true,reconcile=true,token=token,wan=wan.device,nat={},filter={},mappings={}}
 local function mapping(public,private)
  out.nat[#out.nat+1]='-A HG_ENG_NAT -i '..wan.device..' -p tcp --dport '..public..' -j REDIRECT --to-ports '..private
  out.mappings[#out.mappings+1]={public=public,private=private}
 end
 if has_https then mapping(port(p.public_https_port),port(p.https_port));mapping(80,port(p.http_port))end
 if has_http and port(p.public_http_port,true)>0 and not(has_https and p.public_http_port==80)then mapping(p.public_http_port,port(p.http_port))end
 if #out.mappings==0 then error('ports_disabled')end
 local seen={};for _,m in ipairs(out.mappings)do if not seen[m.private]then out.filter[#out.filter+1]='-A HG_ENG_INPUT -i '..wan.device..' -p tcp --dport '..m.private..' -j ACCEPT';seen[m.private]=true end end
 return out
end
local function append(tab,chain,rule)
 local args={};for part in rule:gmatch('%S+')do args[#args+1]=part end
 if args[1]~='-A' or args[2]~=chain then error('rule')end;must(tab,args)
end
local function guard()local ok=command({'ash',dir..'/homegate-firewall.sh','guard-internal',token});if not ok then error('source')end end
local desired
local ok,err=pcall(function()
 desired=admission(true)
 if mode=='uncertain'then
  if desired then desired.reconcile=false;desired.failure='timeout';save('desired',desired)end
  report(false,false,false,'unavailable',desired);return
 end
 if mode=='status'then
  local observed=observe();local active=not empty(observed);local state=not active and 'inactive' or desired and desired.enabled and matched(observed,desired) and 'active' or 'drift'
  report(true,true,active,state,desired);return
 end
 if mode=='cleanup'then
  -- Disarm only after an actual empty-kernel observation; retained admission
  -- remains enabled when cleanup/timeout is uncertain, blocking quiet reap.
  cleanup();if desired then desired.enabled=false;desired.reconcile=false;desired.failure=nil;save('desired',desired)end
  report(true,true,false,'inactive',desired);return
 end
 if mode~='apply' and mode~='watch'then error('mode')end
 if mode=='watch' and (not desired or not desired.enabled or not desired.reconcile or desired.token~=token)then return end
 guard();local next=plan()
 if desired and desired.enabled and desired.token~=token then error('stale')end
 desired=next;save('desired',desired);report(false,false,false,'applying',desired,true)
 local observed=observe()
 if not matched(observed,desired)then
  cleanup();guard()
  must('nat',{'-N','HG_ENG_NAT'});must('filter',{'-N','HG_ENG_INPUT'})
  for _,rule in ipairs(desired.nat)do guard();append('nat','HG_ENG_NAT',rule)end
  for _,rule in ipairs(desired.filter)do guard();append('filter','HG_ENG_INPUT',rule)end
  guard();must('filter',{'-I','INPUT','1','-j','HG_ENG_INPUT'});must('nat',{'-I','PREROUTING','1','-j','HG_ENG_NAT'})
 end
 guard();if not matched(observe(),desired)then error('verify')end;report(true,true,true,'active',desired)
end)
if not ok then
 local kind=tostring(err):match(': ([a-z_]+)$')
 local allowed={disabled=true,token=true,source=true,wan_unavailable=true,ports_disabled=true,backend=true,command=true,cleanup=true,foreign_reference=true,hook_limit=true,chain=true,verify=true,stale=true,admission=true}
 failure=allowed[kind] and kind or 'internal'
 if desired and (mode=='apply' or mode=='watch')then
  desired.reconcile=false;desired.failure=failure;pcall(save,'desired',desired)
  local clean=pcall(cleanup)
  pcall(report,false,clean,false,clean and 'apply_failed_clean' or 'cleanup_failed',desired)
 else pcall(report,false,false,false,'unavailable',desired)end
 os.exit(7)
end
