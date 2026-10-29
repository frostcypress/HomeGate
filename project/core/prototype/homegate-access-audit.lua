-- Bounded best-effort observations. No request URI, query or upstream URL.
local dir=assert(arg[0]:match('^(.*)/[^/]+$'));local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local json=require('luci.jsonc');local nx=require('nixio');local fs=require('nixio.fs')
local ip=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local run='/var/run/homegate';local root=run..'/proxy';local path=run..'/access.json';local sockpath='/var/run/homegate-audit/socket'
local function fail()os.exit(1)end
local function property(p,kind,mode,max)
 local s=fs.lstat(p);return s and s.type==kind and s.uid==0 and s.modedec==mode and (kind~='reg' or s.nlink==1 and s.size<=max)
end
local function read(p,n)
 if not property(p,'reg',600,n)then fail()end;local f=assert(io.open(p,'rb'));local s=f:read(n+1);f:close();if not s or #s>n then fail()end;return s
end
local function write(p,s)
 local st=fs.lstat(p);if st and not property(p,'reg',600,65536)then fail()end
 local f=assert(io.open(p,'wb'));assert(f:write(s));assert(f:close())
end
local function address(v)
 if type(v)~='string' or #v>45 then return nil end
 local a,b,c,d=v:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
 if a then for _,x in ipairs({a,b,c,d})do if #x>3 or tonumber(x)>255 or (#x>1 and x:sub(1,1)=='0')then return nil end end;return v end
 return ip.ipv6(v) and v:lower() or nil
end
local reasons={['manual-deny']=false,denied=false,disabled=true,ip=true,region=true}
local function event(d)
 if type(d)~='table' or not address(d.ip) or type(d.host)~='string' or #d.host>253 or #d.host<1 or d.host:find('[^a-zA-Z0-9.*-]') or type(d.allowed)~='boolean' or reasons[d.reason]==nil or d.allowed~=reasons[d.reason]then return nil end
 return {ip=address(d.ip),host=d.host:lower():gsub('%.$',''),allowed=d.allowed,reason=d.reason,region=d.reason=='region' and 'CN' or '',time=os.date('!%Y-%m-%dT%H:%M:%SZ'),count=1}
end
local function entries()
 if not fs.lstat(path)then return {}end
 local d=json.parse(read(path,65536));if type(d)~='table' or type(d.entries)~='table' or #d.entries>64 then fail()end
 local out={};for _,row in ipairs(d.entries)do local e=event(row);if not e or type(row.time)~='string' or #row.time~=20 or not row.time:match('^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%dZ$') or type(row.count)~='number' or row.count<1 or row.count>2147483647 or row.count%1~=0 then fail()end;e.time=row.time;e.count=row.count;out[#out+1]=e end;return out
end
--[=[ The socket is nonblocking. A private independently generated syslog tag
binds messages to this session; a local sender cannot use a public session ID
as an audit token. This remains a best-effort observation channel, not a grant
or a lossless/security journal. ]=]
if nx.getuid()~=0 or not property(run,'dir',700)then fail()end
local mode=arg[1]
if mode=='read'then io.write(codec.json({api_version=1,engineering=true,ok=true,phase='access-recent',entries=entries(),best_effort=true,observations_only=true,effect='none',write_ready=false})..'\n');return end
if mode=='clear'then
 if arg[2]~='all' and arg[2]~='denied'then fail()end
 if not property(root,'dir',700) or read(root..'/audit-health',6)~='true\n' or fs.lstat(root..'/audit-clear')then fail()end
 write(root..'/audit-clear.next',arg[2]..'\n');assert(os.rename(root..'/audit-clear.next',root..'/audit-clear'));io.write(codec.json({api_version=1,engineering=true,ok=true,phase='access-recent',clear_pending=true,effect='none',write_ready=false})..'\n');return
end
if mode~='serve' or not property(root,'dir',700) or read(root..'/token',33)~=arg[2]..'\n' or fs.lstat(sockpath)then fail()end
local secret=read(root..'/audit-token',33):match('^([0-9a-f]+)\n$');if not secret or #secret~=32 then fail()end
local plan=json.parse(read(root..'/plan.json',131072));if type(plan)~='table' or type(plan.routes)~='table'then fail()end
local function managed(host)
 for _,r in ipairs(plan.routes)do if host==r.domain or (r.domain:sub(1,2)=='*.' and host:match('^[^.]+%.(.+)$')==r.domain:sub(3))then return true end end;return false
end
local socket=assert(nx.socket('unix','dgram'));assert(socket:bind(sockpath));assert(fs.chmod(sockpath,'622'));assert(socket:setblocking(false))
local rows=entries();local dirty=true;local last=0;local tag=' '..secret..': '
local function flush()
 if not dirty then return end
 local body=codec.json({entries=rows})..'\n';if #body>65536 then fail()end
 if fs.lstat(path..'.next')then if not property(path..'.next','reg',600,65536)then fail()end;assert(fs.unlink(path..'.next'))end
 write(path..'.next',body);assert(os.rename(path..'.next',path));dirty=false
end
write(root..'/audit-health','true\n')
while true do
 if fs.lstat(root..'/stop')then flush();write(root..'/audit-health','false\n');socket:close();return end
 if fs.lstat(root..'/audit-clear')then
  local clear=read(root..'/audit-clear',8);if clear~='all\n' and clear~='denied\n' then fail()end
  local kept={};if clear=='denied\n' then for _,e in ipairs(rows)do if e.allowed then kept[#kept+1]=e end end end;rows=kept;dirty=true;flush();assert(fs.unlink(root..'/audit-clear'))
 end
 for i=1,128 do
  local raw=socket:recv(4096);if not raw then break end
  local start=raw:find(tag,1,true)
  if start and #raw<4096 then
   local d=json.parse(raw:sub(start+#tag));local e=event(d)
   if e and managed(e.host)then
    local kept={};for _,old in ipairs(rows)do if old.ip==e.ip and old.host==e.host then e.count=math.min(2147483647,old.count+1)else kept[#kept+1]=old end end
    kept[#kept+1]=e;if #kept>64 then table.remove(kept,1)end;rows=kept;dirty=true
   end
  end
 end
 local sec,usec=nx.gettimeofday();local now=sec+usec/1000000;if dirty and now-last>=0.1 then flush();last=now end
 nx.poll({{fd=socket,events=nx.poll_flags('in')}},100);nx.nanosleep(0,1000000)
end
