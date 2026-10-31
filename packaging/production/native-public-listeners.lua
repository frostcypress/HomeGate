-- Read-only socket ownership proof. No connect, signal or configured-port guess.
return function()
 local fs=require('nixio.fs');local function read(p,n,private)
  if private then local a=fs.lstat(p);if not a or a.type~='reg' or a.uid~=0 or a.nlink~=1 or a.modedec~=600 or a.size>n then return nil end end
  local f=io.open(p,'rb');if not f then return nil end;local b=f:read(n+1) or '';f:close();return #b<=n and b or nil
 end
 local root='/var/run/homegate/proxy';local owner=read(root..'/owner',128,true);local pid=read(root..'/nginx.pid',32,true)
 local op,ot;if owner then op,ot=owner:match('^(%d+):(%d+)\n$')end;pid=pid and pid:match('^(%d+)\n$')
 if not op or not ot or not pid or #pid>9 then return {}end
 local function sample()
  local function stat(p)local raw=read('/proc/'..p..'/stat',8192);if not raw then return nil end;local id,tail=raw:match('^(%d+) %(.+%) (.+)$');if id~=p then return nil end;local a={};for v in tail:gmatch('%S+')do a[#a+1]=v end;return a end
  local a,b=stat(op),stat(pid);if not a or not b or a[20]~=ot or a[1]=='Z' or a[1]=='X' or b[1]=='Z' or b[1]=='X' or b[2]~=op or b[3]~=op or b[4]~=op then return nil end
  local cmd=read('/proc/'..pid..'/cmdline',8192)
  local original=cmd and cmd:find('\0-p\0'..root..'/\0-c\0'..root..'/active.conf\0',1,true)
  local title=cmd and cmd:sub(1,22)=='nginx: master process ' and cmd:find(' -p '..root..'/ -c '..root..'/active.conf -g daemon off;',1,true)
  if not original and not title then return nil end
  return b[20]
 end
 local birth=sample();if not birth then return {}end
 local sockets={};local iter=fs.dir('/proc/'..pid..'/fd');if not iter then return {}end
 for fd in iter do if fd:match('^%d+$')then local target=fs.readlink('/proc/'..pid..'/fd/'..fd);local inode=target and target:match('^socket:%[(%d+)%]$');if inode then sockets[inode]=true end end end
 local ports={}
 for _,p in ipairs({'/proc/net/tcp','/proc/net/tcp6'})do
  local raw=read(p,1048576);if not raw then return {}end
  for line in raw:gmatch('[^\n]+')do local a={};for v in line:gmatch('%S+')do a[#a+1]=v end
   if a[4]=='0A' and sockets[a[10]]then local port=a[2]:match(':([0-9A-Fa-f]+)$');if port then ports[tonumber(port,16)]=true end end
  end
 end
 if sample()~=birth or read(root..'/owner',128,true)~=owner or read(root..'/nginx.pid',32,true)~=pid..'\n' then return {}end
 return ports
end
