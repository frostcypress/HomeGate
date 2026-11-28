-- Time-bound the two local DNS commands using the existing LuCI runtime.
local dir=arg[0]:match('^(.*)/[^/]+$')
if not dir then os.exit(125) end
local records=assert(loadfile(dir..'/cloudflare-record-plan.lua'))()
local action,host,server=arg[1],arg[2],arg[3]
if not host or records.name(host)~=host then os.exit(125) end
local command,args
if action=='lookup' and (server=='127.0.0.1' or server=='127.0.0.1#5333') and not arg[4] then
    command,args='nslookup',{host,server}
elseif action=='evict' and not server then
    command,args='pdnsd-ctl',{'-c','/var/dnscache','record',host,'delete'}
else
    os.exit(125)
end

local nx=require('nixio')
local pid=nx.fork()
if not pid then os.exit(125) end
if pid==0 then
    nx.execp(command,unpack(args))
    os.exit(127)
end
for tick=1,21 do
    local child,status,code=nx.waitpid(pid,'nohang')
    if child==pid then os.exit(status=='exited' and code or 125) end
    if child~=false then os.exit(125) end
    if tick==21 or nx.nanosleep(0,100000000)~=true then break end
end
-- A successfully polled, unreaped child cannot have its PID reused.
if nx.kill(pid,9) then nx.waitpid(pid) end
os.exit(124)
