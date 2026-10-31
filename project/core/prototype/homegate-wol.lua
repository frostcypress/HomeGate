-- WOL configuration selection and untrusted transport report validation.
local dir=assert(arg[0]:match('^(.*)/[^/]+$'));local json=require('luci.jsonc')
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local mode=arg[1];local function fail()os.exit(2)end
local function id(s)return type(s)=='string' and #s>0 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$')end
local function iface(s)return type(s)=='string' and #s>0 and #s<=32 and s~='.' and s~='..' and s:match('^[a-zA-Z0-9_.:%-]+$')end
local function read(p,n)local f=assert(io.open(p,'rb'));local s=f:read(n+1) or '';f:close();if #s>n then fail()end;return s end
local function version()return read(dir..'/../../../VERSION',64):gsub('\n$','')..'-r'..read(dir..'/../../../RELEASE',16):gsub('\n$','')end
local function mac(s)
 if type(s)~='string'then return nil end;s=s:match('^%s*(.-)%s*$');local hex
 if #s==17 and (s:sub(3,3)==':' or s:sub(3,3)=='-')then
  local sep=s:sub(3,3);local parts={};for i=1,17,3 do if i>1 and s:sub(i-1,i-1)~=sep then return nil end;parts[#parts+1]=s:sub(i,i+1)end;hex=table.concat(parts)
 elseif #s==14 and s:sub(5,5)=='.' and s:sub(10,10)=='.'then hex=s:gsub('%.','')
 else return nil end
 if #hex~=12 or hex:find('[^%x]')then return nil end;return hex:upper():gsub('(..)','%1:'):sub(1,-2)
end
local function snapshot()
 local d=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec);if not d then fail()end
 local main,hosts={},{ }
 for _,s in ipairs(d.configuration)do if s.kind=='homegate'then main=s.values elseif s.kind=='wol_host'then hosts[#hosts+1]={id=s.name,name=s.values.name,mac=s.values.mac}end end
 return main,hosts
end
local root='/var/run/homegate/wol';local function plan(d)
 local f=assert(io.open(root..'/plan.json','wb'));assert(f:write(codec.json(d)..'\n'));assert(f:close())
end
if mode=='status' or mode=='host' or mode=='interface'then
 local main,hosts=snapshot();local selected=main.wol_interface~='' and main.wol_interface or 'br-lan';if not iface(selected)then fail()end
 if mode=='interface'then io.write(selected,'\n');return end
 if mode=='status'then io.write(codec.json({api_version=1,engineering=true,ok=true,phase='wol',version=version(),interface=selected,selected_host=main.last_wol_host,hosts=hosts,effect='none',write_ready=false})..'\n');return end
 if not id(arg[2])then fail()end
 for _,h in ipairs(hosts)do if h.id==arg[2]then plan({interface=selected,mac=assert(mac(h.mac)),host=h.id,name=h.name});return end end;fail()
end
if mode=='direct'then
 local name=arg[2]=='' and 'br-lan' or arg[2];local address=mac(arg[3]);if not iface(name) or not address then fail()end
 plan({interface=name,mac=address});return
end
local p=json.parse(read(root..'/plan.json',8192));if type(p)~='table' or not iface(p.interface) or not mac(p.mac)then fail()end
if mode=='fields'then io.write(p.interface,' ',p.mac,'\n');return end
if mode=='result'then
 local d=json.parse(read(root..'/result',131072));local rc=tonumber(arg[2]);local maximum=tonumber(arg[3])
 if type(d)~='table' or d.api_version~=1 or d.phase~='wol-transport' or type(d.ok)~='boolean' or type(maximum)~='number' or maximum<1 or maximum>1025 then fail()end
 for _,key in ipairs({'raw_sent','udp_sent'})do if type(d[key])~='number' or d[key]<0 or d[key]%1~=0 or d[key]>(key=='raw_sent' and maximum*3 or 6)then fail()end end
 if type(d.interfaces)~='table' or #d.interfaces>maximum or type(d.warnings)~='table' or #d.warnings>maximum+1 or (d.raw_sent>0)~=(#d.interfaces>0) or #d.interfaces>d.raw_sent then fail()end
 local allowed={};for name in read(root..'/allowed',65536):gmatch('([^\n]+)\n')do if not iface(name)then fail()end;allowed[name]=true end
 local seen={};for _,name in ipairs(d.interfaces)do if not iface(name) or seen[name] or not allowed[name]then fail()end;seen[name]=true end
 if d.raw_sent>#d.interfaces*3 then fail()end
 for _,warning in ipairs(d.warnings)do
  if type(warning)~='string' or #warning>100 then fail()end
  local raw=warning:match('^raw/(.+) failed$');local udp=warning:match('^udp/(.+) failed$')
  if warning~='control_unavailable' and warning~='interface_unavailable' and not(raw and allowed[raw]) and not(udp and udp==p.interface)then fail()end
 end
 local sent=d.raw_sent+d.udp_sent>0;if d.ok~=sent or (rc==0)~=sent then fail()end
 io.write(codec.json({api_version=1,engineering=true,ok=sent,phase='wol',version=version(),host=p.host,name=p.name,interface=p.interface,mac=p.mac,raw_sent=d.raw_sent,udp_sent=d.udp_sent,interfaces=d.interfaces,warnings=d.warnings,device_wake_verified=false,effect=sent and 'confirmed' or 'none',write_ready=false})..'\n');return
end
fail()
