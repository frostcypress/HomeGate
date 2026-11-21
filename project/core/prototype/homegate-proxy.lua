-- Private proxy planner. No target URL, key bytes or filesystem path is public.
local dir=assert(arg[0]:match('^(.*)/[^/]+$'))
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local validation=assert(loadfile(dir..'/configuration-validation.lua'))()
local json=require('luci.jsonc')
local function fail()os.exit(1)end
local function read(p,n)local f=io.open(p,'rb');if not f then fail()end;local s=f:read(n+1);f:close();if not s or #s>n then fail()end;return s end
local function write(p,s)local f=io.open(p,'wb');if not f or not f:write(s) or not f:close()then fail()end end
local function id(s)return type(s)=='string' and #s>0 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$')end
local root='/var/run/homegate/proxy'
local function load()local d=json.parse(read(root..'/plan.json',131072));if type(d)~='table' or type(d.routes)~='table' or (#d.routes==0 and not d.management) or #d.routes>16 then fail()end;return d end
local function quote(s)return '"'..s:gsub('\\','\\\\'):gsub('"','\\"')..'"'end
local function occupied_ports()
 local occupied={}
 for _,path in ipairs({'/proc/net/tcp','/proc/net/tcp6'})do
  validation.listening_ports(read(path,1048576),occupied)
 end
 return occupied
end
local mode=arg[1]
if mode=='plan' then
 local selection,policy=arg[2],arg[3];if (arg[4] and arg[4]~='native') or (policy~='open' and policy~='allow') or type(selection)~='string' or #selection>1039 then fail()end
 local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec);if not snapshot then fail()end
 local indexed,certificates={},{}
 for _,s in ipairs(snapshot.configuration)do
  indexed[s.name]=s
  if s.kind=='certificate'then certificates[s.name]=s end
 end
 local main=indexed.main.values
 if policy=='allow' and main.access_region=='CN'then local f=io.open('/etc/homegate/access/CN.cidr','rb');if not f then fail()end;local ok=pcall(assert(loadfile(dir..'/access-region.lua'))().cache,f,nil,os.time());f:close();if not ok then fail()end end
 local hp,sp=tonumber(main.proxy_http_port),tonumber(main.proxy_https_port)
 if not hp or hp<1024 or not sp or sp<1024 or hp==sp then fail()end
 local out={routes={},certificates={},policy=policy,http_port=hp,https_port=sp,public_https_port=tonumber(main.https_port),public_http_port=tonumber(main.http_port),auto_firewall=main.auto_firewall=='1',allow=main.access_allow,deny=main.access_deny,region=policy=='allow' and main.access_region or ''}
 local native=arg[4]=='native'
 local management,local_listeners
 if native then
  out.optional_certificates={}
  out.custom_ports_only=true
  management=assert(loadfile('/usr/libexec/homegate/native-management.lua'))()
  local_listeners=management.read()
 end
 local seen,certs,ports={},{},{}
 local function covers(pattern,name)return pattern==name or (pattern:sub(1,2)=='*.' and name:match('^[^.]+%.(.+)$')==pattern:sub(3))end
 local function add_certificate(cert)
  if not certs[cert]then
   certs[cert]=true;out.certificates[#out.certificates+1]=cert
   if native and indexed[cert].values.source=='acme'then out.optional_certificates[cert]=true end
  end
 end
 local management_domain=native and codec.active_management_domain(snapshot.configuration)
 if management_domain then
  local cert=indexed[main.management_certificate]
  if not out.auto_firewall or not local_listeners or not local_listeners.backend or not cert or cert.kind~='certificate' then fail()end
  out.management={domain=management_domain,wan=true,
                  certificate=cert.name,backend=local_listeners.backend}
  add_certificate(cert.name)
 end
 if native and selection=='-' and out.management then selection='' end
 if selection=='' and not out.management then fail()end
 for name in (selection..','):gmatch('(.-),')do
  if selection=='' then break end
  if not id(name) or seen[name] or #out.routes>=16 then fail()end;seen[name]=true
  local s=indexed[name];if not s or s.kind~='web_rule' then fail()end
  local v=s.values;local target=snapshot.credentials['web.'..name..'.target']
  if codec.web_port_conflicts(main,v) then fail()end
  if not validation.target(target,assert(loadfile(dir..'/cloudflare-record-plan.lua'))())then fail()end
  local upstreams
  if native then
   if not codec.custom_public_port(v.external_port) then fail()end
   local allowed,_,addresses=management.ordinary_target(local_listeners,target)
   if not allowed then fail()end
   upstreams=addresses
  end
  local scheme,authority,tail=target:match('^(https?)://([^/?]+)(.*)$');if not scheme then fail()end
  local host=authority:match('^%[([^%]]+)%]') or authority:match('^([^:]+)')
  local base,query=tail:match('^(.-)%?(.*)$');if not base then base=tail end
  if base:sub(-1)=='/'then base=base:sub(1,-2)end
  local cert=''
  if v.https=='1'then
   cert=codec.web_certificate_id(v,certificates)
   if not indexed[cert] or indexed[cert].kind~='certificate'then fail()end
   local covered=false;for _,d in ipairs(indexed[cert].values.domains)do if covers(d,v.domain)then covered=true end end;if not covered then fail()end
   add_certificate(cert)
  end
  local public=codec.web_port(main,v)
  local default=v.https=='1' and out.public_https_port or out.public_http_port
  local route={id=name,domain=v.domain,https=v.https=='1',certificate=cert,scheme=scheme,authority=authority,upstreams=upstreams,host=host,base=base,query=query,public_port=public}
  route.redirect_http=not native and route.https and public>0 and (not v.external_port or public==443)
  if not native and (not v.external_port or public==default or (not route.https and public==80))then
   route.listen_port=route.https and sp or hp
  else
   if ports[public]~=nil and ports[public]~=route.https then fail()end
   ports[public]=route.https
  end
  out.routes[#out.routes+1]=route
 end
 local extras={};for public in pairs(ports)do extras[#extras+1]=public end;table.sort(extras)
 if #extras>0 then
  local busy=occupied_ports();local internal={};local next_port=20000
  for _,r in ipairs(out.routes)do busy[r.public_port]=busy[r.public_port] or false end
  for _,public in ipairs(extras)do
   if busy[public] then fail()end
   if out.auto_firewall then
    while next_port==hp or next_port==sp or busy[next_port]~=nil do next_port=next_port+1 end
    if next_port>65535 then fail()end
    internal[public]=next_port;next_port=next_port+1
   else internal[public]=public end
  end
  for _,r in ipairs(out.routes)do r.listen_port=r.listen_port or internal[r.public_port] end
 end
 table.sort(out.certificates);io.write(codec.json(out)..'\n');return
end
if mode=='selection-certificates'then local d=json.parse(io.stdin:read(131073));if type(d)~='table' or type(d.certificates)~='table'then fail()end;for _,c in ipairs(d.certificates)do if not id(c)then fail()end;io.write(c,'\n')end;return end
if mode=='certificates'then for _,c in ipairs(load().certificates)do if not id(c)then fail()end;io.write(c,'\n')end;return end
if mode=='certificate-ok'then
 local d=json.parse(io.stdin:read(16385));if type(d)~='table' or d.ok~=true or d.certificate~=arg[2] then fail()end
 if arg[3]=='native' and d.source=='acme' and (d.exists==false or
    (d.pending==false and (d.error_kind=='configuration_changed' or d.error_kind=='validity'))) then os.exit(3)end
 if d.valid~=true or d.pending~=false or d.identity_valid~=true then fail()end;return
end
local function optional(p,id)return p.optional_certificates and p.optional_certificates[id]==true end
local function material(which)
 if which~='accepted' and which~='candidate'then fail()end
 local d=json.parse(read(root..'/'..which..'.json',32768));local p=load()
 if type(d)~='table' or type(d.generation)~='number' or d.generation<1 or d.generation>2147483647 or d.generation%1~=0 or type(d.certificates)~='table' or type(d.waiting)~='table' then fail()end
 local i=1
 local waiting={}
 for _,name in ipairs(p.certificates)do
  local c=d.certificates[i]
  if type(c)=='table' and c.id==name then
   if not id(c.id) or type(c.pair)~='string' or not c.pair:match('^pair%-[0-9a-f]+$') or #c.pair~=37 or type(c.fingerprint)~='string' or not c.fingerprint:match('^[0-9a-f]+$') or #c.fingerprint~=64 or type(c.expires_epoch)~='number' or type(c.not_before_epoch)~='number'then fail()end
   i=i+1
  elseif optional(p,name) and d.waiting[name] then waiting[name]=true
  else fail()end
 end
 if i~=#d.certificates+1 then fail()end
 for name,v in pairs(d.waiting)do
  if not waiting[name] or type(v)~='string' or (v~='absent\n' and (#v~=38 or not v:match('^pair%-[0-9a-f]+\n$'))) then fail()end
 end
 return d
end
if mode=='certificate-may-wait'then
 local p=load();if not optional(p,arg[2]) then fail()end
 if arg[3]~='1' then for _,c in ipairs(material('accepted').certificates)do if c.id==arg[2] then fail()end end end
 return
end
if mode=='capture'then
 local generation=tonumber(arg[2]);if not generation or generation<1 or generation>2147483647 or generation%1~=0 then fail()end
 local out={generation=generation,certificates={},waiting={}}
 local p=load()
 for _,c in ipairs(p.certificates)do
  local base=root..'/next/'..c..'/'
  local f=io.open(base..'pointer','rb')
  if f then f:close()
  local pair=read(base..'pointer',38):match('^(pair%-[0-9a-f]+)\n$');if not pair or #pair~=37 then fail()end
  local d=json.parse(read(base..'result.json',65536));local fingerprint=read(base..'fingerprint',65):match('^([0-9a-f]+)\n$')
  if type(d)~='table' or d.certificate~=c or d.identity_valid~=true or d.key_matches~=true or type(d.expires_epoch)~='number' or type(d.not_before_epoch)~='number' or os.time()<d.not_before_epoch or os.time()>=d.expires_epoch or not fingerprint or #fingerprint~=64 then fail()end
  out.certificates[#out.certificates+1]={id=c,pair=pair,fingerprint=fingerprint,expires_epoch=d.expires_epoch,not_before_epoch=d.not_before_epoch}
  elseif optional(p,c) then out.waiting[c]=read(base..'waiting',38)
  else fail()end
 end
 write(root..'/candidate.json',codec.json(out)..'\n');return
end
if mode=='probes'then
 local d=material(arg[2]);local certs={};for _,c in ipairs(d.certificates)do certs[c.id]=c end
 local p=load();local exact={};for _,r in ipairs(p.routes)do if r.domain:sub(1,2)~='*.'then exact[r.domain]=true end end
 for _,r in ipairs(p.routes)do if r.https and certs[r.certificate] then
  local host=r.domain
  if host:sub(1,2)=='*.'then
   host=nil;for i=1,17 do local candidate=string.char(96+i)..'.'..r.domain:sub(3);if not exact[candidate]then host=candidate;break end end
   if not host then fail()end
  end
  io.write(host,':',certs[r.certificate].fingerprint,':',r.listen_port or p.https_port,'\n')
 end end
 local management=p.management
 if management and certs[management.certificate] then
  io.write(management.domain,':',certs[management.certificate].fingerprint,':',p.https_port,':6\n')
 end
 return
end
if mode=='port'then io.write(load().https_port,'\n');return end
if mode=='access-port'then io.write(load().http_port,'\n');return end
if mode=='generation'then io.write(material('accepted').generation,'\n');return end
if mode=='material-check'then material('accepted');return end
if mode=='render' or mode=='render-access'then
 local m=material(mode=='render-access' and 'accepted' or 'candidate');local pairs={};for _,c in ipairs(m.certificates)do pairs[c.id]='/etc/homegate/certs/'..c.id..'/'..c.pair end
 local d=load();local token=read(root..'/token',33):match('^([0-9a-f]+)\n$');if not token or #token~=32 then fail()end
 local marker=token
 if arg[2]=='native' then
  local rules=assert(loadfile('/usr/libexec/homegate/native-access.lua'))().read(d.allow or '',d.deny or '')
  if rules then d.allow,d.deny,marker=rules.allow,rules.deny,rules.stamp end
 end
 local lines={};local function add(s)lines[#lines+1]=s end
 add('worker_processes 1;\nerror_log /dev/null crit;\npid '..root..'/nginx.pid;\nevents { worker_connections 128; }\nhttp {')
 -- Exact DNS names can reach 253 bytes before NGINX hash entry overhead.
 add('server_names_hash_bucket_size 512;')
 add('access_log off; server_tokens off; client_max_body_size 0; client_body_buffer_size 128k; client_header_timeout 15s; client_body_timeout 60s; send_timeout 60s; keepalive_timeout 30s;')
 local temp='/var/run/homegate-proxy-body/'..token
 for _,n in ipairs({'client_body','proxy','fastcgi','uwsgi','scgi'})do add(n..'_temp_path '..temp..'/'..n..';')end
 add('map $http_upgrade $hg_upgrade { default ""; ~*^websocket$ websocket; }\nmap $hg_upgrade $hg_connection { default ""; websocket upgrade; }')
 add('geo $hg_dollar { default "$"; }')
 add('map $request_uri $hg_raw_path { ~^(?<hg_path>[^?]*) $hg_path; }\nmap $args $hg_join { "" ""; default "&"; }')
 for _,kind in ipairs({'allow','deny'})do
  add('geo $hg_'..kind..' { default 0;');for cidr in d[kind]:gmatch('[^,;%s]+')do add(cidr..' 1;')end;add('}')
 end
 add('geo $hg_cn { default 0; include '..root..'/cn.conf; }')
 if d.policy=='open'then
  add('map $hg_deny $hg_reason { default disabled; 1 manual-deny; }')
 else
  add('map "$hg_deny:$hg_allow:$hg_cn" $hg_reason { ~^1: manual-deny; ~^0:1: ip; ~^0:0:1 region; default denied; }')
 end
 add('map $hg_reason $hg_allowed { manual-deny false; denied false; default true; }')
 local audit=read(root..'/audit-token',33):match('^([0-9a-f]+)\n$');if not audit or #audit~=32 then fail()end
 local function public_port(port,default)return type(port)=='number' and port>0 and port or default end
 local http_public=public_port(d.public_http_port,80)
 local formats={}
 local function format(port,management)
  local name=(management and 'hg_management_' or 'hg_access_')..port
  if not formats[name]then
   formats[name]=true
   local allowed,reason='$hg_allowed','$hg_reason'
   if management then allowed,reason='true','disabled' end
   add(string.format([[log_format %s escape=json '{"ip":"$remote_addr","host":"$host","scheme":"$scheme","port":%d,"allowed":%s,"reason":"%s"}';]],name,port,allowed,reason))
  end
  return name
 end
 local function route_port(r)return r.public_port or (r.https and public_port(d.public_https_port,443) or http_public) end
 format(http_public)
 for _,r in ipairs(d.routes)do format(route_port(r))end
 if d.management then format(80,true);format(443,true)end
 local function logging(port,management)
  add('access_log syslog:server=unix:/var/run/homegate-audit/socket,nohostname,tag='..audit..' '..format(port,management)..';')
 end
 local function listeners(port,tls,default)
  add('listen 0.0.0.0:'..port..(tls and ' ssl' or '')..(default and ' default_server' or '')..';')
  add('listen [::]:'..port..(tls and ' ssl' or '')..(default and ' default_server ipv6only=on' or '')..';')
 end
 local default_ports={[d.http_port]=true}
 add('server {');listeners(d.http_port,false,true);add('server_name "";')
 if arg[2]=='native' then
  add('location = /.homegate-'..token..' { if ($remote_addr != 127.0.0.1) { return 404; } return 200 "'..marker..':$pid"; }')
 end
 add('location / { return 404; } }')
 if #d.certificates>0 then
  default_ports[d.https_port]=true
  add('server {');listeners(d.https_port,true,true);add('server_name ""; ssl_reject_handshake on; return 404; }')
 end
 local redirect,http_names={},{}
 for _,r in ipairs(d.routes)do
  local port=r.listen_port or (r.https and d.https_port or d.http_port)
  if not default_ports[port] then
   default_ports[port]=true
   add('server {');listeners(port,r.https,true)
   add('server_name "";'..(r.https and ' ssl_reject_handshake on;' or '')..' return 404; }')
  end
  if not r.https and port==d.http_port then http_names[r.domain]=true end
  if validation.redirects_http(d,r) then
   local first=redirect[r.domain]
   local public=r.public_port or d.public_https_port
   if not first or public==443 then redirect[r.domain]=r end
  end
 end
 local function servername(domain)
  if domain:sub(1,2)=='*.'then return quote('~^[^.]+\\.'..domain:sub(3):gsub('%.','\\.')..'$')end
  return domain
 end
 local function acl(port)logging(port);add('if ($hg_reason = manual-deny) { return 403; }');add('if ($hg_reason = denied) { return 403; }')end
 local function upgrade_to_https(public)
  add('add_header Cache-Control "no-store" always; return 307 https://$host'..(public==443 and '' or ':'..public)..'$request_uri;')
 end
 local function complex(s)return s:gsub('%$', '${hg_dollar}')end
 local management=d.management
 if management then
  local name=management.domain
  local pair=pairs[management.certificate]
  add('server { listen [::]:'..d.http_port..'; server_name '..name..';')
  logging(80,true)
  add('if ($http_host = "") { return 421; } if ($host != '..name..') { return 421; }')
  if pair then add('add_header Cache-Control "no-store" always; return 307 https://'..name..'$request_uri; }')
  else add('return 503; }') end
  add('server { listen [::]:'..d.https_port..' ssl; server_name '..name..';')
  if not pair then add('ssl_reject_handshake on; return 503; }')
  else
   logging(443,true)
   add('ssl_protocols TLSv1.2 TLSv1.3; ssl_certificate '..pair..'/fullchain.pem; ssl_certificate_key '..pair..'/privkey.pem;')
   add('if ($http_host = "") { return 421; } if ($host != '..name..') { return 421; }')
   add('location = / { return 307 https://'..name..'/cgi-bin/luci/; }')
   add('location ~ ^/(?:cgi-bin/luci(?:/|$)|luci-static/|ubus$) { proxy_http_version 1.1; proxy_buffering off; proxy_connect_timeout 5s;')
   add('proxy_set_header Host '..name..'; proxy_set_header Forwarded ""; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Host '..name..'; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Real-IP $remote_addr;')
   add('proxy_redirect http://'..name..'/ https://'..name..'/;')
   add('proxy_pass '..management.backend.scheme..'://'..management.backend.authority..'; }')
   add('location / { return 404; } }')
  end
 end
 for _,r in ipairs(d.routes)do
  local port=r.listen_port or (r.https and d.https_port or d.http_port)
  local redirects=redirect[r.domain]==r and not http_names[r.domain]
  if r.https and not pairs[r.certificate] then
   -- Keep an exact pending name from falling through to a working wildcard.
   if redirects then add('server {');listeners(d.http_port,false,false);add('server_name '..servername(r.domain)..';');acl(http_public);add('return 503; }')end
   add('server {');listeners(port,true,false);add('server_name '..servername(r.domain)..'; ssl_reject_handshake on; return 503; }')
  else
  add('upstream hg_up_'..r.id..' {')
  for _,authority in ipairs(r.upstreams or {r.authority})do add('server '..authority..';')end
  add('keepalive 4; }')
  if redirects then
   add('server {');listeners(d.http_port,false,false);add('server_name '..servername(r.domain)..';');acl(http_public)
   upgrade_to_https(r.public_port or d.public_https_port);add('}')
  end
  add('server {');listeners(port,r.https,false);add('server_name '..servername(r.domain)..';');acl(route_port(r))
  if r.https then
   add('ssl_protocols TLSv1.2 TLSv1.3; ssl_certificate '..pairs[r.certificate]..'/fullchain.pem; ssl_certificate_key '..pairs[r.certificate]..'/privkey.pem;')
   local public=r.public_port or d.public_https_port
   if public>0 and public~=443 then
    add('error_page 497 = @hg_https_same_port; location @hg_https_same_port {');acl(public)
    upgrade_to_https(public);add('}')
   end
  end
  add('location / { proxy_http_version 1.1; proxy_buffering off; proxy_request_buffering off; proxy_connect_timeout 10s; proxy_read_timeout 3600s; proxy_send_timeout 60s;')
  add('proxy_set_header Host '..quote(r.authority)..'; proxy_set_header Forwarded ""; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Host $http_host; proxy_set_header X-Forwarded-Proto $scheme; proxy_set_header X-Real-IP $remote_addr; proxy_set_header Upgrade $hg_upgrade; proxy_set_header Connection $hg_connection;')
  -- Keep IPv6 brackets through nginx's port stripping and SNI suppression.
  -- The required private component uses binary IP SAN matching, never DNS/CN.
  if r.scheme=='https'then
   local ipv6=r.host:find(':',1,true);local literal=ipv6 or r.host:match('^[%d.]+$');local name=ipv6 and '['..r.host..']' or r.host
   add('proxy_ssl_verify on; proxy_ssl_verify_depth 8; proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; proxy_ssl_server_name '..(literal and 'off' or 'on')..'; proxy_ssl_name '..quote(name)..';')
  end
  local uri=complex(r.base)..'$request_uri'
  if r.query then uri=complex(r.base)..'$hg_raw_path?'..complex(r.query)..'$hg_join$args' end
  add('proxy_pass '..quote(r.scheme..'://hg_up_'..r.id..uri)..'; } }')
  end
 end
 add('}');write(root..'/candidate.conf',table.concat(lines,'\n')..'\n')
 if mode=='render-access'then io.write(marker,'\n')end
 return
end
if mode=='version'then
 local major,minor,patch=read(root..'/version',8192):match('^nginx version: nginx/(%d+)%.(%d+)%.(%d+) %(homegate%-ip%-san%-v1%)\n$')
 major,minor,patch=tonumber(major),tonumber(minor),tonumber(patch)
 if major~=1 or not minor or minor<30 or (minor==30 and patch<6)then fail()end;return
end
if mode=='validity'then
 for _,d in ipairs(material('accepted').certificates)do if os.time()<d.not_before_epoch or os.time()>=d.expires_epoch then fail()end end;return
end
if mode=='changed'then
 local d=material('accepted');local seen={};for _,c in ipairs(d.certificates)do
  seen[c.id]=true
  if read('/etc/homegate/certs/'..c.id..'/current',38)~=c.pair..'\n' then os.exit(3)end
 end
 for _,id in ipairs(load().certificates)do if not seen[id] then
  local f=io.open('/etc/homegate/certs/'..id..'/current','rb')
  local current=f and f:read(39) or 'absent\n';if f then f:close()end
  if current~=d.waiting[id] then os.exit(3)end
 end end;return
end
if mode=='report'then
 local state=arg[2];if not ({starting=true,running=true,stopped=true,failed=true,restart_required=true})[state]then fail()end
 local reload=arg[3] or 'idle';if not ({idle=true,reloading=true,verified=true,rejected=true})[reload]then fail()end
 local cleanup=arg[4];if cleanup and cleanup~='true' and cleanup~='false'then fail()end
 local step=arg[5];if step==''then step=nil end
 if step and not ({worker=true,nginx_test=true,audit_start=true,nginx_start=true,nginx_identity=true,nginx_worker=true,nginx_reload=true})[step]then fail()end
 local report={state=state,reload_state=reload,failure_step=step};if cleanup then report.firewall_cleanup_ok=cleanup=='true'end;write(root..'/report.next',codec.json(report)..'\n');if not os.rename(root..'/report.next',root..'/report')then fail()end;return
end
if mode=='status'then
 local d=json.parse(read(root..'/report',1024));if type(d)~='table' or type(d.state)~='string'then fail()end
 local p=load();io.write(codec.json({api_version=1,engineering=true,ok=true,phase='proxy',state=d.state,running=arg[2]=='true',routes=#p.routes,policy=p.policy,health_checked=false,automatic_reload=true,reload_state=d.reload_state or 'idle',failure_step=d.failure_step,generation=material('accepted').generation,cn_available=p.region=='CN',audit_available=arg[2]=='true' and read(root..'/audit-health',6)=='true\n',cn_snapshot=true,firewall_status_separate=true,firewall_cleanup_ok=d.firewall_cleanup_ok,effect='none',write_ready=false})..'\n');return
end
fail()
