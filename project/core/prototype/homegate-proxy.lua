-- Private proxy planner. No target URL, key bytes or filesystem path is public.
local dir=assert(arg[0]:match('^(.*)/[^/]+$'))
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local json=require('luci.jsonc')
local function fail()os.exit(1)end
local function read(p,n)local f=io.open(p,'rb');if not f then fail()end;local s=f:read(n+1);f:close();if not s or #s>n then fail()end;return s end
local function write(p,s)local f=io.open(p,'wb');if not f or not f:write(s) or not f:close()then fail()end end
local function id(s)return type(s)=='string' and #s>0 and #s<=64 and s:match('^[a-zA-Z0-9_-]+$')end
local root='/var/run/homegate/proxy'
local function load()local d=json.parse(read(root..'/plan.json',131072));if type(d)~='table' or type(d.routes)~='table' or #d.routes<1 or #d.routes>16 then fail()end;return d end
local function quote(s)return '"'..s:gsub('\\','\\\\'):gsub('"','\\"')..'"'end
local mode=arg[1]
if mode=='plan' then
 local selection,policy=arg[2],arg[3];if arg[4] or (policy~='open' and policy~='allow') or type(selection)~='string' or #selection>1039 then fail()end
 local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec);if not snapshot then fail()end
 local indexed={};for _,s in ipairs(snapshot.configuration)do indexed[s.name]=s end
 local main=indexed.main.values
 if policy=='allow' and main.access_region=='CN'then local f=io.open('/etc/homegate/access/CN.cidr','rb');if not f then fail()end;local ok=pcall(assert(loadfile(dir..'/access-region.lua'))().cache,f,nil,os.time());f:close();if not ok then fail()end end
 local hp,sp=tonumber(main.proxy_http_port),tonumber(main.proxy_https_port)
 if not hp or hp<1024 or not sp or sp<1024 or hp==sp then fail()end
 local out={routes={},certificates={},policy=policy,http_port=hp,https_port=sp,public_https_port=tonumber(main.https_port),public_http_port=tonumber(main.http_port),auto_firewall=main.auto_firewall=='1',allow=main.access_allow,deny=main.access_deny,region=policy=='allow' and main.access_region or ''}
 local seen,certs={},{}
 local function covers(pattern,name)return pattern==name or (pattern:sub(1,2)=='*.' and name:match('^[^.]+%.(.+)$')==pattern:sub(3))end
 for name in (selection..','):gmatch('(.-),')do
  if not id(name) or seen[name] or #out.routes>=16 then fail()end;seen[name]=true
  local s=indexed[name];if not s or s.kind~='web_rule' then fail()end
  local v=s.values;local target=snapshot.credentials['web.'..name..'.target']
  if not assert(loadfile(dir..'/configuration-validation.lua'))().target(target,assert(loadfile(dir..'/cloudflare-record-plan.lua'))())then fail()end
  local scheme,authority,tail=target:match('^(https?)://([^/?]+)(.*)$');if not scheme then fail()end
  local host=authority:match('^%[([^%]]+)%]') or authority:match('^([^:]+)')
  local base,query=tail:match('^(.-)%?(.*)$');if not base then base=tail end
  if base:sub(-1)=='/'then base=base:sub(1,-2)end
  local cert=''
  if v.https=='1'then
   cert=v.certificate
   if cert==''then
    local candidates={};for n,c in pairs(indexed)do if c.kind=='certificate'then for _,d in ipairs(c.values.domains)do if covers(d,v.domain)then candidates[#candidates+1]={name=n,exact=d==v.domain};break end end end end
    table.sort(candidates,function(a,b)if a.exact~=b.exact then return a.exact end;return a.name<b.name end);if #candidates==0 then fail()end;cert=candidates[1].name
   end
   if not indexed[cert] or indexed[cert].kind~='certificate'then fail()end
   local covered=false;for _,d in ipairs(indexed[cert].values.domains)do if covers(d,v.domain)then covered=true end end;if not covered then fail()end
   if not certs[cert]then certs[cert]=true;out.certificates[#out.certificates+1]=cert end
  end
  out.routes[#out.routes+1]={id=name,domain=v.domain,https=v.https=='1',certificate=cert,scheme=scheme,authority=authority,host=host,base=base,query=query}
 end
 table.sort(out.certificates);io.write(codec.json(out)..'\n');return
end
if mode=='selection-certificates'then local d=json.parse(io.stdin:read(131073));if type(d)~='table' or type(d.certificates)~='table'then fail()end;for _,c in ipairs(d.certificates)do if not id(c)then fail()end;io.write(c,'\n')end;return end
if mode=='certificates'then for _,c in ipairs(load().certificates)do if not id(c)then fail()end;io.write(c,'\n')end;return end
if mode=='certificate-ok'then local d=json.parse(io.stdin:read(16385));if type(d)~='table' or d.ok~=true or d.certificate~=arg[2] or d.valid~=true or d.pending~=false or d.identity_valid~=true then fail()end;return end
local function material(which)
 if which~='accepted' and which~='candidate'then fail()end
 local d=json.parse(read(root..'/'..which..'.json',32768));local p=load()
 if type(d)~='table' or type(d.generation)~='number' or d.generation<1 or d.generation>2147483647 or d.generation%1~=0 or type(d.certificates)~='table' or #d.certificates~=#p.certificates then fail()end
 for i,c in ipairs(d.certificates)do
  if type(c)~='table' or c.id~=p.certificates[i] or not id(c.id) or not c.pair:match('^pair%-[0-9a-f]+$') or #c.pair~=37 or not c.fingerprint:match('^[0-9a-f]+$') or #c.fingerprint~=64 or type(c.expires_epoch)~='number' or type(c.not_before_epoch)~='number'then fail()end
 end;return d
end
if mode=='capture'then
 local generation=tonumber(arg[2]);if not generation or generation<1 or generation>2147483647 or generation%1~=0 then fail()end
 local out={generation=generation,certificates={}}
 for _,c in ipairs(load().certificates)do
  local base=root..'/next/'..c..'/'
  local pair=read(base..'pointer',38):match('^(pair%-[0-9a-f]+)\n$');if not pair or #pair~=37 then fail()end
  local d=json.parse(read(base..'result.json',65536));local fingerprint=read(base..'fingerprint',65):match('^([0-9a-f]+)\n$')
  if type(d)~='table' or d.certificate~=c or d.identity_valid~=true or d.key_matches~=true or type(d.expires_epoch)~='number' or type(d.not_before_epoch)~='number' or os.time()<d.not_before_epoch or os.time()>=d.expires_epoch or not fingerprint or #fingerprint~=64 then fail()end
  out.certificates[#out.certificates+1]={id=c,pair=pair,fingerprint=fingerprint,expires_epoch=d.expires_epoch,not_before_epoch=d.not_before_epoch}
 end
 write(root..'/candidate.json',codec.json(out)..'\n');return
end
if mode=='probes'then
 local d=material(arg[2]);local certs={};for _,c in ipairs(d.certificates)do certs[c.id]=c end
 local p=load();local exact={};for _,r in ipairs(p.routes)do if r.domain:sub(1,2)~='*.'then exact[r.domain]=true end end
 for _,r in ipairs(p.routes)do if r.https then
  local host=r.domain
  if host:sub(1,2)=='*.'then
   host=nil;for i=1,17 do local candidate=string.char(96+i)..'.'..r.domain:sub(3);if not exact[candidate]then host=candidate;break end end
   if not host then fail()end
  end
  io.write(host,':',certs[r.certificate].fingerprint,'\n')
 end end;return
end
if mode=='port'then io.write(load().https_port,'\n');return end
if mode=='generation'then io.write(material('accepted').generation,'\n');return end
if mode=='material-check'then material('accepted');return end
if mode=='render'then
 local m=material('candidate');local pairs={};for _,c in ipairs(m.certificates)do pairs[c.id]='/etc/homegate/certs/'..c.id..'/'..c.pair end
 local d=load();local token=read(root..'/token',33):match('^([0-9a-f]+)\n$');if not token or #token~=32 then fail()end
 local lines={};local function add(s)lines[#lines+1]=s end
 add('worker_processes 1;\nerror_log /dev/null crit;\npid '..root..'/nginx.pid;\nevents { worker_connections 128; }\nhttp {')
 add('access_log off; server_tokens off; client_max_body_size 0; client_body_buffer_size 128k; client_header_timeout 15s; client_body_timeout 60s; send_timeout 60s; keepalive_timeout 30s;')
 local temp='/var/run/homegate-proxy-body/'..token
 for _,n in ipairs({'client_body','proxy','fastcgi','uwsgi','scgi'})do add(n..'_temp_path '..temp..'/'..n..';')end
 add('map $http_upgrade $hg_upgrade { default ""; ~*^websocket$ websocket; }\nmap $hg_upgrade $hg_connection { default ""; websocket upgrade; }')
 add('geo $hg_dollar { default "$"; }')
 add('map $request_uri $hg_raw_path { ~^(?<hg_path>[^?]*) $hg_path; }\nmap $args $hg_join { "" ""; default "&"; }')
 for _,kind in ipairs({'allow','deny'})do
  add('geo $hg_'..kind..' { default 0;');for cidr in d[kind]:gmatch('[^,; ]+')do add(cidr..' 1;')end;add('}')
 end
 add('geo $hg_cn { default 0; include '..root..'/cn.conf; }')
 if d.policy=='open'then
  add('map $hg_deny $hg_reason { default disabled; 1 manual-deny; }')
 else
  add('map "$hg_deny:$hg_allow:$hg_cn" $hg_reason { ~^1: manual-deny; ~^0:1: ip; ~^0:0:1 region; default denied; }')
 end
 add('map $hg_reason $hg_allowed { manual-deny false; denied false; default true; }')
 local audit=read(root..'/audit-token',33):match('^([0-9a-f]+)\n$');if not audit or #audit~=32 then fail()end
 add([[log_format hg_access escape=json '{"ip":"$remote_addr","host":"$host","allowed":$hg_allowed,"reason":"$hg_reason"}';]])
 local function logging()add('access_log syslog:server=unix:/var/run/homegate-audit/socket,nohostname,tag='..audit..' hg_access;')end
 local function listeners(port,tls,default)
  add('listen 0.0.0.0:'..port..(tls and ' ssl' or '')..(default and ' default_server' or '')..';')
  add('listen [::]:'..port..(tls and ' ssl' or '')..(default and ' default_server ipv6only=on' or '')..';')
 end
 add('server {');listeners(d.http_port,false,true);add('server_name ""; return 404; }')
 if #d.certificates>0 then add('server {');listeners(d.https_port,true,true);add('server_name ""; ssl_reject_handshake on; return 404; }')end
 local function servername(domain)
  if domain:sub(1,2)=='*.'then return quote('~^[^.]+\\.'..domain:sub(3):gsub('%.','\\.')..'$')end
  return domain
 end
 local function acl()logging();add('if ($hg_reason = manual-deny) { return 403; }');add('if ($hg_reason = denied) { return 403; }')end
 local function complex(s)return s:gsub('%$', '${hg_dollar}')end
 for _,r in ipairs(d.routes)do
  add('upstream hg_up_'..r.id..' { server '..r.authority..'; keepalive 4; }')
  if r.https then
   add('server {');listeners(d.http_port,false,false);add('server_name '..servername(r.domain)..';');acl()
   local port=d.public_https_port==443 and '' or ':'..d.public_https_port
   add('return 308 https://$host'..port..'$request_uri; }')
  end
  add('server {');listeners(r.https and d.https_port or d.http_port,r.https,false);add('server_name '..servername(r.domain)..';');acl()
  if r.https then add('ssl_protocols TLSv1.2 TLSv1.3; ssl_certificate '..pairs[r.certificate]..'/fullchain.pem; ssl_certificate_key '..pairs[r.certificate]..'/privkey.pem;')end
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
 add('}');write(root..'/candidate.conf',table.concat(lines,'\n')..'\n');return
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
 local d=material('accepted');for _,c in ipairs(d.certificates)do
  if read('/etc/homegate/certs/'..c.id..'/current',38)~=c.pair..'\n' then os.exit(3)end
 end;return
end
if mode=='report'then
 local state=arg[2];if not ({starting=true,running=true,stopped=true,failed=true,restart_required=true})[state]then fail()end
 local reload=arg[3] or 'idle';if not ({idle=true,reloading=true,verified=true,rejected=true})[reload]then fail()end
 local cleanup=arg[4];if cleanup and cleanup~='true' and cleanup~='false'then fail()end
 local report={state=state,reload_state=reload};if cleanup then report.firewall_cleanup_ok=cleanup=='true'end;write(root..'/report.next',codec.json(report)..'\n');if not os.rename(root..'/report.next',root..'/report')then fail()end;return
end
if mode=='status'then
 local d=json.parse(read(root..'/report',1024));if type(d)~='table' or type(d.state)~='string'then fail()end
 local p=load();io.write(codec.json({api_version=1,engineering=true,ok=true,phase='proxy',state=d.state,running=arg[2]=='true',routes=#p.routes,policy=p.policy,health_checked=false,automatic_reload=true,reload_state=d.reload_state or 'idle',generation=material('accepted').generation,cn_available=p.region=='CN',audit_available=arg[2]=='true' and read(root..'/audit-health',6)=='true\n',cn_snapshot=true,firewall_status_separate=true,firewall_cleanup_ok=d.firewall_cleanup_ok,effect='none',write_ready=false})..'\n');return
end
fail()
