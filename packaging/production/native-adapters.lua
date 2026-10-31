-- Compatibility data adapters. Private inputs never enter shell arguments.
local base=assert(arg[0]:match('^(.*)/[^/]+$'));local dir=base..'/project/core/prototype'
local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local json=require('luci.jsonc');local fs=require('nixio.fs')
local function fail()os.exit(7)end
local function emit(d)
 local f=assert(io.open(base..'/VERSION','rb'));local v=f:read(65);f:close()
 f=assert(io.open(base..'/RELEASE','rb'));local r=f:read(65);f:close()
 if not v or not v:match('^%d+%.%d+%.%d+\n$') or not r or not r:match('^[1-9]%d*\n$')then fail()end
 d.version=v:sub(1,-2)..'-r'..r:sub(1,-2);d.native=true;io.write(codec.json(d),'\n')
end
local function read(p,n,optional)
 local a=fs.lstat(p);if not a and optional then return nil end
 if not a or a.type~='reg' or a.uid~=0 or a.nlink~=1 or a.modedec~=600 or a.size>n then fail()end
 local f=assert(io.open(p,'rb'));local raw=f:read(n+1) or '';assert(f:close());local b=fs.lstat(p)
 if #raw>n or not b or a.dev~=b.dev or a.ino~=b.ino or a.size~=b.size or a.modedec~=b.modedec then fail()end;return raw
end
local function input(n)local raw=io.stdin:read(n+1) or '';if #raw>n then fail()end;return raw end
local mode=arg[1]
if mode=='access-select'then
 local region=arg[2];if type(region)~='string' or arg[3]then fail()end
 region=region:match('^%s*(.-)%s*$'):upper()
 if region=='CN'then io.write('CN\n');return end
 emit({api_version=1,ok=false,phase='access',region=#region<=32 and region or '',error='Unsupported access region',effect='none',write_ready=false});os.exit(1)
elseif mode=='access-error'then
 emit({api_version=1,ok=false,phase='access',region='CN',error='CN cache operation unavailable; inspect retained task',native_state='unavailable',effect='unknown',write_ready=false});os.exit(1)
elseif mode=='access-token'then
 local token=read('/var/run/homegate/access-update/token',33)
 if not token:match('^[0-9a-f]+\n$') or #token~=33 then fail()end;io.write(token);return
elseif mode=='access-row'then
 local operation,token=arg[2],arg[3]
 if not ({update=true,refresh=true})[operation] or type(token)~='string' or #token~=32 or not token:match('^[0-9a-f]+$') or arg[4]then fail()end
 if read('/var/run/homegate/access-update/token',33)~=token..'\n' then fail()end
 local d=json.parse(input(16384));if type(d)~='table' or type(d.running)~='boolean' or type(d.state)~='string' or type(d.cache_valid)~='boolean'then fail()end
 if d.running or d.state=='starting' or d.state=='downloading'then os.exit(3)end
 local success=d.cache_valid and (d.state=='published' or d.state=='cached')
 local fallback=d.cache_valid and (d.state=='failed' or d.state=='stopped')
 local report={api_version=1,ok=success or fallback,phase='access',region='CN',label='China / Mainland',
  ipv4=d.cache_valid and d.ipv4 or nil,ipv6=d.cache_valid and d.ipv6 or nil,native_state=d.state,
  cache_retained=fallback or nil,effect=success and d.state=='published' and 'confirmed' or 'none',write_ready=false}
 if d.state=='cached'then report.source='cache'
 elseif fallback then report.source='stale-cache';report.warning='Region download failed; last validated dual-stack cache retained'
 elseif success then report.native_source_unknown=true
 else report.error='Region download failed; validated cache unavailable'end
 if read('/var/run/homegate/access-update/token',33)~=token..'\n' then fail()end
 emit(report);if not success and not(fallback and operation=='update')then os.exit(1)end;return
elseif mode=='private-provider' or mode=='private-frame'then
 local raw=read(arg[2],2097152);local d=json.parse(raw);local f
 if type(d)=='table'then
  for k in pairs(d)do if k~='route' and k~='form' and k~='write'then fail()end end
  if d.route~=nil and type(d.route)~='string' or d.write~=nil and type(d.write)~='boolean'then fail()end
  f=d.form
 else
  if #raw>16384 or raw:find('%z')then fail()end
  local a={};for line in (raw:gsub('\n$','')..'\n'):gmatch('(.-)\n')do a[#a+1]=line end
  if #a~=5 then fail()end;f={provider=a[1],key_id=a[2],secret=a[3],account_id=a[4],endpoint=a[5]}
 end
 if type(f)~='table'then fail()end
 local allowed={provider=true,key_id=true,secret=true,account_id=true,endpoint=true}
 for k,v in pairs(f)do if not allowed[k] or type(v)~='string' or #v>4096 or v:find('[%z\r\n]')then fail()end end
 local aliases={cf='cloudflare',alidns='aliyun',tencent='dnspod',tencentcloud='dnspod',huawei='huaweicloud',hwcloud='huaweicloud'}
 local provider=aliases[f.provider] or f.provider
 if not ({cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true})[provider]then fail()end
 if mode=='private-provider'then io.write(provider,'\n');return end
 if provider~=arg[3]then fail()end
 local public=codec.canonical("# homegate-backup-format: 2\n# plugin: homegate\n# schema: public-uci-v1\n# secrets: omitted\nconfig homegate 'main'\nconfig dns_account 'offline_probe'\n option provider '"..provider.."'\n")
 if not public then fail()end
 local slots={};for _,key in ipairs({'account_id','endpoint','key_id','secret'})do
  if f[key] and f[key]~=''then slots[#slots+1]={provider..'.offline_probe.'..key,f[key]}end
 end
 local frame={'HGPRIVATE1\n1\n'..#public..'\n'..#slots..'\n',public}
 for _,row in ipairs(slots)do frame[#frame+1]=#row[1]..'\n'..#row[2]..'\n'..row[1]..row[2]end
 frame[#frame+1]='END\n';io.write(table.concat(frame));return
elseif mode=='private-result'then
 local d=json.parse(input(131072));if type(d)~='table' or type(d.ok)~='boolean'then fail()end
 emit({api_version=1,ok=d.ok,scope='live-read-only',operation='DNS authentication and zone discovery',provider=d.provider,zone_count=d.ok and #(d.zones or {}) or nil,error_kind=d.error_kind,retryable=d.retryable,effect='none',write_ready=false})
 if not d.ok then os.exit(1)end;return
elseif mode=='ca-response'then
 local raw=input(65570);local body,code=raw:match('^(.*)\nHGCA:(%d+)\n$');local d=body and #body<=65536 and json.parse(body)
 local env=arg[2];local host=env=='staging' and 'acme-staging-v02.api.letsencrypt.org' or 'acme-v02.api.letsencrypt.org'
 local ok=code=='0' and type(d)=='table'
 for _,k in ipairs({'newNonce','newAccount','newOrder'})do
  local u=ok and d[k];if type(u)~='string' or #u>2048 or u:sub(1,#host+9)~='https://'..host..'/' or u:find('[%s%z]')then ok=false end
 end
 emit({api_version=1,ok=ok,phase='acme-ca',ca='letsencrypt',environment=env,directory='https://'..host..'/directory',direct=true,reachable=ok,error=not ok and 'CA directory unavailable' or nil,effect='none',write_ready=false})
 if not ok then os.exit(1)end;return
elseif mode=='renew-row'then
 local d=json.parse(input(16384));if type(d)~='table' or type(d.pending)~='boolean'then fail()end
 if d.pending then os.exit(3)end
 local ok=d.ok==true and d.cleanup_required==false and (d.state=='issued' or d.state=='skipped')
 emit({api_version=1,ok=ok,phase='acme',certificate=d.certificate,job=d.job,state=d.state,pending=false,error=not ok and 'Certificate operation retained; inspect job' or nil,effect=ok and 'confirmed' or 'unknown',write_ready=false})
 if not ok then os.exit(1)end;return
elseif mode=='renew-aggregate'then
 local rows={};local ok=true;for line in input(524288):gmatch('[^\n]+')do local d=json.parse(line)
  if type(d)~='table' or d.phase~='acme' or #rows>=32 then fail()end;rows[#rows+1]=d;ok=ok and d.ok==true
 end;emit({api_version=1,ok=ok,phase='acme',results=rows});if not ok then os.exit(1)end;return
elseif mode=='access-file' or mode=='access-stdin'then
 local raw=mode=='access-stdin' and input(262144) or read(arg[2],262144);local ip=assert(loadfile(dir..'/cloudflare-record-plan.lua'))();local seen,rows={},{}
 for token in raw:gmatch('[^,;%s]+')do
  if #rows>=4096 then fail()end
  local address,bits=token:match('^(.-)/(%d+)$');if not address then address=token end
  local groups={};local width;local v6=address:find(':',1,true)
  if v6 then local expanded=ip.ipv6(address);if not expanded then fail()end;for g in expanded:gmatch('[^:]+')do groups[#groups+1]=tonumber(g,16)end;width=16
  else for g in address:gmatch('[^.]+')do if not g:match('^%d+$') or #g>3 or tonumber(g)>255 or #g>1 and g:sub(1,1)=='0'then fail()end;groups[#groups+1]=tonumber(g)end
   if #groups~=4 or table.concat(groups,'.')~=address then fail()end;width=8
  end
  local max=v6 and 128 or 32;bits=bits and tonumber(bits) or max;if bits<0 or bits>max then fail()end
  for i,g in ipairs(groups)do local keep=math.min(width,math.max(0,bits-(i-1)*width));local unit=2^(width-keep);groups[i]=math.floor(g/unit)*unit end
  local normalized
  if not v6 then normalized=table.concat(groups,'.')
  else
   local best,start,length=0,0,0;for i=1,9 do
    if i<=8 and groups[i]==0 then if length==0 then start=i end;length=length+1
    else if length>best then best=length;address=start end;length=0 end
   end
   local words={};for _,g in ipairs(groups)do words[#words+1]=string.format('%x',g)end
   if best>=2 then normalized=table.concat(words,':',1,address-1)..'::'..table.concat(words,':',address+best,8)else normalized=table.concat(words,':')end
  end
  normalized=normalized..'/'..bits;if not seen[normalized]then seen[normalized]=true;rows[#rows+1]=normalized end
 end
 table.sort(rows);local out={};for _,row in ipairs(rows)do out[#out+1]=row:gsub('/32$',''):gsub('/128$','')end
 emit({api_version=1,ok=true,phase='access',normalized=table.concat(out,', '),count=#rows});return
elseif mode=='access-result'then
 local d=json.parse(input(65536));if type(d)~='table' or d.ok~=true or type(d.entries)~='table'then fail()end
 d.phase='access';emit(d);return
elseif mode=='log-events'then
 local max=tonumber(arg[2] or '1024');if not max or max%1~=0 or max<1 or max>20000 or arg[3]then os.exit(2)end
 local raw=read('/var/log/homegate.log',8388608,true) or '';local rows={}
 local keys={accesskeyid=true,access_key_id=true,accesskeysecret=true,access_key_secret=true,signature=true,signaturenonce=true,token=true,api_token=true,['api-token']=true,secret=true,password=true}
 local pem=false
 for line in raw:gmatch('[^\n]+')do
  if line:find('-----BEGIN',1,true)then pem=true end
  local safe=pem and '[redacted PEM]' or line:gsub('([%w_-]+)=([^&%s"]+)',function(k,v)return k..'='..(keys[k:lower()] and '<redacted>' or v)end)
  local lower=safe:lower();local auth=lower:find('authorization:',1,true);if auth then safe=safe:sub(1,auth-1)..'Authorization: <redacted>'end
  if line:find('-----END',1,true)then pem=false end
  local stamp,level,message=safe:match('^(%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%d) %[(%u+)%] (.*)$');level=level or 'INFO';message=message or safe
  local event={timestamp=stamp,level=level,category='system',kind='generic_'..level:lower(),summary=level=='ERROR' and 'Operation failed' or level=='WARN' and 'Attention required' or 'Runtime event',important=level=='ERROR' or level=='WARN',raw=safe}
  local m=message:lower();if m:find('ddns',1,true)then event.category='ddns' elseif m:find('certificate',1,true) or m:find('acme',1,true)then event.category='certificate' elseif m:find('access ',1,true)then event.category='access' elseif m:find('proxy',1,true) or m:find('firewall',1,true)then event.category='public' elseif m:find('wol ',1,true) or m:find('network ',1,true)then event.category='network'end
  rows[#rows+1]=event;if #rows>max then table.remove(rows,1)end
 end
 emit({api_version=1,ok=true,phase='log-events',count=#rows,events=rows});return
end
fail()
