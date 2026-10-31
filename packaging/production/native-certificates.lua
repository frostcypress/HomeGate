-- Only previously validated native pairs and explicitly adopted legacy bytes.
-- A durable inventory precedes quarantine; partial removal resumes that inventory.
local base=assert(arg[0]:match('^(.*)/[^/]+$'));local fs=require('nixio.fs');local nx=require('nixio');require('nixio.util')
local json=require('luci.jsonc');local codec=assert(loadfile(base..'/project/luci/lua/luasrc/model/homegate/backup.lua'))()
local id=arg[2];assert(arg[1]=='purge' and type(id)=='string' and #id<=64 and id:match('^[a-zA-Z0-9_-]+$') and not arg[3])
local root='/etc/homegate/certs';local source=root..'/'..id;local trash=root..'/.purge-'..id;local journal=root..'/.purge-'..id..'.json'
local function quote(s)return "'"..s:gsub("'","'\\''").."'"end
local function sync(p)assert(os.execute('fsync '..quote(p)..' 2>/dev/null')==0)end
local function dir(p)local a=assert(fs.lstat(p));assert(a.type=='dir' and a.uid==0 and a.modedec==700);return a end
local function read(p,public)
 local a=assert(fs.lstat(p));assert(a.type=='reg' and a.uid==0 and a.nlink==1 and (a.modedec==600 or public and a.modedec==644) and a.size<=65536)
 local f=assert(io.open(p,'rb'));local body=f:read(65537) or '';assert(f:close());local b=assert(fs.lstat(p));assert(a.ino==b.ino and a.dev==b.dev and a.size==b.size and #body<=65536);return body,a
end
local function hash(p)local f=assert(io.popen('sha256sum '..quote(p)..' 2>/dev/null','r'));local raw=f:read(1024);assert(f:close());local h=raw and raw:match('^([0-9a-f]+)  ');assert(h and #h==64);return h end
local function pair(n)return #n==37 and n:match('^pair%-[0-9a-f]+$')end
local leaf={['fullchain.pem']=true,['privkey.pem']=true,['scope.json']=true,['result.json']=true,manifest=true}
local flat={current=true,['legacy-adopted']=true,['fullchain.pem']=true,['privkey.pem']=true}
local function path_ok(p)local d,n=p:match('^([^/]+)/([^/]+)$');return d and pair(d) and leaf[n] or not p:find('/',1,true) and flat[p]end
local function list(p)local rows={};for n in assert(fs.dir(p))do if n~='.' and n~='..'then rows[#rows+1]=n end end;table.sort(rows);return rows end
local function inventory()
 dir(source);local out={format='native-certificate-purge-v1',id=id,files={},directories={}}
 local function file(relative,public)local _,a=read(source..'/'..relative,public);out.files[#out.files+1]={path=relative,ino=a.ino,dev=a.dev,size=a.size,digest=hash(source..'/'..relative)}end
 local names=list(source);local current=read(source..'/current');assert(#current==38 and pair(current:sub(1,-2)) and current:sub(-1)=='\n')
 local legacy=fs.lstat(source..'/fullchain.pem') or fs.lstat(source..'/privkey.pem')
 if legacy then
  local marker=read(source..'/legacy-adopted');local f=assert(io.popen('for p in '..quote(source..'/fullchain.pem')..' '..quote(source..'/privkey.pem')..';do stat -c \'%d:%i:%u:%a:%h:%s\' "$p" && sha256sum "$p" || exit 1;done','r'));local expected=f:read(8193);assert(f:close());assert(marker==expected)
 end
 local count=0
 for _,n in ipairs(names)do
  if pair(n)then
   count=count+1;assert(count<=16);dir(source..'/'..n)
   local files=list(source..'/'..n);assert(#files==5)
   local sums={};for _,key in ipairs({'fullchain.pem','privkey.pem','scope.json','result.json'})do read(source..'/'..n..'/'..key);sums[#sums+1]=hash(source..'/'..n..'/'..key)..'  '..key..'\n'end
   assert(read(source..'/'..n..'/manifest')==table.concat(sums))
   local scope=json.parse(read(source..'/'..n..'/scope.json'));local result=json.parse(read(source..'/'..n..'/result.json'));assert(scope and scope.id==id and result and result.certificate==id)
   out.directories[#out.directories+1]=n
   for _,key in ipairs(files)do assert(leaf[key]);file(n..'/'..key)end
  else assert(flat[n]);file(n,n=='fullchain.pem')end
 end
 assert(count>0);return out
end
dir('/etc/homegate')
if not fs.lstat(root)then io.write('{"ok":true,"removed":false}\n');return end;dir(root)
if not fs.lstat(source) and not fs.lstat(trash) and not fs.lstat(journal)then io.write('{"ok":true,"removed":false}\n');return end
local plan
if fs.lstat(journal)then plan=json.parse(read(journal))else
 assert(not fs.lstat(trash));plan=inventory();local raw=codec.json(plan)..'\n'
 local f=assert(nx.open(journal,nx.open_flags('wronly','creat','excl'),'600'));assert(f:writeall(raw)==#raw);assert(f:close());sync(journal);sync(root)
end
assert(plan and plan.format=='native-certificate-purge-v1' and plan.id==id and type(plan.files)=='table' and #plan.files<=84 and #plan.files>0 and type(plan.directories)=='table' and #plan.directories<=16)
local expected,dirs={},{}
for _,n in ipairs(plan.directories)do assert(pair(n) and not dirs[n]);dirs[n]=true end
for _,r in ipairs(plan.files)do assert(type(r.path)=='string' and path_ok(r.path) and not expected[r.path] and type(r.digest)=='string' and #r.digest==64 and r.digest:match('^[0-9a-f]+$'));expected[r.path]=r end
local function check(p,relative)local _,a=read(p,relative=='fullchain.pem');local r=assert(expected[relative]);assert(a.ino==r.ino and a.dev==r.dev and a.size==r.size and hash(p)==r.digest)end
if fs.lstat(source)then
 assert(not fs.lstat(trash));dir(source)
 local actual=inventory();assert(codec.json(actual)==codec.json(plan));assert(fs.rename(source,trash));sync(root)
end
if fs.lstat(trash)then
 dir(trash)
 for _,n in ipairs(list(trash))do
  if dirs[n]then dir(trash..'/'..n);for _,key in ipairs(list(trash..'/'..n))do check(trash..'/'..n..'/'..key,n..'/'..key)end
  else check(trash..'/'..n,n)end
 end
 for _,r in ipairs(plan.files)do local p=trash..'/'..r.path;if fs.lstat(p)then check(p,r.path);assert(fs.unlink(p))end end
 for _,n in ipairs(plan.directories)do if fs.lstat(trash..'/'..n)then assert(fs.rmdir(trash..'/'..n))end end
 assert(fs.rmdir(trash));sync(root)
end
assert(not fs.lstat(source) and not fs.lstat(trash));assert(fs.unlink(journal));sync(root)
io.write('{"api_version":1,"ok":true,"removed":true,"phase":"certificate-cleanup"}\n')
