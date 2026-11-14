-- Invalidate only derived LuCI menu indexes and HomeGate's cached Lua modules.
-- Never load cached code or touch configuration, jobs or other modules.
local fs=require'nixio.fs';local nx=require'nixio'
local function run()
 assert(nx.getuid()==0 and #arg==1 and (arg[1]=='check' or arg[1]=='invalidate'))
 local planned={};local seen={}
 local function add(path)
  if seen[path]then return end;seen[path]=true
  local s=fs.lstat(path);if not s then return end
  assert(s.type=='reg' and s.uid==0 and s.nlink==1,'unsafe cache entry')
  planned[#planned+1]={path=path,dev=s.dev,ino=s.ino}
 end
 local modules='/tmp/luci-modulecache';local m=fs.lstat(modules)
 if m then
  assert(m.type=='dir' and m.uid==0 and (m.modedec==700 or m.modedec==755),'unsafe module cache')
  for _,name in ipairs({
   'luci.controller.homegate','luci.controller.homegate_ddns',
   'luci.model.homegate.backup','luci.model.homegate.configuration','luci.model.homegate.ddns',
   'luci.model.homegate.legacy','luci.model.homegate.writer',
  })do
   local encoded=name:gsub('.',function(c)return string.format('%02X',string.byte(c))end)
   add(modules..'/'..encoded);add(modules..'/'..encoded:lower());add(modules..'/'..name)
  end
 end
 -- Remove these after the module entries so newly built indexes use fresh code.
 local count=0
 for name in fs.dir('/tmp')do
  count=count+1;assert(count<=4096,'temporary directory bound')
  if name=='luci-indexcache' or name:match('^luci%-indexcache%.[%w_.%-]+$')then add('/tmp/'..name)end
 end
 if arg[1]=='check'then return end
 for _,item in ipairs(planned)do
  local s=assert(fs.lstat(item.path))
  assert(s.type=='reg' and s.uid==0 and s.nlink==1 and s.dev==item.dev and s.ino==item.ino,'cache identity changed')
  assert(fs.unlink(item.path),'cache unlink failed')
 end
end
local ok=pcall(run)
if not ok then io.stderr:write('HomeGate LuCI cache refresh refused.\n');os.exit(7)end
