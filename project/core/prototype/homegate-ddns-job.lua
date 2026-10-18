local dir=assert(arg[0]:match('^(.*)/[^/]+$'))
local shared=assert(loadfile(dir..'/cloudflare-codec.lua'))('library')
local batch=assert(loadfile(dir..'/ddns-batch.lua'))()
local planner=assert(loadfile(dir..'/ddns-plan.lua'))()
local sync=assert(loadfile(dir..'/ddns-sync.lua'))()
local policy=assert(loadfile(dir..'/ddns-job.lua'))()
if arg[1]=='origin' then
 local function read(fd,n)local f=assert(io.open('/proc/self/fd/'..fd,'rb'));local b=f:read(n+1) or '';assert(f:close() and #b<=n);return b end
 local raw=io.stdin:read(65537) or '';local d=shared.parse(raw)
 local fields={};for v in read(3,512):gmatch('([^\n]*)\n') do fields[#fields+1]=v end
 local formats={cloudflare='HGCFJOURNAL1',aliyun='HGALIJOURNAL1',dnspod='HGDNPJOURNAL1',huaweicloud='HGHWJOURNAL1'}
 if arg[8] or #fields~=10 or fields[1]~=formats[arg[4]] or fields[2]~='homegate' or fields[3]~=arg[5] or fields[4]~=arg[7] or fields[5]~=arg[3] or fields[8]~=arg[6] or not planner.id(fields[6]) or not fields[7]:match('^[1-9]%d*$') or #fields[7]>9 or tonumber(fields[7])<2 then os.exit(1) end
 local receipt=read(4,4096);local original,effect=sync.result(receipt,shared.parse(receipt),arg[4],fields[6],arg[3],arg[2],'0')
 if not original or original~=raw or effect~='confirmed' then os.exit(1) end
 io.write(fields[6]..':'..fields[7]..'\n');return
end
local raw=io.stdin:read(65537) or ''
if #raw>65536 then os.exit(1) end
local d=shared.parse(raw)
if arg[1]=='row' and arg[2] and arg[3] and arg[4] and not arg[5] then
 local row=batch.row(raw,d,arg[3],arg[2],arg[4],planner,sync,shared.parse)
 if not row or not policy.row(shared.parse(row),arg[2]) then os.exit(1) end
 io.write(row..'\n');return
end
if arg[1]=='validate' and arg[2] and not arg[3] and policy.row(d,arg[2]) then io.write(raw);return end
if arg[1]=='effect' and arg[2] and not arg[3] and policy.row(d,arg[2]) then io.write(d.effect..'\n');return end
if arg[1]=='status' and arg[2] and not arg[3] and type(d)=='table' and d.phase=='ddns-state' and d.rule==arg[2] and (d.status=='ready' or d.status=='stale') and d.authorized==true and d.blocked==false and batch.row(raw,d,tostring(d.configuration_revision),arg[2],'0',planner,sync,shared.parse) then io.write(d.provider..'\n');return end
os.exit(1)
