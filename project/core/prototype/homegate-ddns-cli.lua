-- Enumerate public rule identifiers from a verified private frame, never secrets.
local dir=arg[0]:match('^(.*)/[^/]+$');if not dir then os.exit(1) end
local codec=assert(loadfile(dir..'/../../luci/lua/luasrc/model/homegate/backup.lua'))()
local id=assert(loadfile(dir..'/ddns-plan.lua'))().id
if arg[1]~='names' or arg[4] or not arg[2] or not arg[2]:match('^[1-9]%d*$') or tonumber(arg[2])>32 or not arg[3] then os.exit(1) end
if arg[3]~='' and not id(arg[3]) then os.exit(1) end
local snapshot=assert(loadfile(dir..'/private-snapshot.lua'))().read(io.stdin,codec)
if not snapshot or snapshot.revision~=tonumber(arg[2]) then os.exit(1) end
local names,seen={},{}
for _,s in ipairs(snapshot.configuration) do
    if s.kind=='ddns_rule' then
        if not id(s.name) or seen[s.name] then os.exit(1) end
        seen[s.name]=true;names[#names+1]=s.name
    end
end
if #names>32 or (arg[3]~='' and not seen[arg[3]]) then os.exit(1) end
table.sort(names)
if arg[3]~='' then names={arg[3]} end
if #names>0 then io.write(table.concat(names,'\n')..'\n') end
