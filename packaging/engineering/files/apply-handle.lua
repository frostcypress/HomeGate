local raw=io.stdin:read(4097)
local role=arg[1] or 'apply'
if not raw or #raw>4096 or arg[2] or (role~='apply' and role~='restore') then os.exit(1) end
local json=require('luci.jsonc');local value=json.parse(raw)
if type(value)~='table' or value.ok~=true then os.exit(1) end
if role=='restore' and value.application_pending==false and value.worker_acknowledged==true then io.write('settled\n');return end
local pending=role=='apply' and value.application_pending or value.restoration_pending
local handle=role=='apply' and value.apply_handle or value.restore_handle
if pending~=true or type(handle)~='string' or #handle~=32 or handle:find('[^0-9a-f]') then os.exit(1) end
io.write(handle,'\n')
