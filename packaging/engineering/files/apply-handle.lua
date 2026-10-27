local raw=io.stdin:read(4097)
if not raw or #raw>4096 or arg[1] then os.exit(1) end
local json=require('luci.jsonc');local value=json.parse(raw)
if type(value)~='table' or value.ok~=true or value.application_pending~=true or
   type(value.apply_handle)~='string' or #value.apply_handle~=32 or
   value.apply_handle:find('[^0-9a-f]') then os.exit(1) end
io.write(value.apply_handle,'\n')
