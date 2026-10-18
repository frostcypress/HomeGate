-- Public DDNS permission/status contract. No I/O, grant creation or DNS writes.
local M={}
local function keys(d,allowed,n)
 if type(d)~='table' then return false end
 local count=0;for k in pairs(d) do if not allowed[k] then return false end;count=count+1 end;return count==n
end
local function hex(s)return type(s)=='string' and #s==32 and s:match('^[0-9a-f]+$') end
function M.request(d,select,id)
 if type(d)~='table' then return nil end
 if d.action=='maintain_preview' and keys(d,{action=true,job=true},2) and hex(d.job) then return 'maintain_preview',d.job end
 if d.action=='maintain_commit' and keys(d,{action=true,job=true,confirmation=true,consent=true},4) and hex(d.job) and hex(d.confirmation) and d.consent=='1' then return 'maintain_commit',d.job..':'..d.confirmation end
 if d.action=='submit' and keys(d,{action=true,job=true,rule=true,consent=true},4) and hex(d.job) and id(d.rule) and d.consent=='1' then return 'submit',d.job..':'..d.rule end
 if d.action=='jobs' and keys(d,{action=true},1) then return 'jobs','' end
 if d.action=='status' and keys(d,{action=true},1) then return 'status','' end
 if d.action=='revoke' and keys(d,{action=true,consent=true},2) and d.consent=='1' then return 'revoke','' end
 if d.action=='commit' and keys(d,{action=true,confirmation=true,consent=true},3) and d.consent=='1' and hex(d.confirmation) then return 'commit',d.confirmation end
 if d.action=='preview' and keys(d,{action=true,selection=true},2) then
  local names=select(d.selection,id);if names then return 'preview',table.concat(names,',') end
 end
 return nil
end
function M.response(action,payload,d,raw,select,id,json,schedule,jobs)
 if type(d)~='table' or d.api_version~=1 or d.prototype~=true or d.ok~=true then return false end
 if action=='jobs' or action=='submit' or action=='maintain_preview' or action=='maintain_commit' then return jobs and jobs.response(action,payload,d) end
 if action=='status' then
  if not keys(d,{api_version=true,prototype=true,ok=true,phase=true,configuration_revision=true,effect=true,write_ready=true,rules=true},8) or d.phase~='ddns-status' or d.effect~='none' or d.write_ready~=false or type(d.rules)~='table' or #d.rules>32 then return false end
  for k in pairs(d.rules) do if type(k)~='number' or k<1 or k>#d.rules or k~=math.floor(k) then return false end end
  local names={};for i,row in ipairs(d.rules) do if type(row)~='table' or not id(row.rule) or (i>1 and names[i-1]>=row.rule) then return false end;names[i]=row.rule end
  local copy={};for k,v in pairs(d) do copy[k]=v end;copy.phase='ddns-batch';copy.sampled=false
  local frame
  if raw then frame=raw:gsub('"phase":"ddns%-status"','"phase":"ddns-batch"'):gsub('"write_ready":false','"sampled":false,"write_ready":false')
  else
   local rows={}
   for i,row in ipairs(d.rules) do
    if not id(row.provider) or not id(row.status) or type(row.error_kind)~='string' or not row.error_kind:match('^[a-z_]*$') or type(row.retryable)~='boolean' or type(row.retry_in)~='number' then return false end
    rows[i]=string.format('{"rule":"%s","provider":"%s","status":"%s","effect":"none","error_kind":"%s","retryable":%s,"retry_in":%s}',row.rule,row.provider,row.status,row.error_kind,tostring(row.retryable),tostring(row.retry_in))
   end
   frame=string.format('{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-batch","configuration_revision":%s,"effect":"none","sampled":false,"write_ready":false,"rules":[%s]}\n',tostring(d.configuration_revision),table.concat(rows,','))
  end
  return schedule.batch(frame,copy,tostring(d.configuration_revision),'0',names,json)=='none'
 end
 if d.phase~='ddns-authority' or d.service_started~=false then return false end
 if action=='revoke' then return keys(d,{api_version=true,prototype=true,ok=true,phase=true,authorized=true,revoked=true,service_started=true},7) and d.authorized==false and d.revoked==true end
 local fields={api_version=true,prototype=true,ok=true,phase=true,configuration_revision=true,provider=true,authorized=true,service_started=true}
 local count=9
 if d.rules~=nil then fields.rules=true elseif d.rule~=nil then fields.rule=true else return false end
 if action=='preview' then fields.confirmation=true;fields.expires_in=true;count=count+2
 elseif action~='commit' then return false end
 if not keys(d,fields,count) or type(d.configuration_revision)~='number' or d.configuration_revision<1 or d.configuration_revision>32 or d.configuration_revision~=math.floor(d.configuration_revision) or not ({cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true,multiple=true})[d.provider] then return false end
 local joined=d.rule
 if d.rules~=nil then
  if type(d.rules)~='table' or #d.rules<2 or #d.rules>32 then return false end
  for k,v in pairs(d.rules) do if type(k)~='number' or k<1 or k>#d.rules or k~=math.floor(k) or not id(v) then return false end end
  joined=table.concat(d.rules,',');local names=select(joined,id);if not names or json(names)~=json(d.rules) then return false end
 elseif not id(joined) then return false end
 if action=='preview' then return d.authorized==false and hex(d.confirmation) and d.expires_in==300 and joined==payload end
 return d.authorized==true
end
return M
