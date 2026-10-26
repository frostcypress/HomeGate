-- Public RAM job summaries. No paths, owner identities or provider payloads.
local M={}
local function keys(d,names,n)
 if type(d)~='table' then return false end
 local c=0;for k in pairs(d) do if not names[k] then return false end;c=c+1 end;return c==n
end
local function hex(s)return type(s)=='string' and #s==32 and s:match('^[0-9a-f]+$') end
local function id(s)return type(s)=='string' and #s<=64 and s:match('^[a-zA-Z0-9_-]+$') end
local function integer(n,max)return type(n)=='number' and n>=0 and n<=max and n==math.floor(n) end
function M.row(d,rule)
 if not keys(d,{rule=true,provider=true,status=true,effect=true,error_kind=true,retryable=true,retry_in=true},7) or d.rule~=rule or not id(rule) or not ({cloudflare=true,aliyun=true,dnspod=true,huaweicloud=true})[d.provider] then return false end
 if not ({ready=true,stale=true,blocked=true,reconciliation_required=true,unauthorized=true,clock_invalid=true,paused=true,retry_wait=true,waiting=true,created=true,updated=true,unchanged=true,failed=true,network_unavailable=true})[d.status] then return false end
 if not ({['']=true,authentication=true,not_found=true,unsupported=true,invalid_request=true,invalid_zone=true,temporary=true,network_unavailable=true,timeout=true,rate_limit=true,invalid_configuration=true})[d.error_kind] or type(d.retryable)~='boolean' or not integer(d.retry_in,999999999) then return false end
 if d.status=='network_unavailable' then return d.effect=='none' and d.error_kind=='network_unavailable' and d.retryable==true and d.retry_in==0 end
 if d.status=='created' or d.status=='updated' then return d.effect=='confirmed' and d.error_kind=='' and not d.retryable end
 if d.status=='unchanged' then return d.effect=='none' and d.error_kind=='' and not d.retryable end
 return (d.status=='failed' and (d.effect=='none' or d.effect=='unknown')) or d.effect=='none'
end
function M.report(d)
 if not keys(d,{api_version=true,prototype=true,ok=true,phase=true,job=true,rule=true,configuration_revision=true,pending=true,state=true,result=true,last_effect=true,reason=true,effect=true,write_ready=true},14) or d.api_version~=1 or d.prototype~=true or d.ok~=true or d.phase~='ddns-job' or not hex(d.job) or not id(d.rule) or not integer(d.configuration_revision,32) or d.configuration_revision<1 or d.write_ready~=false or d.effect~='none' then return false end
 if d.state=='pending' then return d.pending==true and d.result==false and d.last_effect=='unknown' and d.reason=='accepted' end
 if d.state=='interrupted' then return d.pending==false and d.result==false and d.last_effect=='unknown' and d.reason=='interrupted' end
 if d.state~='finished' or d.pending~=false or not M.row(d.result,d.rule) or d.last_effect~=d.result.effect then return false end
 return (d.reason=='archived' and d.last_effect=='confirmed') or (d.reason=='compacted' and d.last_effect=='none') or d.reason=='completed' or (d.reason=='changed' and d.result.effect=='none') or (d.reason=='unavailable' and d.result.effect=='unknown')
end
function M.response(action,payload,d)
 if action=='maintain_preview' or action=='maintain_commit' then
  local fields={api_version=true,prototype=true,ok=true,phase=true,job=true,rule=true,operation=true,effect=true,write_ready=true}
  local n=10;if action=='maintain_preview' then fields.confirmation=true;fields.expires_in=true;n=11 else fields.completed=true end
  return keys(d,fields,n) and d.api_version==1 and d.prototype==true and d.ok==true and d.phase=='ddns-maintenance' and d.job==payload:sub(1,32) and hex(d.job) and id(d.rule) and (d.operation=='compact' or d.operation=='archive') and d.effect=='none' and d.write_ready==false and ((action=='maintain_preview' and hex(d.confirmation) and d.expires_in==300) or (action=='maintain_commit' and d.completed==true))
 end
 if action=='submit' then return M.report(d) and d.job..':'..d.rule==payload end
 if action~='jobs' or not keys(d,{api_version=true,prototype=true,ok=true,phase=true,jobs=true,effect=true,write_ready=true},7) or d.api_version~=1 or d.prototype~=true or d.ok~=true or d.phase~='ddns-jobs' or d.effect~='none' or d.write_ready~=false or type(d.jobs)~='table' or #d.jobs>32 then return false end
 local prev='';for k,v in pairs(d.jobs) do if type(k)~='number' or k<1 or k>#d.jobs or k~=math.floor(k) then return false end end
 for _,v in ipairs(d.jobs) do if not M.report(v) or prev>=v.job then return false end;prev=v.job end;return true
end
return M
