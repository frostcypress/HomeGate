-- Enable intent provenance only. No service or configuration mutation.
local M={}
function M.marker(candidate)
    if type(candidate)~='table' or type(candidate.switches)~='table' or type(candidate.switches.main)~='table' or
       candidate.switches.main.kind~='homegate' then return nil end
    local value=candidate.switches.main.enabled
    if value~='0' and value~='1' then return nil end
    if candidate.public_projection==true then
        if value~='0' then return nil end
        return 'projection-disabled'
    elseif candidate.public_projection~=false then return nil end
    return value=='1' and 'ordinary-enabled' or 'ordinary-disabled'
end
function M.describe(marker)
    if marker=='ordinary-enabled' then
        return {observed_enabled=true,known=true,provenance='ordinary-source',desired_state='enabled'}
    elseif marker=='ordinary-disabled' then
        return {observed_enabled=false,known=true,provenance='ordinary-source',desired_state='disabled'}
    elseif marker=='projection-disabled' then
        return {observed_enabled=false,known=false,provenance='public-disabled-projection',desired_state='unconfirmed'}
    end
    return nil
end
function M.public(marker)
    local d=M.describe(marker);if not d then return nil end
    return {known=d.known,provenance=d.provenance,desired_state=d.desired_state}
end
function M.request(marker,desired)
    local d=M.describe(marker)
    if not d or (desired~='enabled' and desired~='disabled') then return nil end
    return {requested_state=desired,explicit_request=true,confirmation_source='command-argument',
        source_intent=M.public(marker),changes_observed_flag=d.observed_enabled~=(desired=='enabled')}
end
return M
