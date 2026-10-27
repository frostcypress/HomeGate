-- Private, in-memory main-switch candidate. Never export this object.
local M={}
local function copy(value)
    if type(value)~='table' then return value end
    local out={};for k,v in pairs(value) do out[k]=copy(v) end;return out
end
local function switches_valid(source)
    local seen={}
    for _,section in ipairs(source.configuration) do
        local row=source.switches[section.name]
        if type(row)~='table' or row.kind~=section.kind then return false end
        for key,value in pairs(row) do
            if key~='kind' then
                if (key~='enabled' and key~='access_enabled') or
                   (value~='0' and value~='1') or section.values[key]==nil then return false end
            end
        end
        for _,key in ipairs({'enabled','access_enabled'}) do
            if section.values[key]~=nil and row[key]==nil then return false end
        end
        seen[section.name]=true
    end
    for name in pairs(source.switches) do if not seen[name] then return false end end
    return true
end
function M.build(snapshot,source,desired,codec,validator,ip,intent)
    if type(snapshot)~='table' or type(snapshot.revision)~='number' or
       snapshot.revision~=math.floor(snapshot.revision) or snapshot.revision<1 or snapshot.revision>32 then return nil end
    local marker=intent.marker(source)
    if not marker or not intent.request(marker,desired) or not validator.validate(snapshot,source,codec.json,ip) or
       not switches_valid(source) then return nil end
    local candidate={format='private-switch-overlay-v1',base_revision=snapshot.revision,
        configuration=copy(snapshot.configuration),credentials=copy(snapshot.credentials),
        switches=copy(source.switches),public_projection=false,source_intent=intent.public(marker),requested_state=desired}
    candidate.switches.main.enabled=desired=='enabled' and '1' or '0'
    if not validator.validate(snapshot,candidate,codec.json,ip) then return nil end
    -- The safe public document is unchanged. Actual switches form a separate
    -- private overlay; the existing public transaction cannot publish it.
    candidate.active_configuration=copy(candidate.configuration)
    for _,section in ipairs(candidate.active_configuration) do
        local switches=candidate.switches[section.name]
        if switches.enabled then section.values.enabled=switches.enabled end
        if switches.access_enabled then section.values.access_enabled=switches.access_enabled end
    end
    return candidate
end
function M.summary(candidate)
    return {format=candidate.format,checked=true,base_revision=candidate.base_revision,
        main_enabled=candidate.switches.main.enabled=='1',only_main_switch_requested=true,
        other_switches_preserved_as_observed=true,credentials_preserved=true,public_configuration_unchanged=true,
        original_projection_intents_restored=false,persisted=false,ordinary_publication_supported=false}
end
return M
