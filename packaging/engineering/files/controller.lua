module('luci.controller.homegate_engineering',package.seeall)

function index()
    local node=entry({'admin','services','homegate_engineering'},call('action_overview'),_('HomeGate Engineering'),90)
    node.dependent=false
    entry({'admin','services','homegate_engineering','configuration'},call('configuration'),_('Configuration and Credentials'),20).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','read'},call('config_read')).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','schedule_status'},call('config_schedule_status')).leaf=true
    for _,action in ipairs({'provider_status','zones','delete_rule','prepare','cancel','activate_preview','preview_account','preview_rule','secret_put','apply','finish','schedule_start','schedule_stop','schedule_reap'})do
        entry({'admin','services','homegate_engineering','configuration_api',action},post('config_'..action)).leaf=true
    end
end

function configuration()
    local c=require('luci.dispatcher').context or {}
    require('luci.template').render('homegate_engineering/configuration',{token=c.authtoken or ''})
end
local function config(action)
    local h=require('luci.http')
    local length=tonumber(h.getenv('CONTENT_LENGTH') or '0')
    if not length or length<0 or length>32768 then h.status(413,'Request Entity Too Large');return end
    local value=require('luci.model.homegate_engineering.configuration').call(action,h.formvalue() or {})
    if not value.ok then h.status(503,'Service Unavailable') end
    h.prepare_content('application/json');h.write(require('luci.jsonc').stringify(value)..'\n')
end
function config_provider_status()config('provider_status')end
function config_zones()config('zones')end
function config_delete_rule()config('delete_rule')end
function config_read()config('read')end
function config_prepare()config('prepare')end
function config_cancel()config('cancel')end
function config_activate_preview()config('activate_preview')end
function config_preview_account()config('preview_account')end
function config_preview_rule()config('preview_rule')end
function config_secret_put()config('secret_put')end
function config_apply()config('apply')end
function config_finish()config('finish')end
function config_schedule_status()config('schedule_status')end
function config_schedule_start()config('schedule_start')end
function config_schedule_stop()config('schedule_stop')end
function config_schedule_reap()config('schedule_reap')end

function action_overview()
    local sys=require('luci.sys')
    local json=require('luci.jsonc')
    local function read(action)
        local raw=sys.exec('/usr/bin/homegate-engineering '..action..' 2>/dev/null')
        if type(raw)~='string' or #raw>8192 then return nil end
        local ok,value=pcall(json.parse,raw)
        if not ok or type(value)~='table' or value.ok~=true then return nil end
        return value
    end
    local version,dns,ca=read('version'),read('dns-provider-catalog'),read('acme-ca-catalog')
    require('luci.template').render('homegate_engineering/overview',{
        backend_available=version~=nil and dns~=nil and ca~=nil,
        version=version and version.version or '',providers=dns and dns.providers or {},cas=ca and ca.cas or {}})
end
