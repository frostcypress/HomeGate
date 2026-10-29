module('luci.controller.homegate_engineering',package.seeall)

function index()
    local node=entry({'admin','services','homegate_engineering'},call('action_overview'),_('HomeGate Engineering'),90)
    node.dependent=false
    entry({'admin','services','homegate_engineering','configuration'},call('configuration'),_('Configuration and Credentials'),20).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','read'},call('config_read')).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','schedule_status'},call('config_schedule_status')).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','lifecycle_status'},call('config_lifecycle_status')).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','cert_status'},call('config_cert_status')).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','acme_status'},call('config_acme_status')).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','acme_schedule_status'},call('config_acme_schedule_status')).leaf=true
    entry({'admin','services','homegate_engineering','configuration_api','proxy_status'},call('config_proxy_status')).leaf=true
    for _,action in ipairs({'access_status','access_recent'})do entry({'admin','services','homegate_engineering','configuration_api',action},call('config_'..action)).leaf=true end
    for _,action in ipairs({'preview_access','access_update','access_refresh','access_clear','access_clear_denied','access_stop','access_reap','preview_web_rule','web_target_put','proxy_start','proxy_stop','proxy_reap','acme_schedule_start','acme_schedule_stop','acme_schedule_reap','acme_issue','acme_renew','acme_stop','acme_cleanup','preview_acme_certificate','cert_import','cert_resume','cert_cancel','preview_local_certificate','recover','production_copy_preview','production_copy_commit','lifecycle_enable','lifecycle_disable','provider_status','zones','delete_rule','prepare','cancel','activate_preview','preview_account','preview_rule','secret_put','apply','finish','schedule_serve','schedule_start','schedule_stop','schedule_reap'})do
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
    if not length or length<0 or length>(action=='cert_import' and 262144 or 32768) then h.status(413,'Request Entity Too Large');return end
    local value=require('luci.model.homegate_engineering.configuration').call(action,h.formvalue() or {})
    if not value.ok then h.status(503,'Service Unavailable') end
    h.prepare_content('application/json');h.write(require('luci.jsonc').stringify(value)..'\n')
end
function config_acme_schedule_status()config('acme_schedule_status')end
function config_acme_schedule_start()config('acme_schedule_start')end
function config_acme_schedule_stop()config('acme_schedule_stop')end
function config_acme_schedule_reap()config('acme_schedule_reap')end
function config_acme_status()config('acme_status')end
function config_acme_issue()config('acme_issue')end
function config_acme_renew()config('acme_renew')end
function config_acme_stop()config('acme_stop')end
function config_acme_cleanup()config('acme_cleanup')end
function config_preview_acme_certificate()config('preview_acme_certificate')end
function config_cert_status()config('cert_status')end
function config_cert_import()config('cert_import')end
function config_cert_resume()config('cert_resume')end
function config_cert_cancel()config('cert_cancel')end
function config_preview_local_certificate()config('preview_local_certificate')end
function config_recover()config('recover')end
function config_production_copy_preview()config('production_copy_preview')end
function config_production_copy_commit()config('production_copy_commit')end
function config_provider_status()config('provider_status')end
function config_zones()config('zones')end
function config_delete_rule()config('delete_rule')end
function config_lifecycle_status()config('lifecycle_status')end
function config_lifecycle_enable()config('lifecycle_enable')end
function config_lifecycle_disable()config('lifecycle_disable')end
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
function config_schedule_serve()config('schedule_serve')end
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

function config_preview_web_rule()config('preview_web_rule')end

function config_web_target_put()config('web_target_put')end

function config_proxy_start()config('proxy_start')end

function config_proxy_status()config('proxy_status')end

function config_proxy_stop()config('proxy_stop')end

function config_proxy_reap()config('proxy_reap')end

function config_preview_access()config('preview_access')end

function config_access_update()config('access_update')end

function config_access_refresh()config('access_refresh')end

function config_access_status()config('access_status')end

function config_access_recent()config('access_recent')end

function config_access_clear()config('access_clear')end

function config_access_clear_denied()config('access_clear_denied')end

function config_access_stop()config('access_stop')end

function config_access_reap()config('access_reap')end
