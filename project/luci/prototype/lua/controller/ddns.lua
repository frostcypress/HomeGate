module('luci.controller.homegate_ddns',package.seeall)
local native_ddns_page_enabled=false
function index()
 if not native_ddns_page_enabled then return end
 entry({'admin','services','homegate','settings','ddns'},call('page'),_('DDNS Authorization'),25).leaf=true
 entry({'admin','services','homegate','ddns_native','maintain_preview'},post('maintain_preview')).leaf=true
 entry({'admin','services','homegate','ddns_native','maintain_commit'},post('maintain_commit')).leaf=true
 entry({'admin','services','homegate','ddns_native','jobs'},call('jobs')).leaf=true
 entry({'admin','services','homegate','ddns_native','submit'},post('submit')).leaf=true
 entry({'admin','services','homegate','ddns_native','status'},call('status')).leaf=true
 entry({'admin','services','homegate','ddns_native','preview'},post('preview')).leaf=true
 entry({'admin','services','homegate','ddns_native','commit'},post('commit')).leaf=true
 entry({'admin','services','homegate','ddns_native','revoke'},post('revoke')).leaf=true
end
function page()
 local c=require('luci.dispatcher').context or {}
 require('luci.template').render('homegate/ddns',{token=c.authtoken or ''})
end
local function respond(action)
 local h=require('luci.http');local d=require('luci.model.homegate.ddns').call(action,h.formvalue())
 if not d.ok then h.status(503,'Service Unavailable') end
 h.prepare_content('application/json');h.write(require('luci.jsonc').stringify(d)..'\n')
end
function maintain_preview()respond('maintain_preview')end
function maintain_commit()respond('maintain_commit')end
function jobs()respond('jobs')end
function submit()respond('submit')end
function status()respond('status')end
function preview()respond('preview')end
function commit()respond('commit')end
function revoke()respond('revoke')end
