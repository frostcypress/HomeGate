#!/usr/bin/env python3
"""Stage a native production-path candidate; never install or start a host service.

Reuse the exact business gates, serializers and lock protocols already exercised
by the engineering deployment. Native procd/package sources are staged; full CLI and target acceptance remain pending.
"""
from pathlib import Path
import argparse
from engineering_runtime import payload as business_payload, web_payload

BASE = 'usr/libexec/homegate/'

def native(raw):
    text = raw.decode('utf-8').replace('homegate-engineering', 'homegate').replace('homegate_engineering', 'homegate')
    text = text.replace('engineering=true', 'native=true').replace('"engineering":true', '"native":true')
    text = text.replace('.engineering', '.native').replace('HomeGate Engineering', 'HomeGate')
    # Own distinct chains; legacy HOMEGATE_* and engineering HG_ENG_* are foreign.
    text = text.replace('HG_ENG_NAT', 'HG_NATIVE_NAT').replace('HG_ENG_INPUT', 'HG_NATIVE_INPUT')
    return text.encode('utf-8')

def payload(root):
    files={BASE+name:native(raw) for name,raw in business_payload(root).items()}
    readonly={
        'homegate-network-read.sh':['network_resolve_enabled'],
        'homegate-network-worker.sh':['network_resolve_enabled'],
        'homegate-health-read.sh':['health_status_enabled'],
        'homegate-health-worker.sh':['health_status_enabled'],
        'homegate-recovery-read.sh':['recovery_status_enabled','ddns_recovery_read_enabled'],
        'homegate-recovery-worker.sh':['recovery_status_enabled','ddns_recovery_read_enabled'],
        'homegate-service-observer-watchdog.sh':['network_resolve_enabled','health_status_enabled','recovery_status_enabled','ddns_recovery_read_enabled'],
    }
    for name,gates in readonly.items():
        key=BASE+'project/core/prototype/'+name
        for gate in gates:
            old=(gate+'=false\n').encode()
            assert files[key].count(old)==1,(name,gate)
            files[key]=files[key].replace(old,(gate+'=true\n').encode())
    support=['engineering.lua','ddns-control.sh','apply-handle.lua','service-disabled','config-web.sh','config-web.lua','schedule-control.sh']
    for name in support:
        files[BASE+name]=native((root/'packaging/engineering/files'/name).read_bytes())
    # Source adoption uses the production transaction's bound migration source,
    # not the engineering copy of a different namespace.
    files[BASE+'config-web.sh']=files[BASE+'config-web.sh'].replace(b'production-copy-preview',b'import-preview').replace(b'production-copy-commit',b'import-commit')
    key=BASE+'project/core/prototype/homegate-config-prototype.sh'
    files[key]=files[key].replace(b'production_copy_enabled=true',b'production_copy_enabled=false')
    files['usr/bin/homegate']=(root/'packaging/production/native-cli.sh').read_bytes()
    for name in ['native-cli.lua','native-service.sh','native-service.lua','native-package.sh','native-package.lua','native-adapters.sh','native-adapters.lua','native-certificates.sh','native-certificates.lua','native-public.lua','native-public-listeners.lua']:
        files[BASE+name]=(root/'packaging/production'/name).read_bytes()
    files['etc/init.d/homegate']=(root/'packaging/production/homegate.init').read_bytes()
    files['etc/hotplug.d/iface/95-homegate']=(root/'packaging/production/95-homegate').read_bytes()
    files[BASE+'factory.config']=(root/'packaging/production/homegate.config').read_bytes()
    control=BASE+'ddns-control.sh'
    anchor=b'action=${1:-};shift || fail\n';assert anchor in files[control]
    files[control]=files[control].replace(anchor,anchor+b'''if [ -e /etc/homegate/package-state ] || [ -L /etc/homegate/package-state ] || [ -e /etc/.homegate-transition/hold ] || [ -L /etc/.homegate-transition/hold ];then
 case "$action" in config-status|config-export|*-status|*-quiescent|*-stop|*-reap|acme-job|acme-stop|acme-cleanup|firewall-cleanup) ;;*) fail 4;;esac
fi
''')
    ui=BASE+'project/core/prototype/homegate-ddns-ui.sh'
    anchor=b'action=${parsed%%:*};payload=${parsed#*:};rc=0\n'
    assert anchor in files[ui]
    files[ui]=files[ui].replace(anchor,anchor+b'''
if [ -e /etc/homegate/package-state ] || [ -L /etc/homegate/package-state ] || [ -e /etc/.homegate-transition/hold ] || [ -L /etc/.homegate-transition/hold ];then
 case "$action" in status|jobs) ;;*) fail 4;;esac
fi
''',1)
    for name,raw in web_payload(root).items():files[native(name.encode()).decode()]=native(raw)
    for name,path in [('controller.lua','usr/lib/lua/luci/controller/homegate.lua'),('overview.htm','usr/lib/lua/luci/view/homegate/overview.htm')]:
        files[path]=native((root/'packaging/engineering/files'/name).read_bytes())
    # The candidate UI must describe in-place adoption accurately. It never
    # asserts the legacy source remains unchanged after explicit publication.
    view='usr/lib/lua/luci/view/homegate/configuration.htm'
    text=files[view].decode()
    start=text.index('  <div class="cbi-section"><h3>复制现有 HomeGate 配置</h3>')
    end=text.index('</div>',start)+len('</div>')
    old=text[start:end]
    # Retain the existing actual button IDs, not a second controller/form path.
    import re
    buttons=''.join(re.findall(r'<button\b.*?</button>',old,re.S))
    text=text[:start]+'''  <div class="cbi-section"><h3>接管现有配置</h3>
    <p>先初始化私有配置库，再预览现有配置与秘密。确认迁移保留完整私有原始备份并分离秘密；随后预览应用，确认后原子发布到 /etc/config/homegate。此候选入口不启动旧服务或新服务。来源变化须重新预览，未完成的发布使用续完或恢复。</p>
'''+buttons+'</div>'+text[end:]
    files[view]=text.encode()
    js='www/luci-static/resources/homegate/configuration.js'
    files[js]=files[js].replace(b"d.report.operation==='production-copy'",b"d.report.operation==='migration-source'").replace('确认复制生产配置'.encode(),'确认迁移源配置'.encode())
    def change(name,old,new):
        raw=files[name];old=old.encode();assert old in raw,(name,old)
        files[name]=raw.replace(old,new.encode())
    controller='usr/lib/lua/luci/controller/homegate.lua'
    files[controller]=files[controller].replace(b"call('action_overview'),_('HomeGate'),90",b"alias('admin','services','homegate','overview'),_('HomeGate'),56")
    files[controller]=files[controller].replace(b"call('configuration'),_('Configuration and Credentials'),20",b"call('configuration'),nil,90")
    change(controller,"or value.ok~=true then return nil end", "or (action=='version' and (value.api_version~=1 or type(value.version)~='string') or action~='version' and value.ok~=true) then return nil end")
    change(controller,"{'backup_export','wol_status'","{'service_status','backup_export','wol_status'")
    change(controller,"ipairs({'backup_preview'","ipairs({'service_start','service_stop','service_plan_set','backup_preview'")
    files[controller]+=b"\nfunction config_service_status()config('service_status')end\nfunction config_service_start()config('service_start')end\nfunction config_service_stop()config('service_stop')end\nfunction config_service_plan_set()config('service_plan_set')end\n"
    model='usr/lib/lua/luci/model/homegate/configuration.lua'
    change(model,'local writes={','local writes={service_start=true,service_stop=true,service_plan_set=true,')
    change(model,"if action~='backup_export'","if action~='service_status' and action~='backup_export'")
    change(model,'if not ({backup=true,','if not ({service_ddns=true,service_certs=true,service_web=true,backup=true,')
    change(model,'local request={action=action};local count=0',"if writes[action] and action~='service_stop' and (require('nixio.fs').lstat('/etc/homegate/package-state') or require('nixio.fs').lstat('/etc/.homegate-transition/hold')) then return refused() end\n local request={action=action};local count=0")
    change(model,"#v>(k=='backup'","#v>(k:match('^service_') and 2111 or k=='backup'")
    cfg=BASE+'config-web.lua'
    change(cfg,'local schemas={',"local schemas={service_status={},service_start={'consent'},service_stop={'consent'},service_plan_set={'service_ddns','service_certs','service_web','policy','consent'},")
    change(cfg,"#v>(k=='backup'","#v>(k:match('^service_') and 2111 or k=='backup'")
    change(cfg,"if d.job and not hex", "if d.action=='service_plan_set' then for _,k in ipairs({'service_ddns','service_certs','service_web'})do if not d[k]:match('^[a-zA-Z0-9_,%-]+$')then return nil end end;if d.policy~='open' and d.policy~='allow'then return nil end end\n if d.job and not hex")
    change(cfg,"if d.action=='rollback_preview'then", "if d.action=='service_plan_set'then io.write(':',d.service_ddns,':',d.service_certs,':',d.service_web,':',d.policy)\n  elseif d.action=='rollback_preview'then")
    change(cfg,'local allowed={device_wake_verified', 'local allowed={service=true,coordinator=true,launch_requested=true,stop_requested=true,plan_saved=true,authority_granted=true,device_wake_verified')
    change(BASE+'config-web.sh','case "$action" in\n', '''case "$action" in
 service_status) raw=$(/usr/bin/homegate status) || rc=$?;;
 service_stop) raw=$(/usr/bin/homegate service-stop --confirm) || rc=$?;;
 service_start) if /etc/init.d/homegate start >/dev/null 2>&1;then raw='{"api_version":1,"native":true,"ok":true,"phase":"native-service","launch_requested":true}';else fail 4;fi;;
 service_plan_set) ddns=${payload%%:*};rest=${payload#*:};certs=${rest%%:*};rest=${rest#*:};web=${rest%%:*};policy=${rest#*:};raw=$(/usr/bin/homegate service-plan-set "$ddns" "$certs" "$web" "$policy" --confirm) || rc=$?;;
''')
    change(js,"write=action!=='backup_export'","write=action!=='service_status'&&action!=='backup_export'")
    change(js,'}());',(root/'packaging/production/service.js').read_text()+'\n}());')
    change(view,'  <div class="cbi-section"><h3>配置备份与恢复</h3>',(root/'packaging/production/service.htm').read_text()+'\n  <div class="cbi-section"><h3>配置备份与恢复</h3>')
    change(view,'此候选入口不启动旧服务或新服务。','迁移操作不会自动启动服务；确认任务后使用“启动服务”。')
    web_runtime(root,files)
    return files

def web_runtime(root,files):
    """Frozen legacy forms; bounded native execution, never the Go backend."""
    import json
    core=BASE+'project/core/prototype/homegate-config-prototype.sh'
    assert files[core].count(b'native_editor_enabled=false\n')==1
    files[core]=files[core].replace(b'native_editor_enabled=false\n',b'native_editor_enabled=true\n')
    key=BASE+'project/core/prototype/homegate-certificate.sh'
    assert files[key].count(b'native_certificate_maintenance_enabled=false\n')==1
    files[key]=files[key].replace(b'native_certificate_maintenance_enabled=false\n',b'native_certificate_maintenance_enabled=true\n')
    for name in ['native-web.sh','native-web.lua','native-web-store.lua','native-selftest.lua']:
        files[BASE+name]=(root/'packaging/production'/name).read_bytes()
    parser=(root/'project/core/prototype/cloudflare-codec.lua').read_text()
    parser=parser[parser.index('local function parse(body)'):parser.index('local function envelope(')]
    files[BASE+'strict-web-json.lua']=("local json=require('luci.jsonc')\n"+parser.replace('#body>65536','#body>2097152')+'return parse\n').encode()
    contract=json.loads((root/'docs/核心CLI合同.json').read_text())
    routes=contract['routes'] if 'routes' in contract else contract['web_routes']
    files[BASE+'legacy-routes.json']=(json.dumps(routes,ensure_ascii=False,separators=(',',':'))+'\n').encode()
    files[BASE+'legacy-controller.lua']=(root/'project/luci/lua/luasrc/controller/homegate.lua').read_bytes()
    # Private preview reuses the production PEM/key/date/SAN validator verbatim.
    # Its generated variant has a fixed per-job scratch root and cannot publish.
    cert=(root/'project/core/prototype/homegate-certificate.lua').read_text()
    old="local root='/etc/homegate/certs/'..selected"
    assert cert.count(old)==1
    cert=cert.replace(old,"""local job=arg[3];if not job or #job~=32 or not job:match('^[0-9a-f]+$') or selected~='check' or not ({receive=true,material=true,validated=true})[mode] then fail()end
local root='/tmp/homegate-frontend-jobs/'..job..'/certificate-check'""")
    a=cert.index('local function scope()');b=cert.index('\nlocal function pattern(',a)
    cert=cert[:a]+"""local function scope()
 local names={};if mode=='validated'then for name in read(root..'/.pending/san',16384):gmatch('DNS:([^,%s]+)')do names[#names+1]=name:lower():gsub('%.$','')end;if #names==0 then fail()end;table.sort(names)end
 return {id=selected,source='local',domains=names}
end"""+cert[b:]
    cert=cert.replace('if arg[3] then fail() end','if arg[4] then fail() end')
    cert=cert.replace('local function fail()os.exit(1)end',"""local function fail()
 if arg[1]=='validated' and arg[3] and #arg[3]==32 and arg[3]:match('^[0-9a-f]+$')then
  local f=io.open('/tmp/homegate-frontend-jobs/'..arg[3]..'/certificate-check/.pending/rejection','wb');if f then f:write(tostring(debug.getinfo(2,'l').currentline));f:close()end
 end
 os.exit(1)
end""",1)
    files[BASE+'project/core/prototype/native-web-certificate.lua']=cert.encode()
    worker=(root/'project/core/prototype/homegate-certificate-worker.sh').read_text()
    worker=worker.replace('id=$1;', 'job=$1;[ "${#job}" = 32 ] || exit 2;case "$job" in *[!0-9a-f]*) exit 2;;esac;id=check;')
    worker=worker.replace('base=/etc/homegate/certs/$id/.pending','base=/tmp/homegate-frontend-jobs/$job/certificate-check/.pending')
    worker=worker.replace('homegate-certificate.lua" material "$id"','native-web-certificate.lua" material "$id" "$job"').replace('homegate-certificate.lua" validated "$id"','native-web-certificate.lua" validated "$id" "$job"')
    lines=[];step=0
    for line in worker.splitlines():
        if line.startswith(('lua ','openssl ','a=$(sha256sum')):
            step+=1;lines.append('printf '+str(step)+' > "$base/phase"')
        lines.append(line)
    worker='\n'.join(lines)+'\n'
    files[BASE+'project/core/prototype/native-web-certificate-worker.sh']=worker.encode()
    watchdog=(root/'project/core/prototype/homegate-service-observer-watchdog.sh').read_text()
    watchdog=watchdog.replace('#!/bin/sh\n','#!/bin/sh\n[ "${1:-}" = --certificate-validate ] || exit 2\n',1)
    watchdog=watchdog.replace('certificate_validation_enabled=false\n','certificate_validation_enabled=true\n',1)
    watchdog=watchdog.replace('homegate-certificate-worker.sh','native-web-certificate-worker.sh')
    files[BASE+'project/core/prototype/native-web-certificate-watchdog.sh']=watchdog.encode()
    files[BASE+'native-web-cert-preview.sh']=(root/'packaging/production/native-web-cert-preview.sh').read_bytes()
    guard=b'''# Additional admission fence; existing transaction locks remain unchanged.
if [ -e /var/run/homegate/frontend-web.lock ] || [ -L /var/run/homegate/frontend-web.lock ];then
 [ -f /var/run/homegate/frontend-web.lock ] && [ ! -L /var/run/homegate/frontend-web.lock ] && [ "$(stat -c '%u:%a:%h:%s' /var/run/homegate/frontend-web.lock)" = 0:600:1:0 ] || fail 7
 case "$action" in version|selftest|status|check|*-status|*-quiescent|*-stop|*-reap|*-cleanup|config-export|service-admission|acme-job|web-*|network-resolve|dns-provider-catalog|acme-ca-catalog|log-events|access-recent) ;;
 *) if [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null)" != "$(stat -c '%d:%i' /var/run/homegate/frontend-web.lock)" ];then exec 8>>/var/run/homegate/frontend-web.lock;flock -n 8 || fail 4;exec 8>&-;else flock -n 8 || fail 4;fi;;esac
fi
'''
    for key,anchor in [('usr/bin/homegate',b'action=$1;shift\n'),(BASE+'ddns-control.sh',b'action=${1:-};shift || fail\n')]:
        assert files[key].count(anchor)==1
        files[key]=files[key].replace(anchor,anchor+guard)
    key=BASE+'ddns-control.sh'
    files[key]=files[key].replace(b'exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-',b'exec 3>&- 4>&- 5>&- 6>&- 7>&- 9>&-',1)
    files[key]=files[key].replace(guard,guard+b'exec 8>&-\n',1)
    cli='usr/bin/homegate'
    files[cli]=files[cli].replace(b'case "$action" in version|selftest|status|check|config-status|',b'case "$action" in web-read|web-job-status|web-job-ack|version|selftest|status|check|config-status|',1)
    anchor=b'case "$action" in\n version)'
    assert files[cli].count(anchor)==1
    files[cli]=files[cli].replace(anchor,b'''case "$action" in
 web-read|web-submit|web-job|web-job-status|web-job-ack)
  [ "$#" = 1 ] || fail
  case "$action" in web-read) mode=read;;web-submit) mode=submit;;web-job) mode=job;;web-job-status) mode=status;;web-job-ack) mode=ack;;esac
  exec ash "$base/native-web.sh" "$mode" "$1";;
 cert-adopt|cert-purge) [ "$#" = 2 ] && id "$1" && [ "$2" = --confirm ] || fail;exec ash "$base/native-certificates.sh" "${action#cert-}" "$1" --confirm;;
 cert-import-stdin) [ "$#" = 1 ] && id "$1" || fail;control cert-import "$1" --confirm;;
 version)''')
    internal=files[cli].replace(b'exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-',b'exec 3>&- 4>&- 5>&- 6>&- 7>&- 9>&-',1)
    prefix=b'''#!/bin/sh
[ "$(id -u)" = 0 ] && [ -f /var/run/homegate/frontend-web.lock ] && [ ! -L /var/run/homegate/frontend-web.lock ] && [ "$(stat -Lc '%d:%i' /proc/self/fd/8 2>/dev/null)" = "$(stat -c '%d:%i' /var/run/homegate/frontend-web.lock)" ] && flock -n 8 || exit 7
'''
    files[BASE+'native-cli-internal.sh']=prefix+internal
    files[BASE+'native-cli-core.sh']=files[cli]
    files[cli]=(root/'packaging/production/native-public.sh').read_bytes()
    for path in (root/'project/luci/lua/luasrc/view/homegate').glob('*.htm'):
        if path.stem in ['overview','basic','public','wol','maintenance','common']:
            raw=path.read_text().replace('homegate/common','homegate_legacy/common')
            if path.stem in ['basic','public','wol']:
                raw=raw.replace('<%+homegate_legacy/common%>','<%+homegate_legacy/common%>\n<p>保存配置会暂停运行中的任务；保存并应用会按启用范围重启并核验。<a href="<%=url("admin/services/homegate/configuration")%>">任务与恢复操作</a></p>')
            if path.stem=='maintenance':raw=raw.replace('<%+footer%>','''<p><a href="<%=luci.dispatcher.build_url("admin","services","homegate","configuration")%>">配置接管、授权与故障恢复</a></p>
<script type="text/javascript">
window.homegatePreviewImport=function(values){
 var base='<%=url("admin/services/homegate")%>',job,attempt=0;
 function read(url,options){return fetch(url,options).then(function(r){if(!r.ok)throw new Error('预览请求未完成');return r.json();});}
 function poll(){return read(base+'/compat_job/'+job,{credentials:'same-origin',cache:'no-store'}).then(function(d){
  if(!d.ok)throw new Error('预览查询未完成');
  if(d.pending){if(++attempt>=190)throw new Error('预览状态未确认，任务号：'+job);return new Promise(function(resolve){setTimeout(resolve,1000);}).then(poll);}
  var result=d.result;if(!result||!result.ok||result.uncertain)throw new Error('预览未完成，任务号：'+job);
  var preview=JSON.parse(result.body);if(!preview||typeof preview.ok!=='boolean')throw new Error('预览回执无效');
  return read(base+'/compat_ack/'+job,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'token='+encodeURIComponent(values.token)}).then(function(ack){if(!ack.ok)throw new Error('预览回执已保留');return preview;});
 });}
 return read(base+'/config_import',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},body:'token='+encodeURIComponent(values.token)+'&config_payload='+encodeURIComponent(values.config_payload)}).then(function(d){if(!d.ok||!d.pending||typeof d.job!=='string'||!/^[0-9a-f]{32}$/.test(d.job))throw new Error('预览任务未受理');job=d.job;return poll();});
};
</script>
<%+footer%>''')
            files['usr/lib/lua/luci/view/homegate_legacy/'+path.name]=raw.encode()
    for name,dest in [('native-web-http.lua','usr/lib/lua/luci/model/homegate/legacy.lua'),('native-web-pending.htm','usr/lib/lua/luci/view/homegate_legacy/pending.htm')]:
        files[dest]=(root/'packaging/production'/name).read_bytes()
    controller='usr/lib/lua/luci/controller/homegate.lua'
    # Keep existing advanced configuration actions; register each frozen route.
    addition=["\nlocal legacy=require('luci.model.homegate.legacy')\nfunction legacy_status(id)legacy.status(id)end\nfunction legacy_ack(id)legacy.ack(id)end\n"]
    entries=["entry({'admin','services','homegate','compat_job'},call('legacy_status')).leaf=true", "entry({'admin','services','homegate','compat_ack'},post('legacy_ack')).leaf=true"]
    for i,(route,spec) in enumerate(routes.items()):
        name='legacy_route_'+str(i)
        addition.append("function "+name+"()legacy.dispatch("+repr(route)+","+str(spec['write']).lower()+")end\n")
        path=','.join(repr(v) for v in ['admin','services','homegate',*route.split('/')])
        title={'overview':'概览','settings/basic':'基础设置','settings/public':'公网服务','settings/wol':'网络唤醒','maintenance':'维护'}.get(route)
        entries.append('entry({'+path+'},'+('post' if spec['write'] else 'call')+'('+repr(name)+')'+(','+repr(title) if title else '')+').leaf=true')
    entries.append("entry({'admin','services','homegate','settings'},alias('admin','services','homegate','settings','basic'),'设置',20)")
    marker=b"function index()\n";assert files[controller].count(marker)==1
    files[controller]=files[controller].replace(marker,marker+b'''    local web_http=require('luci.http');local web_size=tonumber(web_http.getenv('CONTENT_LENGTH') or '0')
    if web_http.getenv('REQUEST_METHOD')=='POST' and (web_http.getenv('PATH_INFO') or ''):match('^/admin/services/homegate/') and web_size and web_size>=0 and web_size<=2097152 then web_http.HTTP_MAX_CONTENT=2097152 end
''',1)
    # Registration after existing routes deliberately replaces its overview only.
    end=files[controller].index(b'\nend\n',files[controller].index(marker))
    files[controller]=files[controller][:end]+('\n    '+'\n    '.join(entries)).encode()+files[controller][end:]+''.join(addition).encode()

def stage_package(root,destination):
    """Source-only SDK feed input. Does not compile, install, enable or publish."""
    if destination.exists() and (destination.is_symlink() or any(destination.iterdir())):
        raise ValueError('Package staging destination must be empty')
    destination.mkdir(parents=True,exist_ok=True)
    import shutil
    for name,raw in payload(root).items():
        kind='web' if name.startswith(('usr/lib/lua/luci/','www/')) else 'core'
        path=destination/'payload'/kind/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        path.chmod(0o755 if name in ['usr/bin/homegate','etc/init.d/homegate','etc/hotplug.d/iface/95-homegate'] or name.endswith('.sh') or name.endswith('service-disabled') else 0o644)
    config=destination/'payload/core/etc/config/homegate';config.parent.mkdir(parents=True,exist_ok=True)
    config.write_bytes((root/'packaging/production/homegate.config').read_bytes());config.chmod(0o600)
    license=destination/'payload/core/usr/share/licenses/homegate-core';license.mkdir(parents=True)
    shutil.copyfile(root/'LICENSE',license/'LICENSE');shutil.copyfile(root/'third_party/acme.sh-3.1.6/LICENSE.md',license/'acme.sh.LICENSE.md')
    for path in license.iterdir():path.chmod(0o644)
    hook=(root/'packaging/production/native-package.sh').read_text()
    preinst=hook+'\n'  # action is a literal SDK hook argument, not caller text.
    preinst=preinst.replace('action=${1:-};shift || exit 2','action=preinst')
    make=(root/'packaging/production/Makefile').read_text().replace('@HOMEGATE_PREINST@',preinst.replace('$','$$').rstrip()).replace('@HOMEGATE_POSTRM@',(root/'packaging/production/postrm.sh').read_text().replace('$','$$').rstrip())
    assert '@HOMEGATE_' not in make
    (destination/'Makefile').write_text(make,encoding='utf-8')
    (destination/'tools').mkdir();shutil.copyfile(root/'project/luci/common/tools/po2lmo.py',destination/'tools/po2lmo.py')
    po=destination/'po/zh_Hans';po.mkdir(parents=True)
    import importlib.util,json
    spec=importlib.util.spec_from_file_location('native_po_builder',root/'project/luci/common/tools/po2lmo.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    entries=dict(builder.parse_po(root/'packaging/engineering/po/zh_Hans/engineering.po'))
    entries.update(builder.parse_po(root/'project/luci/common/po/zh_Hans/homegate.po'))
    entries.pop('HomeGate Engineering',None)
    encoded=['msgid ""\nmsgstr "Content-Type: text/plain; charset=UTF-8\\nLanguage: zh_CN\\n"\n']
    for key,value in sorted(entries.items()):encoded.append('msgid '+json.dumps(key,ensure_ascii=False)+'\nmsgstr '+json.dumps(value,ensure_ascii=False)+'\n')
    (po/'homegate.po').write_text('\n'.join(encoded),encoding='utf-8')

def stage(root,destination):
    if destination.exists() and (destination.is_symlink() or any(destination.iterdir())):
        raise ValueError('Staging destination must be an empty real directory')
    for name,raw in payload(root).items():
        path=destination/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw);path.chmod(0o755 if name in ['usr/bin/homegate','etc/init.d/homegate','etc/hotplug.d/iface/95-homegate'] or name.endswith('.sh') or name.endswith('service-disabled') else 0o644)

def stage_installed(root,installed,destination):
    """Copy verified plugin bytes from a pristine real opkg offline root.

    The source generator supplies expected bytes/modes only. Runtime files are
    read from the installed root, including the SDK-built Chinese translation.
    Foreign dependency binaries are not substituted into the host test runtime.
    """
    import hashlib,importlib.util,json,os,stat,tempfile
    root=Path(root);installed=Path(installed);destination=Path(destination)
    if installed.is_symlink() or not installed.is_dir() or destination.exists():raise ValueError('Require installed directory and new staging path')
    with tempfile.TemporaryDirectory() as work:
        feed=Path(work)/'expected';stage_package(root,feed)
        expected={}
        for part in ('core','web'):
            for path in (feed/'payload'/part).rglob('*'):
                if path.is_file():expected[path.relative_to(feed/'payload'/part).as_posix()]=(path.read_bytes(),path.stat().st_mode&0o777)
        spec=importlib.util.spec_from_file_location('installed_native_po',root/'project/luci/common/tools/po2lmo.py')
        po=importlib.util.module_from_spec(spec);spec.loader.exec_module(po)
        translated=Path(work)/'homegate.zh-cn.lmo';po.build(feed/'po/zh_Hans/homegate.po',translated)
        expected['usr/lib/lua/luci/i18n/homegate.zh-cn.lmo']=(translated.read_bytes(),0o644)
        actual={};owners=set()
        for name,(wanted,mode) in expected.items():
            source=installed/name
            for parent in [source,*source.parents]:
                if parent==installed.parent:break
                if parent.is_symlink():raise ValueError('Installed package path contains a symlink: '+name)
            before=source.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_mode&0o777!=mode or before.st_size!=len(wanted):raise ValueError('Installed file metadata differs: '+name)
            raw=source.read_bytes();after=source.lstat()
            if raw!=wanted or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('Installed bytes differ or changed: '+name)
            owners.add(before.st_uid);actual[name]=(raw,mode)
        if owners!={os.getuid()}:raise ValueError('Installed root must belong to the original test UID')
        destination.mkdir()
        for name,(raw,mode) in actual.items():
            path=destination/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
        return {'scope':'actual-opkg-installed-shell-Lua-and-LuCI-payload-on-host-fixture',
            'installed_root':str(installed),'source_uid':os.getuid(),'files_sha256':{n:hashlib.sha256(raw).hexdigest() for n,(raw,_) in actual.items()},
            'source_generated_runtime_files':False,'SDK_translation_bytes_verified':True,
            'AArch64_dependency_binaries_executed':False,'QWRT_runtime_ABI_verified':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--output',type=Path);group.add_argument('--package-output',type=Path)
    args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    if args.package_output:stage_package(root,args.package_output)
    else:stage(root,args.output)
