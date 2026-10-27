"""Explicit deployment profile for the isolated, manually operated DDNS package.

The prototypes stay closed. Only these gates and fixed namespaces change in
installed copies; no caller environment variable can select paths or features.
"""
from pathlib import Path
import re

SCOPE = 'isolated-ddns-contract-engineering'
PROTO = 'project/core/prototype/'
GATES = {
 'homegate-dns-status.sh': ['dns_status_cli_enabled'],
 'homegate-ddns-schedule.sh': ['ddns_schedule_enabled','ddns_schedule_events_enabled'],
 'homegate-ddns-batch.sh': ['ddns_batch_enabled'],
 'homegate-cli.sh': ['native_cli_enabled'],
 'homegate-ddns-ui.sh': ['ddns_ui_enabled'],
 'homegate-ddns-job.sh': ['ddns_ui_jobs_enabled','ddns_ui_maintenance_enabled'],
 'homegate-cloudflare-worker.sh': ['dns_read_enabled','dns_records_enabled','dns_reconcile_enabled','dns_receipt_enabled'],
 'homegate-aliyun-worker.sh': ['aliyun_read_enabled','aliyun_records_enabled','aliyun_reconcile_enabled','aliyun_receipt_enabled'],
 'homegate-dnspod-worker.sh': ['dnspod_read_enabled','dnspod_records_enabled','dnspod_reconcile_enabled','dnspod_receipt_enabled'],
 'homegate-huaweicloud-worker.sh': ['huaweicloud_read_enabled','huaweicloud_records_enabled','huaweicloud_reconcile_enabled','huaweicloud_receipt_enabled'],
 'homegate-store-bootstrap-prototype.sh': ['bootstrap_enabled'],
 'homegate-lifecycle-prepare.sh': ['runtime_prepare_enabled'],
 'homegate-config-prototype.sh': ['production_writes_enabled','persistent_namespace_enabled',
  'orphan_recovery_enabled','dns_recovery_read_enabled','lifecycle_migration_enabled',
  'ddns_plan_enabled','ddns_authority_enabled'],
 'homegate-ddns-authority.sh': ['ddns_authority_enabled','ddns_multi_authority_enabled'],
 'homegate-ddns-read.sh': ['ddns_plan_enabled','ddns_sync_enabled','ddns_work_enabled','ddns_runtime_enabled','ddns_batch_enabled','ddns_delete_enabled'],
 'homegate-ddns-plan-worker.sh': ['ddns_plan_enabled'],
 'homegate-ddns-work.sh': ['ddns_work_enabled','ddns_runtime_enabled'],
 'homegate-ddns-state.sh': ['ddns_state_enabled','ddns_batch_enabled'],
 'homegate-service-observer-watchdog.sh': ['ddns_plan_enabled','dns_read_enabled',
  'aliyun_read_enabled','dnspod_read_enabled','huaweicloud_read_enabled','dns_records_enabled',
  'dns_reconcile_enabled','dns_receipt_enabled','aliyun_records_enabled','aliyun_reconcile_enabled',
  'aliyun_receipt_enabled','dnspod_records_enabled','dnspod_reconcile_enabled','dnspod_receipt_enabled',
  'huaweicloud_records_enabled','huaweicloud_reconcile_enabled','huaweicloud_receipt_enabled'],
 'homegate-cloudflare-read.sh': ['dns_read_enabled','dns_status_read_enabled','ddns_sync_enabled',
  'ddns_work_enabled','ddns_runtime_enabled','ddns_closeout_enabled','dns_migrated_read_enabled','dns_records_enabled',
  'dns_reconcile_enabled','dns_receipt_enabled','aliyun_read_enabled','aliyun_records_enabled',
  'aliyun_reconcile_enabled','aliyun_receipt_enabled','dnspod_read_enabled','dnspod_records_enabled',
  'dnspod_reconcile_enabled','dnspod_receipt_enabled','huaweicloud_read_enabled',
  'huaweicloud_records_enabled','huaweicloud_reconcile_enabled','huaweicloud_receipt_enabled',
  'dns_settlement_enabled','aliyun_settlement_enabled','dnspod_settlement_enabled','huaweicloud_settlement_enabled',
  'dns_retention_enabled','aliyun_retention_enabled','dnspod_retention_enabled','huaweicloud_retention_enabled',
  'dns_orphan_collection_enabled','aliyun_orphan_collection_enabled','dnspod_orphan_collection_enabled','huaweicloud_orphan_collection_enabled'],
 'homegate-dns-recovery.sh': ['ddns_closeout_enabled','dns_settlement_enabled','aliyun_settlement_enabled',
  'dnspod_settlement_enabled','huaweicloud_settlement_enabled','dns_orphan_collection_enabled',
  'aliyun_orphan_collection_enabled','dnspod_orphan_collection_enabled','huaweicloud_orphan_collection_enabled'],
 'homegate-dns-orphan.sh': ['ddns_closeout_enabled','dns_orphan_collection_enabled',
  'aliyun_orphan_collection_enabled','dnspod_orphan_collection_enabled','huaweicloud_orphan_collection_enabled'],
 'homegate-dns-retention.sh': ['ddns_closeout_enabled','dns_retention_enabled','aliyun_retention_enabled',
  'dnspod_retention_enabled','huaweicloud_retention_enabled'],
 'homegate-dns-receipt.sh': ['dns_receipt_enabled','ddns_runtime_enabled','aliyun_receipt_enabled',
  'dnspod_receipt_enabled','huaweicloud_receipt_enabled'],
}

def render(name, raw):
    text = raw.decode('utf-8')
    for gate in GATES.get(Path(name).name, []):
        text, count = re.subn('^'+gate+'=false$',gate+'=true',text,flags=re.M)
        if count != 1: raise ValueError('Deployment gate drift: '+name+':'+gate)
    # Keep the on-disk schema and protocol identifiers intact. Only filesystem
    # namespaces and the observer's service identity are relocated.
    text = text.replace('/etc/config/.homegate-projection.', '/etc/config/.homegate_engineering-projection.')
    text = text.replace('/etc/config/homegate','/etc/config/homegate_engineering')
    text = text.replace('/etc/homegate','/etc/homegate-engineering')
    text = text.replace('/var/run/homegate','/var/run/homegate-engineering')
    text = text.replace('/tmp/homegate-ddns-ui-','/tmp/homegate-engineering-ddns-ui-')
    text = text.replace('runtime="$runtime_base/homegate"','runtime="$runtime_base/homegate-engineering"')
    text = text.replace('/usr/libexec/homegate/config-transaction',
        '/usr/libexec/homegate-engineering/project/core/prototype/homegate-config-prototype.sh')
    text = text.replace('/usr/libexec/homegate/','/usr/libexec/homegate-engineering/')
    text = text.replace('/etc/init.d/homegate','/usr/libexec/homegate-engineering/service-disabled')
    text = text.replace('/usr/bin/homegate','/usr/bin/homegate-engineering')
    if Path(name).name == 'homegate-service-observer.lua':
        text = text.replace('doc.homegate','doc.homegate_engineering')
        text = text.replace("name~='homegate'", "name~='homegate_engineering'")
        text = text.replace('"homegate"','"homegate_engineering"')
    # The original single-provider experiments intentionally exclude the CF
    # receipt profile when using another provider. Select that same profile
    # internally, after parsing the fixed provider, for one multi-provider IPK.
    if Path(name).name == 'homegate-cloudflare-read.sh':
        anchor='watchdog_mode=--cloudflare-check\nif [ "$provider" = aliyun ]; then\n'
        if text.count(anchor)!=1: raise ValueError('Provider dispatch drift')
        text=text.replace(anchor,'[ "$provider" = cloudflare ] || dns_receipt_enabled=false\n'+anchor,1)
    if Path(name).name == 'homegate-service-observer-watchdog.sh':
        for provider in ['aliyun','dnspod','huaweicloud']:
            anchor='dns_provider='+provider+'\n'
            if text.count(anchor)!=1: raise ValueError('Watchdog provider drift')
            text=text.replace(anchor,'dns_provider='+provider+';dns_receipt_enabled=false\n')
    return text.encode('utf-8')

def payload(root):
    files={}
    for file in sorted((root/PROTO).iterdir()):
        if file.suffix in ('.sh','.lua'):
            files[PROTO+file.name]=render(file.name,file.read_bytes())
    for name in ['project/luci/lua/luasrc/model/homegate/backup.lua','VERSION','RELEASE']:
        files[name]=(root/name).read_bytes()
    return files

def stage(root, destination):
    for name, raw in payload(root).items():
        dest=destination/name;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(raw);dest.chmod(0o755 if name.endswith('.sh') else 0o644)

def web_payload(root):
    files={}
    for kind,name,dest in [
      ('controller','ddns.lua','usr/lib/lua/luci/controller/homegate_engineering_ddns.lua'),
      ('model','ddns.lua','usr/lib/lua/luci/model/homegate_engineering/ddns.lua'),
      ('view','ddns.htm','usr/lib/lua/luci/view/homegate_engineering/ddns.htm')]:
        text=(root/'project/luci/prototype/lua'/kind/name).read_text()
        text=text.replace('native_ddns_page_enabled=false','native_ddns_page_enabled=true')
        text=text.replace('native_ddns_ui_enabled=false','native_ddns_ui_enabled=true')
        text=text.replace('luci.controller.homegate_ddns','luci.controller.homegate_engineering_ddns')
        text=text.replace("'homegate'","'homegate_engineering'")
        text=text.replace('luci.model.homegate.','luci.model.homegate_engineering.')
        text=text.replace('homegate/ddns','homegate_engineering/ddns')
        text=text.replace('admin/services/homegate/','admin/services/homegate_engineering/')
        text=text.replace("local root='/usr/libexec/homegate'","local root='/usr/libexec/homegate-engineering/project/core/prototype'")
        text=text.replace('/ddns-ui ', '/homegate-ddns-ui.sh ')
        text=text.replace('/tmp/homegate-ddns-ui-','/tmp/homegate-engineering-ddns-ui-')
        text=text.replace('/homegate/ddns-ui.js','/homegate-engineering/ddns-ui.js')
        text=text.replace('/homegate_engineering/ddns-ui.js','/homegate-engineering/ddns-ui.js')
        if kind=='controller':
            text=text.replace("local h=require('luci.http');local d=", "local h=require('luci.http');local length=tonumber(h.getenv('CONTENT_LENGTH') or '0');if not length or length<0 or length>4096 then h.status(413,'Request Entity Too Large');return end;local d=")
        files[dest]=text.encode('utf-8')
    files['www/luci-static/resources/homegate-engineering/ddns-ui.js']=(root/'project/luci/prototype/js/ddns-ui.js').read_bytes()
    files['usr/lib/lua/luci/model/homegate_engineering/backup.lua']=(root/'project/luci/lua/luasrc/model/homegate/backup.lua').read_bytes()
    for name,dest in [('config-model.lua','usr/lib/lua/luci/model/homegate_engineering/configuration.lua'),
      ('configuration.htm','usr/lib/lua/luci/view/homegate_engineering/configuration.htm'),
      ('configuration.js','www/luci-static/resources/homegate-engineering/configuration.js')]:
        files[dest]=(root/'packaging/engineering/files'/name).read_bytes()
    return files
