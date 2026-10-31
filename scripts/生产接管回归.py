#!/usr/bin/env python3
"""Native production paths under the original unprivileged LuCI namespace.

Uses the actual staged scripts, fixed paths, UCI transaction and real pinned
LuCI/CSRF. No host installation, host service change or remote provider calls.
"""
import argparse,ast,hashlib,http.client,http.server,importlib.util,json,os,shutil,subprocess,sys,tempfile,threading,time,unittest
from pathlib import Path
from urllib.parse import urlencode
from project import ROOT
from production_runtime import payload,stage,stage_package,stage_installed
spec=importlib.util.spec_from_file_location('production_web',ROOT/'scripts/工程网页回归.py')
web=importlib.util.module_from_spec(spec);spec.loader.exec_module(web)
rpc,luci,STATE=web.rpc,web.luci,web.STATE
BASE='/cgi-bin/luci/admin/services/homegate';PAGE=BASE+'/configuration'
NGINX=ROOT/'build/nginx';FIXTURE=ROOT/'build/nginx-fixture';PROXY=False;INSTALLED=None
WOL=ROOT/'build/wol';WOL_FIXTURE=ROOT/'build/wol-fixture';ACTIONS=False
ACTION_GROUPS=('cli_actions','web_access_actions','web_maintenance_actions')

def setup_state(s):
    web.setup_state(s)
    curl=s/'curl-fixture';raw=curl.read_text();anchor="p=Path(sys.argv[sys.argv.index('--config')+1]);raw=p.read_text()"
    injected="""if '--config' not in sys.argv:
 u=sys.argv[-1];assert u in ['https://acme-v02.api.letsencrypt.org/directory','https://acme-staging-v02.api.letsencrypt.org/directory']
 host=u.rsplit('/',1)[0];bad=Path('/teststate/ca-bad').exists()
 print(json.dumps({'newNonce':('https://foreign.invalid' if bad else host)+'/nonce','newAccount':host+'/account','newOrder':host+'/order'}));sys.exit(0)
"""
    signed="""
if Path('/teststate/private-provider-fixture').exists():
 if 'alidns.aliyuncs.com' in raw:
  assert 'DescribeDomains' in raw and 'Signature' in raw
  print(json.dumps({'RequestId':'fixture','TotalCount':1,'PageNumber':1,'PageSize':100,'Domains':{'Domain':[{'DomainName':'example.test'}]}}));print('HGHTTP:200');sys.exit(0)
 if 'dnspod.tencentcloudapi.com' in raw:
  assert 'DescribeDomainList' in raw and 'TC3-HMAC-SHA256' in raw
  print(json.dumps({'Response':{'RequestId':'fixture','DomainCountInfo':{'DomainTotal':1},'DomainList':[{'Name':'example.test'}]}}));print('HGHTTP:200');sys.exit(0)
 if 'myhuaweicloud.com' in raw:
  assert '/v2/zones' in raw and 'SDK-HMAC-SHA256' in raw
  print(json.dumps({'zones':[{'id':'zone_1','name':'example.test.','zone_type':'public'}],'metadata':{'total_count':1}}));print('HGHTTP:200');sys.exit(0)
"""
    assert anchor in raw;curl.write_text(raw.replace(anchor,injected+anchor+signed))
    if ACTIONS:
        # Reuse the existing fixed external APNIC/RIPE transport fixture.
        source=ast.parse((ROOT/'scripts/工程代理回归.py').read_text())
        function=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='setup_state')
        snippet=next(n.value.value for n in ast.walk(function) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='injected' for t in n.targets))
        raw=curl.read_text();anchor="if '--config' not in sys.argv:\n";assert raw.count(anchor)==1;curl.write_text(raw.replace(anchor,snippet+anchor))
        for name in ['br-lan','eth1','eth2']:(s/'wol-sys-net'/name).mkdir(parents=True)
        (s/'wol-sys-net/br-lan/brif').mkdir()
        for name in ['eth1','eth2']:(s/'wol-sys-net/br-lan/brif'/name).touch()
        component=s/'libexec/homegate-wol';component.mkdir()
        (component/'send').write_text('#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\np=Path("/teststate/wol-mode")\nos.environ["HOMEGATE_WOL_FIXTURE_MODE"]=p.read_text() if p.exists() else "ok"\nos.environ["LD_PRELOAD"]='+repr(str(WOL_FIXTURE/'transport.so'))+'\nos.execv('+repr(str(WOL/'send'))+',["send",*sys.argv[1:]])\n')
        (component/'send').chmod(0o755)
    tree=s/'native-installed'
    if INSTALLED:
        receipt=stage_installed(ROOT,INSTALLED,tree)
        (s/'native-package-stage.json').write_text(json.dumps(receipt))
        shutil.copytree(tree/'usr/lib/lua/luci/i18n',s/'i18n')
        # The pinned host LuCI has no catalog directory. Compose an identical
        # private library tree with that mount point; never alter the runtime.
        shutil.copytree(luci.LUA/'prefix/lib/lua/luci',s/'luci-library')
        (s/'luci-library/i18n').mkdir(exist_ok=True)
    else:stage(ROOT,tree)
    old=s/'libexec/homegate'
    assert old.resolve().parent==(s/'libexec').resolve() and old.is_dir() and not old.is_symlink()
    shutil.rmtree(old)
    shutil.copytree(tree/'usr/libexec/homegate',s/'libexec/homegate')
    for part,origin in [('controllers','controller'),('models','model'),('view','view')]:
        shutil.copytree(tree/('usr/lib/lua/luci/'+origin),s/part,dirs_exist_ok=True)
    shutil.copytree(tree/'www',s/'www',dirs_exist_ok=True)
    for dest in [s/'usr-bin/homegate',s/'tools/homegate']:
        if dest.exists() or dest.is_symlink():dest.unlink()
        shutil.copyfile(tree/'usr/bin/homegate',dest);dest.chmod(0o755)
    (s/'etc/homegate').mkdir(mode=0o700)
    (s/'etc/rc.d').mkdir(exist_ok=True)
    (s/'var-log').mkdir(mode=0o700)
    (s/'view/footer.htm').write_text('<!-- fixture footer -->\n')
    (s/'etc/.homegate-transition').mkdir(mode=0o700)
    (s/'etc/config/homegate').write_bytes((ROOT/'packaging/engineering/files/homegate_engineering.config').read_bytes())
    (s/'etc/config/homegate').chmod(0o600)
    for name in ['etc/init.d/homegate','etc/hotplug.d/iface/95-homegate']:
        dest=s/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(tree/name,dest);dest.chmod(0o755)
    # Assert independence from the established engineering deployment.
    (s/'engineering-before').write_bytes((s/'etc/config/homegate_engineering').read_bytes())
    (s/'etc/rc.common').write_text('''#!/bin/sh
script=$1;shift
procd_open_instance(){ :; }
procd_set_param(){ printf '%s\\n' "$*" >> /teststate/procd-api; }
procd_close_instance(){
 if [ -f /var/run/homegate/native-service.lock ];then
  exec 8>>/var/run/homegate/native-service.lock
  if ! flock -n 8;then exec 8>&-;return 0;fi
  exec 8>&-
 fi
 /usr/bin/homegate daemon </dev/null >/teststate/procd-daemon-output 2>&1 &
}
procd_add_reload_trigger(){ :; }
start(){ start_service; }
. "$script"
case "${1:-}" in start) start_service;;stop) stop_service;;reload) reload_service;;enable) enable;;disable) disable;;enabled) enabled;;*) exit 2;;esac
''');(s/'etc/rc.common').chmod(0o755)
    if PROXY:
        (s/'etc/passwd').write_text((s/'etc/passwd').read_text()+'root:x:0:0:fixture:/tmp:/bin/false\n')
        (s/'etc/group').write_text((s/'etc/group').read_text()+'root:x:0:\n')
        component=s/'libexec/homegate-nginx';component.mkdir()
        (component/'nginx').write_text('#!/usr/bin/python3\nimport os,sys\na=sys.argv[1:]\nif "-g" in a:a[a.index("-g")+1]="daemon off; master_process on;"\nos.environ["LD_PRELOAD"]='+repr(str(FIXTURE/'same-credentials.so'))+'\nos.execv('+repr(str(NGINX/'nginx'))+',["nginx",*a])\n');(component/'nginx').chmod(0o755)
        (s/'tools/ip6tables').write_text((ROOT/'scripts/firewall-kernel-fixture.py').read_text().replace('HG_ENG_','HG_NATIVE_'));(s/'tools/ip6tables').chmod(0o755)
        (s/'fw-kernel.json').write_text(json.dumps({'nat':{'PREROUTING':[['-j','HOMEGATE_NAT']],'HOMEGATE_NAT':[['-j','RETURN']]},'filter':{'INPUT':[['-j','HOMEGATE_INPUT']],'HOMEGATE_INPUT':[['-j','RETURN']]}}))

class Native(web.Web):
    def tearDown(self):
        owner=getattr(self,'owner',None)
        if owner and owner.poll() is None:
            subprocess.run(['/usr/bin/homegate','service-stop','--confirm'],capture_output=True,timeout=20)
            owner.wait(timeout=25)
        if Path('/var/run/homegate/native-service.lock').exists():
            subprocess.run(['/usr/bin/homegate','service-stop','--confirm'],capture_output=True,timeout=20)
        super().tearDown()
    def cli(self,*args,ok=True):
        p=subprocess.run(['/usr/bin/homegate',*args],capture_output=True,timeout=75 if args and args[0] in ['cert-renew','access-update','access-refresh'] else 18)
        if ok and p.returncode and args and args[0] in ['firewall-apply','firewall-cleanup']:
            # Failure-only public state: no raw admission token/configuration.
            detail={'command':args[0],'exit':p.returncode}
            for name in ['desired.json','report.json','reply']:
                try:
                    with Path('/var/run/homegate/firewall',name).open('rb') as f:raw=f.read(32769)
                    d=json.loads(raw) if len(raw)<=32768 else {}
                    detail[name]={k:d[k] for k in ['ok','known','active','state','enabled','reconcile','failure','error_kind'] if k in d}
                except (OSError,ValueError,TypeError):detail[name]='unavailable'
            detail['locks']=Path('/proc/locks').read_text()[:4096]
            print('FIREWALL_FAILURE_STATE:'+json.dumps(detail),flush=True)
        self.assertEqual(p.returncode==0,ok,(args,p.returncode,p.stdout[:400]))
        d=json.loads(p.stdout);self.assertNotIn('SECRET_SENTINEL',p.stdout.decode())
        if INSTALLED:print('PACKAGE_CLI:'+json.dumps({'command':args[0],'arity':len(args)-1,'exit_code':p.returncode,'ok':d.get('ok'),'fields':sorted(d)}),flush=True)
        return d
    def api(self,area,action,session=None,fields=None,expected=200,verb=None):
        sid,token=session if session else (None,None);form=dict(fields or {})
        write=action not in ['service_status','backup_export','read','status','jobs','schedule_status','lifecycle_status','cert_status','acme_status','acme_status','acme_schedule_status']
        if write and token:form['token']=token
        path=BASE+'/'+area+'/'+action
        if not write and form:path+='?'+urlencode(form);form={}
        status,_,body=self.cgi(path,cookie=sid,verb=verb or ('POST' if write else 'GET'),fields=form)
        self.assertEqual(status,expected,(action,status,body[:400] if b'SECRET_SENTINEL' not in body else b'[redacted]'))
        self.assertNotIn(b'SECRET_SENTINEL',body)
        if expected!=200:return None
        d=json.loads(body);self.assertTrue(d['ok'],d);return d
    def verify_unchanged(self,allow_provider_calls=False):
        self.assertEqual(Path('/etc/config/homegate_engineering').read_bytes(),(STATE/'engineering-before').read_bytes())
        if not allow_provider_calls:self.assertFalse((STATE/'provider-calls').exists())
        self.assertEqual(list(Path('/tmp').glob('homegate-web-*')),[])
        for n,raw in payload(ROOT).items():
            if n.startswith('usr/libexec/homegate/'):
                self.assertEqual(Path('/'+n).read_bytes(),raw,n)
        for key in ['CapEff','CapPrm','CapBnd']:
            line=next(x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith(key+':'))
            self.assertEqual(int(line.split(':')[1].strip(),16),0)
    def backup(self,s):
        d=self.cfg('backup_export',s);self.assertFalse(d['secrets_included']);self.assertNotIn('SECRET_SENTINEL',d['backup']);return d['backup']
    def test_migration(self):
        source,_=self.production_fixture();legacy=source.read_bytes();s=self.login();self.cfg('prepare',s)
        p=self.cfg('production_copy_preview',s)['report'];self.assertEqual(p['operation'],'migration-source')
        self.api('configuration_api','apply',s,{'confirmation':p['confirmation'],'consent':'1'},expected=503)
        source.write_bytes(legacy+b'\n')
        self.api('configuration_api','production_copy_commit',s,{'confirmation':p['confirmation'],'consent':'1'},expected=503)
        source.write_bytes(legacy)
        d=self.cfg('production_copy_commit',s,confirmation=p['confirmation'],consent='1')['report'];self.assertTrue(d['migration_copied'])
        self.assertEqual(source.read_bytes(),legacy)
        store=Path('/etc/homegate/transactions');generation=store/('gen-'+(store/'current').read_text().strip())
        self.assertEqual((generation/'legacy.conf').read_bytes(),legacy)
        self.assertEqual((generation/'credentials/cloudflare.dns_a.secret').read_bytes(),b'SECRET_SENTINEL')
        self.publish(s);self.assertNotIn(b'SECRET_SENTINEL',source.read_bytes())
        self.assertEqual(source.read_bytes(),self.backup(s).encode());self.assertFalse((store/'ddns-authority').exists())
        for p in store.rglob('*'):self.assertEqual(p.stat().st_mode&0o777,0o700 if p.is_dir() else 0o600)
        self.assertEqual(self.cli('version')['version'],'1.3.0-r'+(ROOT/'RELEASE').read_text().strip())
        self.verify_unchanged()
    def configured(self):
        s=self.login();self.prepare_account(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);return s
    def test_backup(self):
        s=self.configured();original=self.backup(s);source=Path('/etc/config/homegate');before=source.read_bytes()
        large=original+('# '+('a'*64)+'\n')*1800
        self.assertGreater(len(large),102400)
        self.cfg('backup_preview',s,backup=large);self.cfg('cancel',s)
        candidate=original.replace('DNS account','<script>changed</script>')
        self.assertNotEqual(candidate,original)
        p=self.cfg('backup_preview',s,backup=candidate)['report'];self.assertEqual(source.read_bytes(),before)
        self.api('configuration_api','apply',s,{'confirmation':p['confirmation']},expected=503)
        self.cfg('apply',s,confirmation=p['confirmation'],consent='1')
        self.assertIn('<script>changed</script>',self.backup(s));self.assertNotIn(b'SECRET_SENTINEL',source.read_bytes())
        store=Path('/etc/homegate/transactions');self.assertEqual((store/('gen-'+(store/'current').read_text().strip())/'credentials/cloudflare.dns_a.secret').read_bytes(),b'SECRET_SENTINEL')
        self.api('configuration_api','apply',s,{'confirmation':p['confirmation'],'consent':'1'},expected=503)
        self.cfg('backup_preview',s,backup=original);self.cfg('cancel',s)
        self.assertIn('<script>changed</script>',self.backup(s))
        p=self.cfg('backup_preview',s,backup=original+"\nconfig dns_account 'dns_b'\n option name 'Missing credentials'\n option provider 'cloudflare'\n")
        self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
        generation=store/('gen-'+(store/'current').read_text().strip())
        self.assertFalse((generation/'credentials/cloudflare.dns_b.secret').exists())
        self.assertFalse((store/'ddns-authority').exists());self.verify_unchanged()
    def test_rollback(self):
        s=self.configured();store=Path('/etc/homegate/transactions');ancestor=(store/'current').read_text().strip();original=self.backup(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECOND_SECRET_SENTINEL',consent='1');self.publish(s)
        p=self.cfg('backup_preview',s,backup=original.replace('DNS account','Later account'))
        self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
        p=self.cfg('rollback_preview',s,generation=ancestor);self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
        self.assertEqual(self.backup(s),original)
        self.assertEqual((store/('gen-'+(store/'current').read_text().strip())/'credentials/cloudflare.dns_a.secret').read_bytes(),b'SECRET_SENTINEL')
        current=(store/'current').read_text().strip()
        self.api('configuration_api','rollback_preview',s,{'generation':current},expected=503)
        self.api('configuration_api','rollback_preview',s,{'generation':'32'},expected=503)
        self.cli('config-rollback-preview','../1',ok=False);self.verify_unchanged()
    def test_recovery(self):
        s=self.configured();old=self.backup(s);source=Path('/etc/config/homegate')
        p=self.cfg('backup_preview',s,backup=old.replace('DNS account','Recover account'))
        tool=STATE/'tools/fsync';tool.unlink();tool.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/config/.homegate-projection.*) exit 1;; esac\nexec /usr/sbin/busybox fsync "$@"\n');tool.chmod(0o755)
        status,_,body=self.cgi(BASE+'/configuration_api/apply',cookie=s[0],verb='POST',fields={'token':s[1],'confirmation':p['report']['confirmation'],'consent':'1'})
        self.assertEqual(status,503);d=json.loads(body);handle=d['report']['apply_handle'];self.assertTrue(d['report']['application_pending'])
        self.assertEqual(source.read_bytes(),old.encode());self.assertTrue(Path('/etc/homegate/transactions/application').exists())
        tool.unlink();tool.symlink_to('busybox')
        self.cfg('finish',s,confirmation=handle,consent='1');self.assertIn('Recover account',self.backup(s))
        p=self.cfg('backup_preview',s,backup=old)
        tool.unlink();tool.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/config/.homegate-projection.*) exit 1;; esac\nexec /usr/sbin/busybox fsync "$@"\n');tool.chmod(0o755)
        self.api('configuration_api','apply',s,{'confirmation':p['report']['confirmation'],'consent':'1'},expected=503)
        tool.unlink();tool.symlink_to('busybox');self.cfg('recover',s,consent='1')
        self.assertIn('Recover account',self.backup(s));self.assertFalse(Path('/etc/homegate/transactions/application').exists());self.verify_unchanged()
    def test_security(self):
        s=self.configured();source=Path('/etc/config/homegate');before=source.read_bytes();old=self.backup(s)
        self.api('configuration_api','backup_preview',None,{'backup':old},expected=403)
        self.api('configuration_api','backup_preview',s,{'backup':old},expected=405,verb='GET')
        status,_,_=self.cgi(BASE+'/configuration_api/backup_preview',cookie=s[0],verb='POST',fields={'backup':old,'token':'bad'});self.assertEqual(status,403)
        for bad in [old.replace('# plugin: homegate','# plugin: other'),old+"\nconfig dns_account 'foreign'\n option secret 'SECRET_SENTINEL'\n",'x'*262145]:
            self.api('configuration_api','backup_preview',s,{'backup':bad},expected=503)
        for generation in ['0','01','-1','33','../1']:
            self.api('configuration_api','rollback_preview',s,{'generation':generation},expected=503)
        self.assertEqual(source.read_bytes(),before);self.verify_unchanged()
    def test_diagnostics(self):
        s=self.configured()
        for command,field in [('dns-provider-catalog','providers'),('acme-ca-catalog','cas')]:
            self.assertTrue(self.cli(command)[field])
        status=self.cli('status');self.assertFalse(status['service']['running'])
        self.assertEqual(status['service']['healthy'],status['service']['configured'] and not status['service']['enabled'])
        p=subprocess.run(['/usr/bin/homegate','check'],capture_output=True,timeout=18)
        self.assertIn(p.returncode,[0,1]);self.assertEqual(p.returncode==0,json.loads(p.stdout)['ok'])
        for command in ['network-resolve','recovery-status','ddns-status','wol-status']:
            self.assertEqual(self.cli(command)['api_version'],1)
        self.verify_unchanged()
    def start_owner(self):
        self.owner=subprocess.Popen(['/usr/bin/homegate','daemon'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return self.owner
    def wait_service(self,predicate,seconds=15):
        deadline=time.monotonic()+seconds;last=None
        while time.monotonic()<deadline:
            p=Path('/var/run/homegate/native-service.json')
            if p.exists():
                try:last=json.loads(p.read_text())
                except ValueError:pass
                if last and predicate(last):return last
            if getattr(self,'owner',None) and self.owner.poll() is not None:break
            time.sleep(.1)
        probe=subprocess.run(['/usr/bin/homegate','schedule-status'],capture_output=True,timeout=8)
        try:
            d=json.loads(probe.stdout);ddns={k:d.get(k) for k in ['phase','status','reason','running','ticks','last_effect']}
        except ValueError:ddns={'unavailable':True}
        processes=[]
        for p in Path('/proc').glob('[0-9]*'):
            try:
                raw=(p/'cmdline').read_bytes().split(b'\0');names=[Path(x.decode()).name for x in raw[:3] if x]
                tail=(p/'stat').read_text().rsplit(') ',1)[1].split()
                if any(n.endswith('.sh') or n.endswith('.lua') for n in names) or names and names[0] in ['sleep','busybox','lua5.1']:
                    processes.append({'pid':p.name,'ppid':tail[1],'state':tail[0],'modules':[n for n in names if n.endswith(('.sh','.lua'))],'wait':(p/'wchan').read_text().strip()})
            except (OSError,ValueError,UnicodeError):pass
        self.fail({'service':last,'ddns':ddns,'provider_called':(STATE/'provider-calls').exists(),'processes':processes,'owner_rc':self.owner.poll() if getattr(self,'owner',None) else None,'firewall':{p.name:p.read_text()[:2000] for p in Path('/var/run/homegate/firewall').glob('*.json')},'kernel_calls':(STATE/'fw-calls').read_text()[-4000:] if (STATE/'fw-calls').exists() else None})
    def enable_owner(self):
        s=self.configured();self.cfg('lifecycle_enable',s,consent='1');return s
    def test_daemon(self):
        s=self.enable_owner();self.cli('service-plan-set','-','-','-','open','--confirm')
        self.start_owner();d=self.wait_service(lambda d:d['state']=='running');self.assertTrue(d['healthy'])
        status=self.cli('status');self.assertTrue(status['service']['running'],status);self.assertTrue(status['service']['enabled'],status);self.assertTrue(status['service']['healthy'],status)
        self.cli('service-quiescent',ok=False)
        # A second canonical foreground daemon must not acquire or replace it.
        duplicate=subprocess.run(['/usr/bin/homegate','daemon'],capture_output=True,timeout=10);self.assertEqual(duplicate.returncode,1)
        self.assertEqual(self.cli('status')['coordinator']['state'],'running')
        # Exercise the actual rc.common service body with external procd API capture.
        shell="""procd_open_instance(){ echo open; };procd_set_param(){ printf '%s\\n' \"$*\"; };procd_close_instance(){ echo close; };. /etc/init.d/homegate; stop_service; start_service"""
        p=subprocess.run(['/usr/sbin/ash','-c',shell],capture_output=True,timeout=30);self.assertEqual(p.returncode,0,p.stdout);self.assertIn(b'command /usr/bin/homegate daemon',p.stdout)
        self.owner.wait(timeout=20);self.assertEqual(self.owner.returncode,0);self.assertFalse(self.cli('status')['service']['running']);self.cli('service-quiescent')
        self.verify_unchanged()
    def test_daemon_ddns(self):
        s=self.enable_owner();self.rule(s)
        # Applying a changed generation requires a new explicit source intent.
        self.cfg('lifecycle_enable',s,consent='1')
        p=self.cli('grant-preview','ddns_a');self.cli('grant-commit',p['confirmation'])
        self.cli('service-plan-set','ddns_a','-','-','open','--confirm')
        grant=Path('/etc/homegate/transactions/ddns-authority').read_bytes()
        self.start_owner();self.wait_service(lambda d:d['state']=='running',seconds=30)
        deadline=time.monotonic()+30
        while time.monotonic()<deadline and not (STATE/'provider-calls').exists():time.sleep(.1)
        self.assertTrue((STATE/'provider-calls').exists());self.assertEqual(Path('/etc/homegate/transactions/ddns-authority').read_bytes(),grant)
        self.cli('schedule-event','ifupdate','wan6','pppoe-wan')
        self.cli('service-stop','--confirm');self.owner.wait(timeout=20);self.assertEqual(self.owner.returncode,0);self.cli('service-quiescent')
        calls=(STATE/'provider-calls').read_bytes();time.sleep(.3);self.assertEqual((STATE/'provider-calls').read_bytes(),calls)
        # Durable configuration/authorization survive a new coordinator instance.
        self.start_owner();self.wait_service(lambda d:d['state']=='running');self.cli('service-stop','--confirm');self.owner.wait(timeout=20)
        self.assertEqual(Path('/etc/homegate/transactions/ddns-authority').read_bytes(),grant)
    def test_daemon_source(self):
        s=self.enable_owner();self.cli('service-plan-set','-','-','-','open','--confirm');self.start_owner();self.wait_service(lambda d:d['state']=='running')
        receipt=lambda:subprocess.run(['/usr/sbin/ash','/usr/libexec/homegate/native-service.sh','receipt',Path('/etc/homegate/transactions/current').read_text().strip()],capture_output=True,timeout=8)
        self.assertEqual(receipt().returncode,0)
        public=Path('/etc/config/homegate');before=public.read_bytes();public.write_bytes(before+b'\n')
        self.assertNotEqual(receipt().returncode,0)
        d=self.wait_service(lambda d:d['state']=='restart_required');self.owner.wait(timeout=20);self.assertEqual(self.owner.returncode,1)
        self.assertEqual(d['reason'],'source_changed');self.assertFalse((STATE/'provider-calls').exists())
        public.write_bytes(before)
        self.cli('service-plan-set','../x','-','-','open','--confirm',ok=False);self.verify_unchanged()
    def test_daemon_component_failure(self):
        import signal
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body=b'NATIVE_COMPONENT_RECOVERY';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*a):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start();self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        canary=subprocess.Popen(['/usr/sbin/busybox','sleep','85'],start_new_session=True)
        def stop_canary():
            if canary.poll() is None:canary.terminate()
            canary.wait(timeout=3)
        self.addCleanup(stop_canary)
        session=self.configured();p=self.cfg('preview_web_rule',session,id='plain',domain='example.test',https='0',certificate='')
        self.cfg('apply',session,confirmation=p['report']['confirmation'],consent='1');self.cfg('web_target_put',session,id='plain',value='http://127.0.0.1:'+str(server.server_port),consent='1')
        public=self.backup(session);lines=public.splitlines()
        for n,line in enumerate(lines):
            if line.strip().startswith("option 'http_port'") or line.strip().startswith('option http_port'):lines[n]="\toption http_port '18080'"
        p=self.cfg('backup_preview',session,backup='\n'.join(lines)+'\n');self.cfg('apply',session,confirmation=p['report']['confirmation'],consent='1');self.publish(session);self.cfg('lifecycle_enable',session,consent='1')
        self.cli('service-plan-set','-','-','plain','open','--confirm')
        store=Path('/etc/homegate/transactions');before={str(p.relative_to(store)):p.read_bytes() for p in store.rglob('*') if p.is_file()}
        source=Path('/etc/config/homegate').read_bytes();plan=Path('/etc/homegate/native-service-plan').read_bytes()
        self.start_owner();first=self.wait_service(lambda d:d['state']=='running',seconds=30)
        self.assertTrue(self.cli('status')['service']['healthy']);self.assertTrue(self.cli('firewall-status')['active'])
        def request():
            conn=http.client.HTTPConnection('127.0.0.1',10080,timeout=5);conn.request('GET','/',headers={'Host':'example.test'});response=conn.getresponse();self.assertEqual(response.status,200);self.assertEqual(response.read(),b'NATIVE_COMPONENT_RECOVERY');conn.close()
        request();proxy=Path('/var/run/homegate/proxy');owner,birth=(proxy/'owner').read_text().strip().split(':');pid=(proxy/'nginx.pid').read_text().strip()
        def info(pid):
            p=subprocess.run(['/usr/sbin/lua','/usr/libexec/homegate/project/core/prototype/worker-process.lua','info',str(pid),'none'],capture_output=True,timeout=5);self.assertEqual(p.returncode,0);return p.stdout.decode().strip().split(':')
        parent=info(owner);master=info(pid);self.assertEqual(parent[4],birth);self.assertEqual(master[1:4],[owner,owner,owner]);self.assertNotEqual(int(pid),canary.pid)
        os.kill(int(pid),signal.SIGKILL)
        failed=self.wait_service(lambda d:d['state']=='failed',seconds=25);self.owner.wait(timeout=20);self.assertEqual(self.owner.returncode,1);self.assertEqual(failed['reason'],'proxy_stopped')
        status=self.cli('status');self.assertFalse(status['service']['running']);self.assertFalse(status['service']['healthy']);self.assertTrue(status['service']['enabled']);self.cli('service-quiescent')
        kernel=json.loads((STATE/'fw-kernel.json').read_text());self.assertNotIn('HG_NATIVE_NAT',kernel['nat']);self.assertNotIn('HG_NATIVE_INPUT',kernel['filter']);self.assertEqual(kernel['nat']['HOMEGATE_NAT'],[['-j','RETURN']]);self.assertFalse(Path('/etc/homegate/firewall-owned').exists());self.assertIsNone(canary.poll())
        self.assertEqual(Path('/etc/config/homegate').read_bytes(),source);self.assertEqual(Path('/etc/homegate/native-service-plan').read_bytes(),plan);self.assertEqual({str(p.relative_to(store)):p.read_bytes() for p in store.rglob('*') if p.is_file()},before)
        self.action_result('component-crash-contained',master_identity_verified=True,coordinator_failed=True,managed_rules_removed=True,legacy_rules_and_canary_preserved=True,configuration_and_credentials_retained=True)
        self.start_owner();recovered=self.wait_service(lambda d:d['state']=='running',seconds=30);self.assertNotEqual(recovered['pid'],first['pid']);self.assertNotEqual((proxy/'owner').read_text().strip().split(':')[0],owner)
        request();self.assertTrue(self.cli('status')['service']['healthy']);self.assertTrue(self.cli('firewall-status')['active']);self.assertIsNone(canary.poll())
        self.cli('service-stop','--confirm');self.owner.wait(timeout=20);self.assertEqual(self.owner.returncode,0);self.cli('service-quiescent')
        self.assertFalse((STATE/'provider-calls').exists());self.assertFalse((STATE/'acme-fixture.json').exists());self.assertEqual(Path('/etc/config/homegate').read_bytes(),source);self.assertEqual(Path('/etc/homegate/native-service-plan').read_bytes(),plan)
        self.assertEqual({str(p.relative_to(store)):p.read_bytes() for p in store.rglob('*') if p.is_file()},before)
        self.action_result('component-explicit-recovery',fresh_owner_and_listener=True,healthy_after_restart=True,normal_stop_after_recovery=True,no_DNS_or_ACME_replay=True,real_procd_and_device_verified=False);self.verify_unchanged()
    def test_daemon_security(self):
        s=self.configured();self.cli('daemon',ok=False);self.assertFalse(Path('/var/run/homegate/native-service.lock').exists())
        self.cfg('lifecycle_enable',s,consent='1');self.cli('service-plan-set','-','-','-','open','--confirm')
        target=STATE/'keep-service';target.write_text('KEEP');Path('/var/run/homegate/native-service.lock').symlink_to(target)
        self.cli('daemon',ok=False);self.assertEqual(target.read_text(),'KEEP');self.assertFalse((STATE/'provider-calls').exists())
        Path('/var/run/homegate/native-service.lock').unlink()
        plan=Path('/etc/homegate/native-service-plan');body=plan.read_text();data=json.loads(body);data['source_binding']='changed';plan.write_text(json.dumps(data))
        self.cli('daemon',ok=False);self.assertFalse((STATE/'provider-calls').exists());plan.write_text(body)
        marker=Path('/etc/homegate/package-state');marker.write_text('HGPKG1\nstopping\n0\n0\n');marker.chmod(0o600)
        self.cli('service-plan-set','-','-','-','open','--confirm',ok=False)
        self.api('configuration_api','preview_account',s,{'id':'dns_b','name':'Blocked','provider':'cloudflare'},expected=503)
        self.assertEqual(plan.read_text(),body);self.assertFalse(Path('/etc/homegate/transactions/ddns-authority').exists())
        marker.unlink();self.verify_unchanged()
    def test_daemon_web(self):
        s=self.enable_owner()
        fields={'service_ddns':'-','service_certs':'-','service_web':'-','policy':'open','consent':'1'}
        self.api('configuration_api','service_plan_set',None,fields,expected=403)
        self.api('configuration_api','service_plan_set',s,fields,expected=405,verb='GET')
        self.cfg('service_plan_set',s,**fields);self.assertFalse(Path('/etc/homegate/transactions/ddns-authority').exists())
        self.cfg('service_start',s,consent='1');self.wait_service(lambda d:d['state']=='running')
        self.assertTrue(self.cfg('service_status',s)['report']['service']['healthy'])
        self.cfg('service_start',s,consent='1');self.assertTrue(self.cfg('service_status',s)['report']['service']['running'])
        self.cfg('service_stop',s,consent='1');self.wait_service(lambda d:d['state']=='stopped');self.cli('service-quiescent');self.verify_unchanged()
    def test_daemon_acme(self):
        s=self.acme_setup();self.cfg('lifecycle_enable',s,consent='1')
        self.cli('service-plan-set','-','cert_a','-','open','--confirm');self.start_owner()
        self.wait_service(lambda d:d['state']=='running',seconds=65)
        status=self.cfg('cert_status',s,id='cert_a')['report'];self.assertTrue(status['valid'])
        self.assertTrue(self.cli('cert-status')['certificates'][0]['valid'])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['orders']),1);self.assertEqual(db['records'],[])
        self.cli('service-stop','--confirm');self.owner.wait(timeout=20);self.cli('service-quiescent');self.verify_unchanged()
    def test_daemon_acme_unknown(self):
        s=self.acme_setup();(STATE/'acme-mode').write_text('dns-unknown');self.cfg('lifecycle_enable',s,consent='1')
        self.cli('service-plan-set','-','cert_a','-','open','--confirm');self.start_owner()
        self.wait_service(lambda d:d['state']=='failed',seconds=30);self.owner.wait(timeout=25);self.assertNotEqual(self.owner.returncode,0)
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertTrue(db['records']);self.cli('daemon',ok=False)
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db);self.cli('service-quiescent',ok=False)
    def test_daemon_proxy(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body=b'NATIVE_COORDINATOR_PROXY';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*a):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start();self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        s=self.configured();p=self.cfg('preview_web_rule',s,id='plain',domain='example.test',https='0',certificate='')
        self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
        self.cfg('web_target_put',s,id='plain',value='http://127.0.0.1:'+str(server.server_port),consent='1')
        public=self.backup(s);lines=public.splitlines()
        for i,line in enumerate(lines):
            if line.strip().startswith("option 'http_port'") or line.strip().startswith('option http_port'):lines[i]="\toption http_port '18080'"
        candidate='\n'.join(lines)+'\n';self.assertNotEqual(candidate,public)
        preview=self.cfg('backup_preview',s,backup=candidate);self.cfg('apply',s,confirmation=preview['report']['confirmation'],consent='1')
        self.publish(s);self.cfg('lifecycle_enable',s,consent='1')
        self.cli('service-plan-set','-','-','plain','open','--confirm');self.start_owner();self.wait_service(lambda d:d['state']=='running',seconds=30)
        public_status=self.cli('proxy-status')
        if not public_status['http_listening']:
            root=Path('/var/run/homegate/proxy');pid=(root/'nginx.pid').read_text().strip();owner=(root/'owner').read_text().strip().split(':')[0]
            print('LISTENER_PROOF_DIAGNOSTIC:'+json.dumps({'pid_mode':oct((root/'nginx.pid').stat().st_mode&0o777),'owner':owner,'pid':pid,'stat':Path('/proc',pid,'stat').read_text(),'owner_stat':Path('/proc',owner,'stat').read_text(),'cmdline':Path('/proc',pid,'cmdline').read_bytes().replace(b'\0',b'|').decode(errors='replace'),'fds':[os.readlink(p) for p in Path('/proc',pid,'fd').iterdir()],'tcp':Path('/proc/net/tcp').read_text(),'tcp6':Path('/proc/net/tcp6').read_text()},sort_keys=True),flush=True)
        self.assertTrue(public_status['http_listening'],public_status);self.assertFalse(public_status['https_listening']);self.assertEqual(public_status['http_port'],10080)
        pidfile=Path('/var/run/homegate/proxy/nginx.pid');saved_pid=pidfile.read_bytes();pidfile.write_text(str(os.getpid())+'\n')
        self.assertFalse(self.cli('proxy-status')['http_listening']);pidfile.write_bytes(saved_pid);self.assertTrue(self.cli('proxy-status')['http_listening'])
        conn=http.client.HTTPConnection('127.0.0.1',10080,timeout=5);conn.request('GET','/',headers={'Host':'example.test'})
        response=conn.getresponse();self.assertEqual(response.status,200);self.assertEqual(response.read(),b'NATIVE_COORDINATOR_PROXY');conn.close()
        conn=http.client.HTTPConnection('127.0.0.1',10080,timeout=5,source_address=('127.0.0.2',0));conn.request('GET','/',headers={'Host':'example.test'});response=conn.getresponse();self.assertEqual(response.status,200);response.read();conn.close()
        def audit(predicate):
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                rows=self.cli('access-recent')['entries']
                if predicate(rows):return rows
                time.sleep(.1)
            self.fail(('Audit observation timeout',rows))
        audit(lambda rows:len(rows)==2)
        self.assertEqual(len(self.cli('access-clear-entry','127.0.0.1','EXAMPLE.TEST.')['entries']),1)
        rows=audit(lambda rows:len(rows)==1);self.assertEqual(rows[0]['ip'],'127.0.0.2')
        conn=http.client.HTTPConnection('::1',10080,timeout=5);conn.request('GET','/',headers={'Host':'example.test'});response=conn.getresponse();self.assertEqual(response.status,200);response.read();conn.close()
        audit(lambda rows:len(rows)==2)
        rows=self.cli('access-clear-entry','0:0:0:0:0:0:0:1','example.test')['entries'];self.assertEqual(len(rows),1);self.assertEqual(rows[0]['ip'],'127.0.0.2')
        self.assertEqual(self.cli('access-clear-denied')['entries'],rows)
        self.assertEqual(self.cli('access-clear-all')['entries'],[])
        rules=json.loads((STATE/'fw-kernel.json').read_text());self.assertIn('HG_NATIVE_NAT',rules['nat']);self.assertEqual(rules['nat']['HOMEGATE_NAT'],[['-j','RETURN']])
        self.cli('service-stop','--confirm');self.owner.wait(timeout=20);self.cli('service-quiescent')
        rules=json.loads((STATE/'fw-kernel.json').read_text());self.assertNotIn('HG_NATIVE_NAT',rules['nat']);self.assertEqual(rules['nat']['HOMEGATE_NAT'],[['-j','RETURN']]);self.verify_unchanged()
    def test_cli_firewall(self):
        import fcntl
        session=self.configured();kernel=STATE/'fw-kernel.json';baseline=json.loads(kernel.read_text())
        self.cli('firewall-apply',ok=False);self.assertEqual(json.loads(kernel.read_text()),baseline)
        idle=self.cli('firewall-cleanup');self.assertTrue(idle['known']);self.assertFalse(idle['active'])
        p=self.cfg('preview_web_rule',session,id='plain',domain='example.test',https='0',certificate='')
        self.cfg('apply',session,confirmation=p['report']['confirmation'],consent='1');self.cfg('web_target_put',session,id='plain',value='http://127.0.0.1:9',consent='1')
        public=self.backup(session);lines=public.splitlines()
        for n,line in enumerate(lines):
            if line.strip().startswith("option 'http_port'") or line.strip().startswith('option http_port'):lines[n]="\toption http_port '18080'"
        candidate='\n'.join(lines)+'\n';self.assertNotEqual(candidate,public)
        p=self.cfg('backup_preview',session,backup=candidate);self.cfg('apply',session,confirmation=p['report']['confirmation'],consent='1');self.publish(session);self.cfg('lifecycle_enable',session,consent='1')
        self.cli('proxy-start','plain','open','--confirm');deadline=time.monotonic()+12
        while self.cli('proxy-status')['state']!='running':self.assertLess(time.monotonic(),deadline);time.sleep(.1)
        applied=self.cli('firewall-apply');self.assertTrue(applied['known']);self.assertTrue(applied['active']);self.assertEqual(applied['wan_device'],'pppoe-wan')
        active=json.loads(kernel.read_text());self.assertEqual(active['nat']['HG_NATIVE_NAT'],[['-i','pppoe-wan','-p','tcp','--dport','18080','-j','REDIRECT','--to-ports','10080']])
        self.assertEqual(active['filter']['HG_NATIVE_INPUT'],[['-i','pppoe-wan','-p','tcp','--dport','10080','-j','ACCEPT']])
        self.cli('firewall-apply');self.assertEqual(json.loads(kernel.read_text()),active)
        marker=Path('/etc/homegate/firewall-owned');self.assertTrue(marker.is_file())
        for table,parent,chain,extra in [('nat','PREROUTING','HG_NATIVE_NAT',['-i','br-lan','-j','HG_NATIVE_NAT']),('filter','INPUT','HG_NATIVE_INPUT',['-i','br-lan','-j','HG_NATIVE_INPUT']),('nat','PREROUTING','HG_NATIVE_NAT',['-g','HG_NATIVE_NAT']),('filter','THIRD_PARTY_FILTER','HG_NATIVE_INPUT',['-j','HG_NATIVE_INPUT'])]:
            before=json.loads(kernel.read_text());new_parent=parent not in before[table];before[table].setdefault(parent,[]).append(extra);kernel.write_text(json.dumps(before))
            refused=self.cli('firewall-cleanup',ok=False);self.assertFalse(refused['known']);self.assertEqual(refused['error_kind'],'foreign_reference');self.assertEqual(json.loads(kernel.read_text()),before);self.assertTrue(marker.is_file())
            before[table][parent].remove(extra)
            if new_parent:del before[table][parent]
            kernel.write_text(json.dumps(before))
        self.action_result('firewall-foreign-reference',both_tables_refused=True,goto_and_other_chain_refused=True,entire_kernel_model_retained=True,owner_marker_retained=True)
        with Path('/var/run/homegate/firewall.lock').open('ab') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);before=kernel.read_bytes();calls=(STATE/'fw-calls').read_bytes()
            self.cli('firewall-apply',ok=False);self.cli('firewall-cleanup',ok=False);self.assertEqual(kernel.read_bytes(),before);self.assertEqual((STATE/'fw-calls').read_bytes(),calls)
        saved=marker.with_name('.saved-firewall-owner');self.assertFalse(saved.exists());marker.rename(saved);marker.symlink_to(saved)
        before=kernel.read_bytes();self.cli('firewall-cleanup',ok=False);self.assertEqual(kernel.read_bytes(),before);marker.unlink();saved.rename(marker)
        # Duplicate exact owned jumps may be removed; legacy chains remain.
        duplicate=json.loads(kernel.read_text());duplicate['nat']['PREROUTING'].append(['-j','HG_NATIVE_NAT']);kernel.write_text(json.dumps(duplicate))
        self.cli('firewall-cleanup');self.assertEqual(json.loads(kernel.read_text()),baseline);self.assertFalse(marker.exists())
        self.cli('firewall-cleanup');self.assertEqual(json.loads(kernel.read_text()),baseline)
        self.action_result('firewall-direct-success-and-ownership',exact_rules=True,idempotent_apply_and_cleanup=True,duplicate_owned_jumps_removed=True,legacy_chains_preserved=True,concurrent_owner_refused=True,unsafe_marker_refused=True)
        fault=STATE/'fw-fault';fault.write_text('fail-once');failed=self.cli('firewall-apply',ok=False)
        self.assertTrue(failed['known']);self.assertFalse(failed['active']);self.assertEqual(failed['state'],'apply_failed_clean');self.assertEqual(json.loads(kernel.read_text()),baseline);self.assertTrue(marker.exists())
        self.cli('firewall-cleanup');self.cli('firewall-apply');before=json.loads(kernel.read_text());fault.write_text('cleanup-fail')
        failed=self.cli('firewall-cleanup',ok=False);self.assertFalse(failed['known']);self.assertEqual(json.loads(kernel.read_text()),before);self.assertTrue(marker.exists());fault.unlink()
        self.cli('firewall-cleanup');self.assertEqual(json.loads(kernel.read_text()),baseline);self.assertFalse(marker.exists())
        fault.write_text('permission');unknown=self.cli('firewall-status');self.assertFalse(unknown['known']);self.assertFalse(unknown['ok']);self.assertEqual(json.loads(kernel.read_text()),baseline);fault.unlink()
        self.action_result('firewall-direct-failure',partial_apply_cleaned=True,failed_cleanup_retained=True,explicit_recovery_succeeded=True,backend_denial_unknown=True,real_kernel_verified=False)
        self.cli('proxy-stop','--confirm');deadline=time.monotonic()+12
        while True:
            report=self.cli('proxy-status')
            # Only after accepted stop: a query may return the exact unknown
            # response while the owner exits between its lock/identity reads.
            # Unknown never proves stopped; retain the original12s deadline.
            unknown=all(report.get(k)==v for k,v in {'api_version':1,'native':True,'ok':False,'phase':'proxy','effect':'none','write_ready':False,'error':'Proxy unavailable; inspect retained session'}.items())
            if not unknown:
                self.assertIs(report.get('ok'),True,report);self.assertIsInstance(report.get('running'),bool,report)
                if report.get('state')=='stopped' and report['running'] is False:break
            self.assertLess(time.monotonic(),deadline);time.sleep(.1)
        self.cli('proxy-reap','--confirm');self.verify_unchanged()
    def test_cli_selftest(self):
        s=self.configured();before=self.backup(s);store=Path('/etc/homegate/transactions')
        snapshot={str(p.relative_to(store)):p.read_bytes() for p in store.rglob('*') if p.is_file()}
        report=self.cli('selftest');self.assertTrue(report['ok'],report)
        self.assertEqual(report['cases'],sorted(report['cases'],key=lambda x:x['name']))
        cases={x['name']:x for x in report['cases']}
        for name in ['basic/save','basic/reject-invalid','basic/commit-failure','request/unknown-route','request/invalid-field','request/nul-field','request/oversize']:
            self.assertEqual(cases[name]['status'],'PASS',report)
        self.assertEqual(cases['live-DNS-ACME-proxy-firewall-WOL']['status'],'SKIP')
        self.assertTrue(all(x['scope']=='isolated-fake-host' for x in report['cases'] if x['status']!='SKIP'))
        self.assertFalse(report['target_ABI_verified']);self.assertGreaterEqual(report['duration_ms'],0)
        # Fault only this interpreter's controller loader. Installed code stays
        # under the original read-only mount and no privilege is added.
        fault=STATE/'offline-fault.lua';fault.write_text("""local original=loadfile
function loadfile(path)
 if path=='/usr/libexec/homegate/legacy-controller.lua' then
  local f=assert(io.open(path,'rb'));local raw=f:read('*a');f:close()
  local n;raw,n=raw:gsub('function action_basic_apply%(%)',\"function action_basic_apply() error('injected offline failure')\",1);assert(n==1)
  return loadstring(raw,'@'..path)
 end
 return original(path)
end
arg[0]='/usr/libexec/homegate/native-cli.lua';arg[1]='selftest'
assert(original(arg[0]))()
""")
        p=subprocess.run(['/usr/sbin/lua',str(fault)],capture_output=True,timeout=18)
        self.assertEqual(p.returncode,1,p.stderr);bad=json.loads(p.stdout);self.assertFalse(bad['ok'])
        self.assertEqual(next(x['status'] for x in bad['cases'] if x['name']=='basic/save'),'FAIL')
        self.assertEqual(self.backup(s),before)
        self.assertEqual({str(p.relative_to(store)):p.read_bytes() for p in store.rglob('*') if p.is_file()},snapshot)
        self.assertFalse(Path('/tmp/homegate-frontend-jobs').exists());self.verify_unchanged()
    def test_cli_ddns(self):
        import datetime
        s=self.configured();self.rule(s);self.cfg('lifecycle_enable',s,consent='1')
        before=self.cli('ddns-status')['results'][0];self.assertTrue(before['at_unknown']);self.assertEqual(before['at'],'')
        grant=self.cli('grant-preview','ddns_a');self.cli('grant-commit',grant['confirmation'])
        started=time.time();d=self.cli('ddns-sync','ddns_a');self.assertTrue(d['ok'],d)
        self.assertEqual(d['phase'],'ddns');row=d['results'][0]
        self.assertEqual((row['rule'],row['domain'],row['status']),('ddns_a','www.example.test','unchanged'))
        self.assertGreaterEqual(datetime.datetime.fromisoformat(row['at'].replace('Z','+00:00')).timestamp(),int(started))
        status=self.cli('ddns-status')['results'][0];self.assertFalse(status['at_unknown']);self.assertEqual(status['status'],'unchanged')
        observed=status['at'];calls=(STATE/'provider-calls').read_bytes()
        d=self.cli('ddns-sync','ddns_a',ok=False);self.assertFalse(d['ok']);self.assertEqual(d['results'][0]['native_status'],'waiting')
        d=self.cli('ddns-sync',ok=False);self.assertFalse(d['ok']);self.assertEqual(d['results'][0]['native_status'],'waiting')
        self.assertEqual(self.cli('ddns-status')['results'][0]['at'],observed)
        self.assertEqual((STATE/'provider-calls').read_bytes(),calls)
        d=self.cli('ddns-sync','missing',ok=False);self.assertFalse(d['ok']);self.assertEqual(d['results'],[])
        (STATE/'provider-mode').write_text('delete-present')
        d=self.cli('ddns-delete','ddns_a');self.assertTrue(d['ok']);self.assertEqual(d['results'][0]['status'],'deleted')
        self.assertEqual(d['results'][0]['domain'],'www.example.test')
        self.assertEqual(self.cli('ddns-status')['results'][0]['at'],observed)
        self.verify_unchanged(allow_provider_calls=True)
    def test_cli_ddns_unknown(self):
        s=self.configured();self.rule(s);self.cfg('lifecycle_enable',s,consent='1')
        grant=self.cli('grant-preview','ddns_a');self.cli('grant-commit',grant['confirmation'])
        (STATE/'provider-mode').write_text('unknown')
        d=self.cli('ddns-sync','ddns_a',ok=False);self.assertFalse(d['ok']);self.assertEqual(d['results'][0]['status'],'error')
        self.assertTrue(d['results'][0]['reconciliation_required']);self.assertEqual(d['results'][0]['native_effect'],'unknown')
        status=self.cli('ddns-status');self.assertFalse(status['ok']);self.assertEqual(status['results'][0]['status'],'error');self.assertFalse(status['results'][0]['at_unknown'])
        calls=(STATE/'provider-calls').read_bytes();store=Path('/etc/homegate/transactions')
        retained={str(p.relative_to(store)):p.read_bytes() for p in store.rglob('*') if p.is_file()}
        self.cli('ddns-sync','ddns_a',ok=False);self.cli('ddns-sync',ok=False)
        self.assertEqual((STATE/'provider-calls').read_bytes(),calls)
        self.assertEqual({str(p.relative_to(store)):p.read_bytes() for p in store.rglob('*') if p.is_file()},retained)
        self.verify_unchanged(allow_provider_calls=True)
    def test_cli_ddns_batch(self):
        s=self.configured();self.rule(s);self.cfg('lifecycle_enable',s,consent='1')
        grant=self.cli('grant-preview','ddns_a');self.cli('grant-commit',grant['confirmation'])
        d=self.cli('ddns-sync');self.assertTrue(d['ok']);self.assertEqual(d['native_phase'],'ddns-batch')
        self.assertEqual(len(d['results']),1);self.assertEqual(d['results'][0]['status'],'unchanged')
        self.assertEqual(d['results'][0]['domain'],'www.example.test');self.assertEqual(d['results'][0]['at_scope'],'request-start')
        status=self.cli('ddns-status');self.assertEqual(status['results'][0]['at'],status['updated_at']);self.assertFalse(status['results'][0]['at_unknown'])
        self.verify_unchanged(allow_provider_calls=True)
    def test_cli_queue(self):
        s=self.configured();before=Path('/etc/config/homegate').read_bytes()
        request=STATE/'request';request.write_text('{"route":"config_export","form":{},"write":true}');request.chmod(0o600)
        root=Path('/tmp/homegate-frontend-jobs');root.mkdir(mode=0o700)
        for n in range(8):(root/('%032x'%n)).mkdir(mode=0o700)
        d=self.cli('web-submit',str(request));self.assertFalse(d['ok']);self.assertTrue(d['queue_unavailable']);self.assertEqual(d['error'],'Unable to queue action')
        request.write_text('{"route":"unknown","form":{}}')
        p=subprocess.run(['/usr/bin/homegate','web-submit',str(request)],capture_output=True,timeout=8);self.assertEqual(p.returncode,1);self.assertEqual(json.loads(p.stdout)['error'],'Invalid request file')
        request.write_text('{"route":"config_export","form":{},"write":true}')
        hold=Path('/etc/homegate/package-state');hold.write_text('HGPKG1\nready\n');hold.chmod(0o600)
        d=self.cli('web-submit',str(request));self.assertFalse(d['ok']);self.assertTrue(d['queue_unavailable'])
        hold.unlink();self.assertEqual(Path('/etc/config/homegate').read_bytes(),before);self.verify_unchanged()
    def test_cli_reports(self):
        import re,fcntl
        s=self.configured();current=Path('/etc/homegate/transactions/current').read_bytes()
        reference={
          'selftest':('frontend/selftest.go','OfflineReport'),'status':('status/status.go','Report'),
          'recovery-status':('recovery/status.go','Report'),'network-resolve':('network/report.go','Report'),
          'dns-provider-catalog':('app/app.go','DNSProviderCatalogReport'),'acme-ca-catalog':('app/app.go','ACMECACatalogReport'),
          'dns-provider-status':('app/app.go','DNSProviderReport'),'dns-zones':('app/app.go','DNSZonesReport'),
          'ddns-status':('ddns/state.go','Report'),'cert-status':('acme/service.go','StatusReport'),
          'proxy-status':('proxy/proxy.go','Status'),'access-status':('access/access.go','Status'),
          'access-recent':('access/access.go','RecentReport'),'firewall-status':('firewall/firewall.go','Status'),
          'wol-status':('wol/report.go','Status'),'log-events':('logger/events.go','EventsReport'),
          'web-job-status':('frontend/jobs.go','JobStatus')}
        def fields(d,file,name):
            src=(ROOT/'project/core/src/internal'/file).read_text();body=re.search(r'type '+name+r' struct \{(.*?)\n\}',src,re.S).group(1)
            for typ,tag in re.findall(r'^\s*\w+\s+(\S+)\s+`json:"([^"]+)"`',body,re.M):
                key=tag.split(',')[0]
                if 'omitempty' in tag and key not in d:continue
                self.assertIn(key,d,(name,key,d));v=d[key]
                if typ.startswith('[]'):self.assertIsInstance(v,list,(key,v))
                elif typ=='bool':self.assertIs(type(v),bool,(key,v))
                elif typ.startswith('int'):self.assertIs(type(v),int,(key,v))
                elif typ=='string':self.assertIsInstance(v,str,(key,v))
                elif typ=='Service':fields(v,file,'Service')
        def schema(d):
            if isinstance(d,dict):return {k:schema(v) for k,v in d.items()}
            if isinstance(d,list):return [schema(d[0])] if d else []
            return type(d).__name__
        for args in [('version',),('selftest',),('status',),('recovery-status',),('network-resolve',),('dns-provider-catalog',),('acme-ca-catalog',),('dns-provider-status','dns_a'),('dns-zones','dns_a'),('ddns-status',),('cert-status',),('proxy-status',),('access-status',),('access-recent',),('firewall-status',),('wol-status',),('log-events',),('web-job-status','bad')]:
            p=subprocess.run(['/usr/bin/homegate',*args],capture_output=True,timeout=18)
            d=json.loads(p.stdout);self.assertNotIn(b'SECRET_SENTINEL',p.stdout)
            if args[0]=='version':self.assertEqual(p.returncode,0);self.assertIsInstance(d['arch'],str)
            else:fields(d,*reference[args[0]]);self.assertEqual(p.returncode,1 if args[0]=='selftest' and not d['ok'] else 0,(args,d))
            print('CLI_REPORT:'+json.dumps({'command':args[0],'code':p.returncode,'schema':schema(d)},sort_keys=True),flush=True)
        self.assertEqual(Path('/etc/homegate/transactions/current').read_bytes(),current)
        with Path('/var/run/homegate/frontend.lock').open('ab') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX)
            p=subprocess.run(['/usr/bin/homegate','status'],capture_output=True,timeout=8);d=json.loads(p.stdout);self.assertEqual(p.returncode,0);self.assertFalse(d['ok']);self.assertFalse(d['service']['healthy']);self.assertTrue(d['state_unknown'])
            p=subprocess.run(['/usr/bin/homegate','check'],capture_output=True,timeout=8);self.assertEqual(p.returncode,1);self.assertFalse(json.loads(p.stdout)['ok'])
        for value in ['+00001024','00000000000000000000000000000000000001','20000']:
            self.assertEqual(self.cli('log-events',value)['events'],[])
        for value in ['0','20001','1e2','1.0','+','-1','0000','0x10',' 1']:
            p=subprocess.run(['/usr/bin/homegate','log-events',value],capture_output=True,timeout=3);self.assertEqual(p.returncode,2,value)
        init=STATE/'untrusted-init.lua';init.write_text("assert(io.open('/teststate/untrusted-init-ran','w')):close()")
        p=subprocess.run(['/usr/bin/homegate','log-events','+0001'],capture_output=True,timeout=8,env={**os.environ,'LUA_INIT':'@'+str(init),'LUA_PATH':'/teststate/?.lua','LUA_CPATH':'/teststate/?.so','HOMEGATE_CONFIG_PROTO_STORE':'/teststate/foreign-store'})
        self.assertEqual(p.returncode,0,p.stdout);self.assertFalse((STATE/'untrusted-init-ran').exists());self.assertFalse((STATE/'foreign-store').exists())
        self.rule(s);d=self.cli('ddns-status');fields(d,*reference['ddns-status']);self.assertEqual(len(d['results']),1);fields(d['results'][0],'ddns/service.go','Result')
        api=self.web_request('api/ddns');fields(json.loads(api['body']),*reference['ddns-status'])
        self.certificate_config(s);d=self.cli('cert-status');self.assertEqual(len(d['certificates']),1);fields(d['certificates'][0],'acme/service.go','CertificateStatus');self.assertFalse(d['certificates'][0]['exists'])
        p=subprocess.run(['/usr/bin/homegate','dns-provider-status','missing'],capture_output=True,timeout=8);self.assertEqual(p.returncode,1);fields(json.loads(p.stdout),'app/app.go','DNSProviderReport')
        if (STATE/'provider-calls').exists():(STATE/'provider-calls').unlink()
        self.verify_unchanged()
    def test_cli_compat(self):
        s=self.configured();before=self.backup(s);store=Path('/etc/homegate/transactions');current=(store/'current').read_bytes()
        self.assertTrue(self.cli('dns-provider-status','dns_a')['credentials_valid'])
        self.assertTrue(self.cli('dns-zones','dns_a')['ok'])
        private=STATE/'private-dns';private.write_text('cloudflare\n\nSECRET_SENTINEL\n\n\n');private.chmod(0o600)
        d=self.cli('dns-check-private',str(private));self.assertTrue(d['ok']);self.assertEqual(d['provider'],'cloudflare');self.assertGreaterEqual(d['zone_count'],0)
        (STATE/'private-provider-fixture').touch()
        for provider in ['aliyun','dnspod','huaweicloud']:
            form={'provider':provider,'key_id':'KEY_SENTINEL','secret':'SECRET_SENTINEL'}
            if provider=='huaweicloud':form.update(account_id='f'*32,endpoint='https://dns.cn-north-4.myhuaweicloud.com')
            private.write_text(json.dumps({'route':'','write':False,'form':form}))
            d=self.cli('dns-check-private',str(private));self.assertTrue(d['ok']);self.assertEqual(d['provider'],provider);self.assertEqual(d['zone_count'],1)
        self.assertEqual((store/'current').read_bytes(),current);self.assertEqual(self.backup(s),before);self.assertFalse((store/'ddns-authority').exists())
        unsafe=STATE/'private-link';unsafe.symlink_to(private);self.cli('dns-check-private',str(unsafe),ok=False)
        private.chmod(0o644);self.cli('dns-check-private',str(private),ok=False);private.chmod(0o600)
        allow=STATE/'allow';allow.write_text('192.0.2.123/24, 192.0.2.0/24; 2001:db8::abcd/64\n127.0.0.1\n');allow.chmod(0o600)
        d=self.cli('access-validate-file',str(allow));self.assertEqual(d['normalized'],'127.0.0.1, 192.0.2.0/24, 2001:db8::/64');self.assertEqual(d['count'],3)
        self.assertEqual(self.cli('cert-renew')['results'],[])
        self.assertEqual(self.cli('log-events')['events'],[])
        for command in [('dns-provider-status',),('dns-zones','../bad'),('cert-renew','a','b'),('dns-check-private',),('acme-ca-status','unknown')]:
            self.cli(*command,ok=False)
        self.assertEqual(list(Path('/var/run/homegate').glob('.dns-check-*')),[])
        # Provider fixture calls are expected in this read-only scenario.
        (STATE/'provider-calls').unlink();self.verify_unchanged()
    def action_result(self,name,**fields):
        print('ACTION_RESULT:'+json.dumps({'case':name,**fields},sort_keys=True),flush=True)
    def verify_wake_capture(self,report):
        path=STATE/'wol-wire.bin';raw=path.read_bytes() if path.exists() else b'';frames=[]
        while raw:
            self.assertGreaterEqual(len(raw),12);self.assertEqual(raw[:4],b'WOL1')
            kind,index,size=raw[4],raw[5],int.from_bytes(raw[6:8],'big');self.assertGreaterEqual(len(raw),12+size)
            dst,packet=raw[8:12],raw[12:12+size];raw=raw[12+size:];frames.append((kind,index,dst,packet))
        self.assertEqual(sum(k==1 for k,_,_,_ in frames),report['raw_sent']);self.assertEqual(sum(k==2 for k,_,_,_ in frames),report['udp_sent'])
        payload=b'\xff'*6+bytes.fromhex('C87F54536B80')*16
        for kind,index,dst,packet in frames:
            if kind==1:
                self.assertEqual(packet[:6],b'\xff'*6);self.assertEqual(packet[6:12],bytes([0,17,34,51,68,index]));self.assertEqual(packet[12:14],b'\x08\x42');self.assertEqual(packet[14:],payload)
            else:self.assertIn(dst,[bytes([192,0,2,255]),b'\xff'*4]);self.assertEqual(packet,payload)
        self.assertFalse(report['device_wake_verified']);path.unlink(missing_ok=True)
        self.action_result('wol-packet-capture',raw_sent=report['raw_sent'],udp_sent=report['udp_sent'],real_network=False)
    def test_cli_actions(self):
        s=self.configured()
        first=self.cli('access-update',' cn ');self.assertTrue(first['ok']);self.assertEqual((first['phase'],first['region'],first['native_state']),('access','CN','published'));self.assertGreater(first['ipv4'],0);self.assertGreater(first['ipv6'],0)
        calls=(STATE/'access-calls').read_bytes();cached=self.cli('access-update','CN');self.assertEqual(cached['source'],'cache');self.assertEqual((STATE/'access-calls').read_bytes(),calls)
        fresh=self.cli('access-refresh','CN');self.assertEqual(fresh['native_state'],'published');self.assertGreater(len((STATE/'access-calls').read_bytes()),len(calls))
        cache=Path('/etc/homegate/access/CN.cidr');before=cache.read_bytes();(STATE/'access-mode').write_text('truncated')
        failed=self.cli('access-refresh','CN',ok=False);self.assertTrue(failed['ok']);self.assertEqual(failed['source'],'stale-cache');self.assertTrue(failed['warning']);self.assertEqual(cache.read_bytes(),before)
        self.assertFalse(self.cli('access-update','US',ok=False)['ok']);self.assertEqual(cache.read_bytes(),before)
        self.action_result('CN-update-refresh',published=True,cached_without_download=True,failed_refresh_exit_1=True,validated_cache_retained=True)
        (STATE/'access-mode').write_text('ok')
        done=self.web_wait(self.web_request('access_update',{'region':'CN'},True)['job']);self.assertTrue(done['ok'],{'result':done,'access':self.cli('access-status')});cache=Path('/etc/homegate/access/CN.cidr');before=cache.read_bytes()
        (STATE/'access-mode').write_text('truncated');done=self.web_wait(self.web_request('access_update',{'region':'CN'},True)['job']);self.assertFalse(done['ok']);self.assertEqual(cache.read_bytes(),before)
        self.action_result('access-route-refresh',success=True,failed_download_not_reported_as_updated=True,cache_retained=True)
        import fcntl
        audit=Path('/var/run/homegate/access.json');lock=Path('/var/run/homegate/proxy.lock')
        audit.write_text(json.dumps({'entries':[{'ip':ip,'host':'example.test','allowed':allow,'reason':'ip' if allow else 'denied','region':'','time':'2026-10-30T00:00:00Z','count':1} for ip,allow in [('192.0.2.1',True),('192.0.2.2',False),('192.0.2.3',True)]]}));audit.chmod(0o600)
        lock.touch(mode=0o600,exist_ok=True);before_audit=audit.read_bytes()
        with lock.open('ab') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);self.cli('access-clear-all',ok=False);self.assertEqual(audit.read_bytes(),before_audit)
        self.cli('access-clear-entry','192.0.2.1','example.test');self.assertEqual([e['ip'] for e in self.cli('access-recent')['entries']],['192.0.2.2','192.0.2.3'])
        self.cli('access-clear-denied');self.assertEqual([e['ip'] for e in self.cli('access-recent')['entries']],['192.0.2.3'])
        self.cli('access-clear-all');self.assertEqual(self.cli('access-recent')['entries'],[])
        self.action_result('access-clear-idle',entry_and_denied_and_all=True,concurrent_owner_refused=True,old_records_retained_on_refusal=True)
        self.certificate_config(s);pair=self.certificate_pair('direct-import',date_case='current')
        cert,key=STATE/'import-cert.pem',STATE/'import-key.pem';cert.write_text(pair[0]);key.write_text(pair[1]);cert.chmod(0o600);key.chmod(0o600)
        imported=self.cli('cert-import','cert_a',str(cert),str(key));self.assertTrue(imported['ok']);self.assertTrue(self.cli('cert-status')['certificates'][0]['exists'])
        material=Path('/etc/homegate/certs/cert_a/current').read_bytes();key.chmod(0o644);self.cli('cert-import','cert_a',str(cert),str(key),ok=False)
        self.assertEqual(Path('/etc/homegate/certs/cert_a/current').read_bytes(),material);key.chmod(0o600)
        self.action_result('certificate-file-import',success=True,unsafe_key_mode_refused=True,old_material_retained=True)
        for action,fields in [('preview_wol_host',{'id':'wake_a','name':'Wake host','mac':'c8-7f-54-53-6b-80'}),('preview_wol_settings',{'interface':'br-lan','selected_host':'wake_a'})]:
            preview=self.cfg(action,s,**fields);self.cfg('apply',s,confirmation=preview['report']['confirmation'],consent='1')
        report=self.cli('wol','wake_a');self.assertEqual((report['raw_sent'],report['udp_sent']),(9,6));self.verify_wake_capture(report)
        (STATE/'wol-mode').write_text('all-fail');report=self.cli('wol','wake_a',ok=False);self.assertEqual((report['raw_sent'],report['udp_sent']),(0,0));self.verify_wake_capture(report)
        (STATE/'wol-mode').write_text('ok');self.cli('wol','eth1;id','C8:7F:54:53:6B:80',ok=False);self.assertFalse((STATE/'wol-wire.bin').exists())
        done=self.web_wait(self.web_request('wol_action',{'op':'wake','id':'wake_a'},True)['job']);self.assertTrue(done['ok'],done)
        self.verify_wake_capture({'raw_sent':9,'udp_sent':6,'device_wake_verified':False})
        self.action_result('wol-cli-and-route',saved_host=True,all_fail_refused=True,injection_refused=True,device_wake_verified=False);self.verify_unchanged()
    def test_web_access_actions(self):
        s=self.configured();base={'mode':'save','public_service_count':'0','access_enabled':'0','access_allow':'192.0.2.1','access_deny':'198.51.100.2','access_region':''}
        self.assertTrue(self.web_wait(self.web_request('basic_apply',{'mode':'save'},True)['job'])['ok'])
        self.assertTrue(self.web_wait(self.web_request('public_apply',base,True)['job'])['ok'])
        for route,form in [('access_clear_entry',{'ip':'192.0.2.1','host':'example.test'}),('access_clear_denied',{}),('access_clear_all',{}),('access_delete_entry',{'ip':'192.0.2.1','host':'example.test'})]:
            done=self.web_wait(self.web_request(route,form,True)['job']);self.assertTrue(done['ok'],(route,done))
            self.action_result(route,completed=True)
        main=self.web_request('public')['data']['main'];self.assertNotIn('192.0.2.1',main['access_allow']);self.assertIn('198.51.100.2',main['access_deny'])
        # Data rule_token and transport CSRF token must remain independent.
        sid,token=s;fields={'kind':'deny','rule_token':'198.51.100.2'}
        code,_,_=self.cgi(BASE+'/access_delete_rule',cookie=sid,verb='POST',fields={**fields,'token':'bad'});self.assertNotEqual(code,200)
        self.assertIn('198.51.100.2',self.web_request('public')['data']['main']['access_deny'])
        code,_,raw=self.exchange(path=BASE+'/access_delete_rule',verb='POST',headers={'Cookie':'sysauth='+sid,'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},raw=urlencode({**fields,'token':token}).encode())
        self.assertEqual(code,200,raw[:300]);done=self.web_wait(json.loads(raw)['job']);self.assertTrue(done['ok'],done)
        self.assertNotIn('198.51.100.2',self.web_request('public')['data']['main']['access_deny'])
        self.action_result('access_delete_rule-real-HTTP',valid_CSRF_and_rule_data_succeeded=True,bad_CSRF_refused=True)
        done=self.web_wait(self.web_request('access_delete_rule',{'kind':'unknown','rule_token':'192.0.2.1'},True)['job']);self.assertFalse(done['ok'])
        done=self.web_wait(self.web_request('access_delete_all',{},True)['job']);self.assertTrue(done['ok'],done)
        self.assertEqual(self.web_request('public')['data']['main']['access_allow'],'');self.assertEqual(self.web_request('public')['data']['main']['access_deny'],'')
        self.verify_unchanged()
    def test_web_maintenance_actions(self):
        s=self.configured();source=Path('/etc/config/homegate');before=source.read_bytes()
        done=self.web_wait(self.web_request('diagnostic_download',{},True)['job']);self.assertTrue(done['ok'],done);self.assertIn('HomeGate diagnostic report',done['body']);self.assertNotIn('SECRET_SENTINEL',done['body']);self.assertEqual(source.read_bytes(),before)
        log=Path('/var/log/homegate.log');log.write_text('2026-10-30 00:00:00 [INFO] fixture maintenance\n');log.chmod(0o600)
        done=self.web_wait(self.web_request('log_clear',{},True)['job']);self.assertTrue(done['ok'],done);self.assertEqual(log.read_bytes(),b'');self.assertEqual(source.read_bytes(),before)
        done=self.web_wait(self.web_request('config_import',{'config_payload':self.backup(s)},True)['job']);self.assertTrue(done['ok'],done);self.assertFalse(json.loads(done['body'])['can_commit']);self.assertEqual(source.read_bytes(),before)
        done=self.web_wait(self.web_request('certificate_apply',{'name':'ACME certificate','zone':'example.test','domains':'example.test','renew_days':'30','account_id':'dns_a','certificate_ca':'letsencrypt','certificate_environment':'production'},True)['job']);self.assertTrue(done['ok'],done)
        self.action_result('maintenance-read-log-preview-certificate',diagnostic_redacted=True,log_cleared=True,import_preview_only=True,legacy_certificate_metadata_saved=True)
        done=self.web_wait(self.web_request('config_reset',{},True)['job'],seconds=50);self.assertTrue(done['ok'],done)
        self.assertEqual(self.web_request('basic')['data']['main']['enabled'],'1');self.assertTrue(self.cli('status')['service']['running'])
        self.action_result('config-reset',completed=True,default_switch_restored=True,empty_coordinator_running=True);self.verify_unchanged()
    def test_cli_acme(self):
        s=self.acme_setup();self.cfg('lifecycle_enable',s,consent='1')
        self.assertEqual(self.cli('cert-renew')['results'],[]);self.assertFalse((STATE/'acme-fixture.json').exists())
        d=self.cli('cert-renew','cert_a');self.assertTrue(d['ok']);self.assertEqual(d['state'],'issued')
        self.assertTrue(self.cli('cert-status')['certificates'][0]['valid']);self.verify_unchanged()
    def test_cli_acme_all(self):
        s=self.acme_setup();self.cfg('lifecycle_enable',s,consent='1');self.cli('service-plan-set','-','cert_a','-','open','--confirm')
        d=self.cli('cert-renew');self.assertTrue(d['ok']);self.assertEqual(len(d['results']),1);self.assertEqual(d['results'][0]['state'],'issued')
        self.assertEqual(self.cli('cert-renew')['results'],[])
        self.assertEqual(len(json.loads((STATE/'acme-fixture.json').read_text())['orders']),1);self.verify_unchanged()
    def test_cli_acme_unknown(self):
        s=self.acme_setup();(STATE/'acme-mode').write_text('dns-unknown');self.cfg('lifecycle_enable',s,consent='1')
        d=self.cli('cert-renew','cert_a',ok=False);self.assertFalse(d['ok']);self.assertEqual(d['effect'],'unknown');self.assertEqual(len(d['job']),32)
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertTrue(db['records'])
        self.cli('cert-renew','cert_a',ok=False);self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db)
    def test_cli_ca_logs(self):
        self.configured()
        self.assertTrue(self.cli('acme-ca-status','letsencrypt','staging')['reachable'])
        self.assertEqual(self.cli('acme-ca-status','letsencrypt')['environment'],'production')
        self.assertEqual(self.cli('acme-ca-status',' LE ',' STAGING ')['environment'],'staging')
        self.assertEqual(self.cli('acme-ca-status','','')['environment'],'production')
        (STATE/'ca-bad').touch();self.cli('acme-ca-status','letsencrypt','staging',ok=False)
        log=Path('/var/log/homegate.log');log.write_text('2026-10-29 12:00:00 [INFO] DDNS unchanged token=SECRET_SENTINEL\n2026-10-29 12:00:01 [ERROR] ACME failed Authorization: Bearer SECRET_SENTINEL\n');log.chmod(0o600)
        d=self.cli('log-events','1');self.assertEqual(d['count'],1);self.assertEqual(d['events'][0]['category'],'certificate');self.assertTrue(d['events'][0]['important'])
        self.assertEqual(self.cli('log-events')['count'],2)
        log.unlink();log.symlink_to(STATE/'private-foreign');p=subprocess.run(['/usr/bin/homegate','log-events'],capture_output=True);self.assertEqual(p.returncode,0);self.assertFalse(json.loads(p.stdout)['ok'])
        hold=Path('/etc/.homegate-transition/hold');hold.touch();hold.chmod(0o600)
        self.cli('cert-renew',ok=False);self.api('configuration_api','preview_account',self.login(),{'id':'dns_b','provider':'cloudflare','name':'Blocked'},expected=503)
        hold.unlink();self.verify_unchanged()
    def test_transition_source(self):
        # Literal source driver + codec, private fixed-path mapping, external opkg
        # model. These dummy transport files are not SDK/IPK validation.
        parent=STATE/'transition-model';parent.mkdir()
        factory=(ROOT/'packaging/production/homegate.config').read_bytes()
        for index in range(6):
            root=parent/str(index);root.mkdir();data=root/'data';data.mkdir(mode=0o700)
            keep=data/'credentials';keep.write_bytes(b'PRIVATE_DATA_SENTINEL');keep.chmod(0o600)
            for name in ['kit','config','run','info','jobs']:(root/name).mkdir(mode=0o700)
            source=root/'config/homegate';source.write_bytes(b'PRIVATE_LEGACY_CONFIGURATION\n');source.chmod(0o600);inode=source.stat().st_ino
            running=root/'running';running.write_text(str(index%2));boot=root/'boot';boot.write_text(str(index//2%2))
            old=root/'oldcmd';old.write_text('#!/usr/sbin/ash\nprintf \'{"api_version":1,"service":{"running":%s}}\\n\' "$(if [ "$(cat '+str(running)+')" = 1 ];then echo true;else echo false;fi)"\n');old.chmod(0o755)
            init=root/'init';init.write_text('#!/usr/sbin/ash\ncase "$1" in enabled) [ "$(cat '+str(boot)+')" = 1 ];;stop) printf 0 > '+str(running)+';;enable) printf 1 > '+str(boot)+';;disable) printf 0 > '+str(boot)+';;*) exit 7;;esac\n');init.chmod(0o755)
            hooks={}
            names=['homegate','luci-app-homegate','luci-i18n-homegate-zh-cn']
            for name in names:
                (root/'info'/ (name+'.control')).write_text('Package: '+name+'\nVersion: legacy\n')
                for hook in ['prerm','postrm']:
                    path=root/'info'/(name+'.'+hook);body='#!/usr/sbin/ash\nrm -f '+str(keep)+'\n';path.write_text(body);path.chmod(0o755);hooks[path.name]=body
            opkg=root/'opkg';opkg.write_text('''#!/usr/bin/python3
import sys,json
from pathlib import Path
r=Path(__file__).parent
if sys.argv[1]=='remove':
 if (r/'remove-fail').exists():sys.exit(4)
 import subprocess
 for name in sys.argv[2:]:
  for hook in ['prerm','postrm']:subprocess.run([str(r/'info'/(name+'.'+hook))],check=True)
  for p in (r/'info').glob(name+'.*'):p.unlink()
else:
 version=json.loads((r/'kit/receipt.json').read_text())['version']
 if (r/'stale-install').exists():version='1.3.0-r1'
 def control(name):return 'Package: '+name+'\\nVersion: '+version+'\\n'
 (r/'info/luci-app-homegate.control').write_text(control('luci-app-homegate'))
 (r/'info/luci-app-homegate.postrm').write_text('NEW_UI_KEEP')
 if (r/'install-fail').exists():sys.exit(4)
 (r/'info/homegate-core.control').write_text(control('homegate-core'))
 (r/'info/luci-i18n-homegate-zh-cn.control').write_text(control('luci-i18n-homegate-zh-cn'))
 (r/'status').write_text('\\n'.join(control(name)+'Status: install ok installed\\n' for name in ['homegate-core','luci-app-homegate','luci-i18n-homegate-zh-cn']))
 (r/'config/homegate').write_bytes((r/'kit/factory.config').read_bytes())
 (r/'config/homegate').chmod(0o600)
''');opkg.chmod(0o755)
            def mapped(raw):
                pairs=[('/etc/.homegate-transition',str(root/'transition')),('/tmp/homegate-native-kit',str(root/'kit')),('/usr/lib/opkg/info',str(root/'info')),('/etc/homegate',str(data)),('/etc/config',str(root/'config')),('/var/run/homegate',str(root/'run')),('/usr/bin/homegate',str(old)),('/etc/init.d/homegate',str(init)),('/tmp/.homegate-purge-request',str(root/'purge')),('/tmp/homegate-frontend-jobs',str(root/'jobs'))]
                for n,(a,b) in enumerate(pairs):raw=raw.replace(a,'@@PATH_'+str(n)+'@@')
                for n,(a,b) in enumerate(pairs):raw=raw.replace('@@PATH_'+str(n)+'@@',b)
                return raw.replace('opkg remove ',str(opkg)+' remove ').replace('opkg install ',str(opkg)+' install ')
            kit=root/'kit';driver=kit/'native-transition.sh';driver.write_text(mapped((ROOT/'packaging/production/native-transition.sh').read_text()));driver.chmod(0o600)
            (kit/'native-transition.lua').write_text(mapped((ROOT/'packaging/production/native-transition.lua').read_text()))
            (kit/'factory.config').write_bytes(factory)
            for name in ['homegate-core','luci-app-homegate','luci-i18n-homegate-zh-cn']:(kit/(name+'.ipk')).write_bytes(b'EXTERNAL_MODEL_TRANSPORT_ONLY')
            for path in kit.iterdir():path.chmod(0o600)
            receipt={'format':'homegate-native-kit-v1','architecture':'all','version':'1.3.0-r'+(ROOT/'RELEASE').read_text().strip(),'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in kit.iterdir()}}
            (kit/'receipt.json').write_text(json.dumps(receipt));(kit/'receipt.json').chmod(0o600)
            def call(action,ok=True):
                p=subprocess.run(['/usr/sbin/ash',str(driver),action,'--confirm'],capture_output=True,timeout=12)
                self.assertEqual(p.returncode==0,ok,(index,action,p.returncode,p.stdout,p.stderr[-250:]));return json.loads(p.stdout)
            d=call('prepare');self.assertTrue(d['prepared']);self.assertFalse(old.exists());self.assertFalse(source.exists());self.assertEqual(keep.read_bytes(),b'PRIVATE_DATA_SENTINEL')
            self.assertEqual((root/'transition/source.config').stat().st_ino,inode)
            if index==0:
                d=call('install');self.assertTrue(d['packages_replaced']);self.assertTrue(d['activation_pending']);self.assertFalse(d['runtime_authority_granted'])
            elif index==1:
                call('recover');self.assertTrue(old.exists());self.assertEqual(old.stat().st_mode&0o777,0o755)
                for name,body in hooks.items():self.assertEqual((root/'info'/name).read_text(),body)
            elif index==2:
                (root/'remove-fail').touch();call('install',ok=False);call('recover');self.assertTrue(old.exists())
            elif index==3:
                (root/'install-fail').touch();call('install',ok=False);call('recover')
                self.assertFalse(old.exists());self.assertEqual((root/'info/luci-app-homegate.postrm').read_text(),'NEW_UI_KEEP')
            elif index==4:
                source.write_bytes(b'FOREIGN_REPLACEMENT');source.chmod(0o600);call('install',ok=False);call('recover',ok=False)
                self.assertEqual(source.read_bytes(),b'FOREIGN_REPLACEMENT');self.assertEqual((root/'transition/source.config').stat().st_ino,inode)
            else:
                (root/'stale-install').touch();call('install',ok=False)
                self.assertTrue((root/'transition/hold').exists());self.assertTrue((root/'transition/source.config').exists())
                call('recover');self.assertEqual(source.stat().st_ino,inode)
            self.assertEqual(keep.read_bytes(),b'PRIVATE_DATA_SENTINEL')
            if index<4:self.assertEqual(source.stat().st_ino,inode);self.assertEqual(source.read_bytes(),b'PRIVATE_LEGACY_CONFIGURATION\n')
        self.verify_unchanged()
    def test_transition_identity(self):
        root=STATE/'transition-identity';root.mkdir(mode=0o700)
        executable=root/'old';shutil.copyfile('/fixture-host-bin/sleep',executable);executable.chmod(0o755)
        raw=(ROOT/'packaging/production/native-transition.lua').read_text().replace('/etc/.homegate-transition',str(root)).replace('/usr/bin/homegate',str(executable))
        script=root/'codec.lua';script.write_text(raw)
        def call(mode):return subprocess.run(['/usr/sbin/lua',str(script),mode],capture_output=True,timeout=5).returncode
        self.assertEqual(call('old-identity'),0);child=subprocess.Popen([str(executable),'10'])
        try:
            time.sleep(.05);self.assertEqual(call('old-quiet'),7);self.assertEqual(executable.stat().st_mode&0o777,0o755)
        finally:child.terminate();child.wait(timeout=5)
        self.assertEqual(call('old-quiet'),0);self.verify_unchanged()
    def test_package_source(self):
        # Source-level lifecycle model. Map only fixed paths into one private
        # filesystem so rename/inode preservation can be checked without
        # deleting namespace bind-mount roots. This is not an opkg/IPK audit.
        parent=STATE/'package-model';parent.mkdir()
        factory=(ROOT/'packaging/production/homegate.config').read_bytes()
        for index,(boot,running) in enumerate([(0,0),(0,1),(1,0),(1,1)]):
            root=parent/str(index);root.mkdir();data=root/'data/homegate';data.mkdir(parents=True,mode=0o700);data.chmod(0o700)
            config=root/'etc/config';config.mkdir(parents=True);(root/'etc/rc.d').mkdir();(root/'etc/init.d').mkdir()
            run=root/'run/homegate';run.mkdir(parents=True,mode=0o700);run.chmod(0o700);(root/'log').mkdir();(root/'info').mkdir()
            source=config/'homegate';source.write_bytes(b'PRIVATE_CONFIG_SENTINEL\n');source.chmod(0o600);inode=source.stat().st_ino
            keep=data/'keep';keep.write_bytes(b'PRIVATE_DATA_SENTINEL');keep.chmod(0o600)
            state=root/'running';state.write_text(str(running));blocked=root/'blocked'
            cli=root/'cli';cli.write_text('#!/usr/sbin/ash\ncase "$1" in status) printf \'{"api_version":1,"service":{"running":%s}}\\n\' "$(if [ "$(cat '+str(state)+')" = 1 ];then echo true;else echo false;fi)";;service-stop) [ ! -e '+str(blocked)+' ] || exit 4;printf 0 > '+str(state)+';;service-quiescent) [ "$(cat '+str(state)+')" = 0 ];;*) exit 0;;esac\n');cli.chmod(0o755)
            def mapped(raw):
                pairs=[('/etc/.homegate-transition',str(root/'transition')),('/usr/lib/opkg/info',str(root/'info')),('/etc/homegate',str(data)),('/etc/config',str(config)),('/etc/rc.d',str(root/'etc/rc.d')),('/var/run/homegate',str(run)),('/var/log/homegate.log',str(root/'log/homegate.log')),('/etc/init.d/homegate',str(root/'etc/init.d/homegate')),('/usr/bin/homegate',str(cli)),('/usr/libexec/homegate/native-package.lua',str(root/'codec.lua'))]
                for n,(old,new) in enumerate(pairs):raw=raw.replace(old,'@@FIXTURE_PATH_'+str(n)+'@@')
                for n,(old,new) in enumerate(pairs):raw=raw.replace('@@FIXTURE_PATH_'+str(n)+'@@',new)
                return raw
            codec=root/'codec.lua';codec.write_text(mapped((ROOT/'packaging/production/native-package.lua').read_text()))
            hook=root/'hook';hook.write_text('#!/usr/sbin/ash\n'+mapped((ROOT/'packaging/production/native-package.sh').read_text()));hook.chmod(0o755)
            postrm=root/'postrm';postrm.write_text(mapped((ROOT/'packaging/production/postrm.sh').read_text()));postrm.chmod(0o755)
            init=root/'etc/init.d/homegate';init.write_text('#!/usr/sbin/ash\n'+mapped((ROOT/'packaging/production/homegate.init').read_text())+'\nprocd_open_instance(){ :; };procd_set_param(){ :; };procd_close_instance(){ printf 1 > '+str(state)+'; };case "$1" in enable) enable;;disable) disable;;enabled) enabled;;start) start_service;;stop) stop_service;;esac\n');init.chmod(0o755)
            def call(args,ok=True,env=None):
                p=subprocess.run(args,capture_output=True,timeout=10,env=env);self.assertEqual(p.returncode==0,ok,(args,p.returncode,p.stderr[-250:]));return p
            if boot:call([str(init),'enable'])
            call([str(hook),'prerm','upgrade'],env={**os.environ,'PKG_UPGRADE':'1'})
            self.assertFalse(source.exists());self.assertEqual((data/'package-config').stat().st_ino,inode)
            source.write_bytes(factory);source.chmod(0o600);call([str(hook),'postinst'])
            self.assertEqual(source.stat().st_ino,inode);self.assertEqual(source.read_bytes(),b'PRIVATE_CONFIG_SENTINEL\n')
            call([str(init),'enable']);call([str(init),'start'])
            self.assertEqual((root/'etc/rc.d/S95homegate').is_symlink(),bool(boot));self.assertEqual(state.read_text(),str(running));self.assertEqual(keep.read_bytes(),b'PRIVATE_DATA_SENTINEL')
            if index==3:
                call(['/usr/sbin/ash','-c','"$1" prerm remove; code=$?; exit "$code"','--force-reinstall',str(hook)])
                self.assertEqual((data/'package-state').read_text().splitlines()[1],'reinstall')
                call([str(postrm),'remove']);self.assertTrue(keep.exists())
                source.write_bytes(factory);source.chmod(0o600);call([str(hook),'postinst']);call([str(init),'enable']);call([str(init),'start'])
                self.assertEqual(source.stat().st_ino,inode);self.assertEqual(state.read_text(),'1')
            (root/'info/homegate.control').write_text('legacy')
            call([str(hook),'preinst'],ok=False);self.assertTrue(keep.exists());(root/'info/homegate.control').unlink()
            transition=root/'transition';transition.mkdir(mode=0o700);protected=transition/'source.config';protected.write_bytes(b'RETAINED_PRIVATE_SOURCE');protected.chmod(0o600)
            call([str(hook),'prerm','remove'],ok=False);self.assertTrue(keep.exists());self.assertEqual(protected.read_bytes(),b'RETAINED_PRIVATE_SOURCE');protected.unlink()
            retained=transition/'old-hook';retained.write_text('RETAINED_OLD_HOOK');retained.chmod(0o600)
            # Unknown stop cannot authorize postrm to delete data.
            blocked.touch();state.write_text('1');call([str(hook),'prerm','remove'],ok=False)
            call([str(postrm),'remove'],ok=False);self.assertTrue(keep.exists());blocked.unlink()
            # SDK default_prerm still calls these after custom-hook failure.
            # Even if the external stop blocker has cleared, no completed
            # package transaction authorizes those default side effects yet.
            link=root/'etc/rc.d/S95homegate';before_link=link.is_symlink()
            call([str(init),'disable'],ok=False);call([str(init),'stop'],ok=False)
            self.assertEqual(link.is_symlink(),before_link);self.assertEqual(state.read_text(),'1')
            foreign=root/'foreign-lease';foreign.write_text('KEEP');foreign.chmod(0o600)
            call(['/usr/sbin/ash','-c','exec 9>>"$1"; flock -n 9; "$2" disable','sdk-default',str(foreign),str(init)],ok=False);self.assertEqual(foreign.read_text(),'KEEP')
            call([str(hook),'prerm','remove']);call([str(postrm),'remove']);self.assertFalse(data.exists());self.assertFalse(source.exists());self.assertFalse(transition.exists())
        self.verify_unchanged()

    def web_request(self,route,form=None,write=False):
        p=Path('/tmp/native-web-request');p.write_text(json.dumps({'route':route,'form':form or {},'write':write}));p.chmod(0o600)
        try:
            result=self.cli('web-submit' if write else 'web-read',str(p))
            if INSTALLED:print('PACKAGE_ROUTE:'+json.dumps({'route':route,'write':write,'ok':result.get('ok'),'fields':sorted(result)}),flush=True)
            return result
        finally:p.unlink()
    def web_wait(self,job,ack=True,seconds=18):
        start=time.monotonic()
        while time.monotonic()-start<seconds:
            d=self.cli('web-job-status',job)
            if not d['pending']:
                result=d['result']
                if ack and not result.get('uncertain'):self.cli('web-job-ack',job)
                return result
            time.sleep(.1)
        processes=[]
        for p in Path('/proc').glob('[0-9]*/stat'):
            try:
                raw=p.read_text();fields=raw.rsplit(') ',1)[1].split();fds=[]
                for fd in (p.parent/'fd').iterdir():
                    try:
                        target=os.readlink(fd)
                        if target.startswith('/var/run/homegate/') or target.endswith('/.supervisor.lock'):fds.append((fd.name,target))
                    except OSError:pass
                command=(p.parent/'cmdline').read_bytes().split(b'\0')[:2];processes.append((p.parent.name,fields[:4],(p.parent/'wchan').read_text(),command,fds))
            except OSError:pass
        reports={}
        for action in ['service-admission','lifecycle-status','config-status','status']:
            p=subprocess.run(['/usr/bin/homegate',action],capture_output=True,timeout=5);raw=p.stdout[:3000].decode(errors='replace');reports[action]=(p.returncode,raw if 'SECRET_SENTINEL' not in raw else '[redacted]')
        for name in ['procd-api','procd-daemon-output']:
            if (STATE/name).exists():reports[name]=(STATE/name).read_text()[:3000]
        self.fail('Web task did not settle: '+str({'status':d,'processes':processes,'reports':reports,'store_files':[str(p.relative_to('/etc/homegate/transactions')) for p in Path('/etc/homegate/transactions').iterdir()]}))
    def test_web_forms(self):
        s=self.configured()
        for route in ['overview','basic','public','wol','maintenance','settings/basic','settings/public','settings/wol']:
            d=self.web_request(route);self.assertIn('template',d,(route,d));self.assertNotIn('SECRET_SENTINEL',json.dumps(d))
        for route in ['api/status','api/version','api/network','api/ddns','api/certs','api/proxy','api/firewall','api/wol','api/logs','api/log_events','api/access_recent','api/dns_zones','domain','web']:
            d=self.web_request(route);self.assertTrue(d['ok'],(route,d));self.assertTrue('body' in d or 'redirect' in d,(route,d))
        d=self.web_request('basic_apply',{'mode':'save','ddns_interval':'420','https_port':'444','proxy_https_port':'10444','auto_firewall':'1'},True)
        result=self.web_wait(d['job']);self.assertTrue(result['ok'],result);self.assertIn('notice=',result['redirect'])
        self.assertIn("option ddns_interval '420'",Path('/etc/config/homegate').read_text())
        self.assertEqual(self.web_request('basic')['data']['main']['ddns_interval'],'420')
        d=self.web_request('wol_apply',{'wol_interface':'br-lan','wol_host_count':'1','wol_host_name_1':'Test desktop','wol_host_mac_1':'02:11:22:33:44:55'},True)
        result=self.web_wait(d['job']);self.assertTrue(result['ok'],result)
        hosts=self.web_request('wol')['data']['hosts'];self.assertEqual(len(hosts),1);self.assertEqual(hosts[0]['mac'],'02:11:22:33:44:55')
        before=Path('/etc/config/homegate').read_bytes()
        d=self.web_request('basic_apply',{'https_port':'99999'},True);result=self.web_wait(d['job']);self.assertFalse(result['ok']);self.assertEqual(Path('/etc/config/homegate').read_bytes(),before)
        d=self.web_request('config_export',{},True);result=self.web_wait(d['job']);self.assertTrue(result['ok'],result);self.assertIn('# secrets: omitted',result['body']);self.assertNotIn('SECRET_SENTINEL',result['body'])
        d=self.web_request('basic_apply',{'mode':'apply','enabled':'1'},True);result=self.web_wait(d['job'],seconds=25);self.assertTrue(result['ok'],result);self.assertTrue(result['runtime_applied'])
        self.assertEqual(self.web_request('basic')['data']['main']['enabled'],'1');self.assertTrue(self.cli('status')['service']['running'])
        self.verify_unchanged()
    def test_web_http(self):
        s=self.configured();sid,token=s
        for route in ['overview','settings/basic','settings/public','settings/wol','maintenance']:
            code,_,body=self.cgi(BASE+'/'+route,cookie=sid);self.assertEqual(code,200,(route,body[:300]));self.assertNotIn(b'SECRET_SENTINEL',body)
            self.assertIn(b'<form' if route!='overview' else b'Overview',body,(route,body[:200]));self.assertNotIn(b'Internal Server Error',body)
            import re
            scripts=[v.decode().replace(token,'0'*32) for v in re.findall(rb'<script\b[^>]*>(.*?)</script>',body,re.S)]
            print('NATIVE_WEB_SCRIPTS:'+json.dumps({'route':route,'scripts':scripts}),flush=True)
        code,_,_=self.cgi(BASE+'/basic_apply',cookie=sid);self.assertNotEqual(code,200)
        code,_,_=self.cgi(BASE+'/basic_apply',cookie=sid,verb='POST',fields={'https_port':'444'});self.assertNotEqual(code,200)
        code,_,body=self.cgi(BASE+'/basic_apply',cookie=sid,verb='POST',fields={'token':token,'mode':'save','https_port':'445'})
        self.assertEqual(code,200,body[:400]);self.assertIn('请求已受理'.encode(),body)
        print('NATIVE_WEB_SCRIPTS:'+json.dumps({'route':'pending','scripts':[v.decode().replace(token,'0'*32) for v in re.findall(rb'<script\b[^>]*>(.*?)</script>',body,re.S)]}),flush=True)
        import re
        job=re.search(rb"var id='([0-9a-f]{32})'",body).group(1).decode();result=self.web_wait(job,ack=False);self.assertTrue(result['ok'],result)
        print('NATIVE_WEB_RESULT:'+json.dumps(result),flush=True)
        code,_,body=self.cgi(BASE+'/compat_job/'+job,cookie=sid);self.assertEqual(code,200);self.assertFalse(json.loads(body)['pending'])
        code,_,_=self.cgi(BASE+'/compat_ack/'+job,cookie=sid,verb='POST',fields={'token':token});self.assertEqual(code,200)
        before=Path('/etc/config/homegate').read_bytes()
        code,_,body=self.exchange(path=BASE+'/config_import',verb='POST',headers={'Cookie':'sysauth='+sid,'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},raw=urlencode({'token':token,'config_payload':self.backup(s)}).encode())
        self.assertEqual(code,200,body[:300]);submitted=json.loads(body);self.assertTrue(submitted['pending'])
        result=self.web_wait(submitted['job']);self.assertTrue(result['ok'],result);preview=json.loads(result['body']);self.assertTrue(preview['ok']);self.assertFalse(preview['can_commit']);self.assertEqual(Path('/etc/config/homegate').read_bytes(),before)
        print('NATIVE_WEB_PREVIEW:'+json.dumps(preview),flush=True)
        self.verify_unchanged()
    def test_web_security(self):
        self.configured();p=Path('/tmp/web-invalid');before=Path('/etc/config/homegate').read_bytes()
        for raw in ['{"route":"basic","route":"overview","form":{}}','{"route":"basic","form":[]}','{"route":"basic","form":{}} {}','{"route":"basic","form":{"x":"a","x":"b"}}','{"route":"basic_apply","form":{}}']:
            p.write_text(raw);p.chmod(0o600);self.cli('web-read',str(p),ok=False)
        p.unlink();p.symlink_to('/etc/config/homegate');self.cli('web-read',str(p),ok=False);p.unlink()
        self.assertEqual(Path('/etc/config/homegate').read_bytes(),before)
        jobs=[]
        for i in range(8):jobs.append(self.web_request('config_export',{},True)['job'])
        p.write_text(json.dumps({'route':'config_export','form':{},'write':True}));p.chmod(0o600)
        refused=self.cli('web-submit',str(p));self.assertFalse(refused['ok']);self.assertTrue(refused['queue_unavailable']);p.unlink()
        self.assertEqual(len([d for d in Path('/tmp/homegate-frontend-jobs').iterdir() if d.is_dir()]),8)
        for job in jobs:
            result=self.web_wait(job,ack=False);self.assertTrue(result['ok'],result)
            self.assertFalse(self.cli('web-job',job)['pending']);self.cli('web-job-ack',job)
        d=self.web_request('config_export',{},True);self.assertTrue(self.web_wait(d['job'],ack=False)['ok'])
        p=subprocess.run(['/usr/sbin/ash','/usr/libexec/homegate/native-web.sh','purge','-'],capture_output=True,timeout=5);self.assertEqual(p.returncode,0,p.stdout[:300]);self.assertFalse(Path('/tmp/homegate-frontend-jobs').exists())
        self.assertEqual(Path('/etc/config/homegate').read_bytes(),before)
        self.verify_unchanged()
    def test_web_public(self):
        self.configured()
        d=self.web_request('public_account_apply',{'provider':'aliyun','key_id':'WEB_ACCOUNT_ID','secret':'WEB_PRIVATE_SECRET'},True)
        result=self.web_wait(d['job']);self.assertTrue(result['ok'],result)
        rendered=self.web_request('public')['data'];self.assertEqual(len(rendered['dns_accounts']),2)
        encoded=json.dumps(rendered);self.assertNotIn('WEB_PRIVATE_SECRET',encoded);self.assertNotIn('WEB_ACCOUNT_ID',encoded)
        form={'mode':'save','public_service_count':'1','public_service_1_domain':'files.example.test','public_service_1_target':'http://192.168.1.2:8080','public_service_1_provider':'cloudflare','public_service_1_enabled':'1','public_service_1_https':'0'}
        d=self.web_request('public_apply',form,True);result=self.web_wait(d['job']);self.assertTrue(result['ok'],result)
        rows=self.web_request('public')['data']['services'];self.assertEqual(len(rows),1);self.assertEqual(rows[0]['domain'],'files.example.test')
        source=Path('/etc/config/homegate').read_text();self.assertIn('files.example.test',source);self.assertNotIn('192.168.1.2',source)
        current=Path('/etc/homegate/transactions/current').read_text().strip();credentials=Path('/etc/homegate/transactions')/('gen-'+current)/'credentials'
        self.assertEqual((credentials/('web.'+rows[0]['web_id']+'.target')).read_text(),'http://192.168.1.2:8080')
        self.assertIn(b'WEB_PRIVATE_SECRET',[p.read_bytes() for p in credentials.iterdir()])
        self.verify_unchanged()
    def test_web_certificate(self):
        self.configured();pair=self.certificate_pair('web-local',domains='DNS:files.example.test',date_case='current')
        form={'mode':'save','public_service_count':'1','public_service_1_domain':'files.example.test','public_service_1_target':'http://192.168.1.2:8080','public_service_1_provider':'cloudflare','public_service_1_enabled':'1','public_service_1_https':'1','public_service_1_cert_mode':'local','public_service_1_local_cert_pem':pair[0],'public_service_1_local_key_pem':pair[1]}
        original=Path('/etc/config/homegate').read_bytes();bad=dict(form);bad['public_service_1_local_key_pem']=self.certificate_pair('wrong-key',domains='DNS:files.example.test')[1]
        d=self.web_request('public_apply',bad,True);result=self.web_wait(d['job']);self.assertFalse(result['ok']);self.assertEqual(Path('/etc/config/homegate').read_bytes(),original)
        d=self.web_request('public_apply',form,True);result=self.web_wait(d['job']);self.assertTrue(result['ok'],result)
        rows=self.web_request('public')['data']['services'];self.assertEqual(len(rows),1);self.assertTrue(rows[0]['cert_id'])
        self.assertTrue(self.cli('certificate-status',rows[0]['cert_id'])['valid'])
        self.assertNotIn('PRIVATE KEY',json.dumps(self.web_request('public')))
        self.assertFalse(list(Path('/tmp/homegate-frontend-jobs').glob('*/certificate-check')))
        material=Path('/etc/homegate/certs',rows[0]['cert_id']);self.assertTrue(material.is_dir())
        d=self.web_request('public_apply',{'mode':'apply','public_service_count':'0'},True);result=self.web_wait(d['job']);self.assertTrue(result['ok'],result);self.assertFalse(material.exists())
        self.verify_unchanged()
    def test_web_acme(self):
        s=self.acme_setup();self.cfg('lifecycle_enable',s,consent='1')
        d=self.web_request('public_action',{'op':'cert_renew','id':'cert_a'},True)
        result=self.web_wait(d['job'],seconds=65);self.assertTrue(result['ok'],result);self.assertEqual(result['native_job'],d['job'])
        self.assertTrue(self.cli('certificate-status','cert_a')['valid']);self.assertEqual(len(json.loads((STATE/'acme-fixture.json').read_text())['orders']),1)
        self.verify_unchanged()
    def test_web_unknown(self):
        s=self.acme_setup();self.cfg('lifecycle_enable',s,consent='1');(STATE/'acme-mode').write_text('dns-unknown')
        d=self.web_request('public_action',{'op':'cert_renew','id':'cert_a'},True);job=d['job']
        result=self.web_wait(job,seconds=65);self.assertFalse(result['ok']);self.assertTrue(result['uncertain'])
        self.assertFalse(self.cli('web-job-ack',job)['ok']);before=(STATE/'acme-fixture.json').read_bytes()
        self.assertFalse(self.cli('web-job',job)['pending']);self.assertEqual((STATE/'acme-fixture.json').read_bytes(),before)
        p=subprocess.run(['/usr/sbin/ash','/usr/libexec/homegate/native-web.sh','purge','-'],capture_output=True,timeout=5);self.assertNotEqual(p.returncode,0)
        self.assertTrue(Path('/tmp/homegate-frontend-jobs',job,'result').exists())
    def test_web_admission(self):
        import fcntl
        s=self.configured();p=Path('/var/run/homegate/frontend-web.lock');p.write_bytes(b'');p.chmod(0o600)
        before=Path('/etc/config/homegate').read_bytes()
        with p.open('ab') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX)
            d=self.web_request('basic_apply',{'mode':'save','https_port':'446'},True);job=d['job'];time.sleep(.2)
            self.assertTrue(self.cli('web-job-status',job)['pending']);self.cli('config-preview',ok=False)
            self.api('configuration_api','preview_account',s,{'id':'dns_b','provider':'cloudflare','name':'Blocked'},expected=503)
            self.assertTrue(self.web_request('basic')['ok']);self.assertEqual(Path('/etc/config/homegate').read_bytes(),before)
            self.assertTrue(self.cli('web-job',job)['pending'])
            fcntl.flock(lease,fcntl.LOCK_UN)
        self.assertTrue(self.web_wait(job)['ok']);self.assertIn("option https_port '446'",Path('/etc/config/homegate').read_text())
        job='a'*32;root=Path('/tmp/homegate-frontend-jobs',job);root.mkdir(mode=0o700)
        for name,body in [('request',json.dumps({'route':'config_export','form':{},'write':True})),('owner.lock','')]:
            f=root/name;f.write_text(body);f.chmod(0o600)
        d=self.cli('web-job',job);self.assertTrue(d['pending']);self.assertTrue(d['recovery_required']);self.assertFalse(d['owner_running'])
        self.assertFalse(self.cli('web-job-ack',job)['ok']);self.assertFalse((root/'result').exists())

    def test_web_apply(self):
        s=self.configured()
        for port in ['447']:
            import re
            code,_,body=self.cgi(BASE+'/basic_apply',cookie=s[0],verb='POST',fields={'token':s[1],'enabled':'1','mode':'apply','https_port':port});self.assertEqual(code,200)
            job=re.search(rb"var id='([0-9a-f]{32})'",body).group(1).decode()
            result=self.web_wait(job,seconds=25);self.assertTrue(result['ok'],result);self.assertTrue(result['runtime_applied'])
            status=self.cli('status');self.assertTrue(status['service']['healthy']);self.assertTrue(status['service']['running'])
            self.assertEqual(self.web_request('basic')['data']['main']['https_port'],port)
        self.assertFalse(Path('/etc/homegate/transactions/ddns-authority').exists())
        result=self.web_wait(self.web_request('basic_apply',{'mode':'apply'},True)['job'],seconds=25);self.assertTrue(result['ok'],result)
        self.assertFalse(self.cli('status')['service']['running']);self.cli('service-quiescent');self.verify_unchanged()
    def test_web_reapply(self):
        self.configured()
        for port in ['447','448']:
            result=self.web_wait(self.web_request('basic_apply',{'enabled':'1','mode':'apply','https_port':port},True)['job'],seconds=30);self.assertTrue(result['ok'],result);self.assertTrue(result['runtime_applied'])
            self.assertEqual(self.web_request('basic')['data']['main']['https_port'],port)
        self.assertTrue(result['runtime_stopped_for_save'])
        result=self.web_wait(self.web_request('maintenance_apply',{'mode':'save','log_max_lines':'2048'},True)['job']);self.assertTrue(result['ok'],result);self.assertTrue(result['runtime_stopped_for_save'])
        from urllib.parse import unquote
        self.assertIn('任务已停止',unquote(result['redirect']));self.cli('service-quiescent');self.verify_unchanged()
    def test_web_apply_ddns(self):
        self.configured();form={'mode':'save','public_service_count':'2'}
        for i in [1,2]:
            prefix='public_service_'+str(i)+'_';form.update({prefix+k:v for k,v in {'zone':'example.test','host':'web'+str(i),'account_id':'dns_a','provider':'cloudflare','enabled':'1','https':'0'}.items()})
        result=self.web_wait(self.web_request('public_apply',form,True)['job']);self.assertTrue(result['ok'],result)
        ids=sorted(x['ddns_id'] for x in self.web_request('public')['data']['services']);self.assertEqual(len(ids),2)
        result=self.web_wait(self.web_request('basic_apply',{'enabled':'1','mode':'apply'},True)['job'],seconds=60);self.assertTrue(result['ok'],result)
        saved=json.loads(Path('/etc/homegate/native-service-plan').read_text());self.assertEqual(saved['ddns'],ids)
        grant=Path('/etc/homegate/transactions/ddns-authority').read_text();self.assertTrue(all(x in grant for x in ids))
        self.assertTrue(result['runtime_applied']);self.assertTrue(self.cli('schedule-status')['running'])
        # This case checks both selected rules, the exact grant, and real
        # coordinator/scheduler startup. Provider completion and cooperative
        # shutdown are separately exercised by daemon_ddns; an admitted batch
        # keeps FD6/7 and is never killed or declared quiescent by this receipt.
        self.assertTrue(self.cli('service-stop','--confirm')['stop_requested'])
        self.verify_unchanged(allow_provider_calls=True)
    def test_web_apply_proxy(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body=b'LEGACY_WEB_NATIVE_PROXY';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*a):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        s=self.configured();public=self.backup(s);candidate=public.replace("option http_port '0'","option http_port '18080'");self.assertNotEqual(candidate,public)
        p=self.cfg('backup_preview',s,backup=candidate)['report'];self.cfg('apply',s,confirmation=p['confirmation'],consent='1')
        form={'mode':'save','public_service_count':'1','public_service_1_domain':'example.test','public_service_1_target':'http://127.0.0.1:'+str(server.server_port),'public_service_1_provider':'cloudflare','public_service_1_enabled':'1','public_service_1_https':'0'}
        result=self.web_wait(self.web_request('public_apply',form,True)['job']);self.assertTrue(result['ok'],result)
        result=self.web_wait(self.web_request('basic_apply',{'enabled':'1','mode':'apply'},True)['job'],seconds=30);self.assertTrue(result['ok'],result)
        conn=http.client.HTTPConnection('127.0.0.1',10080,timeout=5);conn.request('GET','/',headers={'Host':'example.test'});response=conn.getresponse();self.assertEqual(response.status,200);self.assertEqual(response.read(),b'LEGACY_WEB_NATIVE_PROXY');conn.close()
        self.cli('service-stop','--confirm');self.wait_service(lambda d:d['state']=='stopped');self.cli('service-quiescent');self.verify_unchanged()
    def legacy_material(self):
        s=self.configured();self.certificate_config(s)
        pair=self.certificate_pair('legacy',date_case='current');root=Path('/etc/homegate/certs');root.mkdir(mode=0o700,exist_ok=True);p=root/'cert_a';p.mkdir(mode=0o700)
        for name,raw in zip(['fullchain.pem','privkey.pem'],pair):q=p/name;q.write_text(raw);q.chmod(0o600)
        return s,p,pair
    def test_cert_adopt(self):
        s,p,pair=self.legacy_material();self.cli('cert-adopt','cert_a','--confirm')
        self.assertTrue(self.cli('certificate-status','cert_a')['valid']);self.assertEqual((p/'privkey.pem').read_text(),pair[1]);self.assertTrue((p/'legacy-adopted').exists())
        neighbor=p.parent/'foreign';neighbor.mkdir(mode=0o700);(neighbor/'keep').write_text('foreign')
        result=self.web_wait(self.web_request('public_action',{'op':'cert_delete','id':'cert_a'},True)['job']);self.assertTrue(result['ok'],result)
        self.assertFalse(p.exists());self.assertEqual((neighbor/'keep').read_text(),'foreign');self.verify_unchanged()
    def test_cert_adopt_acme(self):
        self.acme_setup();pair=self.certificate_pair('legacy-acme',date_case='current')
        root=Path('/etc/homegate/certs');root.mkdir(mode=0o700,exist_ok=True);p=root/'cert_a';p.mkdir(mode=0o700)
        for name,value in zip(['fullchain.pem','privkey.pem'],pair):f=p/name;f.write_text(value);f.chmod(0o644 if name=='fullchain.pem' else 0o600)
        self.cli('cert-adopt','cert_a','--confirm');self.assertTrue(self.cli('certificate-status','cert_a')['valid']);self.assertFalse((STATE/'acme-fixture.json').exists());self.assertFalse(Path('/etc/homegate/transactions/ddns-authority').exists());self.verify_unchanged()
    def test_cert_ownership(self):
        s,p,pair=self.legacy_material();key=p/'privkey.pem';key.unlink();key.symlink_to(STATE/'foreign-private')
        failed=subprocess.run(['/usr/bin/homegate','cert-adopt','cert_a','--confirm'],capture_output=True,timeout=8);self.assertNotEqual(failed.returncode,0);self.assertFalse((p/'current').exists())
        key.unlink();key.write_text(pair[1]);key.chmod(0o600)
        if (p/'.pending').exists():self.cfg('cert_cancel',s,id='cert_a',consent='1')
        self.cli('cert-adopt','cert_a','--confirm');(p/'foreign-file').write_text('KEEP');(p/'foreign-file').chmod(0o600)
        result=self.web_wait(self.web_request('public_action',{'op':'cert_delete','id':'cert_a'},True)['job']);self.assertFalse(result['ok']);self.assertTrue(result['material_retained']);self.assertEqual((p/'foreign-file').read_text(),'KEEP')
        (p/'foreign-file').unlink();self.cli('cert-purge','cert_a','--confirm');self.assertFalse(p.exists());self.assertFalse(list(p.parent.glob('.purge-*')));self.verify_unchanged()
    def test_cli_arity(self):
        import re
        source=(ROOT/'project/core/src/cmd/homegate/main.go').read_text();blocks=list(re.finditer(r'^\tcase ((?:"[^"]+"(?:, )?)+):',source,re.M));seen=set()
        for i,m in enumerate(blocks):
            body=source[m.end():blocks[i+1].start() if i+1<len(blocks) else len(source)]
            condition=re.search(r'if (len\(os.Args\)[^\n]+) \{',body).group(1)
            for name in re.findall(r'"([^"]+)"',m.group(1)):
                seen.add(name)
                for count in [1,6]:
                    expression=condition.replace('len(os.Args)',str(count+1)).replace('&&','and').replace('||','or')
                    if eval(expression,{'__builtins__':{}},{}):
                        p=subprocess.run(['/usr/bin/homegate',name,*(['extra']*(count-1))],capture_output=True,timeout=3);self.assertEqual(p.returncode,2,(name,p.returncode))
        self.assertEqual(seen,set(json.loads((ROOT/'docs/核心CLI合同.json').read_text())['cli_commands']))
        for cmd in [['dns-check-private','/tmp/missing'],['dns-provider-status','missing'],['cert-import','missing','/tmp/a','/tmp/b']]:
            p=subprocess.run(['/usr/bin/homegate',*cmd],capture_output=True,timeout=8);self.assertEqual(p.returncode,1,(cmd,p.returncode))
        self.assertNotEqual(self.cli('version')['arch'],'all');self.verify_unchanged()
    def test_web_owner_refusal(self):
        self.configured()
        # Reproduce a status reader holding the freshly created owner lock
        # before the owner has acquired it. The real separate open-file
        # description holds the actual lock; no business lock is replaced.
        tool=STATE/'tools/flock';link=os.readlink(tool) if tool.is_symlink() else None;original=tool.read_bytes() if tool.exists() and link is None else None
        if tool.exists() or tool.is_symlink():tool.unlink()
        tool.write_text('''#!/usr/sbin/ash
parent=$(tr '\\000' ' ' < /proc/$PPID/cmdline)
case "$1:${2:-}:$parent" in
 '-n:9:ash /usr/libexec/homegate/native-web.sh owner '*)
  if mkdir /teststate/owner-probe-once 2>/dev/null;then
   path=$(readlink /proc/$$/fd/9)
   (exec 9>&-;exec 3>>"$path";/usr/sbin/busybox flock 3 || exit 1;touch /teststate/owner-probe-ready;sleep .12) </dev/null >/dev/null 2>&1 &
   tries=0;while [ ! -e /teststate/owner-probe-ready ];do tries=$((tries+1));[ "$tries" -lt 100 ] || exit 1;sleep .01;done
  fi;;
esac
exec /usr/sbin/busybox flock "$@"
''');tool.chmod(0o755)
        try:
            result=self.web_wait(self.web_request('maintenance_apply',{'mode':'save','log_max_lines':'2049'},True)['job'])
            self.assertTrue(result['ok'],result);self.assertTrue((STATE/'owner-probe-ready').exists());self.assertIn("option log_max_lines '2049'",Path('/etc/config/homegate').read_text())
        finally:
            tool.unlink()
            if link is not None:tool.symlink_to(link)
            elif original is not None:tool.write_bytes(original);tool.chmod(0o755)
        before=Path('/etc/config/homegate').read_bytes();launcher=STATE/'tools/lua';raw=launcher.read_text()
        launcher.write_text('#!/bin/sh\nif [ "$1" = /usr/libexec/homegate/project/core/prototype/worker-process.lua ] && [ "${2:-}" = info ] && [ "${4:-}" = none ];then exit 73;fi\n'+raw)
        try:
            job=self.web_request('basic_apply',{'mode':'save','https_port':'450'},True)['job'];result=self.web_wait(job);self.assertFalse(result['ok']);self.assertNotIn('uncertain',result)
        finally:launcher.write_text(raw)
        self.assertEqual(Path('/etc/config/homegate').read_bytes(),before);self.verify_unchanged()
    def test_cert_purge_resume(self):
        s,p,pair=self.legacy_material();self.cli('cert-adopt','cert_a','--confirm')
        # Unknown extra content forces the actual controller to retain material.
        f=p/'keep';f.write_text('KEEP');f.chmod(0o600)
        result=self.web_wait(self.web_request('public_action',{'op':'cert_delete','id':'cert_a'},True)['job']);self.assertFalse(result['ok']);f.unlink()
        shim=STATE/'purge-interrupt.lua';shim.write_text("local fs=require('nixio.fs');local original=fs.unlink;local count=0;fs.unlink=function(p)if p:find('/.purge-cert_a/',1,true)then count=count+1;if count==2 then os.exit(75)end end;return original(p)end;local path=table.remove(arg,1);arg[0]=path;assert(loadfile(path))(unpack(arg))\n")
        launcher=STATE/'tools/lua';raw=launcher.read_text();launcher.write_text('#!/bin/sh\nif [ "$1" = /usr/libexec/homegate/native-certificates.lua ];then exec /usr/bin/lua5.1 /teststate/lua-runner.lua /teststate/purge-interrupt.lua "$@";fi\n'+raw)
        try:
            failed=subprocess.run(['/usr/bin/homegate','cert-purge','cert_a','--confirm'],capture_output=True,timeout=10);self.assertNotEqual(failed.returncode,0)
        finally:launcher.write_text(raw)
        self.assertTrue((p.parent/'.purge-cert_a').is_dir());self.assertTrue((p.parent/'.purge-cert_a.json').is_file())
        self.cli('cert-purge','cert_a','--confirm');self.assertFalse(list(p.parent.glob('.purge-*')));self.assertFalse(p.exists());self.verify_unchanged()

class Deployment(unittest.TestCase):
    def test_transition_kit_source_and_payload(self):
        # Synthetic containers exercise the inspector; no SDK/package build.
        import io,tarfile
        from native_transition import prepare_kit,module,NAMES
        with tempfile.TemporaryDirectory() as work:
            root=Path(work);feed=root/'feed';stage_package(ROOT,feed);packages=root/'packages';packages.mkdir()
            translated=root/'translated';po=module(ROOT/'project/luci/common/tools/po2lmo.py','native_test_po');po.build(feed/'po/zh_Hans/homegate.po',translated)
            make=(feed/'Makefile').read_text();version='1.3.0-r'+(ROOT/'RELEASE').read_text().strip()
            def archive(files):
                out=io.BytesIO()
                with tarfile.open(fileobj=out,mode='w:gz') as t:
                    for name,raw,mode in files:
                        item=tarfile.TarInfo(name);item.size=len(raw);item.mode=mode;t.addfile(item,io.BytesIO(raw))
                return out.getvalue()
            for name,part in zip(NAMES,('core','web','translation')):
                body=[(p.relative_to(feed/'payload'/part).as_posix(),p.read_bytes(),p.stat().st_mode&0o777) for p in (feed/'payload'/part).rglob('*') if p.is_file()] if part!='translation' else [('usr/lib/lua/luci/i18n/homegate.zh-cn.lmo',translated.read_bytes(),0o644)]
                dependencies=('homegate-core (= '+version+')' if part=='web' else
                              'homegate-core (= '+version+'), luci-app-homegate (= '+version+')' if part=='translation' else 'busybox')
                control=[('control',('Package: '+name+'\nVersion: '+version+'\nArchitecture: all\nDepends: '+dependencies+'\n').encode(),0o644)]
                if part=='core':
                    for hook in ['preinst','prerm','postinst','postrm']:
                        raw=(make.split('define Package/homegate-core/'+hook+'\n')[1].split('\nendef')[0].replace('$$','$').strip()+'\n').encode();control.append((hook,raw,0o755))
                container=archive([('debian-binary',b'2.0\n',0o644),('control.tar.gz',archive(control),0o644),('data.tar.gz',archive(body),0o644)])
                (packages/(name+'.ipk')).write_bytes(container)
            result=prepare_kit(ROOT,packages,root/'kit');self.assertEqual(len(result['sha256']),6);self.assertEqual((root/'kit').stat().st_mode&0o777,0o700)
            for p in (root/'kit').iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)
            bad=packages/'homegate-core.ipk';blob=bad.read_bytes();bad.write_bytes(blob[:-40])
            with self.assertRaises(Exception):prepare_kit(ROOT,packages,root/'bad-kit')
            self.assertFalse((root/'bad-kit').exists())
    def test_native_SDK_lifecycle_dispatchers(self):
        # Exercise the real SDK layout and reject wrapper/body injection,
        # missing/duplicate bodies and archive owner/mode substitutions.
        import io,tarfile
        from native_transition import verify_lifecycle_hooks
        with tempfile.TemporaryDirectory() as work:
            feed=Path(work)/'feed';stage_package(ROOT,feed);make=(feed/'Makefile').read_text();files={}
            for hook in ('preinst','prerm','postinst','postrm'):
                wanted=(make.split('define Package/homegate-core/'+hook+'\n')[1].split('\nendef')[0].replace('$$','$').strip()+'\n').encode()
                if hook in ('prerm','postinst'):
                    wrapper=b'#!/bin/sh\n'
                    if hook=='postinst':wrapper+=b'[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0\n'
                    wrapper+=b'[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0\n. ${IPKG_INSTROOT}/lib/functions.sh\ndefault_'+hook.encode()+b' $0 $@\n'
                    files[hook]=wrapper;files[hook+'-pkg']=wanted
                else:files[hook]=wanted
            def archive(rows,unsafe=None):
                out=io.BytesIO()
                with tarfile.open(fileobj=out,mode='w:gz') as t:
                    for name,raw in rows:
                        item=tarfile.TarInfo('./'+name);item.size=len(raw);item.mode=0o755
                        if unsafe=='owner' and name=='prerm-pkg':item.uid=65534
                        if unsafe=='mode' and name=='prerm-pkg':item.mode=0o644
                        t.addfile(item,io.BytesIO(raw))
                return out.getvalue()
            good=list(files.items());result=verify_lifecycle_hooks(archive(good),make)
            self.assertEqual(result['prerm'],'SDK-default-and-exact-pkg-body')
            cases=[([(n,b'exit 0\n'+v if n=='prerm' else v) for n,v in good],None),
                   ([(n,v+b'echo injected\n' if n=='postinst-pkg' else v) for n,v in good],None),
                   ([(n,v) for n,v in good if n!='prerm-pkg'],None),
                   (good+[('prerm-pkg',files['prerm-pkg'])],None),(good,'owner'),(good,'mode')]
            for rows,unsafe in cases:
                with self.subTest(unsafe=unsafe,rows=[n for n,_ in rows]):
                    with self.assertRaises(ValueError):verify_lifecycle_hooks(archive(rows,unsafe),make)
    def test_source_package_tree(self):
        with tempfile.TemporaryDirectory() as work:
            dest=Path(work)/'feed';stage_package(ROOT,dest);make=(dest/'Makefile').read_text()
            self.assertNotIn('@HOMEGATE_',make);self.assertIn('BuildPackage,homegate-core',make);self.assertIn('CONFLICTS:=homegate homegate-engineering-core',make)
            for name in ['preinst','prerm','postinst','postrm']:
                body=make.split('define Package/homegate-core/'+name+'\n')[1].split('\nendef')[0].replace('$$','$')
                p=subprocess.run(['busybox','ash','-n'],input=body.encode(),capture_output=True);self.assertEqual(p.returncode,0,(name,p.stderr))
            self.assertEqual((dest/'payload/core/etc/config/homegate').stat().st_mode&0o777,0o600)
            self.assertEqual((dest/'payload/core/usr/bin/homegate').read_bytes(),payload(ROOT)['usr/bin/homegate'])
            self.assertFalse(list(dest.rglob('*.ipk')))
    def test_native_exact_dependencies(self):
        from native_transition import verify_version_dependencies
        version=(ROOT/'VERSION').read_text().strip()+'-r'+(ROOT/'RELEASE').read_text().strip()
        for package,required in [('luci-app-homegate',['homegate-core']),('luci-i18n-homegate-zh-cn',['homegate-core','luci-app-homegate'])]:
            depends=', '.join(n+' (= '+version+')' for n in required)
            verify_version_dependencies({'name':package,'depends':'libc, '+depends},version)
            for bad in [depends.replace(' (= '+version+')',''),depends.replace('(= ','(>= '),depends.replace(version,'1.3.0-r1'), 'busybox']:
                with self.assertRaises(ValueError):verify_version_dependencies({'name':package,'depends':bad},version)
    def test_actual_payload_and_grammar(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime();files=payload(ROOT)
        self.assertIn('usr/bin/homegate',files)
        for name,raw in files.items():
            self.assertNotIn(b'/etc/homegate-engineering',raw,name);self.assertNotIn(b'/usr/bin/homegate-engineering',raw,name)
            if name.endswith('.sh') or name=='usr/bin/homegate':
                p=subprocess.run(['busybox','ash','-n'],input=raw,capture_output=True);self.assertEqual(p.returncode,0,(name,p.stderr))
            elif name.endswith('.lua'):lua.compile(raw)
        self.assertIn(b'service_actions_enabled=false',files['usr/libexec/homegate/project/core/prototype/homegate-config-prototype.sh'])
        self.assertIn(b'HG_NATIVE_NAT',files['usr/libexec/homegate/project/core/prototype/homegate-firewall.lua'])
        self.assertIn(b'go build', (ROOT/'project/core/Makefile').read_bytes())
        for p in (ROOT/'packaging/production').iterdir():
            if p.suffix=='.lua':lua.compile(p.read_bytes())
            if p.suffix=='.sh':
                r=subprocess.run(['busybox','ash','-n',str(p)],capture_output=True);self.assertEqual(r.returncode,0,(p.name,r.stderr))

def main():
    global NGINX,FIXTURE,PROXY,INSTALLED,WOL,WOL_FIXTURE,ACTIONS
    p=argparse.ArgumentParser();p.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd');p.add_argument('--http-runtime-dir',type=Path,default=ROOT/'build/uhttpd');p.add_argument('--luci-runtime-dir',type=Path,default=ROOT/'build/luci');p.add_argument('--nginx-runtime-dir',type=Path,default=NGINX);p.add_argument('--nginx-fixture-dir',type=Path,default=FIXTURE);p.add_argument('--wol-runtime-dir',type=Path,default=WOL);p.add_argument('--wol-fixture-dir',type=Path,default=WOL_FIXTURE);p.add_argument('--installed-root',type=Path);p.add_argument('--inside-net');p.add_argument('--inside-uid');p.add_argument('--group',choices=['deployment','migration','backup','rollback','recovery','security','diagnostics','daemon','daemon_ddns','daemon_source','daemon_security','daemon_web','daemon_acme','daemon_acme_unknown','daemon_proxy','package_source','cli_compat','cli_acme','cli_ca_logs','cli_acme_unknown','cli_acme_all','transition_source','transition_identity','web_forms','web_http','web_security','web_public','web_certificate','web_acme','web_unknown','web_admission','web_apply','cert_adopt','cert_ownership','cli_arity','web_owner_refusal','cert_purge_resume','web_reapply','web_apply_ddns','web_apply_proxy','cert_adopt_acme','cli_reports','cli_selftest','cli_ddns','cli_ddns_unknown','cli_ddns_batch','cli_queue','cli_actions','web_access_actions','web_maintenance_actions','cli_firewall','daemon_component_failure']);a=p.parse_args()
    NGINX=a.nginx_runtime_dir.resolve();FIXTURE=a.nginx_fixture_dir.resolve();PROXY=a.group in ['daemon_proxy','web_apply_proxy','cli_firewall','daemon_component_failure'];INSTALLED=a.installed_root.resolve() if a.installed_root else None;WOL=a.wol_runtime_dir.resolve();WOL_FIXTURE=a.wol_fixture_dir.resolve();ACTIONS=a.group in ACTION_GROUPS
    if a.group=='deployment':return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Deployment)).wasSuccessful() else 1
    rpc.WORK,luci.HTTP,luci.LUA=a.runtime_dir.resolve(),a.http_runtime_dir.resolve(),a.luci_runtime_dir.resolve();web.BASE,web.PAGE,luci.BASE,luci.PAGE=BASE,PAGE,BASE,PAGE
    if a.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID=a.inside_net,a.inside_uid
        if INSTALLED:
            receipt=json.loads((STATE/'native-package-stage.json').read_text())
            for name,h in receipt['files_sha256'].items():
                if name.startswith('usr/libexec/homegate/') or name=='usr/bin/homegate':
                    assert hashlib.sha256(Path('/'+name).read_bytes()).hexdigest()==h,name
            print('PACKAGE_EXECUTION:'+json.dumps({'installed_root':str(INSTALLED),'verified_files':len(receipt['files_sha256']),'SDK_translation_bytes_verified':True,'AArch64_dependency_binaries_executed':False}),flush=True)
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([Native('test_'+a.group)])).wasSuccessful() else 1
    for group in [a.group] if a.group else ['migration','backup','rollback','recovery','security','diagnostics','daemon','daemon_ddns','daemon_source','daemon_security','daemon_web','daemon_acme','daemon_acme_unknown','daemon_proxy','package_source','cli_compat','cli_acme','cli_ca_logs','cli_acme_unknown','cli_acme_all','transition_source','transition_identity','web_forms','web_http','web_security','web_public','web_certificate','web_acme','web_unknown','web_admission','web_apply','cert_adopt','cert_ownership','cli_arity','web_owner_refusal','cert_purge_resume','web_reapply','web_apply_ddns','web_apply_proxy','cert_adopt_acme','cli_reports','cli_selftest','cli_ddns','cli_ddns_unknown','cli_ddns_batch','cli_queue','cli_actions','web_access_actions','web_maintenance_actions','cli_firewall','daemon_component_failure']:
        PROXY=group in ['daemon_proxy','web_apply_proxy','cli_firewall','daemon_component_failure']
        ACTIONS=group in ACTION_GROUPS
        if ACTIONS:
            spec=importlib.util.spec_from_file_location('native_wol',ROOT/'scripts/prepare-wol.py');component=importlib.util.module_from_spec(spec);spec.loader.exec_module(component);component.validate(WOL)
            data=json.loads((WOL_FIXTURE/'metadata.json').read_text());assert data['source_sha256']==hashlib.sha256((ROOT/'scripts/wol-syscall-fixture.c').read_bytes()).hexdigest() and data['library_sha256']==hashlib.sha256((WOL_FIXTURE/'transport.so').read_bytes()).hexdigest()
        if PROXY:
            spec=importlib.util.spec_from_file_location('native_nginx',ROOT/'scripts/prepare-nginx.py');runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime);runtime.validate_runtime(NGINX)
            runtime.validate_fixture(FIXTURE)
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=((luci.HTTP,luci.LUA,NGINX,FIXTURE) if PROXY else (luci.HTTP,luci.LUA))+((INSTALLED,) if INSTALLED else ())+((WOL,WOL_FIXTURE) if ACTIONS else ()),
          extra_mounts=lambda s:(((s/'luci-library',luci.LUA/'prefix/lib/lua/luci'),) if INSTALLED else ())+((Path('/etc/ssl'),'/etc/ssl'),(Path('/usr/bin'),'/fixture-host-bin'),(s/'usr-bin','/usr/bin'),(s/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),(s/'models',luci.LUA/'prefix/lib/lua/luci/model'),(s/'libexec','/usr/libexec'),(s/'tools','/usr/sbin'),(s/'curl-fixture','/usr/bin/curl'))+(((s/'i18n',luci.LUA/'prefix/lib/lua/luci/i18n'),) if INSTALLED else ())+(((s/'wol-sys-net','/sys/class/net'),) if ACTIONS else ()),
          extra_rw_mounts=lambda s:((s/'etc/rc.d','/etc/rc.d'),(s/'var-log','/var/log'),(s/'etc/.homegate-transition','/etc/.homegate-transition'),(s/'etc/homegate','/etc/homegate'),(s/'etc/homegate-engineering','/etc/homegate-engineering'),(s/'etc/config','/etc/config')),
          state_setup=setup_state,guest_args=['--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--nginx-runtime-dir',str(NGINX),'--nginx-fixture-dir',str(FIXTURE),'--wol-runtime-dir',str(WOL),'--wol-fixture-dir',str(WOL_FIXTURE),'--group',group]+(['--installed-root',str(INSTALLED)] if INSTALLED else []))
        if result:return result
    return 0
if __name__=='__main__':sys.exit(main())
