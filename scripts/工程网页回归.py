#!/usr/bin/env python3
"""Real pinned LuCI sessions/CSRF -> installed engineering configuration/DDNS.

Reuse the established unprivileged bwrap boundary and external tool fixtures.
No target installation, real credentials or remote DNS operations.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess,sys,time,unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode
from project import ROOT
from engineering_runtime import stage,web_payload

spec=importlib.util.spec_from_file_location('engineering_luci',ROOT/'scripts/luci-ddns-regressions.py')
luci=importlib.util.module_from_spec(spec);spec.loader.exec_module(luci)
rpc=luci.rpc;STATE=rpc.STATE
BASE='/cgi-bin/luci/admin/services/homegate_engineering'
PAGE=BASE+'/configuration'
INSTALLED=None

def install_tree(root):
    base=root/'usr/libexec/homegate-engineering';stage(ROOT,base)
    for name in ['engineering.lua','ddns-control.sh','apply-handle.lua','service-disabled','config-web.sh','config-web.lua','schedule-control.sh']:
        dest=base/name;shutil.copyfile(ROOT/'packaging/engineering/files'/name,dest);dest.chmod(0o755)
    entry=root/'usr/bin/homegate-engineering';entry.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/'packaging/engineering/files/homegate-engineering',entry);entry.chmod(0o755)
    for name,raw in web_payload(ROOT).items():
        dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
    for name,path in [('controller.lua','usr/lib/lua/luci/controller/homegate_engineering.lua'),
                      ('overview.htm','usr/lib/lua/luci/view/homegate_engineering/overview.htm'),
                      ('homegate-engineering.init','etc/init.d/homegate-engineering'),
                      ('95-homegate-engineering','etc/hotplug.d/iface/95-homegate-engineering')]:
        dest=root/path;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/'packaging/engineering/files'/name,dest);dest.chmod(0o755 if name in ['homegate-engineering.init','95-homegate-engineering'] else 0o644)

def setup_state(state):
    luci.setup_state(state)
    (state/'etc/ssl').mkdir()  # Mount target exists before the private /etc becomes read-only.
    installed=state/'installed'
    if INSTALLED:shutil.copytree(INSTALLED,installed,symlinks=True)
    else:installed.mkdir();install_tree(installed)
    # Supply the real canonical installed CLI without writing the host /usr/bin.
    # The existing binaries remain readonly through an alias; only the private
    # fixture bin directory contains the package entry and curl mount point.
    private_bin=state/'usr-bin';private_bin.mkdir()
    python=Path(sys.executable).resolve()
    for executable in Path('/usr/bin').iterdir():
        dest=private_bin/executable.name
        if executable.name in ['curl','homegate-engineering']:continue
        if executable.resolve()==python:
            if executable.name==python.name:shutil.copyfile(python,dest);dest.chmod(0o755)
            else:dest.symlink_to(python.name)
        else:dest.symlink_to('/fixture-host-bin/'+executable.name)
    (private_bin/'openssl').unlink();shutil.copyfile('/usr/bin/openssl',private_bin/'openssl');(private_bin/'openssl').chmod(0o755)
    shutil.copyfile(installed/'usr/bin/homegate-engineering',private_bin/'homegate-engineering')
    (private_bin/'homegate-engineering').chmod(0o755);(private_bin/'curl').touch()
    # Real LuCI dispatcher/session modules remain untouched. Only the private
    # admin authentication root and native template header are fixture data.
    (state/'controllers/fixture.lua').write_text("""module('luci.controller.fixture',package.seeall)
function index()
 local p=entry({'admin'},firstchild(),'Fixture',1)
 p.sysauth={'fixture_writer'};p.sysauth_authenticator='htmlauth'
end
""")
    (state/'controllers/homegate_ddns.lua').unlink()
    shutil.copytree(installed/'usr/lib/lua/luci/controller',state/'controllers',dirs_exist_ok=True)
    shutil.copytree(installed/'usr/lib/lua/luci/model',state/'models',dirs_exist_ok=True)
    shutil.copytree(installed/'usr/lib/lua/luci/view',state/'view',dirs_exist_ok=True)
    shutil.copytree(installed/'www',state/'www',dirs_exist_ok=True)
    shutil.copytree(installed/'usr/libexec/homegate-engineering',state/'libexec/homegate-engineering')
    (state/'tools').mkdir(exist_ok=True)
    # Backend paths are the actual installed paths; executable lookup and DNS
    # transport are the same explicit fixed external fixtures used previously.
    shutil.copyfile(installed/'usr/bin/homegate-engineering',state/'tools/homegate-engineering')
    (state/'tools/homegate-engineering').chmod(0o755)
    modules=luci.LUA/'prefix/lib/lua'
    (state/'lua-runner.lua').write_text('package.path='+json.dumps(str(modules/'?.lua')+';'+str(modules/'?/init.lua'))+
      '\npackage.cpath='+json.dumps(str(modules/'?.so'))+"\nlocal f=table.remove(arg,1);arg[0]=f;assert(loadfile(f))(unpack(arg))\n")
    shutil.copyfile(ROOT/'build/busybox-runtime/busybox-1.33.2/busybox',state/'tools/busybox')
    (state/'tools/busybox').chmod(0o755)
    for name in ['ash','fsync']:
        dest=state/'tools'/name
        if dest.exists() or dest.is_symlink():dest.unlink()
        dest.symlink_to('busybox')
    (state/'tools/lua').write_text('#!/bin/sh\nexec /usr/bin/lua5.1 /teststate/lua-runner.lua "$@"\n');(state/'tools/lua').chmod(0o755)
    (state/'etc/homegate-engineering').mkdir(mode=0o700)
    (state/'etc/config/homegate_engineering').write_bytes((ROOT/'packaging/engineering/files/homegate_engineering.config').read_bytes())
    (state/'etc/config/homegate_engineering').chmod(0o600)
    (state/'etc/config/homegate').write_bytes(b'PRODUCTION_CONFIGURATION_KEEP\n')
    (state/'etc/rc.common').write_text('#!/bin/sh\nexit 99\n');(state/'etc/rc.common').chmod(0o755)
    (state/'tools/ubus').write_text("#!/bin/sh\nprintf '{}\\n'\n");(state/'tools/ubus').chmod(0o755)
    # This no-op transport confirms the async worker reaches the real provider
    # planner without mutation. Four-provider real TLS is separately exercised.
    (state/'tools/ip').write_text("#!/bin/sh\ncase \"$*\" in *addr*) printf '12: pppoe-wan inet6 2001:db8::2/64 scope global\\n';; *) printf 'default via fe80::1 dev pppoe-wan metric 512\\n';; esac\n");(state/'tools/ip').chmod(0o755)
    curl=state/'tools/curl'
    curl.write_text("""#!/usr/bin/python3
import sys,json,time,re,os
from pathlib import Path
if Path('/teststate/acme-enabled').exists():os.execv('/usr/bin/python3',['python3','/teststate/acme-fixture.py',*sys.argv[1:]])
p=Path(sys.argv[sys.argv.index('--config')+1]);raw=p.read_text()
with open('/teststate/provider-calls','a') as log:log.write('read\\n')
if Path('/teststate/require-imported-secret').exists():
 if 'Authorization: Bearer SECRET_SENTINEL' not in raw:sys.exit(99)
 Path('/teststate/imported-secret-used').touch()
mode=Path('/teststate/provider-mode').read_text() if Path('/teststate/provider-mode').exists() else 'noop'
if mode=='hold':
 Path('/teststate/provider-entered').write_bytes(b'held')
 deadline=time.monotonic()+15
 while not Path('/teststate/provider-release').exists():
  if time.monotonic()>=deadline:sys.exit(99)
  time.sleep(.03)
if mode.startswith('delete-'):
 rec={'id':'2'*32,'name':'www.example.test','type':'AAAA','content':'2001:db8::2','ttl':120,'proxied':False}
 detail=re.search(r'/dns_records/[0-9a-f]{32}',raw)
 if 'request = "DELETE"' in raw:
  Path('/teststate/provider-mode').write_text('delete-absent')
  if mode=='delete-unknown':print('{"success":false,"errors":[{"code":1000}]}');print('HGHTTP:500')
  else:print(json.dumps({'success':True,'result':{'id':'2'*32}}));print('HGHTTP:200')
  sys.exit(0)
 if detail:
  if mode=='delete-absent':print('{"success":false,"errors":[{"code":81044}]}');print('HGHTTP:404')
  else:print(json.dumps({'success':True,'result':rec}));print('HGHTTP:200')
  sys.exit(0)
if 'request = "POST"' in raw or 'request = "PATCH"' in raw or 'request = "DELETE"' in raw:
 if mode!='unknown':sys.exit(99)
 print('{"success":false,"errors":[{"code":1000,"message":"temporary"}]}');print('HGHTTP:500');sys.exit(0)
record='dns_records' in raw
result=[{'id':'2'*32,'name':'www.example.test','type':'AAAA','content':'2001:db8::2','ttl':120,'proxied':False}] if record else [{'id':'1'*32,'name':'example.test','status':'active'}]
if record and mode in ['unknown','delete-absent']:result=[]
page_source=sys.argv[sys.argv.index('--url')+1] if '--url' in sys.argv else raw
page_size=re.search(r'per_page=([0-9]+)',page_source)
print(json.dumps({'success':True,'result':result,'result_info':{'page':1,'total_pages':1,'per_page':int(page_size.group(1)) if page_size else 5,'total_count':len(result)}}))
print('HGHTTP:200')
""");curl.chmod(0o755)
    shutil.copyfile(ROOT/'scripts/acme-protocol-fixture.py',state/'acme-fixture.py')
    # Workers deliberately require a regular curl at /usr/bin/curl.
    shutil.copyfile(curl,state/'curl-fixture')
    (state/'curl-fixture').chmod(0o755)
    (state/'business-sha.json').write_text(json.dumps({str(f.relative_to(state/'libexec')):hashlib.sha256(f.read_bytes()).hexdigest() for f in (state/'libexec/homegate-engineering').rglob('*') if f.is_file()}))

class Web(luci.LuaLuCI):
    HTTP_TIMEOUT=30;CGI_TIMEOUT=30
    def setUp(self):pass
    def login(self):
        status,headers,_=self.cgi(PAGE,verb='POST',fields={'luci_username':'fixture_writer','luci_password':rpc.FIXTURE_PASSWORD})
        self.assertEqual(status,302,'Private LuCI login failed')
        cookies=SimpleCookie();cookies.load(headers.get('set-cookie',''));sid=cookies['sysauth'].value
        status,_,body=self.cgi(PAGE,cookie=sid);self.assertEqual(status,200)
        token=re.search(rb'data-token="([0-9a-f]+)"',body);self.assertIsNotNone(token)
        return sid,token.group(1).decode()
    def api(self,area,action,session=None,fields=None,expected=200,verb=None):
        sid,token=session if session else (None,None)
        write=action not in ['read','status','jobs','schedule_status','lifecycle_status','cert_status','acme_status','acme_schedule_status'];payload=dict(fields or {})
        if write and token:payload['token']=token
        path=BASE+'/'+area+'/'+action
        if not write and payload:path+='?'+urlencode(payload);payload={}
        status,_,body=self.cgi(path,cookie=sid,verb=verb or ('POST' if write else 'GET'),fields=payload)
        self.assertEqual(status,expected,(area,action,status,body[:250] if b'SECRET_SENTINEL' not in body else b'[suppressed]'))
        self.assertNotIn(b'SECRET_SENTINEL',body)
        if expected!=200:return None
        value=json.loads(body);self.assertTrue(value['ok']);return value
    def cfg(self,action,s,**fields):return self.api('configuration_api',action,s,fields)
    def prepare_account(self,s):
        self.cfg('prepare',s)
        preview=self.cfg('preview_account',s,id='dns_a',name='DNS account',provider='cloudflare')
        self.cfg('apply',s,confirmation=preview['report']['confirmation'],consent='1')
    def publish(self,s):
        p=self.cfg('activate_preview',s);self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
    def rule(self,s):
        p=self.cfg('preview_rule',s,id='ddns_a',account='dns_a',zone='example.test',host='www.example.test',source='auto',interface='')
        self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
    def verify_unchanged(self):
        for n,sha in json.loads((STATE/'business-sha.json').read_text()).items():
            self.assertEqual(hashlib.sha256((STATE/'libexec'/n).read_bytes()).hexdigest(),sha,n)
        self.assertEqual(Path('/etc/config/homegate').read_bytes(),getattr(self,'production_before',b'PRODUCTION_CONFIGURATION_KEEP\n'))
        self.assertEqual(list(Path('/tmp').glob('homegate-engineering-web-*')),[])
        self.assertEqual(list(Path('/tmp').glob('homegate-engineering-ddns-ui-*')),[])
    def test_security(self):
        for page in [PAGE,BASE+'/settings/ddns']:
            status,_,_=self.cgi(page);self.assertEqual(status,403)
        s=self.login()
        for action in ['acme_schedule_start','acme_schedule_stop','acme_schedule_reap','acme_issue','acme_renew','acme_stop','acme_cleanup','preview_acme_certificate','cert_import','cert_resume','cert_cancel','preview_local_certificate','recover','production_copy_preview','production_copy_commit','lifecycle_enable','lifecycle_disable','provider_status','zones','delete_rule','prepare','preview_account','apply','secret_put','schedule_serve','schedule_start','schedule_stop','schedule_reap']:
            self.api('configuration_api',action,None,{},expected=403)
            self.api('configuration_api',action,s,{},expected=405,verb='GET')
            status,_,_=self.cgi(BASE+'/configuration_api/'+action,cookie=s[0],verb='POST',fields={'token':'bad'})
            self.assertEqual(status,403)
        self.api('configuration_api','prepare',s,{'unexpected':'value'},expected=503)
        self.api('configuration_api','preview_account',s,{'id':'../bad','name':'bad','provider':'cloudflare'},expected=503)
        self.assertFalse(Path('/etc/homegate-engineering/transactions').exists())
        status,_,body=self.cgi(BASE+'/settings/ddns',cookie=s[0]);self.assertEqual(status,200)
        self.assertIn(b'/homegate-engineering/ddns-ui.js',body)
        status,_,body=self.exchange(path='/luci-static/resources/homegate-engineering/configuration.js',verb='GET',raw=b'')
        self.assertEqual(status,200);self.assertIn(b'textContent',body)
        self.verify_unchanged()
    def test_configuration(self):
        s=self.login();self.prepare_account(s)
        data=self.cfg('read',s);self.assertEqual(data['accounts'][0]['id'],'dns_a')
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        data=self.cfg('read',s);self.assertEqual(data['rules'][0]['account'],'dns_a')
        store=Path('/etc/homegate-engineering/transactions')
        self.assertTrue(any(b'SECRET_SENTINEL' in p.read_bytes() for p in store.glob('gen-*/credentials/*')))
        self.assertNotIn(b'SECRET_SENTINEL',Path('/etc/config/homegate_engineering').read_bytes())
        p=self.cfg('preview_account',s,id='dns_a',name='<script>unsafe</script>',provider='cloudflare')
        self.cfg('cancel',s)
        self.api('configuration_api','apply',s,{'confirmation':p['report']['confirmation'],'consent':'1'},expected=503)
        self.assertFalse((store/'ddns-authority').exists());self.assertFalse((STATE/'provider-calls').exists())
        public=Path('/etc/config/homegate_engineering');before=public.read_bytes();revision=(store/'current').read_bytes()
        public.write_bytes(before+b'\n')
        self.api('configuration_api','secret_put',s,{'id':'dns_a','provider':'cloudflare','slot':'secret','value':'OTHER_SECRET_SENTINEL','consent':'1'},expected=503)
        self.assertEqual((store/'current').read_bytes(),revision)
        public.write_bytes(before)
        self.verify_unchanged()
    def test_async(self):
        s=self.login();self.prepare_account(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        def ddns(action,**fields):return self.api('ddns_native',action,s,fields)['report']
        before=ddns('status');self.assertEqual(before['rules'][0]['status'],'unauthorized')
        job='a'*32
        self.api('ddns_native','submit',s,{'job':job,'rule':'ddns_a','consent':'1'},expected=503)
        p=ddns('preview',selection='ddns_a')
        self.api('ddns_native','commit',s,{'confirmation':p['confirmation']},expected=503)
        ddns('commit',confirmation=p['confirmation'],consent='1')
        started=time.monotonic();accepted=ddns('submit',job=job,rule='ddns_a',consent='1')
        self.assertTrue(accepted['pending']);self.assertLess(time.monotonic()-started,5)
        deadline=time.monotonic()+25;finished=None
        while time.monotonic()<deadline:
            jobs=ddns('jobs')['jobs']
            if jobs and not jobs[0]['pending']:finished=jobs[0];break
            time.sleep(.1)
        self.assertIsNotNone(finished)
        self.assertEqual(finished['last_effect'],'none',finished)
        result=json.loads((Path('/var/run/homegate-engineering/ddns-ui-jobs')/job/'raw').read_bytes())
        self.assertEqual(result['result'],'unchanged','Async no-op must be a successful provider result')
        self.assertTrue((STATE/'provider-calls').exists(),'Async worker did not reach provider boundary')
        calls=(STATE/'provider-calls').read_bytes()
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='NEW_SECRET_SENTINEL',consent='1')
        self.api('ddns_native','submit',s,{'job':'b'*32,'rule':'ddns_a','consent':'1'},expected=503)
        self.assertEqual((STATE/'provider-calls').read_bytes(),calls)
        ddns('revoke',consent='1')
        self.verify_unchanged()
    def test_contracts(self):
        s=self.login();self.prepare_account(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        self.assertTrue(self.cfg('provider_status',s,id='dns_a')['report']['credentials_valid'])
        self.assertEqual(self.cfg('zones',s,id='dns_a')['report']['zones'],['example.test'])
        count=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a'},expected=503)
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        self.assertEqual((STATE/'provider-calls').read_bytes(),count)
        p=self.api('ddns_native','preview',s,{'selection':'ddns_a'})['report']
        self.api('ddns_native','commit',s,{'confirmation':p['confirmation'],'consent':'1'})
        (STATE/'provider-mode').write_text('delete-success')
        deleted=self.cfg('delete_rule',s,id='ddns_a',consent='1')
        self.assertEqual((deleted['effect'],deleted['report']['effect'],deleted['report']['result']),('confirmed','confirmed','deleted'))
        journal=Path('/etc/homegate-engineering/transactions/dns-operation')
        slot=journal/('slot-'+(journal/'current').read_text().strip());job=(slot/'manifest').read_text().splitlines()[6]
        count=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        self.assertEqual((STATE/'provider-calls').read_bytes(),count)
        command=['/usr/sbin/ash','/usr/libexec/homegate-engineering/ddns-control.sh','ddns-collect-receipt','cloudflare','dns_a',job,'--confirm']
        collected=subprocess.run(command,capture_output=True,timeout=20);self.assertEqual((collected.returncode,collected.stderr),(0,b''),(collected.stdout,collected.stderr))
        self.assertFalse(journal.exists())
        empty=self.cfg('delete_rule',s,id='ddns_a',consent='1');self.assertEqual(empty['report']['result'],'unchanged')
        (STATE/'provider-mode').write_text('delete-unknown')
        status,_,body=self.cgi(BASE+'/configuration_api/delete_rule',cookie=s[0],verb='POST',fields={'id':'ddns_a','consent':'1','token':s[1]})
        self.assertEqual(status,503);unknown=json.loads(body)
        self.assertEqual((unknown['effect'],unknown['report']['effect']),('unknown','unknown'))
        self.assertFalse(unknown['report']['retryable']);self.assertNotIn(b'SECRET_SENTINEL',body)
        saved={str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()};count=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        self.assertEqual((STATE/'provider-calls').read_bytes(),count)
        self.assertEqual({str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()},saved)
        self.verify_unchanged()
    def test_schedule(self):
        run=Path('/var/run/homegate-engineering');work=run/'ddns-schedule'
        base='/usr/libexec/homegate-engineering'
        def direct(*args,expected=0):
            p=subprocess.run(['/usr/sbin/ash',base+'/schedule-control.sh',*args],capture_output=True,timeout=15)
            self.assertEqual((p.returncode,p.stderr),(expected,b''),(args,p.stdout,p.stderr));return json.loads(p.stdout)
        def wait_state(predicate):
            deadline=time.monotonic()+25;last=None
            while time.monotonic()<deadline:
                status,_,body=self.cgi(BASE+'/configuration_api/schedule_status',cookie=s[0]);last=json.loads(body)
                if predicate(last.get('report',{})):return last['report']
                time.sleep(.1)
            self.fail('Scheduler did not reach expected state: '+str(last))
        self.assertFalse(work.exists())
        self.assertFalse(direct('event','ifup','wan6','pppoe-wan')['active'])
        self.assertFalse(run.exists())
        init=STATE/'installed/etc/init.d/homegate-engineering'
        self.assertEqual(subprocess.run(['/bin/sh',str(init),'boot']).returncode,0)
        self.assertEqual(subprocess.run(['/bin/sh',str(init),'start']).returncode,0)
        self.assertFalse(run.exists())
        s=self.login();self.prepare_account(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        self.api('configuration_api','schedule_start',s,{'consent':'1'},expected=503)
        self.assertFalse(work.exists());self.assertFalse((STATE/'provider-calls').exists())
        preview=self.api('ddns_native','preview',s,{'selection':'ddns_a'})['report']
        self.api('ddns_native','commit',s,{'confirmation':preview['confirmation'],'consent':'1'})
        self.cfg('schedule_start',s,consent='1')
        status=wait_state(lambda d:d.get('status')=='waiting' and d.get('ticks')==1)
        self.assertEqual(json.loads((run/'ddns-state/ddns_a').read_bytes())['outcome'],'unchanged')
        lease=(work/'lease').read_bytes();calls=(STATE/'provider-calls').read_bytes()
        self.assertFalse(direct('event','ifupdate','lan','br-lan')['matched'])
        self.assertTrue(direct('event','ifupdate','wan6','pppoe-wan')['matched'])
        self.assertEqual((work/'lease').read_bytes(),lease)
        self.api('configuration_api','schedule_start',s,{'consent':'1'},expected=503)
        self.api('configuration_api','preview_account',s,{'id':'dns_a','name':'blocked change','provider':'cloudflare'},expected=503)
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        time.sleep(1.1)
        self.assertEqual((STATE/'provider-calls').read_bytes(),calls,'Network wake bypassed pacing')
        self.assertEqual((work/'lease').read_bytes(),lease,'Network wake extended authorization')
        self.assertTrue(direct('event','ifdown','wan6','pppoe-wan')['matched'])
        wait_state(lambda d:d.get('status')=='finished' and d.get('reason')=='stopped')
        self.cfg('schedule_reap',s,consent='1');self.assertFalse(work.exists())
        # ifdown must reach the control lease while the admitted batch owns
        # both business locks. It does not cancel or repeat that provider call.
        p=subprocess.run(['/usr/sbin/ash',base+'/ddns-control.sh','ddns-reset','ddns_a','--confirm'],capture_output=True)
        self.assertEqual(p.returncode,0)
        (STATE/'provider-mode').write_text('hold')
        self.cfg('schedule_start',s,consent='1')
        deadline=time.monotonic()+20
        while not (STATE/'provider-entered').exists() and time.monotonic()<deadline:time.sleep(.05)
        _,_,observed=self.cgi(BASE+'/configuration_api/schedule_status',cookie=s[0])
        self.assertTrue((STATE/'provider-entered').exists(),'Admitted batch did not enter held transport: '+observed.decode(errors='replace'))
        self.assertTrue(direct('event','ifdown','wan6','pppoe-wan')['matched'])
        (STATE/'provider-release').write_bytes(b'release')
        wait_state(lambda d:d.get('status')=='finished' and d.get('reason')=='stopped')
        self.cfg('schedule_reap',s,consent='1');self.assertFalse(work.exists())
        # A new session is another explicit user action. Its unknown provider
        # effect must stop the loop and block both restart and local reaping.
        p=subprocess.run(['/usr/sbin/ash',base+'/ddns-control.sh','ddns-reset','ddns_a','--confirm'],capture_output=True)
        self.assertEqual(p.returncode,0)
        (STATE/'provider-mode').write_text('unknown')
        self.cfg('schedule_start',s,consent='1')
        unknown=wait_state(lambda d:d.get('status')=='finished' and d.get('last_effect')=='unknown')
        self.assertEqual(unknown['reason'],'reconciliation_required')
        journal=Path('/etc/homegate-engineering/transactions/dns-operation');self.assertTrue(journal.exists())
        before={str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()}
        calls=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','schedule_reap',s,{'consent':'1'},expected=503)
        self.api('configuration_api','schedule_start',s,{'consent':'1'},expected=503)
        self.assertFalse(direct('event','ifup','wan6','pppoe-wan')['active'])
        self.assertEqual((STATE/'provider-calls').read_bytes(),calls)
        self.assertEqual({str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()},before)
        self.verify_unchanged()


    def test_continuous(self):
        run=Path('/var/run/homegate-engineering');work=run/'ddns-schedule'
        self.assertFalse(run.exists());s=self.login();self.prepare_account(s)
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(s);self.rule(s)
        self.api('configuration_api','schedule_serve',s,{'consent':'1'},expected=503)
        self.assertFalse(work.exists());self.assertFalse((STATE/'provider-calls').exists())
        preview=self.api('ddns_native','preview',s,{'selection':'ddns_a'})['report']
        self.api('ddns_native','commit',s,{'confirmation':preview['confirmation'],'consent':'1'})
        init=STATE/'installed/etc/init.d/homegate-engineering'
        p=subprocess.run(['/bin/sh',str(init),'start','--confirm'],capture_output=True,timeout=15)
        self.assertEqual((p.returncode,p.stderr),(0,b''));self.assertTrue(json.loads(p.stdout)['continuous'])
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            status=self.cfg('schedule_status',s)['report']
            if status['status']=='waiting' and status['ticks']==1:break
            time.sleep(.1)
        else:self.fail('Continuous mode did not reach waiting state')
        self.assertTrue(status['running']);self.assertTrue(status['continuous']);self.assertEqual(status['admission_limit'],0)
        calls=(STATE/'provider-calls').read_bytes()
        self.api('configuration_api','schedule_serve',s,{'consent':'1'},expected=503)
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        self.cfg('schedule_stop',s,consent='1')
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            status=self.cfg('schedule_status',s)['report']
            if status['status']=='finished':break
            time.sleep(.1)
        self.assertEqual(status['reason'],'stopped');self.assertEqual((STATE/'provider-calls').read_bytes(),calls)
        self.cfg('schedule_reap',s,consent='1');self.assertFalse(work.exists())
        # The web entry shares the same explicit authority and cannot start at boot.
        self.cfg('schedule_serve',s,consent='1');self.cfg('schedule_stop',s,consent='1')
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if self.cfg('schedule_status',s)['report']['status']=='finished':break
            time.sleep(.1)
        self.cfg('schedule_reap',s,consent='1');self.assertFalse(work.exists());self.verify_unchanged()

    def lifecycle_account(self):
        session=self.login();self.prepare_account(session)
        self.cfg('secret_put',session,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.publish(session);self.rule(session);return session
    def lifecycle_grant(self,session):
        preview=self.api('ddns_native','preview',session,{'selection':'ddns_a'})['report']
        self.api('ddns_native','commit',session,{'confirmation':preview['confirmation'],'consent':'1'})
    def lifecycle_cli(self,*args,expected=0):
        p=subprocess.run(['/usr/bin/homegate-engineering',*args],capture_output=True,timeout=25)
        self.assertEqual((p.returncode,p.stderr),(expected,b''),(args,p.stdout,p.stderr))
        self.assertNotIn(b'SECRET_SENTINEL',p.stdout);return json.loads(p.stdout)
    def test_lifecycle(self):
        s=self.lifecycle_account();self.lifecycle_grant(s)
        source=Path('/etc/config/homegate_engineering').read_bytes()
        self.assertFalse(self.cfg('lifecycle_status',s)['report']['known'])
        report=self.cfg('lifecycle_enable',s,consent='1')['report'];self.assertTrue(report['intent_applied'])
        self.assertTrue(self.cfg('lifecycle_status',s)['report']['main_enabled'])
        self.assertEqual(Path('/etc/config/homegate_engineering').read_bytes(),source)
        self.assertFalse((STATE/'provider-calls').exists(),'Switch application must not dispatch DNS')
        self.api('configuration_api','schedule_serve',s,{'consent':'1'},expected=503)
        self.lifecycle_grant(s);self.cfg('schedule_serve',s,consent='1')
        # A disable request first cooperatively stops the admitted batch.
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            status,_,raw=self.cgi(BASE+'/configuration_api/lifecycle_disable',cookie=s[0],verb='POST',fields={'consent':'1','token':s[1]})
            value=json.loads(raw)
            if status==200 and value['ok']:break
            self.assertEqual(status,503);time.sleep(.2)
        else:self.fail('Disable did not complete after cooperative stop')
        self.assertFalse(self.cfg('lifecycle_status',s)['report']['main_enabled'])
        self.assertFalse(Path('/var/run/homegate-engineering/ddns-schedule').exists())
        calls=(STATE/'provider-calls').read_bytes() if (STATE/'provider-calls').exists() else b''
        self.api('configuration_api','schedule_serve',s,{'consent':'1'},expected=503)
        self.api('ddns_native','preview',s,{'selection':'ddns_a'},expected=503)
        self.api('configuration_api','delete_rule',s,{'id':'ddns_a','consent':'1'},expected=503)
        self.lifecycle_cli('ddns-sync','ddns_a',expected=4)
        self.assertEqual((STATE/'provider-calls').read_bytes() if (STATE/'provider-calls').exists() else b'',calls)
        self.cfg('lifecycle_enable',s,consent='1')
        self.api('configuration_api','schedule_serve',s,{'consent':'1'},expected=503)
        self.lifecycle_grant(s);self.verify_unchanged()
    def test_intent_recovery(self):
        s=self.lifecycle_account();self.lifecycle_grant(s)
        store=Path('/etc/homegate-engineering/transactions');record=store/'startup-intent';active=store/'startup-active'
        self.lifecycle_cli('lifecycle-record-save','enabled','--confirm');saved=(record/'context').read_bytes()
        source=Path('/etc/config/homegate_engineering');original=source.read_bytes();source.write_bytes(original+b'\n')
        self.lifecycle_cli('lifecycle-record-apply','enabled','--confirm',expected=1)
        self.assertEqual((record/'context').read_bytes(),saved);self.assertFalse(active.exists());source.write_bytes(original)
        self.assertTrue(self.lifecycle_cli('lifecycle-record-cancel','enabled','--confirm')['record_cancelled']);self.assertFalse(record.exists())
        self.lifecycle_cli('lifecycle-record-save','enabled','--confirm');saved=(record/'context').read_bytes()
        fsync=STATE/'tools/fsync';fsync.unlink()
        fsync.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/homegate-engineering/transactions/.startup-active-next) exit 1;; esac\nexec /usr/sbin/busybox fsync "$@"\n');fsync.chmod(0o755)
        self.lifecycle_cli('lifecycle-record-apply','enabled','--confirm',expected=6)
        self.assertEqual((record/'context').read_bytes(),saved);self.assertTrue((store/'.startup-active-next').exists());self.assertFalse(active.exists())
        self.api('configuration_api','schedule_serve',s,{'consent':'1'},expected=503)
        fsync.unlink();fsync.symlink_to('busybox')
        self.assertTrue(self.lifecycle_cli('lifecycle-record-apply','enabled','--confirm')['intent_applied'])
        self.assertFalse(record.exists());self.assertFalse((store/'.startup-active-next').exists())
        self.assertTrue(self.lifecycle_cli('lifecycle-record-apply','enabled','--confirm')['intent_applied'])
        good=active.read_bytes();active.write_bytes(good+b'bad\n')
        self.lifecycle_cli('lifecycle-status',expected=7);self.api('ddns_native','preview',s,{'selection':'ddns_a'},expected=503)
        self.assertEqual(active.read_bytes(),good+b'bad\n');active.write_bytes(good)
        self.assertTrue(self.cfg('lifecycle_status',s)['report']['main_enabled'])
        # Configuration/credential generation changes cannot inherit an old main switch.
        self.cfg('secret_put',s,id='dns_a',provider='cloudflare',slot='secret',value='SECRET_SENTINEL',consent='1')
        self.lifecycle_cli('lifecycle-status',expected=7)
        self.cfg('lifecycle_enable',s,consent='1');self.assertTrue(self.cfg('lifecycle_status',s)['report']['main_enabled'])
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()

    def test_intent_cleanup(self):
        s=self.lifecycle_account();self.lifecycle_grant(s)
        store=Path('/etc/homegate-engineering/transactions');record=store/'startup-intent';active=store/'startup-active'
        self.lifecycle_cli('lifecycle-record-save','enabled','--confirm')
        tool=STATE/'tools/rmdir';tool.unlink(missing_ok=True)
        tool.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/homegate-engineering/transactions/startup-intent) exit 1;; esac\nexec /usr/sbin/busybox rmdir "$@"\n');tool.chmod(0o755)
        self.lifecycle_cli('lifecycle-record-cancel','enabled','--confirm',expected=6)
        self.assertTrue(record.is_dir());self.assertEqual(list(record.iterdir()),[]);self.assertFalse(active.exists())
        self.api('configuration_api','schedule_serve',s,{'consent':'1'},expected=503)
        tool.unlink();tool.symlink_to('busybox')
        self.assertTrue(self.lifecycle_cli('lifecycle-record-cancel','enabled','--confirm')['record_cancelled']);self.assertFalse(record.exists())
        self.lifecycle_cli('lifecycle-enable','--confirm')
        stage=store/'.startup-active-next';stage.write_bytes(active.read_bytes());stage.chmod(0o600)
        self.lifecycle_cli('lifecycle-record-apply','enabled','--confirm',expected=6)
        self.assertTrue(stage.exists());self.lifecycle_cli('lifecycle-status',expected=4)
        stage.unlink();self.assertTrue(self.lifecycle_cli('lifecycle-record-apply','enabled','--confirm')['intent_applied'])
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()
    def test_intent_frames(self):
        s=self.lifecycle_account();self.lifecycle_cli('lifecycle-enable','--confirm')
        store=Path('/etc/homegate-engineering/transactions');active=store/'startup-active';good=active.read_bytes()
        self.lifecycle_cli('lifecycle-record-save','disabled','--confirm');record=store/'startup-intent';saved=(record/'context').read_bytes()
        for invalid in [good+b'unterminated',good.replace(b'HGSTARTUP',b'HG\0STARTUP',1)]:
            active.write_bytes(invalid)
            self.lifecycle_cli('lifecycle-record-apply','disabled','--confirm',expected=7)
            self.lifecycle_cli('lifecycle-record-cancel','disabled','--confirm',expected=7)
            self.assertEqual(active.read_bytes(),invalid);self.assertEqual((record/'context').read_bytes(),saved)
        active.write_bytes(good)
        report=self.lifecycle_cli('lifecycle-record-cancel','disabled','--confirm')
        self.assertTrue(report['record_cancelled']);self.assertNotIn('main_enabled',report)
        self.assertEqual(active.read_bytes(),good);self.assertTrue(self.cfg('lifecycle_status',s)['report']['main_enabled'])
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()

    def production_fixture(self):
        # The complete six-kind legacy fixture is data inside the private mount.
        raw="""package 'homegate'
config homegate 'main'
 option enabled '1'
 option access_enabled '1'
 option access_allow '192.0.2.1,2001:db8::/32'
 option last_wol_host 'host_a'
config dns_account 'dns_a'
 option name 'DNS account'
 option provider 'cloudflare'
 option id 'OLD_ID'
 option secret 'SECRET_SENTINEL'
 option account_id 'PRIVATE_ACCOUNT'
 option endpoint 'https://api.test/private-token'
config ddns_rule 'ddns_a'
 option enabled '1'
 option account 'dns_a'
 option zone 'example.test'
 option host 'www.example.test'
config ddns_rule 'ddns_url'
 option enabled '0'
 option account 'dns_a'
 option zone 'example.test'
 option host 'other.example.test'
 option source 'url'
 option url 'https://user:password@source.test/token'
config certificate 'cert_a'
 option enabled '1'
 option source 'acme'
 option account 'dns_a'
 option zone 'example.test'
 list domains 'example.test'
 list domains '*.example.test'
config web_rule 'web_a'
 option enabled '1'
 option domain 'www.example.test'
 option certificate 'cert_a'
 option target 'http://user:password@192.0.2.1:8080/private-token'
 option certificate_mode 'auto'
 option certificate_managed '1'
config wol_host 'host_a'
 option name 'Computer'
 option mac 'AA-BB-CC-DD-EE-FF'
""".encode()
        source=Path('/etc/config/homegate');source.write_bytes(raw);source.chmod(0o600);self.production_before=raw
        runtime=Path('/var/run/homegate');runtime.mkdir(mode=0o700)
        lock=runtime/'frontend.lock';lock.touch(mode=0o600)
        return source,lock
    def test_production_copy(self):
        source,lock=self.production_fixture();s=self.login();self.cfg('prepare',s)
        preview=self.cfg('production_copy_preview',s)['report'];self.assertEqual(preview['operation'],'production-copy')
        # The ordinary apply route cannot consume an adoption confirmation.
        self.api('configuration_api','apply',s,{'confirmation':preview['confirmation'],'consent':'1'},expected=503)
        self.cfg('production_copy_commit',s,confirmation=preview['confirmation'],consent='1')
        store=Path('/etc/homegate-engineering/transactions');generation=store/('gen-'+(store/'current').read_text().strip())
        self.assertEqual((generation/'legacy.conf').read_bytes(),self.production_before)
        expected={'cloudflare.dns_a.key_id':b'OLD_ID','cloudflare.dns_a.secret':b'SECRET_SENTINEL',
          'cloudflare.dns_a.account_id':b'PRIVATE_ACCOUNT','cloudflare.dns_a.endpoint':b'https://api.test/private-token',
          'ddns.ddns_url.url':b'https://user:password@source.test/token','web.web_a.target':b'http://user:password@192.0.2.1:8080/private-token'}
        for name,value in expected.items():self.assertEqual((generation/'credentials'/name).read_bytes(),value)
        public=Path('/etc/config/homegate_engineering').read_bytes();self.assertEqual(public,(generation/'public.conf').read_bytes())
        self.assertNotIn(b"option enabled '1'",public);self.assertFalse((store/'application').exists());self.assertFalse((store/'ddns-authority').exists())
        visible=json.dumps([preview,self.cfg('read',s)]).encode()+public
        for value in expected.values():self.assertNotIn(value,visible)
        for item in store.rglob('*'):self.assertEqual(item.stat().st_mode&0o777,0o700 if item.is_dir() else 0o600)
        self.api('configuration_api','production_copy_preview',s,{},expected=503)
        self.cfg('lifecycle_enable',s,consent='1');self.lifecycle_grant(s)
        (STATE/'require-imported-secret').touch()
        self.cfg('schedule_serve',s,consent='1')
        deadline=time.monotonic()+30
        while time.monotonic()<deadline and not (STATE/'imported-secret-used').exists():time.sleep(.1)
        self.assertTrue((STATE/'imported-secret-used').exists(),{'schedule':self.cfg('schedule_status',s),'transport_entered':(STATE/'provider-calls').exists()})
        self.cfg('schedule_stop',s,consent='1')
        deadline=time.monotonic()+15;finished=False
        while time.monotonic()<deadline:
            # A read overlapping publication/owner exit may fail closed. Keep
            # it unknown within the original deadline, never count as finished.
            code,_,body=self.cgi(BASE+'/configuration_api/schedule_status',cookie=s[0])
            self.assertNotIn(b'SECRET_SENTINEL',body);self.assertIn(code,[200,503])
            value=json.loads(body)
            if code==503:
                self.assertFalse(value['ok']);self.assertFalse(value['write_ready'])
                self.assertEqual(value['report']['phase'],'ddns-schedule')
                self.assertFalse(value['report']['ok'])
            else:
                self.assertTrue(value['ok']);report=value['report']
                if report['status']=='finished':
                    self.assertFalse(report['running']);finished=True;break
            time.sleep(.1)
        self.assertTrue(finished,'Schedule did not publish a genuine finished state within 15 seconds')
        self.cfg('schedule_reap',s,consent='1')
        self.assertEqual(lock.read_bytes(),b'');self.verify_unchanged()
    def test_production_copy_sources(self):
        import fcntl
        source,lock=self.production_fixture();s=self.login();self.cfg('prepare',s)
        store=Path('/etc/homegate-engineering/transactions')
        with lock.open('rb') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.lifecycle_cli('production-copy-preview',expected=4)
        self.assertFalse((store/'pending').exists())
        for provider in ['aliyun','cloudflare','dnspod','huaweicloud']:
            source.write_bytes(self.production_before.replace(b"provider 'cloudflare'",("provider '"+provider+"'").encode()))
            preview=self.cfg('production_copy_preview',s)['report']
            index=(store/'pending').read_bytes().splitlines()[3].decode();candidate=store/('gen-'+index)
            self.assertEqual((candidate/'credentials'/ (provider+'.dns_a.secret')).read_bytes(),b'SECRET_SENTINEL')
            self.cfg('cancel',s)
        source.write_bytes(self.production_before)
        p=self.cfg('production_copy_preview',s)['report'];source.write_bytes(self.production_before.replace(b'OLD_ID',b'NEW_ID'))
        self.lifecycle_cli('production-copy-commit',p['confirmation'],expected=5)
        self.assertEqual((store/'current').read_bytes(),b'1\n');self.assertFalse((store/'application').exists())
        self.cfg('cancel',s);source.write_bytes(self.production_before)
        source.chmod(0o644);self.lifecycle_cli('production-copy-preview',expected=7);self.assertEqual(source.stat().st_mode&0o777,0o644);source.chmod(0o600)
        retained=source.with_name('retained');source.rename(retained);source.symlink_to(retained)
        self.lifecycle_cli('production-copy-preview',expected=7);self.assertTrue(source.is_symlink());source.unlink();retained.rename(source)
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()
    def test_production_copy_recovery(self):
        source,lock=self.production_fixture();s=self.login();self.cfg('prepare',s)
        preview=self.cfg('production_copy_preview',s)['report'];store=Path('/etc/homegate-engineering/transactions')
        before=Path('/etc/config/homegate_engineering').read_bytes()
        fsync=STATE/'tools/fsync';fsync.unlink()
        fsync.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/config/.homegate_engineering-projection.*) exit 1;; esac\nexec /usr/sbin/busybox fsync "$@"\n');fsync.chmod(0o755)
        status,_,raw=self.cgi(BASE+'/configuration_api/production_copy_commit',cookie=s[0],verb='POST',fields={'confirmation':preview['confirmation'],'consent':'1','token':s[1]})
        self.assertEqual(status,503);report=json.loads(raw)['report'];self.assertTrue(report['application_pending']);handle=report['apply_handle']
        self.assertTrue((store/'application').exists());self.assertEqual(Path('/etc/config/homegate_engineering').read_bytes(),before)
        self.api('configuration_api','production_copy_preview',s,{},expected=503)
        self.lifecycle_cli('production-copy-commit',preview['confirmation'],expected=4)
        fsync.unlink();fsync.symlink_to('busybox')
        self.cfg('finish',s,confirmation=handle,consent='1')
        self.assertFalse((store/'application').exists());self.assertNotEqual(Path('/etc/config/homegate_engineering').read_bytes(),before)
        self.assertEqual((store/'gen-3/legacy.conf').read_bytes(),self.production_before)
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()

    def test_production_copy_rollback(self):
        source,lock=self.production_fixture();s=self.login();self.cfg('prepare',s)
        preview=self.cfg('production_copy_preview',s)['report'];store=Path('/etc/homegate-engineering/transactions')
        before=Path('/etc/config/homegate_engineering').read_bytes()
        fsync=STATE/'tools/fsync';fsync.unlink()
        fsync.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/homegate-engineering/transactions/.work.*) [ ! -f /etc/homegate-engineering/transactions/application ] || exit 1;; esac\nexec /usr/sbin/busybox fsync "$@"\n');fsync.chmod(0o755)
        status,_,raw=self.cgi(BASE+'/configuration_api/production_copy_commit',cookie=s[0],verb='POST',fields={'confirmation':preview['confirmation'],'consent':'1','token':s[1]})
        self.assertEqual(status,503);self.assertNotIn('apply_handle',json.loads(raw)['report'])
        self.assertTrue((store/'application').exists());self.assertEqual((store/'current').read_bytes(),b'1\n')
        self.assertEqual(Path('/etc/config/homegate_engineering').read_bytes(),before)
        fsync.unlink();fsync.symlink_to('busybox')
        self.cfg('recover',s,consent='1')
        self.assertFalse((store/'application').exists());self.assertEqual((store/'current').read_bytes(),b'1\n')
        self.assertEqual(Path('/etc/config/homegate_engineering').read_bytes(),before)
        self.assertEqual((store/'gen-3/legacy.conf').read_bytes(),self.production_before)
        # Explicit recovery consumes the old preview, never repeats the import.
        self.lifecycle_cli('production-copy-commit',preview['confirmation'],expected=5)
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()

    def certificate_config(self,session,domains='example.test,*.example.test'):
        preview=self.cfg('preview_local_certificate',session,id='cert_a',name='Local certificate',domains=domains)
        self.cfg('apply',session,confirmation=preview['report']['confirmation'],consent='1')
    def certificate_pair(self,name,domains='DNS:example.test,DNS:*.example.test',rsa=False,date_case=None):
        work=STATE/'cert-fixtures';work.mkdir(exist_ok=True);key=work/(name+'.key');cert=work/(name+'.pem')
        cmd=['openssl','req','-x509','-newkey','rsa:2048'] if rsa else ['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256']
        cmd+=['-nodes','-subj','/CN=unused.example.test','-days','30','-keyout',str(key),'-out',str(cert)]
        if domains:cmd+=['-addext','subjectAltName='+domains]
        run=lambda args:subprocess.run(args,capture_output=True,timeout=15)
        result=run(cmd);self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace')[-1500:])
        if date_case:
            csr=work/(name+'.csr');result=run(['openssl','req','-new','-key',str(key),'-subj','/CN=unused.example.test','-out',str(csr)]);self.assertEqual(result.returncode,0)
            index=work/(name+'.index');index.touch();serial=work/(name+'.serial');serial.write_text('01\n')
            conf=work/(name+'.cnf');conf.write_text('[ca]\ndefault_ca=local\n[local]\ndatabase='+str(index)+'\nnew_certs_dir='+str(work)+'\nserial='+str(serial)+'\nprivate_key='+str(key)+'\ncertificate='+str(cert)+'\ndefault_md=sha256\npolicy=policy\nx509_extensions=ext\n[policy]\ncommonName=supplied\n[ext]\nsubjectAltName='+domains+'\n')
            dated=work/(name+'.dated.pem');start,end=('20200101000000Z','20200102000000Z') if date_case=='expired' else ('20990101000000Z','20990201000000Z')
            if date_case=='current':
                from datetime import datetime,timedelta,timezone
                now=datetime.now(timezone.utc);start=(now-timedelta(minutes=2)).strftime('%Y%m%d%H%M%SZ');end=(now+timedelta(days=30)).strftime('%Y%m%d%H%M%SZ')
            result=run(['openssl','ca','-batch','-selfsign','-config',str(conf),'-in',str(csr),'-startdate',start,'-enddate',end,'-notext','-out',str(dated)])
            self.assertEqual(result.returncode,0,'Private validity-window fixture generation failed');cert=dated
        return cert.read_text(),key.read_text()
    def certificate_import(self,session,pair,expected=200):
        return self.api('configuration_api','cert_import',session,{'id':'cert_a','certificate_pem':pair[0],'private_key_pem':pair[1],'consent':'1'},expected=expected)
    def test_certificate(self):
        s=self.login();self.cfg('prepare',s);self.certificate_config(s)
        self.assertFalse(self.cfg('cert_status',s,id='cert_a')['report']['exists'])
        first=self.certificate_pair('first');first=(first[0]+first[0],first[1])
        # Parse every PEM block; CRLF uploads normalize before private publication.
        self.certificate_import(s,tuple(v.replace('\n','\r\n') for v in first))
        report=self.cfg('cert_status',s,id='cert_a')['report'];self.assertTrue(report['valid']);self.assertTrue(report['identity_valid']);self.assertFalse(report['trust_checked'])
        base=Path('/etc/homegate-engineering/certs/cert_a');old=(base/'current').read_bytes();pair=base/(base/'current').read_text().strip()
        self.assertEqual((pair/'privkey.pem').read_text(),first[1]);self.assertEqual((pair/'fullchain.pem').read_text(),first[0])
        second=self.certificate_pair('second',rsa=True);self.certificate_import(s,second)
        self.assertNotEqual((base/'current').read_bytes(),old);self.assertEqual((pair/'privkey.pem').read_text(),first[1])
        for f in base.rglob('*'):self.assertEqual(f.stat().st_mode&0o777,0o700 if f.is_dir() else 0o600)
        self.certificate_config(s,'different.example.test')
        report=self.cfg('cert_status',s,id='cert_a')['report'];self.assertTrue(report['exists']);self.assertFalse(report['valid']);self.assertFalse(report['identity_valid'])
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()
    def test_certificate_invalid(self):
        s=self.login();self.cfg('prepare',s);self.certificate_config(s)
        good=self.certificate_pair('valid');self.certificate_import(s,good)
        base=Path('/etc/homegate-engineering/certs/cert_a');before=(base/'current').read_bytes()
        other=self.certificate_pair('other')
        bad=[(good[0],other[1]),self.certificate_pair('cn',domains=''),self.certificate_pair('missing',domains='DNS:example.test'),
             self.certificate_pair('extra',domains='DNS:example.test,DNS:*.example.test,DNS:extra.example.test'),
             self.certificate_pair('expired',date_case='expired'),self.certificate_pair('future',date_case='future'),(good[0]+'garbage\n',good[1]),(good[0],good[1]+'garbage\n')]
        for value in bad:
            self.certificate_import(s,value,expected=503);self.assertEqual((base/'current').read_bytes(),before)
            self.assertTrue(self.cfg('cert_status',s,id='cert_a')['report']['valid'])
            self.cfg('cert_cancel',s,id='cert_a',consent='1')
        self.api('configuration_api','cert_import',s,{'id':'../bad','certificate_pem':good[0],'private_key_pem':good[1],'consent':'1'},expected=503)
        current=base/(base/'current').read_text().strip();key=current/'privkey.pem';original=key.read_bytes();key.write_bytes(original+b'bad')
        self.api('configuration_api','cert_status',s,{'id':'cert_a'},expected=503);self.assertEqual(key.read_bytes(),original+b'bad');key.write_bytes(original)
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()
    def test_certificate_recovery(self):
        s=self.login();self.cfg('prepare',s);self.certificate_config(s)
        good=self.certificate_pair('baseline');self.certificate_import(s,good)
        base=Path('/etc/homegate-engineering/certs/cert_a');before=(base/'current').read_bytes();replacement=self.certificate_pair('replacement')
        tool=STATE/'tools/fsync';tool.unlink();tool.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/homegate-engineering/certs/cert_a/.current.next) exit 1;; esac\nexec /usr/sbin/busybox fsync "$@"\n');tool.chmod(0o755)
        self.certificate_import(s,replacement,expected=503);self.assertEqual((base/'current').read_bytes(),before)
        self.assertTrue(self.cfg('cert_status',s,id='cert_a')['report']['pending']);tool.unlink();tool.symlink_to('busybox')
        self.cfg('cert_resume',s,id='cert_a',consent='1');self.assertNotEqual((base/'current').read_bytes(),before);self.assertFalse((base/'.pending').exists())
        # Configuration generation changes invalidate a retained candidate, not the old pair.
        tool.unlink();tool.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/homegate-engineering/certs/cert_a/.current.next) exit 1;; esac\nexec /usr/sbin/busybox fsync "$@"\n');tool.chmod(0o755)
        self.certificate_import(s,self.certificate_pair('stale'),expected=503);tool.unlink();tool.symlink_to('busybox')
        self.certificate_config(s,'other.example.test');self.api('configuration_api','cert_resume',s,{'id':'cert_a','consent':'1'},expected=503)
        self.cfg('cert_cancel',s,id='cert_a',consent='1');self.assertFalse((base/'.pending').exists());self.assertFalse((base/'.current.next').exists())
        self.assertFalse((STATE/'provider-calls').exists());self.verify_unchanged()
    def test_certificate_timeout(self):
        s=self.login();self.cfg('prepare',s);self.certificate_config(s)
        material=self.certificate_pair('slow');tool=STATE/'tools/openssl'
        tool.write_text('#!/bin/sh\nsleep 20\nprintf leaked > /teststate/certificate-worker-leaked\n');tool.chmod(0o755)
        started=time.monotonic();self.certificate_import(s,material,expected=503);self.assertLess(time.monotonic()-started,16)
        self.assertFalse((STATE/'certificate-worker-leaked').exists());tool.unlink()
        self.cfg('cert_resume',s,id='cert_a',consent='1');self.assertTrue(self.cfg('cert_status',s,id='cert_a')['report']['valid'])
        self.assertFalse((STATE/'certificate-worker-leaked').exists());self.verify_unchanged()

    def acme_config(self,s,environment='staging',domains='example.test,*.example.test'):
        p=self.cfg('preview_acme_certificate',s,id='cert_a',name='ACME certificate',account='dns_a',zone='example.test',domains=domains,email='fixture@example.test',environment=environment)
        self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
    def acme_setup(self,provider='cloudflare'):
        s=self.login();self.cfg('prepare',s)
        p=self.cfg('preview_account',s,id='dns_a',name='DNS account',provider=provider)
        self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
        slots={'secret':'SECRET_SENTINEL'}
        if provider!='cloudflare':slots['key_id']='KEY_SENTINEL'
        if provider=='huaweicloud':slots.update(account_id='f'*32,endpoint='https://dns.cn-north-4.myhuaweicloud.com')
        for slot,value in slots.items():self.cfg('secret_put',s,id='dns_a',provider=provider,slot=slot,value=value,consent='1')
        self.publish(s);self.acme_config(s)
        (STATE/'acme-enabled').touch()
        run=subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=Private ACME fixture','-days','365','-keyout',str(STATE/'fixture-ca.key'),'-out',str(STATE/'fixture-ca.pem')],capture_output=True,timeout=10)
        self.assertEqual(run.returncode,0,run.stderr[-500:])
        # Only the propagation wait is virtual in this private fixture. Production
        # dnssleep=60, the 900-second deadline and all other sleeps stay unchanged.
        tool=STATE/'tools/sleep';tool.write_text('#!/bin/sh\nif [ "$1" = 60 ];then printf waited >> /teststate/propagation-wait;exit 0;fi\nexec /usr/sbin/busybox sleep "$@"\n');tool.chmod(0o755)
        return s
    def acme_wait(self,s,job):
        deadline=time.monotonic()+65
        while time.monotonic()<deadline:
            report=self.cfg('acme_status',s,job=job)['report']
            if not report['pending']:return report
            time.sleep(.1)
        self.fail('ACME job exceeded private fixture budget')
    def acme_diagnostics(self,job):
        root=Path('/etc/homegate-engineering/acme/jobs')/job
        return {p.name:p.read_text(errors='replace')[-3500:] for p in root.glob('*') if p.name in ['client.output','dns.result','install.result','result']}
    def test_acme(self):
        s=self.acme_setup();job='c'*32
        report=self.cfg('acme_issue',s,id='cert_a',job=job,consent='1')['report'];self.assertTrue(report['pending'])
        report=self.acme_wait(s,job);self.assertEqual(report['state'],'issued',self.acme_diagnostics(job))
        status=self.cfg('cert_status',s,id='cert_a')['report'];self.assertTrue(status['valid']);self.assertFalse(status['trust_checked'])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertGreater(db['verified_jws'],6);self.assertEqual(db['records'],[])
        self.assertTrue((STATE/'propagation-wait').exists())
        path=Path('/etc/homegate-engineering/acme/jobs')/job
        challenges=[json.loads(p.read_text()) for p in (path/'challenges').glob('*.json')];self.assertEqual(len(challenges),2);self.assertTrue(all(c['state']=='removed' for c in challenges))
        self.assertEqual(len(list((path/'receipts').glob('*'))),4)
        self.assertFalse(Path('/etc/homegate-engineering/transactions/dns-operation').exists())
        count=len(db['events']);job2='d'*32
        self.cfg('acme_renew',s,id='cert_a',job=job2,consent='1');report=self.acme_wait(s,job2)
        self.assertEqual(report['state'],'skipped',self.acme_diagnostics(job2));self.assertEqual(len(json.loads((STATE/'acme-fixture.json').read_text())['events']),count)
        self.verify_unchanged()
    def acme_provider(self,provider):
        s=self.acme_setup(provider);self.acme_config(s,domains='example.test');job='5'*32
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1');report=self.acme_wait(s,job)
        self.assertEqual(report['state'],'issued',self.acme_diagnostics(job))
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(db['records'],[])
        path=Path('/etc/homegate-engineering/acme/jobs')/job
        self.assertEqual(len(list((path/'receipts').glob('*'))),2)
        self.assertFalse(Path('/etc/homegate-engineering/transactions/dns-operation').exists())
        self.verify_unchanged()
    def test_acme_aliyun(self):self.acme_provider('aliyun')
    def test_acme_dnspod(self):self.acme_provider('dnspod')
    def test_acme_huawei(self):self.acme_provider('huaweicloud')
    def test_acme_accounts(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test')
        keys=[]
        for job in ['1'*32,'2'*32]:
            self.cfg('acme_issue',s,id='cert_a',job=job,consent='1');report=self.acme_wait(s,job)
            self.assertEqual(report['state'],'issued',self.acme_diagnostics(job))
            key=list(Path('/etc/homegate-engineering/acme/accounts/letsencrypt-staging').rglob('account.key'));self.assertEqual(len(key),1);keys.append(key[0].read_bytes())
        self.assertEqual(keys[0],keys[1]);db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['accounts']),1)
        self.acme_config(s,environment='production',domains='example.test');job='3'*32
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1');report=self.acme_wait(s,job)
        self.assertEqual(report['state'],'issued',self.acme_diagnostics(job))
        key=list(Path('/etc/homegate-engineering/acme/accounts/letsencrypt-production').rglob('account.key'));self.assertEqual(len(key),1);self.assertNotEqual(key[0].read_bytes(),keys[0])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['accounts']),2);self.assertEqual(len(db['orders']),3)
        self.verify_unchanged()
    def test_acme_preexisting(self):
        s=self.acme_setup();(STATE/'acme-mode').write_text('preexisting');job='4'*32
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1');report=self.acme_wait(s,job)
        self.assertEqual(report['state'],'issued',self.acme_diagnostics(job))
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['records']),3)
        self.assertFalse(any(e['method']=='DELETE' for e in db['events']))
        path=Path('/etc/homegate-engineering/acme/jobs')/job
        self.assertEqual([json.loads(p.read_text())['state'] for p in (path/'challenges').glob('*.json')],['preexisting','preexisting'])
        self.verify_unchanged()
    def test_acme_stop(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test');(STATE/'acme-mode').write_text('hold-challenge');job='6'*32
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1')
        deadline=time.monotonic()+40
        while not (STATE/'acme-entered').exists() and time.monotonic()<deadline:time.sleep(.1)
        self.assertTrue((STATE/'acme-entered').exists(),self.acme_diagnostics(job))
        self.api('configuration_api','preview_acme_certificate',s,{'id':'cert_a','name':'stale','account':'dns_a','zone':'example.test','domains':'other.example.test','email':'','environment':'production'},expected=503)
        self.cfg('acme_stop',s,job=job,consent='1');report=self.acme_wait(s,job)
        self.assertEqual(report['state'],'interrupted');self.assertTrue(report['cleanup_required'])
        self.assertFalse(Path('/etc/homegate-engineering/certs/cert_a/current').exists())
        remaining=json.loads((STATE/'acme-fixture.json').read_text())['records']
        self.assertLessEqual(len(remaining),1)  # Upstream TERM trap may already clean its owned value.
        self.cfg('acme_cleanup',s,job=job,consent='1');report=self.acme_wait(s,job)
        self.assertEqual(report['state'],'cleaned',self.acme_diagnostics(job));self.assertFalse(report['cleanup_required'])
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text())['records'],[])
        self.verify_unchanged()
    def test_acme_failure(self):
        s=self.acme_setup();(STATE/'acme-mode').write_text('ca-reject');job='e'*32
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1');report=self.acme_wait(s,job)
        self.assertEqual(report['state'],'failed',self.acme_diagnostics(job))
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text())['records'],[])
        self.assertFalse(Path('/etc/homegate-engineering/certs/cert_a/current').exists())
        self.assertFalse(report['cleanup_required']);self.verify_unchanged()
    def test_acme_unknown(self):
        s=self.acme_setup();(STATE/'acme-mode').write_text('dns-unknown');job='f'*32
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1');report=self.acme_wait(s,job)
        self.assertEqual(report['state'],'failed',self.acme_diagnostics(job));self.assertTrue(report['cleanup_required'])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['records']),1)
        self.assertFalse(any(e['method']=='DELETE' for e in db['events']))
        self.assertTrue(Path('/etc/homegate-engineering/transactions/dns-operation').exists())
        self.api('configuration_api','acme_issue',s,{'id':'cert_a','job':'1'*32,'consent':'1'},expected=503)
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db)
        self.verify_unchanged()

    def acme_session_wait(self,s,predicate,seconds=65):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            report=self.cfg('acme_schedule_status',s)['report']
            if predicate(report):return report
            time.sleep(.15)
        root=Path('/var/run/homegate-engineering/acme-schedule')
        job=(root/'current-job').read_text().strip() if (root/'current-job').exists() else None
        self.fail(('Renewal session did not reach state',report,self.acme_diagnostics(job) if job else {}))
    def acme_clock(self):
        # External clock fixture: advance the monotonic hourly check after the
        # admitted order ends. Product check period and per-order budget stay fixed.
        (STATE/'acme-clock.lua').write_text("local f=assert(io.open('/proc/uptime'));local n=assert(tonumber(f:read('*n')));f:close();io.write(math.floor(n)+3601,'\\n')\n")
        tool=STATE/'tools/lua.next';tool.write_text('#!/bin/sh\nif [ "${1##*/}:$2" = worker-process.lua:now ] && [ -f /teststate/acme-hour ];then exec /usr/bin/lua5.1 /teststate/acme-clock.lua;fi\nexec /usr/bin/lua5.1 /teststate/lua-runner.lua "$@"\n');tool.chmod(0o755);tool.replace(STATE/'tools/lua')
        (STATE/'acme-hour').touch()
    def test_acme_schedule(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test');self.rule(s)
        self.cfg('lifecycle_enable',s,consent='1');self.lifecycle_grant(s)
        accepted=self.cfg('acme_schedule_start',s,id='cert_a',consent='1')['report'];self.assertTrue(accepted['running'])
        done=self.acme_session_wait(s,lambda d:d['state']=='waiting' and d['checks']==1)
        self.assertTrue(done['running']);self.assertTrue(self.cfg('cert_status',s,id='cert_a')['report']['valid'])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['orders']),1)
        jobs=Path('/etc/homegate-engineering/acme/jobs');self.assertEqual(len(list(jobs.iterdir())),1)
        for action,fields in [('acme_issue',{'id':'cert_a','job':'a'*32,'consent':'1'}),('acme_schedule_start',{'id':'cert_a','consent':'1'}),('schedule_serve',{'consent':'1'}),('preview_acme_certificate',{'id':'cert_a','name':'changed','account':'dns_a','zone':'example.test','domains':'example.test','email':'','environment':'production'})]:
            self.api('configuration_api',action,s,fields,expected=503)
        self.acme_clock();self.acme_session_wait(s,lambda d:d['state']=='waiting' and d['checks']==2,seconds=15)
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db);self.assertEqual(len(list(jobs.iterdir())),1)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            status,_,raw=self.cgi(BASE+'/configuration_api/lifecycle_disable',cookie=s[0],verb='POST',fields={'consent':'1','token':s[1]})
            if status==200 and json.loads(raw)['ok']:break
            self.assertEqual(status,503);time.sleep(.2)
        else:self.fail('Main disable failed to stop/reap the renewal session')
        self.assertEqual(self.cfg('acme_schedule_status',s)['report']['state'],'idle')
        self.assertFalse(self.cfg('lifecycle_status',s)['report']['main_enabled'])
        self.api('configuration_api','acme_schedule_start',s,{'id':'cert_a','consent':'1'},expected=503)
        self.assertTrue(self.cfg('cert_status',s,id='cert_a')['report']['valid']);self.verify_unchanged()
    def test_acme_schedule_unknown(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test');(STATE/'acme-mode').write_text('dns-unknown')
        self.cfg('acme_schedule_start',s,id='cert_a',consent='1');done=self.acme_session_wait(s,lambda d:d['state']=='failed' and not d['running'])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['orders']),1);self.assertEqual(len(db['records']),1)
        self.acme_clock();time.sleep(1.2);self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db)
        self.api('configuration_api','acme_schedule_reap',s,{'consent':'1'},expected=503)
        self.api('configuration_api','acme_cleanup',s,{'job':done['job'],'consent':'1'},expected=503)
        self.api('configuration_api','acme_issue',s,{'id':'cert_a','job':'b'*32,'consent':'1'},expected=503)
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db);self.verify_unchanged()
    def test_acme_cold(self):
        import signal
        s=self.acme_setup();self.acme_config(s,domains='example.test');(STATE/'acme-mode').write_text('hold-challenge');job='7'*32
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1')
        deadline=time.monotonic()+40
        while not (STATE/'acme-entered').exists() and time.monotonic()<deadline:time.sleep(.1)
        self.assertTrue((STATE/'acme-entered').exists())
        owners=[]
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:args=(proc/'cmdline').read_bytes().split(b'\0')
            except (FileNotFoundError,PermissionError):continue
            if b'/usr/libexec/homegate-engineering/project/core/prototype/homegate-acme-job.sh' in args and b'work' in args and job.encode() in args:owners.append(int(proc.name))
        self.assertEqual(len(owners),1);self.assertEqual(os.getpgid(owners[0]),owners[0]);os.killpg(owners[0],signal.SIGKILL)
        report=self.acme_wait(s,job);self.assertEqual(report['state'],'interrupted')
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['records']),1)
        self.api('configuration_api','acme_issue',s,{'id':'cert_a','job':'8'*32,'consent':'1'},expected=503)
        self.api('configuration_api','acme_schedule_start',s,{'id':'cert_a','consent':'1'},expected=503)
        # Simulate lost volatile runtime only after its process family is dead.
        # The real /var is the existing private namespace tmpfs, never the host.
        self.assertEqual((STATE/'isolation-marker').read_text(),'HomeGate private RPC fixture\n')
        run=Path('/var/run/homegate-engineering');self.assertEqual(run.resolve(),run);shutil.rmtree(run)
        self.cfg('prepare',s);self.assertEqual(self.cfg('acme_status',s,job=job)['report']['state'],'interrupted')
        self.api('configuration_api','preview_acme_certificate',s,{'id':'cert_a','name':'changed','account':'dns_a','zone':'example.test','domains':'example.test','email':'','environment':'production'},expected=503)
        self.cfg('lifecycle_disable',s,consent='1');self.assertFalse(self.cfg('lifecycle_status',s)['report']['main_enabled'])
        self.cfg('acme_cleanup',s,job=job,consent='1');report=self.acme_wait(s,job);self.assertEqual(report['state'],'cleaned',self.acme_diagnostics(job))
        now=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(now['records'],[]);self.assertEqual(len(now['orders']),len(db['orders']))
        self.assertFalse(Path('/etc/homegate-engineering/certs/cert_a/current').exists());self.verify_unchanged()
    def test_acme_schedule_stop(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test');self.cfg('lifecycle_enable',s,consent='1');(STATE/'acme-mode').write_text('hold-directory')
        self.cfg('acme_schedule_start',s,id='cert_a',consent='1')
        deadline=time.monotonic()+20
        while not (STATE/'acme-entered').exists() and time.monotonic()<deadline:time.sleep(.1)
        self.assertTrue((STATE/'acme-entered').exists())
        self.api('configuration_api','lifecycle_disable',s,{'consent':'1'},expected=503)
        done=self.acme_session_wait(s,lambda d:not d['running'],seconds=15);self.assertIn(done['state'],['stopped','interrupted'])
        result=self.acme_wait(s,done['job']);self.assertEqual(result['state'],'interrupted')
        self.assertFalse(Path('/etc/homegate-engineering/certs/cert_a/current').exists())
        self.cfg('acme_cleanup',s,job=done['job'],consent='1');self.assertEqual(self.acme_wait(s,done['job'])['state'],'cleaned')
        self.cfg('lifecycle_disable',s,consent='1');self.assertEqual(self.cfg('acme_schedule_status',s)['report']['state'],'idle')
        self.assertFalse(self.cfg('lifecycle_status',s)['report']['main_enabled'])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(db['orders'],{});self.assertEqual(db['records'],[])
        time.sleep(1.1);self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db);self.verify_unchanged()
    def test_acme_race(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test')
        wrapper='#!/bin/sh\ncase "$1:$2" in\n */homegate-acme-schedule.sh:quiescent)\n  if [ ! -f /teststate/race-seen ];then\n   /usr/sbin/busybox ash "$@" || exit "$?"\n   : > /teststate/race-seen\n   n=0;while [ ! -f /teststate/race-release ];do n=$((n+1));[ "$n" -lt 600 ] || exit 99;sleep .03;done\n   exit 0\n  fi;;\n */homegate-acme-schedule.sh:serve)\n  : > /teststate/race-session-seen\n  n=0;while [ ! -f /teststate/race-session-release ];do n=$((n+1));[ "$n" -lt 600 ] || exit 99;sleep .03;done;;\nesac\nexec /usr/sbin/busybox ash "$@"\n'
        shell=STATE/'tools/ash';shell.unlink();shell.write_text(wrapper);shell.chmod(0o755)
        job='a1'*16
        child=subprocess.Popen(['/usr/bin/homegate-engineering','acme-issue','cert_a',job,'--confirm'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def marker(name):
            deadline=time.monotonic()+15
            while not (STATE/name).exists() and time.monotonic()<deadline:time.sleep(.05)
            self.assertTrue((STATE/name).exists(),name)
        marker('race-seen')
        self.cfg('acme_schedule_start',s,id='cert_a',consent='1');marker('race-session-seen')
        (STATE/'race-release').touch();out,err=child.communicate(timeout=10)
        self.assertEqual((child.returncode,err),(4,b''),out);self.assertFalse(Path('/etc/homegate-engineering/acme/jobs',job).exists())
        self.assertFalse((STATE/'acme-fixture.json').exists(),'Losing admission must not reach the CA/DNS transport')
        self.cfg('acme_schedule_stop',s,consent='1');(STATE/'race-session-release').touch()
        self.acme_session_wait(s,lambda d:not d['running'],seconds=10);self.cfg('acme_schedule_reap',s,consent='1');self.verify_unchanged()
    def test_acme_schedule_timeout(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test');(STATE/'acme-mode').write_text('hold-directory')
        self.cfg('acme_schedule_start',s,id='cert_a',consent='1')
        deadline=time.monotonic()+20
        while not (STATE/'acme-entered').exists() and time.monotonic()<deadline:time.sleep(.1)
        self.assertTrue((STATE/'acme-entered').exists())
        self.acme_clock()  # Cross the unchanged created+900 per-order deadline.
        done=self.acme_session_wait(s,lambda d:d['state']=='failed' and not d['running'],seconds=15)
        report=self.acme_wait(s,done['job']);self.assertEqual(report['state'],'interrupted');self.assertTrue(report['cleanup_required'])
        self.assertFalse(Path('/etc/homegate-engineering/certs/cert_a/current').exists())
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(db['orders'],{});self.assertEqual(db['records'],[])
        self.cfg('acme_cleanup',s,job=done['job'],consent='1');self.assertEqual(self.acme_wait(s,done['job'])['state'],'cleaned')
        self.cfg('acme_schedule_reap',s,consent='1');time.sleep(1.1)
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db);self.verify_unchanged()
    def test_acme_publication_recovery(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test');job='b1'*16
        tool=STATE/'tools/fsync';tool.unlink();tool.write_text('#!/usr/sbin/ash\ncase "$1" in /etc/homegate-engineering/certs/cert_a/.current.next) exit 1;; esac\nexec /usr/sbin/busybox fsync "$@"\n');tool.chmod(0o755)
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1');report=self.acme_wait(s,job);self.assertEqual(report['state'],'failed',self.acme_diagnostics(job));self.assertFalse(report['cleanup_required'])
        tool.unlink();tool.symlink_to('busybox');self.assertTrue(self.cfg('cert_status',s,id='cert_a')['report']['pending'])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['orders']),1);self.assertEqual(db['records'],[])
        self.api('configuration_api','acme_issue',s,{'id':'cert_a','job':'b2'*16,'consent':'1'},expected=503)
        self.cfg('acme_schedule_start',s,id='cert_a',consent='1');self.acme_session_wait(s,lambda d:d['state']=='failed' and not d['running'],seconds=15)
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db);self.cfg('acme_schedule_reap',s,consent='1')
        self.cfg('cert_resume',s,id='cert_a',consent='1');status=self.cfg('cert_status',s,id='cert_a')['report'];self.assertTrue(status['valid']);self.assertFalse(status['pending'])
        self.assertEqual(json.loads((STATE/'acme-fixture.json').read_text()),db);self.verify_unchanged()
    def test_acme_due(self):
        s=self.acme_setup();self.acme_config(s,domains='example.test');(STATE/'acme-mode').write_text('short-cert');job='9'*32
        self.cfg('acme_issue',s,id='cert_a',job=job,consent='1');self.assertEqual(self.acme_wait(s,job)['state'],'issued',self.acme_diagnostics(job))
        base=Path('/etc/homegate-engineering/certs/cert_a');old=(base/'current').read_bytes();self.assertTrue(self.cfg('cert_status',s,id='cert_a')['report']['renew'])
        (STATE/'acme-mode').write_text('success');self.cfg('acme_schedule_start',s,id='cert_a',consent='1')
        done=self.acme_session_wait(s,lambda d:d['state']=='waiting' and d['checks']==1)
        self.assertNotEqual((base/'current').read_bytes(),old);self.assertFalse(self.cfg('cert_status',s,id='cert_a')['report']['renew'])
        db=json.loads((STATE/'acme-fixture.json').read_text());self.assertEqual(len(db['orders']),2);self.assertEqual(db['records'],[])
        self.cfg('acme_schedule_stop',s,consent='1');self.acme_session_wait(s,lambda d:not d['running'],seconds=10)
        self.cfg('acme_schedule_reap',s,consent='1');self.assertTrue((base/old.decode().strip()).is_dir());self.verify_unchanged()

def main():
    global INSTALLED
    p=argparse.ArgumentParser();p.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd')
    p.add_argument('--http-runtime-dir',type=Path,default=ROOT/'build/uhttpd');p.add_argument('--luci-runtime-dir',type=Path,default=ROOT/'build/luci')
    p.add_argument('--installed-root',type=Path);p.add_argument('--group',choices=['security','configuration','async','schedule','contracts','continuous','lifecycle','intent_recovery','intent_cleanup','intent_frames','production_copy','production_copy_sources','production_copy_recovery','production_copy_rollback','certificate','certificate_invalid','certificate_recovery','certificate_timeout','acme','acme_failure','acme_unknown','acme_accounts','acme_preexisting','acme_aliyun','acme_dnspod','acme_huawei','acme_stop','acme_schedule','acme_schedule_unknown','acme_cold','acme_due','acme_schedule_stop','acme_race','acme_schedule_timeout','acme_publication_recovery'])
    p.add_argument('--inside-net');p.add_argument('--inside-uid');a=p.parse_args()
    rpc.WORK,luci.HTTP,luci.LUA=a.runtime_dir.resolve(),a.http_runtime_dir.resolve(),a.luci_runtime_dir.resolve()
    luci.BASE=BASE;luci.PAGE=PAGE;INSTALLED=a.installed_root
    if a.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID=a.inside_net,a.inside_uid
        suite=unittest.TestSuite([Web('test_'+a.group)])
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    for group in ([a.group] if a.group else ['security','configuration','async','schedule','contracts','continuous','lifecycle','intent_recovery','intent_cleanup','intent_frames','production_copy','production_copy_sources','production_copy_recovery','production_copy_rollback','certificate','certificate_invalid','certificate_recovery','certificate_timeout','acme','acme_failure','acme_unknown','acme_accounts','acme_preexisting','acme_aliyun','acme_dnspod','acme_huawei','acme_stop','acme_schedule','acme_schedule_unknown','acme_cold','acme_due','acme_schedule_stop','acme_race','acme_schedule_timeout','acme_publication_recovery']):
        args=['--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--group',group]
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
          extra_mounts=lambda s:((Path('/etc/ssl'),'/etc/ssl'),(Path('/usr/bin'),'/fixture-host-bin'),(s/'usr-bin','/usr/bin'),(s/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
             (s/'models',luci.LUA/'prefix/lib/lua/luci/model'),(s/'libexec','/usr/libexec'),(s/'tools','/usr/sbin'),
             (s/'curl-fixture','/usr/bin/curl')),
          extra_rw_mounts=lambda s:((s/'etc/homegate-engineering','/etc/homegate-engineering'),(s/'etc/config','/etc/config')),
          state_setup=setup_state,guest_args=args)
        if result:return result
    return 0

if __name__=='__main__':sys.exit(main())
