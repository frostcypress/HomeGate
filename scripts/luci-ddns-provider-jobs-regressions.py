#!/usr/bin/env python3
"""Real task workers, pinned curl/TLS and original durable Cloudflare receipts."""
import argparse
import hashlib
import http.server
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse
from project import ROOT

spec=importlib.util.spec_from_file_location('provider_jobs_base',ROOT/'scripts/luci-ddns-jobs-regressions.py')
jobs=importlib.util.module_from_spec(spec);spec.loader.exec_module(jobs)
read,luci,rpc=jobs.read,jobs.luci,jobs.rpc
STORE,RUN,STATE=jobs.STORE,jobs.RUN,jobs.STATE
CURL=ROOT/'build/curl-runtime/curl-7.83.1/src/curl'
ZONE='f'*32
GATES={
    'homegate-ddns-read.sh':('ddns_plan_enabled','ddns_sync_enabled','ddns_work_enabled','ddns_runtime_enabled'),
    'homegate-ddns-work.sh':('ddns_work_enabled','ddns_runtime_enabled'),
    'homegate-ddns-plan-worker.sh':('ddns_plan_enabled',),
    'homegate-service-observer-watchdog.sh':('ddns_plan_enabled','dns_read_enabled','dns_records_enabled','dns_receipt_enabled'),
    'homegate-cloudflare-read.sh':('dns_read_enabled','dns_records_enabled','dns_receipt_enabled','dns_settlement_enabled','dns_migrated_read_enabled','ddns_sync_enabled','ddns_work_enabled','ddns_runtime_enabled'),
    'homegate-cloudflare-worker.sh':('dns_read_enabled','dns_records_enabled','dns_receipt_enabled'),
    'homegate-dns-receipt.sh':('dns_receipt_enabled','ddns_runtime_enabled'),
    'homegate-dns-recovery.sh':('dns_settlement_enabled',),
    'homegate-config-prototype.sh':('ddns_plan_enabled',),
}
MIXED_CASES=('05','06','07','08','09')
CASES=('01','02','03','04')+MIXED_CASES


def setup_state(state):
    jobs.setup_state(state)
    # Real detached work replaces only the earlier launch-failure control.
    (state/'tools/setsid').unlink()
    for name,flags in GATES.items():
        path=state/'project/core/prototype'/name;body=path.read_bytes()
        for flag in flags:
            pattern=rb'^'+re.escape(flag.encode())+rb'=false$'
            body,count=re.subn(pattern,(flag+'=true').encode(),body,flags=re.M)
            if count!=1:raise ValueError('Expected one exact original closed provider gate: '+name+':'+flag)
        path.write_bytes(body)
    tls=state/'tls';tls.mkdir(mode=0o700)
    trust=state/'etc/ssl/certs';trust.mkdir(parents=True)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=api.cloudflare.com','-addext','subjectAltName=DNS:api.cloudflare.com',
        '-keyout',str(tls/'key.pem'),'-out',str(trust/'ca-certificates.crt')],check=True,capture_output=True,timeout=30)
    (tls/'key.pem').chmod(0o600)
    shutil.copyfile(CURL,state/'curl-real');(state/'curl-real').chmod(0o755)
    transport=state/'curl-transport'
    transport.write_text(r'''#!/usr/bin/python3
import os,re,stat,sys
from pathlib import Path
args=sys.argv[1:]
assert args[:2]==['--disable','--config'] and len(args)>2
path=Path(args[2]);s=path.lstat()
assert str(path).startswith('/var/run/homegate/.dns-check-') and path.name=='request'
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=65536
urls=re.findall(r'^url = "([^"]+)"$',path.read_text(),re.M)
assert len(urls)==1 and urls[0].startswith('https://api.cloudflare.com/client/v4/')
assert all(x not in args for x in ['--insecure','--location','--retry','--connect-to','--resolve'])
assert args[args.index('--cacert')+1]=='/etc/ssl/certs/ca-certificates.crt'
port=Path('/teststate/tls-port').read_text().strip();assert port.isdecimal() and 0<int(port)<65536
with open('/teststate/transport-events','ab') as f:f.write(b'pinned-curl-loopback-tls\n')
os.execv('/teststate/curl-real',['curl',*args,'--connect-to','api.cloudflare.com:443:127.0.0.1:'+port])
''')
    transport.chmod(0o755)
    ip=state/'tools/ip'
    ip.write_text(r'''#!/usr/bin/python3
import sys
from pathlib import Path
args=sys.argv[1:]
if args==['-6','-o','addr','show','scope','global']:
    kind='addresses';body='12: pppoe-wan inet6 2001:db8::2/64 scope global dynamic\n13: br-lan inet6 2001:db8:1::1/64 scope global\n'
elif args==['-6','route','show','default']:
    kind='routes';body='default via fe80::1 dev pppoe-wan metric 512\n'
else:sys.exit(99)
with open('/teststate/network-samples','a') as f:f.write(kind+'\n')
sys.stdout.write(body)
''')
    ip.chmod(0o755)


def setup_mixed_state(state):
    setup_state(state)
    configure_mixed_source(state,'ddns_1')


def configure_mixed_source(state,rule):
    if rule not in ('ddns_0','ddns_1','ddns_2','ddns_3'):raise ValueError('Unsupported fixed fixture rule')
    path=state/'etc/config/homegate';body=path.read_text()
    marker="config ddns_rule '"+rule+"'\n"
    if body.count(marker)!=1:raise ValueError('Expected one original rule in fixture')
    path.write_text(body.replace(marker,marker+" option source 'interface'\n option interface 'odd-uplink'\n"))
    (state/'interface-addresses').write_text('12: pppoe-wan inet6 2001:db8::2/64 scope global dynamic\n14: odd-uplink inet6 2001:db8:2::9/64 scope global dynamic\n')
    script=state/'tools/ip'
    script.write_text("#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\nargs=sys.argv[1:]\n"
        "if args==['-6','-o','addr','show','scope','global']:\n kind='addresses';body=Path('/teststate/interface-addresses').read_text()\n"
        "elif args==['-6','route','show','default']:\n kind='routes';body='default via fe80::1 dev pppoe-wan metric 512\\n'\n"
        "else:sys.exit(99)\nwith open('/teststate/network-samples','a') as f:f.write(kind+'\\n')\nsys.stdout.write(body)\n")
    script.chmod(0o755)


class ProviderJobs(jobs.Jobs):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.db={};cls.requests=[];cls.next_record=1000;cls.fail_after_mutation=False
        outer=cls
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self,method):
                parsed=urllib.parse.urlsplit(self.path);query=urllib.parse.parse_qs(parsed.query)
                authenticated=self.headers.get('Authorization')=='Bearer SECRET_SENTINEL'
                outer.requests.append({'method':method,'authenticated':authenticated})
                if not authenticated:
                    code,doc=403,{'success':False,'errors':[]}
                elif parsed.path=='/client/v4/zones' and method=='GET':
                    code,doc=200,{'success':True,'errors':[],'result':[{'id':ZONE,'name':'example.test'}]}
                else:
                    prefix='/client/v4/zones/'+ZONE+'/dns_records'
                    if parsed.path==prefix and method=='GET':
                        records=[dict(r) for r in outer.db.values() if r['name']==query.get('name',[''])[0] and r['type']==query.get('type',[''])[0]]
                        page=int(query.get('page',['1'])[0]);selected=records[(page-1)*100:page*100]
                        code,doc=200,{'success':True,'errors':[],'result':selected,
                            'result_info':{'page':page,'per_page':100,'count':len(selected),'total_count':len(records),'total_pages':(len(records)+99)//100}}
                    elif parsed.path.startswith(prefix+'/') and method=='GET':
                        record=outer.db.get(parsed.path.rsplit('/',1)[1])
                        code,doc=(200,{'success':True,'errors':[],'result':dict(record)}) if record else (404,{'success':False,'errors':[]})
                    elif (parsed.path==prefix and method=='POST') or (parsed.path.startswith(prefix+'/') and method=='PATCH'):
                        size=int(self.headers.get('Content-Length','0'))
                        if not 0<size<=32768:raise ValueError('Invalid fixture payload bound')
                        data=json.loads(self.rfile.read(size))
                        if method=='POST':
                            outer.next_record+=1;rid=format(outer.next_record,'032x');outer.db[rid]={'id':rid,**data}
                        else:
                            rid=parsed.path.rsplit('/',1)[1];outer.db[rid].update(data)
                        if outer.fail_after_mutation:code,doc=500,{'success':False,'errors':[]}
                        else:code,doc=200,{'success':True,'errors':[],'result':dict(outer.db[rid])}
                    else:
                        code,doc=404,{'success':False,'errors':[]}
                body=json.dumps(doc).encode();self.send_response(code)
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_GET(self):self.reply('GET')
            def do_POST(self):self.reply('POST')
            def do_PATCH(self):self.reply('PATCH')
        cls.provider=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.provider.daemon_threads=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('/etc/ssl/certs/ca-certificates.crt',str(STATE/'tls/key.pem'))
        cls.provider.socket=context.wrap_socket(cls.provider.socket,server_side=True)
        (STATE/'tls-port').write_text(str(cls.provider.server_port))
        cls.provider_thread=threading.Thread(target=lambda:cls.provider.serve_forever(poll_interval=0.05),daemon=True)
        cls.provider_thread.start()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'provider'):
            cls.provider.shutdown();cls.provider.server_close();cls.provider_thread.join(timeout=2)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.expected_configuration=self.configuration_snapshot()

    def configuration_snapshot(self):
        result={}
        for key,value in self.snapshot().items():
            path=Path(key)
            if path==Path('/etc/config/homegate'):result[key]=value
            elif path.is_relative_to(STORE) and path!=STORE:
                top=path.relative_to(STORE).parts[0]
                if not (top.startswith('dns-') or top.startswith('.dns-')):result[key]=value
        return result

    def tearDown(self):
        # Keep the genuine task and journal until the disposable namespace ends.
        # No collector, archive deletion or invented source proof is involved.
        self.assertTrue(self.configuration_snapshot()==self.expected_configuration,'Provider work changed configuration; private bytes suppressed')
        self.assertFalse((STATE/'network-calls').exists(),'Unexpected PATH network tool was used')
        self.assertTrue(all(x=='enabled' for x in (STATE/'service-calls').read_text().splitlines()),'A real service action was attempted')
        self.assertEqual(list(Path('/tmp').glob('homegate-ddns-ui-*')),[])

    def authorize(self,session):
        preview=self.post('preview',session,selection='ddns_1')
        self.post('commit',session,confirmation=preview['confirmation'],consent='1')
        self.expected_configuration=self.configuration_snapshot()

    def submit(self,session,job='a'*32,rule='ddns_1',expected=200):
        return self.request_job('submit',session,expected=expected,job=job,rule=rule,consent='1')

    def settled(self,session,job='a'*32):
        end=time.monotonic()+30
        while time.monotonic()<end:
            row=next((r for r in self.jobs(session) if r['job']==job),None)
            if row and not row['pending']:return row
            time.sleep(0.05)
        raise AssertionError('Private provider worker did not settle within bound')

    def run_job(self,session):
        self.authorize(session);ack=self.submit(session)
        self.assertTrue(ack['pending'] and ack['last_effect']=='unknown')
        row=self.settled(session)
        self.assertTrue(all(r['authenticated'] for r in self.requests),'Fixture received an unbound credential')
        samples=(STATE/'network-samples').read_text().splitlines() if (STATE/'network-samples').exists() else []
        self.assertEqual(samples,['addresses','routes'])
        if row['result'] is False or row['result'].get('status') not in ('unchanged','created','updated'):
            raw=jobs.JOBS/('a'*32)/'raw';doc={}
            if raw.exists():
                try:doc=json.loads(raw.read_bytes())
                except ValueError:pass
            def public_fields(path):
                try:value=json.loads(path.read_bytes())
                except (ValueError,OSError):return {}
                if not isinstance(value,dict):return {}
                return {k:v for k,v in value.items() if k in ('phase','ok','effect','result','error_kind','reconciliation_required') and
                    (isinstance(v,(bool,int)) or isinstance(v,str) and re.fullmatch('[a-z0-9_-]{0,64}',v))}
            work=[{'name':p.name,'members':{f.name:f.stat().st_size for f in p.iterdir() if f.is_file()},
                   'public':{n:public_fields(p/n) for n in ('result','provider','public')}}
                  for p in RUN.glob('.ddns-plan-*') if p.is_dir()]
            journal=STORE/'dns-operation'
            print('REDACTED_PROVIDER_DIAGNOSTIC '+json.dumps({'state':row['state'],'effect':row['last_effect'],
                'result_status':row['result'].get('status') if isinstance(row['result'],dict) else False,
                'raw_phase':doc.get('phase'),'raw_keys':sorted(doc),'http':self.requests,
                'transport_calls':(STATE/'transport-events').read_bytes().count(b'\n') if (STATE/'transport-events').exists() else 0,
                'run_entries':sorted(p.name for p in RUN.iterdir()),
                'store_entries':sorted(p.name for p in STORE.iterdir()),'work':work,
                'journal_members':sorted(p.relative_to(journal).as_posix() for p in journal.rglob('*')) if journal.exists() else [],
                'terminal':public_fields(journal/'terminal'),
                'state_cache':{p.name:{'size':p.stat().st_size,'mode':p.stat().st_mode&0o777,
                    'uid':p.stat().st_uid,'nlink':p.stat().st_nlink,'public':public_fields(p)}
                    for p in (RUN/'ddns-state').iterdir() if p.is_file()} if (RUN/'ddns-state').is_dir() else {},
                'outer_raw':public_fields(raw)}),flush=True)
        return row

    def assert_origin(self,row,status):
        self.assertTrue(row['state']=='finished' and row['last_effect']=='confirmed' and row['result']['status']==status,
                        'Expected a real confirmed worker result; inspect redacted provider evidence')
        path=jobs.JOBS/('a'*32);frame=(path/'proof').read_bytes().splitlines()
        self.assertTrue(len(frame)==3 and frame[0]==b'HGDDNSUIORIGIN1','Original source proof absent')
        self.assertTrue(hashlib.sha256(b'\n'.join(frame[:2])+b'\n').hexdigest().encode()==frame[2],'Invalid original source proof')
        account,original_job,manifest_sha,terminal_sha=frame[1].decode().split(':')
        journal=STORE/'dns-operation';slot=(journal/'current').read_text().strip();manifest=journal/('slot-'+slot)/'manifest'
        self.assertEqual(account,'dns_1');self.assertTrue(original_job.isdecimal())
        self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(),manifest_sha)
        self.assertEqual(hashlib.sha256((journal/'terminal').read_bytes()).hexdigest(),terminal_sha)
        self.assertTrue((journal/'terminal-meta').is_file())
        self.assertTrue((path/'raw').is_file() and (path/'result').is_file())

    def test_provider_01_noop_uses_real_tls_without_persistent_attempt(self):
        self.db['c'*32]={'id':'c'*32,'type':'AAAA','name':'www.example.test','content':'2001:db8::2','ttl':600}
        with self.session() as session:
            row=self.run_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='none' and row['result']['status']=='unchanged',
                            'Expected an actual TLS no-op result')
            self.assertTrue(self.requests and all(r['method']=='GET' for r in self.requests))
            self.assertFalse((STORE/'dns-operation').exists());self.assertFalse((jobs.JOBS/('a'*32)/'proof').exists())
            requests=list(self.requests);before=self.snapshot();self.assertEqual(self.submit(session),row)
            self.assertTrue(before==self.snapshot(),'No-op replay changed original task')
            self.assertEqual(self.requests,requests)

    def test_provider_02_create_publishes_original_receipt_and_task_proof(self):
        with self.session() as session:
            row=self.run_job(session);self.assert_origin(row,'created')
            self.assertEqual([r['method'] for r in self.requests if r['method']!='GET'],['POST'])
            self.assertTrue(len(self.db)==1 and next(iter(self.db.values()))['content']=='2001:db8::2')
            requests=list(self.requests);before=self.snapshot()
            self.assertEqual(self.submit(session),row);self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'Confirmed receipt barrier changed on replay')
            self.assertEqual(self.requests,requests)

    def test_provider_03_update_keeps_unrelated_record_fields(self):
        self.db['c'*32]={'id':'c'*32,'type':'AAAA','name':'www.example.test','content':'2001:db8::1','ttl':600,
                         'proxied':True,'comment':'KEEP','tags':['owner:keep']}
        with self.session() as session:
            row=self.run_job(session);self.assert_origin(row,'updated')
            self.assertEqual([r['method'] for r in self.requests if r['method']!='GET'],['PATCH'])
            record=self.db['c'*32]
            self.assertTrue(record['content']=='2001:db8::2' and record['proxied'] is True and record['comment']=='KEEP' and record['tags']==['owner:keep'])

    def test_provider_04_unknown_after_attempt_retains_receipt_and_never_retries(self):
        type(self).fail_after_mutation=True
        with self.session() as session:
            row=self.run_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='unknown' and row['result']['effect']=='unknown',
                            'A failed post-attempt response lost its unknown effect')
            self.assertTrue((STORE/'dns-operation').is_dir());self.assertFalse((jobs.JOBS/('a'*32)/'proof').exists())
            requests=list(self.requests);before=self.snapshot()
            self.assertEqual(self.submit(session),row);self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'Unknown attempt evidence changed on replay')
            self.assertEqual(self.requests,requests)


class MixedJobs(ProviderJobs):
    def authorize(self,session):
        rules=getattr(self,'MIXED_RULES',('ddns_0','ddns_1'))
        if rules not in (('ddns_0','ddns_1'),('ddns_1','ddns_2'),('ddns_1','ddns_3')):raise ValueError('Unsupported fixed mixed authority rules')
        preview=self.post('preview',session,selection=','.join(reversed(rules)))
        self.assertEqual(preview['rules'],list(rules));self.assertEqual(preview['provider'],'multiple')
        result=self.post('commit',session,confirmation=preview['confirmation'],consent='1')
        self.assertEqual(result['rules'],list(rules));self.expected_configuration=self.configuration_snapshot()
        return preview
    def run_mixed_job(self,session):
        self.authorize(session);ack=self.submit(session)
        self.assertTrue(ack['pending'] and ack['last_effect']=='unknown');row=self.settled(session)
        self.assertTrue(all(event['authenticated'] for event in self.requests),'Provider credential binding changed')
        self.assertEqual((STATE/'network-samples').read_text().splitlines(),['addresses'])
        return row
    def test_provider_05_mixed_grant_and_interface_noop_stay_scoped(self):
        self.db['c'*32]={'id':'c'*32,'type':'AAAA','name':'www.example.test','content':'2001:db8:2::9','ttl':600}
        with self.session() as session:
            row=self.run_mixed_job(session)
            self.assertEqual((row['state'],row['last_effect'],row['result']['status']),('finished','none','unchanged'))
            self.assertTrue(self.requests and all(event['method']=='GET' for event in self.requests))
            self.assertFalse((STORE/'dns-operation').exists());self.assertFalse((jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.assertEqual(before,self.snapshot());self.assertEqual(requests,self.requests)
    def test_provider_06_interface_create_keeps_real_receipt_and_replay_barrier(self):
        with self.session() as session:
            row=self.run_mixed_job(session);self.assert_origin(row,'created')
            self.assertEqual([event['method'] for event in self.requests if event['method']!='GET'],['POST'])
            self.assertTrue(len(self.db)==1 and next(iter(self.db.values()))['content']=='2001:db8:2::9')
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row);self.submit(session,job='b'*32,expected=503)
            self.assertEqual(before,self.snapshot());self.assertEqual(requests,self.requests)
    def test_provider_07_missing_interface_finishes_without_wan_fallback_or_proof(self):
        (STATE/'interface-addresses').write_text('12: pppoe-wan inet6 2001:db8::2/64 scope global dynamic\n')
        with self.session() as session:
            row=self.run_mixed_job(session)
            self.assertEqual((row['state'],row['last_effect'],row['result']['status']),('finished','none','network_unavailable'))
            self.assertTrue(row['result']['retryable']);self.assertEqual(self.requests,[]);self.assertFalse((STORE/'dns-operation').exists());self.assertFalse((jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();self.assertEqual(self.submit(session),row);self.assertEqual(before,self.snapshot())
    def test_provider_08_csrf_and_changed_interface_preserve_confirmation(self):
        with self.session() as session:
            calls=(STATE/'entry-calls').read_bytes() if (STATE/'entry-calls').exists() else b'';before=self.snapshot()
            status,_,_=self.cgi(luci.BASE+'/ddns_native/submit',cookie=session[0],verb='POST',fields={'token':'wrong-fixture','job':'a'*32,'rule':getattr(self,'RULE','ddns_1'),'consent':'1'})
            self.assertEqual(status,403);self.assertEqual(before,self.snapshot());self.assertEqual((STATE/'entry-calls').read_bytes() if (STATE/'entry-calls').exists() else b'',calls)
            preview=self.post('preview',session,selection=','.join(getattr(self,'MIXED_RULES',('ddns_0','ddns_1'))));path=Path('/etc/config/homegate');original=path.read_bytes()
            try:
                path.write_bytes(original.replace(b'odd-uplink',b'another-uplink'))
                self.refused('commit',session,confirmation=preview['confirmation'],consent='1')
            finally:path.write_bytes(original)
            self.expected_configuration=self.configuration_snapshot();self.assertEqual(self.requests,[]);self.assertFalse(jobs.JOBS.exists())
    def test_provider_09_unknown_interface_attempt_keeps_original_evidence(self):
        type(self).fail_after_mutation=True
        with self.session() as session:
            row=self.run_mixed_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='unknown' and row['result']['effect']=='unknown')
            self.assertEqual([event['method'] for event in self.requests if event['method']!='GET'],['POST'])
            self.assertTrue(len(self.db)==1 and next(iter(self.db.values()))['content']=='2001:db8:2::9')
            self.assertTrue((STORE/'dns-operation').exists());self.assertFalse((jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row);self.submit(session,job='b'*32,expected=503)
            self.assertEqual(before,self.snapshot());self.assertEqual(requests,self.requests)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd')
    parser.add_argument('--http-runtime-dir',type=Path,default=luci.HTTP)
    parser.add_argument('--luci-runtime-dir',type=Path,default=luci.LUA)
    parser.add_argument('--inside-net',help=argparse.SUPPRESS)
    parser.add_argument('--inside-uid',help=argparse.SUPPRESS)
    parser.add_argument('--case',choices=CASES)
    args=parser.parse_args()
    rpc.WORK,luci.HTTP,luci.LUA=args.runtime_dir.resolve(),args.http_runtime_dir.resolve(),args.luci_runtime_dir.resolve()
    if args.inside_net:
        rpc.OUTER_NET,rpc.OUTER_UID=args.inside_net,args.inside_uid
        cls=MixedJobs if args.case in MIXED_CASES else ProviderJobs
        names=[n for n in sorted(cls.__dict__) if n.startswith('test_provider_') and n.split('_')[2]==args.case]
        if len(names)!=1:raise ValueError('Expected one isolated provider result scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(cls(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    curl=subprocess.run([str(CURL),'--version'],capture_output=True,check=True)
    if not curl.stdout.startswith(b'curl 7.83.1 '):raise ValueError('Use the verified pinned curl7.83.1 runtime')
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER] if p.is_file()}
    result=0
    for case in ((args.case,) if args.case else CASES):
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
            extra_mounts=lambda state:((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),(state/'libexec','/usr/libexec'),
                (state/'tools','/usr/sbin'),(state/'curl-transport','/usr/bin/curl')),
            extra_rw_mounts=lambda state:((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
            state_setup=setup_mixed_state if case in MIXED_CASES else setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--case',case))
        if result:break
    if any(p.read_bytes()!=b for p,b in original.items()):raise ValueError('Original business/candidate source changed during TLS task checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);sys.exit(2)
