#!/usr/bin/env python3
"""Real Aliyun task workers, independently signed loopback TLS and receipts."""
import argparse
import base64
import hashlib
import hmac
import http.server
import importlib.util
import json
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import threading
import unittest
from urllib.parse import parse_qs,quote,urlsplit
from project import ROOT

spec=importlib.util.spec_from_file_location('aliyun_task_provider',ROOT/'scripts/luci-ddns-provider-jobs-regressions.py')
provider=importlib.util.module_from_spec(spec);spec.loader.exec_module(provider)
read,luci,rpc=provider.read,provider.luci,provider.rpc
STORE,RUN,STATE=provider.STORE,provider.RUN,provider.STATE
CASES=('01','02','03','04')
GATES={
    'homegate-cloudflare-read.sh':('aliyun_read_enabled','aliyun_records_enabled','aliyun_receipt_enabled','aliyun_settlement_enabled'),
    'homegate-service-observer-watchdog.sh':('aliyun_read_enabled','aliyun_records_enabled','aliyun_receipt_enabled'),
    'homegate-aliyun-worker.sh':('aliyun_read_enabled','aliyun_records_enabled','aliyun_receipt_enabled'),
    'homegate-dns-receipt.sh':('aliyun_receipt_enabled',),
    'homegate-dns-recovery.sh':('aliyun_settlement_enabled',),
}


def setup_state(state,provider_name='aliyun'):
    if provider_name not in ('aliyun','dnspod','huaweicloud'):raise ValueError('Unsupported signed task fixture')
    host={'aliyun':'alidns.aliyuncs.com','dnspod':'dnspod.tencentcloudapi.com','huaweicloud':'dns.cn-north-4.myhuaweicloud.com'}[provider_name]
    provider.setup_state(state)
    # Host-owned tools are unmapped in the private user namespace. Copy the
    # actual signer so the original root/regular-file/0755 checks still apply.
    shutil.copyfile('/usr/bin/openssl',state/'openssl-real');(state/'openssl-real').chmod(0o755)
    # Signed providers use their own attempt/journal protocol; CF receipt mode must close.
    for name in ('homegate-cloudflare-read.sh','homegate-service-observer-watchdog.sh',
                 'homegate-cloudflare-worker.sh','homegate-dns-receipt.sh'):
        path=state/'project/core/prototype'/name;body=path.read_bytes()
        if body.count(b'dns_receipt_enabled=true')!=1:raise ValueError('Expected one temporary CF receipt gate')
        path.write_bytes(body.replace(b'dns_receipt_enabled=true',b'dns_receipt_enabled=false'))
    gates=GATES if provider_name=='aliyun' else {name.replace('aliyun',provider_name):tuple(flag.replace('aliyun',provider_name) for flag in flags) for name,flags in GATES.items()}
    for name,flags in gates.items():
        path=state/'project/core/prototype'/name;body=path.read_bytes()
        for flag in flags:
            original=(flag+'=false').encode()
            if body.count(original)!=1:raise ValueError('Expected one closed signed-provider fixture gate')
            body=body.replace(original,(flag+'=true').encode())
        path.write_bytes(body)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN='+host,'-addext','subjectAltName=DNS:'+host,
        '-keyout',str(state/'tls/key.pem'),'-out',str(state/'etc/ssl/certs/ca-certificates.crt')],
        check=True,capture_output=True,timeout=30)
    (state/'tls/key.pem').chmod(0o600)
    path=state/'curl-transport';body=path.read_text()
    if body.count('api.cloudflare.com')!=2:raise ValueError('Unexpected pinned transport fixture')
    body=body.replace('api.cloudflare.com/client/v4/',host+'/').replace('api.cloudflare.com',host)
    path.write_text(body)


def record(identity,value='2001:db8::1',**extra):
    return {'RecordId':str(identity),'DomainName':'example.test','RR':'www','Type':'AAAA','Value':value,
            'TTL':600,'Line':'default','Locked':False,'Status':'Enable',**extra}


class AliyunJobs(provider.jobs.Jobs):
    RULE='ddns_0'
    ACCOUNT='dns_0'
    JOURNAL_FORMAT=b'HGALIJOURNAL1'

    @classmethod
    def handler(cls):
        outer=cls
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                parsed=urlsplit(self.path);q=parse_qs(parsed.query,keep_blank_values=True)
                unique=all(len(value)==1 for value in q.values())
                signature=q.pop('Signature',[''])[0]
                canonical='&'.join(quote(k,safe='-._~')+'='+quote(v[0],safe='-._~') for k,v in sorted(q.items()))
                expected=base64.b64encode(hmac.new(b'SECRET_SENTINEL&',('GET&%2F&'+quote(canonical,safe='-._~')).encode(),hashlib.sha1).digest()).decode()
                nonce=q.get('SignatureNonce',[''])[0];timestamp=q.get('Timestamp',[''])[0]
                valid=(parsed.path=='/' and unique and hmac.compare_digest(signature,expected) and
                       q.get('AccessKeyId')==['FIXTURE_ID'] and q.get('Version')==['2015-01-09'] and
                       q.get('SignatureMethod')==['HMAC-SHA1'] and q.get('SignatureVersion')==['1.0'] and
                       q.get('Format')==['JSON'] and bool(re.fullmatch('[0-9a-f-]{36}',nonce)) and
                       nonce not in outer.nonces and bool(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',timestamp)))
                action=q.get('Action',[''])[0]
                outer.requests.append({'method':'GET','action':action if action in ('DescribeDomains','DescribeSubDomainRecords',
                    'DescribeDomainRecordInfo','AddDomainRecord','UpdateDomainRecord') else 'unexpected','authenticated':valid})
                if not valid:code,doc=403,{'Code':'SignatureDoesNotMatch','Message':'fixture refusal'}
                else:
                    outer.nonces.add(nonce);code,doc=200,{'RequestId':'fixture'}
                    if action=='DescribeDomains':
                        doc.update(TotalCount=0,PageNumber=int(q['PageNumber'][0]),PageSize=int(q['PageSize'][0]),Domains={'Domain':[]})
                    elif action=='DescribeSubDomainRecords':
                        rows=[dict(row) for row in outer.db.values() if row['DomainName']==q['DomainName'][0] and
                              row['RR']+'.'+row['DomainName']==q['SubDomain'][0] and row['Type']==q['Type'][0]]
                        page,per=int(q['PageNumber'][0]),int(q['PageSize'][0])
                        doc.update(TotalCount=len(rows),PageNumber=page,PageSize=per,DomainRecords={'Record':rows[(page-1)*per:page*per]})
                    elif action=='AddDomainRecord':
                        outer.next_record+=1;identity=str(outer.next_record)
                        outer.db[identity]=record(identity,q['Value'][0],RR=q['RR'][0],Type=q['Type'][0],
                            DomainName=q['DomainName'][0],TTL=int(q['TTL'][0]),Line=q['Line'][0]);doc['RecordId']=identity
                    elif action in ('DescribeDomainRecordInfo','UpdateDomainRecord'):
                        identity=q['RecordId'][0];row=outer.db.get(identity)
                        if row is None:code,doc=400,{'Code':'InvalidRecordId.NotFound','Message':'fixture refusal'}
                        elif action=='DescribeDomainRecordInfo':doc.update(row)
                        else:
                            row.update(RR=q['RR'][0],Type=q['Type'][0],Value=q['Value'][0],TTL=int(q['TTL'][0]),Line=q['Line'][0])
                            doc['RecordId']=identity
                    else:code,doc=400,{'Code':'InvalidAction','Message':'fixture refusal'}
                    if outer.fail_after_mutation and action in ('AddDomainRecord','UpdateDomainRecord'):
                        code,doc=500,{'Code':'InternalError','Message':'fixture response failure after mutation'}
                body=json.dumps(doc).encode();self.send_response(code)
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        return Handler

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.db={};cls.next_record=1000;cls.requests=[];cls.nonces=set();cls.fail_after_mutation=False
        Handler=cls.handler()
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
        super().setUp();self.expected_configuration=self.configuration_snapshot()

    configuration_snapshot=provider.ProviderJobs.configuration_snapshot
    tearDown=provider.ProviderJobs.tearDown
    settled=provider.ProviderJobs.settled

    def authorize(self,session):
        preview=self.post('preview',session,selection=self.RULE)
        self.post('commit',session,confirmation=preview['confirmation'],consent='1')
        self.expected_configuration=self.configuration_snapshot()

    def submit(self,session,job='a'*32,rule=None,expected=200):
        return self.request_job('submit',session,expected=expected,job=job,rule=self.RULE if rule is None else rule,consent='1')

    def run_job(self,session):
        row=provider.ProviderJobs.run_job(self,session)
        self.assertTrue(self.requests and all(r['authenticated'] for r in self.requests),'Independent provider signer rejected the original request')
        return row

    def assert_origin(self,row,status):
        self.assertTrue(row['state']=='finished' and row['last_effect']=='confirmed' and row['result']['status']==status,
                        'Expected a real confirmed provider worker result; inspect redacted evidence')
        path=provider.jobs.JOBS/('a'*32);frame=(path/'proof').read_bytes().splitlines()
        self.assertTrue(len(frame)==3 and frame[0]==b'HGDDNSUIORIGIN1','Original task proof absent')
        self.assertEqual(hashlib.sha256(b'\n'.join(frame[:2])+b'\n').hexdigest().encode(),frame[2])
        account,job,manifest_sha,terminal_sha=frame[1].decode().split(':')
        journal=STORE/'dns-operation';slot=(journal/'current').read_text().strip();manifest=journal/('slot-'+slot)/'manifest'
        self.assertEqual(account,self.ACCOUNT);self.assertTrue(job.isdecimal())
        self.assertEqual(manifest.read_bytes().splitlines()[0],self.JOURNAL_FORMAT)
        self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(),manifest_sha)
        self.assertEqual(hashlib.sha256((journal/'terminal').read_bytes()).hexdigest(),terminal_sha)
        self.assertTrue((journal/'terminal-meta').is_file() and (path/'raw').is_file() and (path/'result').is_file())

    def mutations(self):return [r['action'] for r in self.requests if r['action'] in ('AddDomainRecord','UpdateDomainRecord')]

    def test_aliyun_01_noop_keeps_no_persistent_attempt(self):
        self.db['1']=record(1,'2001:db8::2')
        with self.session() as session:
            row=self.run_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='none' and row['result']['status']=='unchanged')
            self.assertEqual(self.mutations(),[]);self.assertFalse((STORE/'dns-operation').exists())
            self.assertFalse((provider.jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.assertTrue(before==self.snapshot(),'No-op replay changed the original Aliyun task')
            self.assertEqual(self.requests,requests)

    def test_aliyun_02_create_retains_original_aliyun_receipt_and_proof(self):
        with self.session() as session:
            row=self.run_job(session);self.assert_origin(row,'created')
            self.assertEqual(self.mutations(),['AddDomainRecord'])
            self.assertTrue(len(self.db)==1 and next(iter(self.db.values()))['Value']=='2001:db8::2')
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'Confirmed Aliyun receipt barrier changed on replay')
            self.assertEqual(self.requests,requests)

    def test_aliyun_03_update_preserves_line_and_unrelated_fields(self):
        self.db['1']=record(1,Line='cn_mobile',Remark='KEEP',Weight=8)
        self.db['2']=record(2,RR='other')
        with self.session() as session:
            row=self.run_job(session);self.assert_origin(row,'updated')
            self.assertEqual(self.mutations(),['UpdateDomainRecord'])
            row=self.db['1'];self.assertTrue(row['Value']=='2001:db8::2' and row['Line']=='cn_mobile' and row['Remark']=='KEEP' and row['Weight']==8)
            self.assertEqual(self.db['2']['Value'],'2001:db8::1')

    def test_aliyun_04_unknown_after_attempt_never_retries_or_invents_proof(self):
        type(self).fail_after_mutation=True
        with self.session() as session:
            row=self.run_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='unknown' and row['result']['effect']=='unknown')
            self.assertEqual(self.mutations(),['AddDomainRecord']);self.assertEqual(len(self.db),1)
            self.assertTrue((STORE/'dns-operation').is_dir());self.assertFalse((provider.jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'Unknown Aliyun attempt lost its original evidence')
            self.assertEqual(self.requests,requests)


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
        names=[n for n in sorted(AliyunJobs.__dict__) if n.startswith('test_aliyun_') and n.split('_')[2]==args.case]
        if len(names)!=1:raise ValueError('Expected one Aliyun task scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(AliyunJobs(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    curl=subprocess.run([str(provider.CURL),'--version'],capture_output=True,check=True)
    if not curl.stdout.startswith(b'curl 7.83.1 '):raise ValueError('Use pinned curl7.83.1')
    original={p:p.read_bytes() for p in [*read.PROTO.rglob('*'),luci.MODEL,luci.CONTROLLER] if p.is_file()}
    result=0
    for case in ((args.case,) if args.case else CASES):
        result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA),
            extra_mounts=lambda state:((state/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),
                (state/'models',luci.LUA/'prefix/lib/lua/luci/model'),(state/'libexec','/usr/libexec'),
                (state/'tools','/usr/sbin'),(state/'curl-transport','/usr/bin/curl'),(state/'openssl-real','/usr/bin/openssl')),
            extra_rw_mounts=lambda state:((state/'etc/homegate','/etc/homegate'),(state/'etc/config','/etc/config')),
            state_setup=setup_state,guest_args=('--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--case',case))
        if result:break
    if any(p.read_bytes()!=body for p,body in original.items()):raise ValueError('Original business source changed during Aliyun task checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(str(error),file=sys.stderr);sys.exit(2)
