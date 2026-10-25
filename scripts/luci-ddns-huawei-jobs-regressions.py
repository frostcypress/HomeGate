#!/usr/bin/env python3
"""Real Huawei tasks, independent SDK-HMAC signatures and original receipts."""
import argparse
import hashlib
import hmac
import http.server
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
from urllib.parse import parse_qs,urlsplit
from project import ROOT

spec=importlib.util.spec_from_file_location('huawei_signed_tasks',ROOT/'scripts/luci-ddns-aliyun-jobs-regressions.py')
signed=importlib.util.module_from_spec(spec);spec.loader.exec_module(signed)
read,luci,rpc=signed.read,signed.luci,signed.rpc
STORE,RUN,STATE=signed.STORE,signed.RUN,signed.STATE
HOST='dns.cn-north-4.myhuaweicloud.com'
DOMAIN='1'*32
CASES=('01','02','03','04')


def setup_state(state):
    signed.setup_state(state,'huaweicloud')
    source=state/'etc/config/homegate';body=source.read_text()
    original="config dns_account 'dns_3'\n option provider 'huaweicloud'\n option id 'FIXTURE_ID'\n option secret 'SECRET_SENTINEL'\n option account_id 'PRIVATE_ACCOUNT'\n"
    if body.count(original)!=1:raise ValueError('Expected one private Huawei source account')
    updated=original.replace('PRIVATE_ACCOUNT',DOMAIN)+" option endpoint 'https://"+HOST+"'\n"
    source.write_text(body.replace(original,updated))


def authorization(method,path,query,date,payload):
    names='content-type;host;x-domain-id;x-sdk-date'
    headers='content-type:application/json\nhost:'+HOST+'\nx-domain-id:'+DOMAIN+'\nx-sdk-date:'+date+'\n'
    canonical=(method+'\n'+path.rstrip('/')+'/\n'+query+'\n'+headers+'\n'+names+'\n'+hashlib.sha256(payload).hexdigest()).encode()
    text=b'SDK-HMAC-SHA256\n'+date.encode()+b'\n'+hashlib.sha256(canonical).hexdigest().encode()
    signature=hmac.new(b'SECRET_SENTINEL',text,hashlib.sha256).hexdigest()
    return 'SDK-HMAC-SHA256 Access=FIXTURE_ID, SignedHeaders='+names+', Signature='+signature


def record(identity,values=None,**extra):
    return {'id':str(identity),'zone_id':'zone_1','name':'www.example.test.','type':'AAAA','ttl':600,
            'description':'','status':'ACTIVE','default':False,'records':values or ['2001:db8::1'],**extra}


class HuaweiJobs(signed.AliyunJobs):
    RULE='ddns_3'
    ACCOUNT='dns_3'
    JOURNAL_FORMAT=b'HGHWJOURNAL1'

    @classmethod
    def handler(cls):
        outer=cls
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self,method):
                size=int(self.headers.get('Content-Length','0'))
                if not 0<=size<=32768:raise ValueError('Invalid Huawei fixture payload bound')
                raw=self.rfile.read(size) if size else b'';parsed=urlsplit(self.path)
                query=parse_qs(parsed.query,keep_blank_values=True);date=self.headers.get('X-Sdk-Date','')
                expected=authorization(method,parsed.path,parsed.query,date,raw)
                valid=(hmac.compare_digest(self.headers.get('Authorization',''),expected) and self.headers.get('Host')==HOST and
                       self.headers.get('X-Domain-ID')==DOMAIN and self.headers.get('Content-Type')=='application/json' and
                       bool(re.fullmatch(r'\d{8}T\d{6}Z',date)) and all(len(v)==1 for v in query.values()))
                prefix='/v2/zones/zone_1/recordsets'
                kind='zones' if parsed.path=='/v2/zones' else 'records' if parsed.path==prefix else 'detail' if parsed.path.startswith(prefix+'/') else 'unexpected'
                outer.requests.append({'method':method,'action':kind,'authenticated':valid})
                if not valid:code,doc=403,{'code':'bad-signature','message':'fixture refusal'}
                elif parsed.path=='/v2/zones' and method=='GET':
                    code,doc=200,{'zones':[{'id':'zone_1','name':'example.test.','zone_type':'public','status':'ACTIVE'}],'metadata':{'total_count':1}}
                elif parsed.path==prefix and method=='GET':
                    if set(query)!={'limit','offset'}:raise ValueError('Unexpected Huawei list fields')
                    rows=list(outer.db.values());start=int(query['offset'][0])
                    code,doc=200,{'recordsets':rows[start:start+int(query['limit'][0])],'metadata':{'total_count':len(rows)}}
                elif parsed.path==prefix and method=='POST':
                    data=json.loads(raw);outer.next_record+=1;row=record(outer.next_record,data['records'],
                        name=data['name'],type=data['type'],ttl=data['ttl'],description=data['description'])
                    outer.db[row['id']]=row;code,doc=202,{**row,'status':'PENDING_CREATE'}
                elif parsed.path.startswith(prefix+'/') and method in ('GET','PUT'):
                    identity=parsed.path[len(prefix)+1:];row=outer.db.get(identity)
                    if row is None:code,doc=404,{'code':'not-found'}
                    elif method=='GET':code,doc=200,dict(row)
                    else:row.update(json.loads(raw));code,doc=202,{**row,'status':'PENDING_UPDATE'}
                else:code,doc=400,{'code':'unexpected-operation'}
                if valid and outer.fail_after_mutation and method in ('POST','PUT'):
                    code,doc=500,{'code':'internal-error','message':'fixture response failure after mutation'}
                body=json.dumps(doc).encode();self.send_response(code)
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_GET(self):self.reply('GET')
            def do_POST(self):self.reply('POST')
            def do_PUT(self):self.reply('PUT')
        return Handler

    def run_job(self,session):
        row=super().run_job(session);raw=json.dumps(row).encode()
        self.assertTrue(all(value not in raw for value in (DOMAIN.encode(),HOST.encode(),b'FIXTURE_ID',b'SECRET_SENTINEL')),
                        'Private Huawei configuration escaped; body suppressed')
        return row

    def mutations(self):return [row['method'] for row in self.requests if row['method'] in ('POST','PUT')]

    def test_huawei_01_noop_keeps_no_persistent_attempt(self):
        self.db['1']=record(1,['2001:db8::2'])
        with self.session() as session:
            row=self.run_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='none' and row['result']['status']=='unchanged')
            self.assertEqual(self.mutations(),[]);self.assertFalse((STORE/'dns-operation').exists())
            self.assertFalse((signed.provider.jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.assertTrue(before==self.snapshot(),'Huawei no-op replay changed the original task')
            self.assertEqual(self.requests,requests)

    def test_huawei_02_create_retains_original_huawei_receipt_and_proof(self):
        with self.session() as session:
            row=self.run_job(session);self.assert_origin(row,'created')
            self.assertEqual(self.mutations(),['POST'])
            self.assertTrue(len(self.db)==1 and next(iter(self.db.values()))['records']==['2001:db8::2'])
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'Huawei confirmed receipt barrier changed on replay')
            self.assertEqual(self.requests,requests)

    def test_huawei_03_update_preserves_description_and_other_recordset(self):
        self.db['1']=record(1,description='KEEP')
        self.db['2']=record(2,['2001:db8::8'],name='other.example.test.')
        with self.session() as session:
            row=self.run_job(session);self.assert_origin(row,'updated')
            self.assertEqual(self.mutations(),['PUT'])
            self.assertTrue(self.db['1']['records']==['2001:db8::2'] and self.db['1']['description']=='KEEP')
            self.assertEqual(self.db['2']['records'],['2001:db8::8'])

    def test_huawei_04_unknown_after_attempt_never_retries_or_invents_proof(self):
        type(self).fail_after_mutation=True
        with self.session() as session:
            row=self.run_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='unknown' and row['result']['effect']=='unknown')
            self.assertEqual(self.mutations(),['POST']);self.assertEqual(len(self.db),1)
            self.assertTrue((STORE/'dns-operation').is_dir());self.assertFalse((signed.provider.jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'Huawei unknown attempt lost original evidence')
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
        names=[n for n in sorted(HuaweiJobs.__dict__) if n.startswith('test_huawei_') and n.split('_')[2]==args.case]
        if len(names)!=1:raise ValueError('Expected one Huawei task scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(HuaweiJobs(n) for n in names)).wasSuccessful() else 1
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    curl=subprocess.run([str(signed.provider.CURL),'--version'],capture_output=True,check=True)
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
    if any(p.read_bytes()!=body for p,body in original.items()):raise ValueError('Original source changed during Huawei task checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(str(error),file=sys.stderr);sys.exit(2)
