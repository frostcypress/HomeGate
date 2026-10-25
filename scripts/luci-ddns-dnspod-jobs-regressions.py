#!/usr/bin/env python3
"""Real DNSPod tasks, independent TC3 validation and original durable receipts."""
import argparse
import datetime
import hashlib
import hmac
import http.server
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from project import ROOT

spec=importlib.util.spec_from_file_location('dnspod_signed_tasks',ROOT/'scripts/luci-ddns-aliyun-jobs-regressions.py')
signed=importlib.util.module_from_spec(spec);spec.loader.exec_module(signed)
read,luci,rpc=signed.read,signed.luci,signed.rpc
STORE,RUN,STATE=signed.STORE,signed.RUN,signed.STATE
CASES=('01','02','03','04')


def setup_state(state):signed.setup_state(state,'dnspod')


def authorization(payload,timestamp):
    date=datetime.datetime.fromtimestamp(timestamp,datetime.timezone.utc).strftime('%Y-%m-%d')
    scope=date+'/dnspod/tc3_request'
    canonical=b'POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:dnspod.tencentcloudapi.com\n\ncontent-type;host\n'+hashlib.sha256(payload).hexdigest().encode()
    text=b'TC3-HMAC-SHA256\n'+str(timestamp).encode()+b'\n'+scope.encode()+b'\n'+hashlib.sha256(canonical).hexdigest().encode()
    def mac(key,value):return hmac.new(key,value,hashlib.sha256).digest()
    signature=mac(mac(mac(mac(b'TC3SECRET_SENTINEL',date.encode()),b'dnspod'),b'tc3_request'),text).hex()
    return 'TC3-HMAC-SHA256 Credential=FIXTURE_ID/'+scope+', SignedHeaders=content-type;host, Signature='+signature


def record(identity,value='2001:db8::1',**extra):
    return {'RecordId':identity,'Name':'www','Type':'AAAA','Value':value,'TTL':600,
            'Line':'默认','LineId':'0','Status':'ENABLE','Weight':None,'Remark':'',**extra}


class DNSPodJobs(signed.AliyunJobs):
    RULE='ddns_2'
    ACCOUNT='dns_2'
    JOURNAL_FORMAT=b'HGDNPJOURNAL1'

    @classmethod
    def handler(cls):
        outer=cls
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=32768:raise ValueError('Invalid DNSPod fixture payload bound')
                raw=self.rfile.read(size);action=self.headers.get('X-TC-Action','')
                try:
                    payload=json.loads(raw);expected=authorization(raw,int(self.headers.get('X-TC-Timestamp','')))
                except (ValueError,OverflowError,OSError):payload=None;expected='invalid'
                valid=(self.path=='/' and isinstance(payload,dict) and
                       hmac.compare_digest(self.headers.get('Authorization',''),expected) and
                       self.headers.get('Host')=='dnspod.tencentcloudapi.com' and
                       self.headers.get('X-TC-Version')=='2021-03-23' and
                       self.headers.get('Content-Type')=='application/json; charset=utf-8')
                known=('DescribeDomainList','DescribeRecordList','CreateRecord','ModifyRecord','DescribeRecord')
                outer.requests.append({'method':'POST','action':action if action in known else 'unexpected','authenticated':valid})
                if not valid:code,doc=403,{'Response':{'Error':{'Code':'AuthFailure.SignatureFailure','Message':'fixture refusal'}}}
                else:
                    code,response=200,{'RequestId':'fixture'};q=payload
                    if action=='DescribeDomainList':response.update(DomainCountInfo={'DomainTotal':0},DomainList=[])
                    elif q.get('Domain')!='example.test' or 'DomainId' in q:
                        code,response=400,{'Error':{'Code':'InvalidParameter','Message':'fixture scope refusal'}}
                    elif action=='DescribeRecordList':
                        if set(q)!={'Domain','Offset','Limit','ErrorOnEmpty'}:raise ValueError('Unexpected DNSPod list fields')
                        rows=list(outer.db.values());response.update(RecordCountInfo={'TotalCount':len(rows)},RecordList=rows[q['Offset']:q['Offset']+q['Limit']])
                    elif action=='CreateRecord':
                        outer.next_record+=1;identity=outer.next_record
                        outer.db[identity]=record(identity,q['Value'],Name=q['SubDomain'],Type=q['RecordType'],
                            TTL=q['TTL'],Line=q['RecordLine'],LineId=q['RecordLineId']);response['RecordId']=identity
                    elif action in ('DescribeRecord','ModifyRecord'):
                        identity=q['RecordId'];row=outer.db.get(identity)
                        if row is None:code,response=400,{'Error':{'Code':'InvalidParameter.RecordIdInvalid','Message':'fixture refusal'}}
                        elif action=='DescribeRecord':
                            response['RecordInfo']={'Id':identity,'SubDomain':row['Name'],'RecordType':row['Type'],'Value':row['Value'],
                                'TTL':row['TTL'],'RecordLine':row['Line'],'RecordLineId':row['LineId'],
                                'Enabled':1 if row['Status']=='ENABLE' else 0,'Weight':row['Weight'],'Remark':row['Remark']}
                        else:row.update(Name=q['SubDomain'],Type=q['RecordType'],Value=q['Value'],TTL=q['TTL'],
                            Line=q['RecordLine'],LineId=q['RecordLineId'],Weight=q.get('Weight'),Remark=q['Remark'])
                    else:code,response=400,{'Error':{'Code':'InvalidAction','Message':'fixture refusal'}}
                    if outer.fail_after_mutation and action in ('CreateRecord','ModifyRecord'):
                        code,response=500,{'Error':{'Code':'InternalError','Message':'fixture response failure after mutation'}}
                    doc={'Response':response}
                body=json.dumps(doc).encode();self.send_response(code)
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        return Handler

    def mutations(self):return [row['action'] for row in self.requests if row['action'] in ('CreateRecord','ModifyRecord')]

    def test_dnspod_01_noop_keeps_no_persistent_attempt(self):
        self.db[1]=record(1,'2001:db8::2')
        with self.session() as session:
            row=self.run_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='none' and row['result']['status']=='unchanged')
            self.assertEqual(self.mutations(),[]);self.assertFalse((STORE/'dns-operation').exists())
            self.assertFalse((signed.provider.jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.assertTrue(before==self.snapshot(),'DNSPod no-op replay changed original task')
            self.assertEqual(self.requests,requests)

    def test_dnspod_02_create_retains_original_dnspod_receipt_and_proof(self):
        with self.session() as session:
            row=self.run_job(session);self.assert_origin(row,'created')
            self.assertEqual(self.mutations(),['CreateRecord'])
            self.assertTrue(len(self.db)==1 and next(iter(self.db.values()))['Value']=='2001:db8::2')
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'DNSPod confirmed receipt barrier changed on replay')
            self.assertEqual(self.requests,requests)

    def test_dnspod_03_update_preserves_line_weight_remark_and_other_record(self):
        self.db[1]=record(1,Line='移动',LineId='10=3',Weight=8,Remark='KEEP')
        self.db[2]=record(2,Name='other')
        with self.session() as session:
            row=self.run_job(session);self.assert_origin(row,'updated')
            self.assertEqual(self.mutations(),['ModifyRecord']);row=self.db[1]
            self.assertTrue(row['Value']=='2001:db8::2' and row['Line']=='移动' and row['LineId']=='10=3' and row['Weight']==8 and row['Remark']=='KEEP')
            self.assertEqual(self.db[2]['Value'],'2001:db8::1')

    def test_dnspod_04_unknown_after_attempt_never_retries_or_invents_proof(self):
        type(self).fail_after_mutation=True
        with self.session() as session:
            row=self.run_job(session)
            self.assertTrue(row['state']=='finished' and row['last_effect']=='unknown' and row['result']['effect']=='unknown')
            self.assertEqual(self.mutations(),['CreateRecord']);self.assertEqual(len(self.db),1)
            self.assertTrue((STORE/'dns-operation').is_dir());self.assertFalse((signed.provider.jobs.JOBS/('a'*32)/'proof').exists())
            before=self.snapshot();requests=list(self.requests);self.assertEqual(self.submit(session),row)
            self.submit(session,job='b'*32,expected=503)
            self.assertTrue(before==self.snapshot(),'DNSPod unknown attempt lost original evidence')
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
        names=[n for n in sorted(DNSPodJobs.__dict__) if n.startswith('test_dnspod_') and n.split('_')[2]==args.case]
        if len(names)!=1:raise ValueError('Expected one DNSPod task scenario')
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(DNSPodJobs(n) for n in names)).wasSuccessful() else 1
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
    if any(p.read_bytes()!=body for p,body in original.items()):raise ValueError('Original source changed during DNSPod task checks')
    luci.runtime.validate_runtime(luci.LUA,rpc.WORK);luci.http.runtime.validate_runtime(luci.HTTP,rpc.WORK)
    return result


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(str(error),file=sys.stderr);sys.exit(2)
