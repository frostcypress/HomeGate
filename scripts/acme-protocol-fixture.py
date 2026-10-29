#!/usr/bin/python3
"""Private curl boundary: RFC8555 JWS/CSR fixture, never a public CA.

Runs only inside the existing unprivileged native LuCI namespace. It verifies
real account signatures and signs the client's real CSR with a private CA.
"""
import base64,hashlib,json,re,subprocess,sys,time
from pathlib import Path
from urllib.parse import urlsplit,parse_qs

ROOT=Path('/teststate');DB=ROOT/'acme-fixture.json'
def b64(v):return base64.urlsafe_b64encode(v).decode().rstrip('=')
def un64(v):return base64.urlsafe_b64decode(v+'='*((-len(v))%4))
def run(*args,input=None):
    p=subprocess.run(['openssl',*args],input=input,capture_output=True,timeout=10)
    assert p.returncode==0,(args,p.stderr[-600:]);return p.stdout
def derint(v):
    v=v.lstrip(b'\0') or b'\0'
    if v[0]&128:v=b'\0'+v
    return b'\x02'+bytes([len(v)])+v
def save():DB.write_text(json.dumps(db))
def output(body,status=200,location=None,pem=False):
    if ca:
        db['nonce']+=1;nonce='fixture-nonce-'+str(db['nonce']);db['nonces'].append(nonce)
        headers='HTTP/1.1 '+str(status)+' OK\r\nReplay-Nonce: '+nonce+'\r\nContent-Type: '+('application/pem-certificate-chain' if pem else 'application/json')+'\r\n'
        if location:headers+='Location: '+location+'\r\n'
        Path(config['dump-header'][0]).write_bytes((headers+'\r\n').encode())
        save()
        if method!='HEAD':sys.stdout.write(body if isinstance(body,str) else json.dumps(body,separators=(',',':')))
    else:
        save();print(json.dumps(body,separators=(',',':')));print('HGHTTP:'+str(status))
    sys.exit(0)

raw=Path(sys.argv[sys.argv.index('--config')+1]).read_text();config={}
for line in raw.splitlines():
    m=re.match(r'([a-z-]+)\s*=\s*(.*)$',line)
    if m:
        v=m[2];config.setdefault(m[1],[]).append(json.loads(v) if v.startswith('"') else v)
url=config.get('url',[None])[0] or sys.argv[sys.argv.index('--url')+1]
method=config.get('request',['GET'])[0];parts=urlsplit(url);ca=parts.hostname in ['acme-staging-v02.api.letsencrypt.org','acme-v02.api.letsencrypt.org']
db=json.loads(DB.read_text()) if DB.exists() else {'nonce':0,'nonces':[],'accounts':{},'orders':{},'records':[],'events':[]}
db['events'].append({'host':parts.hostname,'path':parts.path,'method':method})
mode=(ROOT/'acme-mode').read_text() if (ROOT/'acme-mode').exists() else 'success'
if not ca:
    def data_body():
        v=config.get('data-binary',config.get('data',['{}']))[0]
        return json.loads(Path(v[1:]).read_text() if v.startswith('@') else v)
    def record_value(v):return {'RecordId':str(int(v['id'],16)),'DomainName':'example.test','RR':v['name'].removesuffix('.example.test'),'Type':v['type'],'Value':v['content'],'TTL':v['ttl'],'Line':'default','Locked':False,'Status':'Enable'}
    def dnp_value(v,detail=False):
        d={'RecordId':int(v['id'],16),'Name':v['name'].removesuffix('.example.test'),'Type':v['type'],'Value':v['content'],'TTL':v['ttl'],'Line':'default','LineId':'0','Status':'ENABLE','Weight':None,'Remark':''}
        if detail:d={**d,'Id':d.pop('RecordId'),'SubDomain':d.pop('Name'),'RecordType':d.pop('Type'),'RecordLine':d.pop('Line'),'RecordLineId':d.pop('LineId'),'Enabled':1}
        return d
    if parts.hostname=='alidns.aliyuncs.com':
        q={k:v[0] for k,v in parse_qs(parts.query).items()};action=q['Action'];assert q.get('Signature')
        rows=db['records'];rid=format(int(q.get('RecordId','0')),'032x')
        if action=='DescribeSubDomainRecords':output({'RequestId':'fixture','DomainRecords':{'Record':[record_value(v) for v in rows]},'TotalCount':len(rows),'PageSize':100,'PageNumber':1})
        if action=='AddDomainRecord':
            rid=format(len(rows)+100,'032x');rows.append({'id':rid,'type':q['Type'],'name':q['RR']+'.example.test','content':q['Value'],'ttl':int(q['TTL'])});output({'RequestId':'fixture','RecordId':str(int(rid,16))})
        if action=='DescribeDomainRecordInfo':
            v=next((v for v in rows if v['id']==rid),None)
            if not v:output({'RequestId':'fixture','Code':'InvalidRecordId.NotFound'},400)
            output({'RequestId':'fixture',**record_value(v)})
        if action=='DeleteDomainRecord':db['records']=[v for v in rows if v['id']!=rid];output({'RequestId':'fixture','RecordId':str(int(rid,16))})
        raise AssertionError(action)
    if parts.hostname=='dnspod.tencentcloudapi.com':
        headers=config['header'];action=next(v.split(': ',1)[1] for v in headers if v.startswith('X-TC-Action: '));assert any(v.startswith('Authorization: TC3-HMAC-SHA256') for v in headers)
        q=data_body();rows=db['records'];rid=format(q.get('RecordId',0),'032x')
        def dnp(body):output({'Response':{'RequestId':'fixture',**body}})
        if action=='DescribeRecordList':dnp({'RecordList':[dnp_value(v) for v in rows],'RecordCountInfo':{'TotalCount':len(rows)}})
        if action=='CreateRecord':
            rid=format(len(rows)+100,'032x');rows.append({'id':rid,'type':q['RecordType'],'name':q['SubDomain']+'.example.test','content':q['Value'],'ttl':q['TTL']});dnp({'RecordId':int(rid,16)})
        if action=='DescribeRecord':
            v=next((v for v in rows if v['id']==rid),None)
            if not v:dnp({'Error':{'Code':'ResourceNotFound.NoDataOfRecord','Message':'missing'}})
            dnp({'RecordInfo':dnp_value(v,True)})
        if action=='DeleteRecord':db['records']=[v for v in rows if v['id']!=rid];dnp({})
        raise AssertionError(action)
    if parts.hostname=='dns.cn-north-4.myhuaweicloud.com':
        assert any(v.startswith('Authorization: SDK-HMAC-SHA256') for v in config['header'])
        rows=db.setdefault('hw',[]);rid=parts.path.rsplit('/',1)[-1]
        if parts.path=='/v2/zones':output({'zones':[{'id':'zone_1','name':'example.test.','zone_type':'public','status':'ACTIVE'}],'metadata':{'total_count':1}})
        def hw_sync():db['records']=[{'id':v['id'],'type':v['type'],'name':v['name'].rstrip('.'),'content':json.loads(c),'ttl':v['ttl']} for v in rows for c in v['records']]
        if method=='GET':
            if rid=='recordsets':output({'recordsets':rows,'metadata':{'total_count':len(rows)}})
            output(next(v for v in rows if v['id']==rid))
        if method=='POST':
            d={**data_body(),'id':str(len(rows)+100),'zone_id':'zone_1','status':'ACTIVE','default':False};rows.append(d);hw_sync();output(d,202)
        d=next(v for v in rows if v['id']==rid)
        if method=='PUT':d.update(data_body());hw_sync();output(d,202)
        if method=='DELETE':rows.remove(d);hw_sync();output({**d,'status':'PENDING_DELETE'},202)
        raise AssertionError(method)
    assert parts.hostname=='api.cloudflare.com',url
    body={}
    if config.get('data-binary'):
        v=config['data-binary'][0];body=json.loads(Path(v[1:]).read_text() if v.startswith('@') else v)
    if '/dns_records' not in parts.path:
        output({'success':True,'result':[{'id':'1'*32,'name':'example.test','status':'active'}],'result_info':{'page':1,'total_pages':1,'per_page':int(parse_qs(parts.query).get('per_page',['50'])[0]),'total_count':1}})
    key=parts.path.rsplit('/',1)[-1]
    if method=='POST':
        rec={**body,'id':format(len(db['records'])+100,'032x')};db['records'].append(rec)
        if mode=='dns-unknown':output({'success':False,'errors':[{'code':1000}]},500)
        output({'success':True,'result':rec})
    if method=='DELETE':
        db['records']=[v for v in db['records'] if v['id']!=key]
        output({'success':True,'result':{'id':key}})
    rows=[v for v in db['records'] if key=='dns_records' or v['id']==key]
    q=parse_qs(parts.query)
    for field in ['type','name','content']:
        if field in q:rows=[v for v in rows if v.get(field)==q[field][0]]
    if key!='dns_records':
        if not rows:output({'success':False,'errors':[{'code':81044}]},404)
        output({'success':True,'result':rows[0]})
    size=int(q.get('per_page',['5'])[0]);output({'success':True,'result':rows,'result_info':{'page':1,'total_pages':1,'per_page':size,'total_count':len(rows)}})

base='https://'+parts.hostname
if parts.path=='/directory' and mode=='hold-directory':
    save();(ROOT/'acme-entered').touch();time.sleep(30)
if parts.path=='/directory':output({k:base+v for k,v in {'newNonce':'/nonce','newAccount':'/account','newOrder':'/new-order','revokeCert':'/revoke','keyChange':'/key-change'}.items()})
if method=='HEAD' and parts.path=='/nonce':output({})
assert method=='POST',(method,url)
jws=json.loads(Path(config['data-binary'][0][1:]).read_text());protected=json.loads(un64(jws['protected']))
assert protected['url']==url and protected['alg']=='ES256'
assert protected['nonce'] in db['nonces'];db['nonces'].remove(protected['nonce'])
jwk=protected.get('jwk') or db['accounts'][protected['kid']]
assert jwk['kty']=='EC' and jwk['crv']=='P-256'
pub=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004')+un64(jwk['x'])+un64(jwk['y'])
(ROOT/'jws-public.der').write_bytes(pub);run('pkey','-pubin','-inform','DER','-in',str(ROOT/'jws-public.der'),'-out',str(ROOT/'jws-public.pem'))
sig=un64(jws['signature']);assert len(sig)==64
ints=derint(sig[:32])+derint(sig[32:]);(ROOT/'jws-signature.der').write_bytes(b'\x30'+bytes([len(ints)])+ints)
run('dgst','-sha256','-verify',str(ROOT/'jws-public.pem'),'-signature',str(ROOT/'jws-signature.der'),input=(jws['protected']+'.'+jws['payload']).encode())
db['verified_jws']=db.get('verified_jws',0)+1
payload=json.loads(un64(jws['payload'])) if jws['payload'] else None
if parts.path=='/account':
    kid=base+'/account/1';old=db['accounts'].get(kid);assert not old or old==jwk
    db['accounts'][kid]=jwk;output({'status':'valid','orders':base+'/orders'},201,kid)
if parts.path=='/new-order':
    oid=str(len(db['orders'])+1);ids=payload['identifiers'];db['orders'][oid]={'ids':ids,'valid':[],'jwk':jwk}
    if mode=='preexisting':
        thumb=b64(hashlib.sha256(json.dumps({k:jwk[k] for k in ['crv','kty','x','y']},sort_keys=True,separators=(',',':')).encode()).digest())
        db['records'].append({'id':'a'*32,'type':'TXT','name':'_acme-challenge.example.test','content':'UNRELATED_KEEP','ttl':120})
        for i,ident in enumerate(ids):
            token=b64(hashlib.sha256((oid+':'+str(i)).encode()).digest());value=b64(hashlib.sha256((token+'.'+thumb).encode()).digest())
            db['records'].append({'id':format(i+200,'032x'),'type':'TXT','name':'_acme-challenge.'+ident['value'].removeprefix('*.'),'content':value,'ttl':120})
    output({'status':'pending','identifiers':ids,'authorizations':[base+'/authz/'+oid+'/'+str(i) for i in range(len(ids))],'finalize':base+'/finalize/'+oid},201,base+'/order/'+oid)
path=parts.path.strip('/').split('/');kind,oid=path[:2];order=db['orders'][oid]
if kind in ['authz','challenge']:
    i=int(path[2]);domain=order['ids'][i]['value'];token=b64(hashlib.sha256((oid+':'+str(i)).encode()).digest())
    if kind=='challenge':
        if mode=='hold-challenge':
            (ROOT/'acme-entered').touch();time.sleep(30)
        thumb=b64(hashlib.sha256(json.dumps({k:jwk[k] for k in ['crv','kty','x','y']},sort_keys=True,separators=(',',':')).encode()).digest())
        value=b64(hashlib.sha256((token+'.'+thumb).encode()).digest());name='_acme-challenge.'+domain.removeprefix('*.')
        assert any(v['type']=='TXT' and v['name']==name and v['content']==value for v in db['records']), 'Challenge TXT missing'
        if mode=='ca-reject':output({'type':'urn:ietf:params:acme:error:unauthorized','detail':'private fixture rejection'},400)
        if i not in order['valid']:order['valid'].append(i)
        output({'status':'valid'})
    auth={'status':'valid' if i in order['valid'] else 'pending','identifier':{'type':'dns','value':domain.removeprefix('*.')},'challenges':[{'type':'dns-01','url':base+'/challenge/'+oid+'/'+str(i),'token':token,'status':'valid' if i in order['valid'] else 'pending'}]}
    if domain.startswith('*.'):auth['wildcard']=True
    output(auth)
if kind=='finalize':
    assert len(order['valid'])==len(order['ids'])
    csr=ROOT/'acme-request.der';csr.write_bytes(un64(payload['csr']));run('req','-inform','DER','-in',str(csr),'-verify','-noout')
    cert=run('x509','-req','-inform','DER','-in',str(csr),'-CA',str(ROOT/'fixture-ca.pem'),'-CAkey',str(ROOT/'fixture-ca.key'),'-set_serial',oid,'-days','1' if mode=='short-cert' else '90','-copy_extensions','copy')
    order['certificate']=cert.decode();output({'status':'valid','certificate':base+'/certificate/'+oid})
if kind=='order':output({'status':'valid' if order.get('certificate') else 'ready','finalize':base+'/finalize/'+oid,'certificate':base+'/certificate/'+oid})
if kind=='certificate':output(order['certificate']+(ROOT/'fixture-ca.pem').read_text(),pem=True)
raise AssertionError(url)
