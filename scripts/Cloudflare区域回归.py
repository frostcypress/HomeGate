#!/usr/bin/env python3
"""Complete bounded zone discovery over loopback TLS; no live Cloudflare account."""
import argparse,json,os,shlex,signal,subprocess,sys,time,unittest,urllib.parse
from pathlib import Path
from project import ROOT
from Cloudflare只读回归 import Static as ReadStatic,Runtime as ReadRuntime,PROTO

class Static(ReadStatic):
    def test_fixed_zone_mode_and_existing_supervisor(self):
        self.test_shell_grammar_and_closed_fixed_modes()
        self.test_fixed_tls_curl_and_no_arbitrary_command()
        for name in ['cloudflare-codec.lua','cloudflare-zones.lua']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.lua.compile(body)
        self.assertIn('"$2" = --zones',(PROTO/'homegate-cloudflare-read.sh').read_text())
        self.assertIn('while [ "$page" -le 1000 ]',(PROTO/'homegate-cloudflare-worker.sh').read_text())
        self.assertNotIn('os.execute',(PROTO/'cloudflare-zones.lua').read_text())
        # Execute the real Lua data adapter; pre-parsed HTTP is explicit here.
        # Native JSON/TLS parsing is exercised separately by the Linux suite.
        self.lua.globals().fixture_doc=self.lua.table_from({b'success':True,b'result':self.lua.table_from([]),b'result_info':self.lua.table_from({b'page':1,b'per_page':50,b'count':0,b'total_pages':0,b'total_count':0})})
        self.lua.globals().arg=self.lua.table_from({0:b'/fixture/cloudflare-zones.lua',1:b'page',2:b'dns_a',3:b'3',4:b'1'})
        self.lua.execute(b"require=function()return {}end;loadfile=function(p) assert(p=='/fixture/cloudflare-codec.lua');return function()return {envelope=function()return fixture_doc,{result='array',result_info='object'}end}end end;os.exit=function(n)error('__EXIT__'..n)end;state='';zones='';public='';output='';io.stdin={read=function()return ''end};io.write=function(v)output=output..v end;io.open=function(p,m)local fd=p:match('/proc/self/fd/(%d)');assert(fd);return {read=function(self,n)local s=fd=='5' and state or zones;return #s>0 and s:sub(1,n) or nil end,write=function(self,v)if fd=='5' then state=v elseif fd=='4' then zones=zones..v else public=public..v end;return true end,close=function()return true end}end")
        self.lua.execute((PROTO/'cloudflare-zones.lua').read_bytes());self.assertEqual(self.lua.globals().output,b'HGDNSDONE1\n')
        self.assertEqual(self.lua.globals().state,b'HGCFLIST1:2:0:0:0\n')
        self.lua.globals().arg[1]=b'finish';self.lua.globals().arg[4]=None
        self.lua.execute((PROTO/'cloudflare-zones.lua').read_bytes());self.assertEqual(json.loads(self.lua.globals().public)['zones'],[])

    def test_zone_requests_use_same_private_account_and_fixed_fifty(self):
        ok,public,request=self.request(mode=b'zones')
        self.assertTrue(ok);self.assertEqual(public,b'HGDNSREADY1\n')
        self.assertNotIn(b'url =',request);self.assertIn(b'Bearer PRIVATE_SENTINEL',request)
        self.assertIn('zones?page=$page&per_page=50',(PROTO/'homegate-cloudflare-worker.sh').read_text())
        self.setUp();ok,public,request=self.request(mode=b'zones',account=b'missing')
        self.assertFalse(ok);self.assertEqual(request,b'');doc=json.loads(public)
        self.assertEqual(doc['check_scope'],'zone-list');self.assertEqual(doc['zones'],[])

    def test_invalid_zone_credentials_do_not_enter_request_or_public_report(self):
        for token in [None,b'PRIVATE_SENTINEL\x00',b'PRIVATE_SENTINEL\n',b' '*4]:
            self.setUp();ok,public,request=self.request(mode=b'zones',token=token)
            self.assertFalse(ok);self.assertEqual(request,b'');self.assertNotIn(b'PRIVATE_SENTINEL',public)
            self.assertEqual(json.loads(public)['zones'],[])

def zone(i,name=None):return {'id':format(i,'032x'),'name':name or ('z%03d.example.test'%i),'account':{'name':'PRIVATE_METADATA'}}
def page(items,n,total,count):return {'success':True,'errors':[],'result':items,'result_info':{'page':n,'per_page':50,'count':len(items),'total_pages':total,'total_count':count}}

class Runtime(ReadRuntime):
    def setUp(self):
        super().setUp()
        prefix=self.endpoint.split('?')[0]+'?'
        for name in ['cloudflare-codec.lua','homegate-cloudflare-worker.sh']:
            p=self.engine.parent/name;p.write_text(p.read_text().replace('https://api.cloudflare.com/client/v4/zones?',prefix))
        p=self.engine.parent/'cloudflare-zones.lua'
        p.write_text(p.read_text().replace("local json=require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json=require('luci.jsonc')"))
        self.response=page([],1,0,0)

    def zones(self,expected=0,account='dns_a',env=None):
        p=subprocess.run([self.busybox,'ash',str(self.reader),account,'--zones'],env=env or self.env,capture_output=True,timeout=12)
        diag=self.diagnostic.read_text()[:128] if self.diagnostic.exists() else ''
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr,diag));self.assertEqual(p.stderr,b'')
        self.assertNotIn(b'PRIVATE_SENTINEL',p.stdout);self.assertNotIn(b'PRIVATE_METADATA',p.stdout)
        r=json.loads(p.stdout);self.assertEqual(r['ok'],expected==0)
        if expected in [0,1]:self.assertEqual(r['check_scope'],'zone-list');self.assertEqual(r['configuration_revision'],3)
        if expected==1:self.assertEqual(r['zones'],[])
        return r

    def pages(self,pages):
        def respond(path):
            query=urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            self.assertEqual(query['per_page'],['50']);n=int(query['page'][0]);self.assertLessEqual(n,len(pages))
            return pages[n-1]
        self.response=respond

    def test_complete_pages_normalize_deduplicate_sort_and_discard_metadata(self):
        self.pages([(200,page([zone(1,' Z.TEST. '),zone(2,'a.test')],1,2,4)),(200,page([zone(3,'z.test'),zone(4,'b.test')],2,2,4))])
        self.assertEqual(self.zones()['zones'],['a.test','b.test','z.test'])
        self.assertEqual([x['path'] for x in self.calls],['/client/v4/zones?page=1&per_page=50','/client/v4/zones?page=2&per_page=50'])
        self.assertTrue(all(x['authorization']=='Bearer PRIVATE_SENTINEL' for x in self.calls));self.unchanged()

    def test_fifty_entry_page_without_optional_metadata_continues_to_empty_page(self):
        self.pages([(200,{'success':True,'result':[zone(i) for i in range(1,51)]}),(200,{'success':True,'result':[]})])
        self.assertEqual(len(self.zones()['zones']),50);self.assertEqual(len(self.calls),2);self.unchanged()

    def test_short_page_without_metadata_and_empty_account_finish(self):
        self.response={'success':True,'result':[zone(1)]};self.assertEqual(self.zones()['zones'],['z001.example.test'])
        self.response=page([],1,0,0);self.assertEqual(self.zones()['zones'],[]);self.unchanged()

    def test_wrong_page_per_page_count_and_container_types_fail_closed(self):
        for key,value in [('page',2),('page','1'),('per_page',5),('count',2),('total_pages',-1),('total_count',0)]:
            self.response=page([zone(1)],1,1,1);self.response['result_info'][key]=value;self.zones(1)
        for value in [[],False,'bad']:
            self.response=page([],1,0,0);self.response['result_info']=value;self.zones(1)
        self.unchanged()

    def test_changed_or_disappearing_totals_never_publish_first_page(self):
        for second in [page([zone(2)],2,3,2),page([zone(2)],2,2,3),{'success':True,'result':[zone(2)]}]:
            self.pages([(200,page([zone(1)],1,2,2)),(200,second)]);self.zones(1)
        self.unchanged()

    def test_empty_intermediate_page_and_incomplete_final_count_are_refused(self):
        for first,second in [(page([zone(1)],1,3,2),page([],2,3,2)),(page([zone(1)],1,2,3),page([zone(2)],2,2,3))]:
            self.pages([(200,first),(200,second)]);self.zones(1)
        self.unchanged()

    def test_duplicate_zone_id_on_same_or_later_page_is_refused(self):
        self.response=page([zone(1),zone(1,'other.test')],1,1,2);self.zones(1)
        self.pages([(200,page([zone(1)],1,2,2)),(200,page([zone(1)],2,2,2))]);self.zones(1);self.unchanged()

    def test_invalid_names_ids_and_json_duplicates_never_enter_public_list(self):
        for s in ['a..test','-a.test','a-.test','a'*64+'.test','x\nheader.test','x/test','x_1.test','".test','é.test','a'*254]:
            self.response=page([zone(1,s)],1,1,1);self.zones(1)
        self.response=page([{'id':'not-an-id','name':'a.test'}],1,1,1);self.zones(1)
        self.response=b'{"success":true,"result":[],"result_info":{"total_pages":0,"total_pages":1}}';self.zones(1);self.unchanged()

    def test_page_count_and_response_limits_are_explicit_failures(self):
        for pages,count in [(1001,1),(1,50001)]:
            self.response=page([zone(1)],1,pages,count);self.assertEqual(self.zones(1)['provider_code'],'pagination_limit')
        self.response=page([zone(i) for i in range(1,52)],1,1,51);self.zones(1)
        self.pages([(200,page([zone(1)],1,2,2)),(200,b'{"success":true,"result":[],"pad":"'+b'x'*70000+b'"}')]);self.chunked=True;self.zones(1);self.unchanged()

    def test_later_page_http_error_returns_only_sanitized_failure(self):
        for status,kind in [(403,'authentication'),(429,'rate_limit'),(500,'temporary')]:
            self.pages([(200,page([zone(1)],1,2,2)),(status,{'success':False,'errors':[{'code':9109,'message':'PRIVATE_SENTINEL'}]})])
            self.assertEqual(self.zones(1)['error_kind'],kind)
        self.unchanged()

    def test_missing_account_or_secret_and_common_lock_prevent_http(self):
        import fcntl
        self.zones(1,'missing');self.assertEqual(self.calls,[])
        self.cli('credential-delete','cloudflare','dns_a','secret');self.zones(1);self.assertEqual(self.calls,[])
        self.secret(b'PRIVATE_SENTINEL')
        with self.native.lock.open('rb') as held:fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);self.zones(4)
        self.begin();self.zones(4);self.assertEqual(self.calls,[])

    def test_later_page_timeout_does_not_publish_earlier_results(self):
        def respond(path):
            n=int(urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['page'][0])
            if n==2:time.sleep(1)
            return 200,page([zone(n)],n,2,2)
        self.response=respond;self.assertEqual(self.zones(1)['error_kind'],'timeout');self.unchanged()

    def test_independent_deadline_after_first_page_survives_caller_sigkill(self):
        # Actual curl serves page one; a fixed fixture wrapper hangs page two.
        counter=self.base/'curl-count'
        self.curl.write_text('#!'+sys.executable+'\nimport os,signal,sys,time\nfrom pathlib import Path\np=Path('+repr(str(counter))+')\nn=int(p.read_text())+1 if p.exists() else 1\np.write_text(str(n))\nif n==1:os.execv('+repr(str(self.real_curl))+',['+repr(str(self.real_curl))+',*sys.argv[1:]])\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True:time.sleep(0.1)\n');self.curl.chmod(0o700)
        self.response=page([zone(1)],1,2,2)
        p=subprocess.Popen([self.busybox,'ash',str(self.reader),'dns_a','--zones'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.processes.append(p)
        deadline=time.monotonic()+5
        while not counter.exists() or counter.read_text()!='2':self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(0.02)
        self.group();p.kill();p.communicate(timeout=2);self.writer(4)
        time.sleep(3.4);self.writer();self.zones(4);self.assertEqual(len(self.calls),1)

    def test_forged_public_results_wrong_account_unsorted_and_partial_errors_refused(self):
        report={'api_version':1,'prototype':True,'ok':True,'phase':'dns-provider','provider':'cloudflare','account':'dns_a','configuration_revision':3,'check_scope':'zone-list','error_kind':'','retryable':False,'provider_code':'','zones':['a.test']}
        for changes in [{'account':'other'},{'zones':['b.test','a.test']},{'zones':['a.test','a.test']},{'ok':False,'error_kind':'temporary'},{'extra':'PRIVATE_SENTINEL'}]:
            doc={**report,**changes};raw=json.dumps(doc,separators=(',',':'))+'\n'
            worker=self.engine.parent/'homegate-cloudflare-worker.sh';worker.write_text('#!/bin/sh\nprintf \'%s\' '+shlex.quote(raw)+' >&3\nexit 0\n')
            self.zones(7)
        self.assertEqual(self.calls,[]);self.unchanged()

    def test_closed_gate_and_unknown_operation_never_allocate_or_request(self):
        for args in [['dns_a','--zones','extra'],['dns_a','--delete'],['dns_a','--zones;echo']]:
            p=subprocess.run([self.busybox,'ash',str(self.reader),*args],env=self.env,capture_output=True,timeout=5);self.assertEqual(p.returncode,2)
        self.reader.write_text(self.reader.read_text().replace('dns_read_enabled=true','dns_read_enabled=false'))
        self.zones(2,env={**self.env,'dns_read_enabled':'true'});self.assertEqual(self.calls,[])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
