#!/usr/bin/env python3
"""Bounded explicit rule sets, durable confirmation and scoped execution intent."""
import argparse,hashlib,json,os,subprocess,sys,unittest
from concurrent.futures import ThreadPoolExecutor
from project import ROOT
from DDNS运行授权回归 import Static as BaseStatic,Runtime as BaseRuntime
from DDNS普通收尾回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase
PROTO=ROOT/'project/core/prototype'

def rule(name):
    return ("\nconfig ddns_rule '"+name+"'\n option account 'dns_a'\n option zone 'example.test'\n option host 'www.example.test'\n option type 'AAAA'\n option source 'auto'\n option enabled '0'\n").encode()

class Static(BaseStatic):
    def test_bounded_selection_is_unique_canonical_and_explicit(self):
        select=lambda value:self.authority.selection(value,self.planner.id)
        self.assertEqual(list(select(b'z,a')[i] for i in [1,2]),[b'a',b'z'])
        for value in [b'',b'a,a',b'a,',b',a',b'a,,b',b'a, b',b'a,../x',b'a\nb',b'a'*65,b'ALL,*',b','.join(('r'+str(i)).encode() for i in range(33))]:self.assertIsNone(select(value),value)
        names=[('r'+str(i).zfill(2)+'x'*61).encode() for i in range(32)]
        self.assertEqual(len(select(b','.join(names))),32)
    def test_multi_overlay_uses_four_provider_slots_and_no_configuration_mutation(self):
        snapshot=self.frame_snapshot();sections=snapshot[b'configuration'];n=len(sections)
        for i,provider in enumerate(['aliyun','dnspod','huaweicloud'],1):
            account='dns_'+str(i);name='ddns_'+str(i)
            sections[n+2*i-1]=self.table({'kind':'dns_account','name':account,'values':{'provider':provider}})
            sections[n+2*i]=self.table({'kind':'ddns_rule','name':name,'values':{'account':account,'type':'AAAA','source':'auto'}})
            for slot in ['secret','key_id','account_id']:snapshot[b'credentials'][(provider+'.'+account+'.'+slot).encode()]=b'SECRET_SENTINEL'
        before=self.codec.json(snapshot);intent,provider=self.authority.intent(snapshot,b'ddns_a,ddns_3,ddns_1,ddns_2',self.planner.id)
        self.assertEqual(provider,b'multiple');self.assertEqual(set(intent[b'switches'].values()),{b'1'});self.assertEqual(self.codec.json(snapshot),before)
        snapshot[b'credentials'][b'huaweicloud.dns_3.account_id']=None
        self.assertIsNone(self.authority.intent(snapshot,b'ddns_a,ddns_1,ddns_2,ddns_3',self.planner.id))
    def test_missing_or_unsupported_member_invalidates_entire_set(self):
        snapshot=self.frame_snapshot();r=next(s for _,s in snapshot[b'configuration'].items() if s[b'kind']==b'ddns_rule')
        for selected in [b'ddns_a,missing',b'ddns_a,ddns_a']:self.assertIsNone(self.authority.intent(snapshot,selected,self.planner.id))
        r[b'values'][b'type']=b'A';self.assertIsNone(self.authority.intent(snapshot,b'ddns_a',self.planner.id))
    def test_closed_gate_formats_and_fixed_snapshot_scope(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        body=(PROTO/'homegate-ddns-authority.sh').read_bytes();self.assertEqual(body.count(b'ddns_multi_authority_enabled=false'),1)
        self.assertFalse(parser.parse(body).root_node.has_error);self.assertNotIn(b'\r',body)
        self.assertIn(b'HGDDNSAUTH1',body);self.assertIn(b'HGDDNSAUTH2',body)
        self.assertIn('snapshot-rule "$rule"',(PROTO/'homegate-ddns-read.sh').read_text())
        for name in ['ddns-authority.lua','homegate-ddns-authority.lua']:self.lua.compile((PROTO/name).read_bytes())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class Runtime(BaseRuntime):
    def setUp(self):
        super().setUp();self.helper.write_text(self.helper.read_text().replace('ddns_multi_authority_enabled=false','ddns_multi_authority_enabled=true'))
        self.plan=self.preview(self.business+rule('ddns_b')+rule('ddns_c'))
    def many(self,selection='ddns_b,ddns_a'):
        p=self.auth('preview-rules',selection);self.assertFalse(p['authorized']);self.auth('commit',p['confirmation']);return p
    def capture_scope(self,selected=None,expected=0):
        intent=self.base/'multi-intent';intent.touch(mode=0o600);rfd,wfd=os.pipe()
        launch='import os,sys;os.dup2(int(sys.argv[1]),3,inheritable=True);os.dup2(int(sys.argv[2]),4,inheritable=True);os.execv(sys.argv[3],sys.argv[3:])'
        args=['snapshot'] if selected is None else ['snapshot-rule',selected]
        with intent.open('wb') as f:
            p=subprocess.Popen([sys.executable,'-c',launch,str(wfd),str(f.fileno()),self.busybox,'ash',str(self.helper),*args],env=self.env,pass_fds=(wfd,f.fileno()),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        os.close(wfd)
        with os.fdopen(rfd,'rb') as stream,ThreadPoolExecutor(1) as pool:
            future=pool.submit(stream.read);out,err=p.communicate(timeout=12);frame=future.result(timeout=2)
        self.assertEqual((p.returncode,err),(expected,b''),(out,err))
        return json.loads(out),frame,intent.read_bytes()
    def resign(self,path,mutate):
        fields=path.read_bytes().splitlines();mutate(fields);fields[-1]=hashlib.sha256(b'\n'.join(fields[:-1])+b'\n').hexdigest().encode();path.write_bytes(b'\n'.join(fields)+b'\n')
    def test_preview_commit_full_snapshot_and_single_rule_narrowing(self):
        self.ordinary();p=self.many();self.assertEqual(p['rules'],['ddns_a','ddns_b']);self.assertTrue(self.active.read_bytes().startswith(b'HGDDNSAUTH2\n'))
        out,frame,intent=self.capture_scope();self.assertTrue(out['authorized']);self.assertEqual(json.loads(intent)['switches'],{'ddns_a':'1','ddns_b':'1','ddns_c':'0'})
        for name in ['ddns_a','ddns_b']:
            self.auth('check-rule',name);_,single,raw=self.capture_scope(name);self.assertEqual(single,frame);self.assertEqual(json.loads(raw)['switches'],{k:'1' if k==name else '0' for k in ['ddns_a','ddns_b','ddns_c']})
        self.auth('check-rule','ddns_c',expected=7);_,frame,intent=self.capture_scope('ddns_c',7);self.assertEqual((frame,intent),(b'',b''))
        self.assertEqual(self.config_files(),self.before_config);self.assertEqual(self.log(),self.before_actions);self.assertFalse(self.running())
    def test_invalid_set_does_not_replace_active_or_pending(self):
        self.ordinary();self.many();before=self.active.read_bytes();pending=self.auth('preview-rules','ddns_a,ddns_c');raw=self.auth_pending.read_bytes()
        for value in ['ddns_a,missing','ddns_a,ddns_a','ddns_a,','ddns_a','ddns_a,../bad','*','ddns_a, ddns_b']:
            self.auth('preview-rules',value,expected=7 if value=='ddns_a,missing' else 2);self.assertEqual(self.active.read_bytes(),before);self.assertEqual(self.auth_pending.read_bytes(),raw)
        self.auth('commit',pending['confirmation']);self.auth('check-rule','ddns_b',expected=7)
    def test_rule_scoped_actions_refuse_empty_list_path_and_oversized_id(self):
        self.ordinary();self.many();before=self.active.read_bytes()
        for selected in ['', 'ddns_a,ddns_b', '../bad', 'x'*65]:
            self.auth('check-rule',selected,expected=2)
            _,frame,intent=self.capture_scope(selected,2);self.assertEqual((frame,intent),(b'',b''))
        self.assertEqual(self.active.read_bytes(),before);self.auth('check-rule','ddns_b')
    def test_replacing_preview_binds_exact_set_and_rejects_replay(self):
        self.ordinary();a=self.auth('preview-rules','ddns_a,ddns_b');b=self.auth('preview-rules','ddns_a,ddns_c');self.auth('commit',a['confirmation'],expected=5);self.auth('commit',b['confirmation']);self.auth('check-rule','ddns_b',expected=7);self.auth('check-rule','ddns_c');self.auth('commit',b['confirmation'],expected=5)
    def test_explicit_single_grant_replaces_and_narrows_multi_grant(self):
        self.ordinary();self.many();self.grant();self.assertTrue(self.active.read_bytes().startswith(b'HGDDNSAUTH1\n'));self.auth('check-rule','ddns_a');self.auth('check-rule','ddns_b',expected=7);self.assertEqual(json.loads(self.capture_scope()[2])['switches'],{'ddns_a':'1','ddns_b':'0','ddns_c':'0'})
    def test_closed_multi_gate_denies_existing_and_pending_but_allows_revoke(self):
        self.ordinary();self.many();pending=self.auth('preview-rules','ddns_a,ddns_c');self.helper.write_text(self.helper.read_text().replace('ddns_multi_authority_enabled=true','ddns_multi_authority_enabled=false'))
        self.auth('check',expected=7,env={**self.env,'ddns_multi_authority_enabled':'true'});self.capture_scope('ddns_a',7);self.auth('commit',pending['confirmation'],expected=7);self.auth('preview-rules','ddns_a,ddns_b',expected=2);self.auth('revoke','--confirm');self.assertIn(b'\ndisabled\n',self.active.read_bytes());self.assertEqual(self.log(),self.before_actions)
    def test_multi_confirmation_refuses_changed_source(self):
        self.ordinary();p=self.auth('preview-rules','ddns_a,ddns_b');self.source.write_bytes(self.source.read_bytes()+b'\n');self.auth('commit',p['confirmation'],expected=7);self.assertFalse(self.active.exists())
    def test_multi_confirmation_and_active_refuse_changed_credentials(self):
        self.ordinary();self.many();p=self.auth('preview-rules','ddns_a,ddns_c');self.cli('credential-put','cloudflare','dns_a','secret',payload=b'REPLACED_TOKEN');self.auth('commit',p['confirmation'],expected=5);self.auth('check',expected=7);self.capture_scope('ddns_a',7)
    def test_multi_stages_explicitly_resume_after_rename_and_sync_failures(self):
        self.ordinary()
        for tool,suffix in [('mv','/.ddns-authority-next'),('fsync','/.ddns-authority-next'),('fsync','/ddns-authority')]:
            p=self.auth('preview-rules','ddns_a,ddns_b');self.fault(tool,'sys.exit(1) if any(a.endswith('+repr(suffix)+') for a in sys.argv[1:]) else None');self.auth('commit',p['confirmation'],expected=7)
            if self.auth_next.exists():self.auth('check',expected=7)
            self.restore_tool(tool);self.auth('commit',p['confirmation']);self.auth('check-rule','ddns_b')
    def test_noncanonical_or_wrong_format_set_is_preserved_and_denied(self):
        self.ordinary();self.many();original=self.active.read_bytes()
        for value,fmt in [(b'ddns_b,ddns_a',b'HGDDNSAUTH2'),(b'ddns_a,ddns_a',b'HGDDNSAUTH2'),(b'ddns_a',b'HGDDNSAUTH2'),(b'ddns_a,ddns_b',b'HGDDNSAUTH1')]:
            self.active.write_bytes(original);self.resign(self.active,lambda f:(f.__setitem__(0,fmt),f.__setitem__(6,value)));raw=self.active.read_bytes();self.auth('check',expected=7);self.assertEqual(self.active.read_bytes(),raw)
        self.active.write_bytes(original);self.auth('check')
    def test_cancel_does_not_revoke_multi_grant(self):
        self.ordinary();self.many();raw=self.active.read_bytes();p=self.auth('preview-rules','ddns_a,ddns_c');self.auth('cancel','--confirm');self.auth('commit',p['confirmation'],expected=5);self.assertEqual(self.active.read_bytes(),raw);self.auth('check-rule','ddns_b')
    def test_multi_preview_expiry_boot_and_previous_grant_are_bound(self):
        self.ordinary();self.many()
        clock=self.engine.parent/'worker-process.lua';clock.write_text("if arg[1]=='now' then io.write('1000\\n');return end\n"+clock.read_text())
        p=self.auth('preview-rules','ddns_a,ddns_c');self.resign(self.auth_pending,lambda f:f.__setitem__(9,b'0'));self.auth('commit',p['confirmation'],expected=5)
        p=self.auth('preview-rules','ddns_a,ddns_c');self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.auth('commit',p['confirmation'],expected=5);self.auth('check-rule','ddns_b')
        p=self.auth('preview-rules','ddns_a,ddns_c');self.auth('revoke','--confirm');self.auth('commit',p['confirmation'],expected=5)
    def test_maximum_set_record_exceeds_old_limit_and_remains_bounded(self):
        names=['r'+str(i).zfill(2)+'x'*61 for i in range(31)]
        self.plan=self.preview(self.business+b''.join(rule(n) for n in names));self.ordinary();self.many(','.join(['ddns_a',*reversed(names)]));self.assertGreater(self.active.stat().st_size,1024);self.assertLess(self.active.stat().st_size,4096);self.auth('check-rule',names[-1]);self.assertEqual(sum(v=='1' for v in json.loads(self.capture_scope()[2])['switches'].values()),32)

class ExecuteMixin:
    def setUp(self):
        super().setUp();self.auth_helper.write_text(self.auth_helper.read_text().replace('ddns_multi_authority_enabled=false','ddns_multi_authority_enabled=true'))
        current=self.cli('status')['revision'];body=(self.store/f'gen-{current}/public.conf').read_bytes()+rule('ddns_b')+rule('ddns_c')
        p=self.cli('preview',payload=body);tx=self.cli('commit-apply-projection',p['confirmation']);self.cli('projection-publish',tx['apply_handle'],'apply');self.cli('apply-finish-projection',tx['apply_handle'])
        p=self.auth('preview-rules','ddns_a,ddns_b');self.auth('commit',p['confirmation']);self.baseline_config=self.config_bytes()
    def test_granted_second_rule_executes_and_ungranted_rule_never_samples(self):
        self.sync_call(7,['--runtime-sync','ddns_c','--confirm']);self.assertEqual(self.calls,[]);self.assertFalse(self.netlog.exists())
        out=self.sync_call(args=['--runtime-sync','ddns_b','--confirm']);self.assertEqual(out['effect'],'confirmed');self.assertEqual(len(self.mutations()),1)
        slot=(self.journal/'current').read_text().strip();context=json.loads((self.journal/('slot-'+slot)/'context').read_bytes());self.assertEqual(context['request']['resource'],'ddns_b')
        self.sync_call(4,['--runtime-sync','ddns_a','--confirm']);self.assertEqual(len(self.mutations()),1)
    def test_multi_grant_survives_explicit_closeout_without_automatic_collection(self):
        self.sync_call(args=['--runtime-sync','ddns_b','--confirm']);self.maintenance('collect-receipt');self.maintenance('retire-archive');out=self.sync_call();self.assertEqual(out['result'],'unchanged');self.assertEqual(len(self.mutations()),1)

class CF(ExecuteMixin,CFBase):pass
class Ali(ExecuteMixin,AliBase):pass
class DNP(ExecuteMixin,DNPBase):pass
class HW(ExecuteMixin,HWBase):pass

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',action='store_true');args=parser.parse_args();suite=unittest.TestSuite()
    for cls in ([Runtime,CF,Ali,DNP,HW] if args.runtime else [Static]):
        methods=ExecuteMixin.__dict__ if cls in [CF,Ali,DNP,HW] else cls.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v))
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
