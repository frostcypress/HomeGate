#!/usr/bin/env python3
"""Published normal generations, one-use grant confirmation and private overlays."""
import argparse,hashlib,json,os,re,subprocess,sys,unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from project import ROOT
from DDNS计划回归 import Static as PlanStatic,fixture_uid
from 固定服务动作回归 import Runtime as ServiceRuntime
PROTO=ROOT/'project/core/prototype'

class Static(PlanStatic):
    def setUp(self):
        super().setUp();self.authority=self.lua.execute((PROTO/'ddns-authority.lua').read_bytes())
    def frame_snapshot(self,provider='cloudflare'):
        s=self.parse(self.frame());account=next(x for _,x in s[b'configuration'].items() if x[b'kind']==b'dns_account');account[b'values'][b'provider']=provider.encode()
        for slot in ['key_id','secret','account_id']:s[b'credentials'][(provider+'.dns_a.'+slot).encode()]=b'SECRET_SENTINEL'
        return s
    def test_one_rule_overlay_does_not_enable_or_mutate_import_candidate(self):
        s=self.frame_snapshot();before=self.codec.json(s);intent,p=self.authority.intent(s,b'ddns_a',self.planner.id);self.assertEqual(p,b'cloudflare');self.assertEqual(dict(intent[b'switches'].items()),{b'ddns_a':b'1'});self.assertEqual(self.codec.json(s),before)
        self.assertNotIn(b'SECRET_SENTINEL',self.codec.json(intent));self.assertNotIn(b"enabled '1'",self.public)
    def test_all_providers_require_their_credential_slots(self):
        required={'cloudflare':['secret'],'aliyun':['key_id','secret'],'dnspod':['key_id','secret'],'huaweicloud':['key_id','secret','account_id']}
        for provider,slots in required.items():
            s=self.frame_snapshot(provider);self.assertIsNotNone(self.authority.intent(s,b'ddns_a',self.planner.id))
            for slot in slots:
                key=(provider+'.dns_a.'+slot).encode();old=s[b'credentials'][key];s[b'credentials'][key]=None;self.assertIsNone(self.authority.intent(s,b'ddns_a',self.planner.id));s[b'credentials'][key]=old
    def test_bad_selection_type_source_and_account_are_not_granted(self):
        s=self.frame_snapshot()
        for name in [b'missing',b'../bad',b'']:self.assertIsNone(self.authority.intent(s,name,self.planner.id))
        r=next(x for _,x in s[b'configuration'].items() if x[b'kind']==b'ddns_rule')
        for k,v in [(b'type',b'A'),(b'source',b'url'),(b'source',b'interface'),(b'account',b'missing')]:
            old=r[b'values'][k];r[b'values'][k]=v;self.assertIsNone(self.authority.intent(s,b'ddns_a',self.planner.id));r[b'values'][k]=old
    def test_closed_gates_grammar_and_no_service_or_cloud_action(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for n in ['homegate-config-prototype.sh','homegate-ddns-authority.sh']:
            b=(PROTO/n).read_bytes();self.assertEqual(b.count(b'ddns_authority_enabled=false'),1);self.assertNotIn(b'\r',b);self.assertFalse(parser.parse(b).root_node.has_error,n)
        for n in ['homegate-ddns-authority.lua','ddns-authority.lua']:self.lua.compile((PROTO/n).read_bytes())
        s=(PROTO/'homegate-ddns-authority.sh').read_text()
        for forbidden in ['curl','wget','uci set','/etc/init.d','kill ','eval ','source ']:self.assertNotIn(forbidden,s)
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class Runtime(ServiceRuntime):
    def setUp(self):
        super().setUp();self.secret(b'SECRET_SENTINEL');self.original=self.original.replace(b"config dns_account 'dns_a'",b"config dns_account 'dns_a'\n option secret 'SECRET_SENTINEL'");self.source.write_bytes(self.original)
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))
        self.helper=self.engine.parent/'homegate-ddns-authority.sh';self.active=self.store/'ddns-authority';self.auth_pending=self.store/'ddns-authority-pending';self.auth_next=self.store/'.ddns-authority-next'
        self.engine.write_text(self.engine.read_text().replace('ddns_authority_enabled=false','ddns_authority_enabled=true'))
        s=self.helper.read_text().replace('ddns_authority_enabled=false','ddns_authority_enabled=true');mapping={'/etc/homegate/transactions':str(self.store),'/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)};s=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],s);self.helper.write_text(fixture_uid(s.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
        # The fixed helper uses the shared nonce/context library with the real LuCI parser.
        p=self.engine.parent/'cloudflare-codec.lua';s=p.read_text().replace("local json=require('luci.jsonc')","package.cpath="+json.dumps(str(ROOT/'build/service-observer/?.so')+';;')+"\nlocal json=require('luci.jsonc')");p.write_text(s)
    def ordinary(self):
        self.begin(boot=0,running=0);self.apply();self.assertFalse(self.running());self.before_config=self.config_files();self.before_actions=self.log()
    def config_files(self):return {p.relative_to(self.store).as_posix():p.read_bytes() for p in self.store.rglob('*') if p.is_file() and not p.name.startswith(('ddns-authority','.ddns-authority'))}
    def auth(self,*args,expected=0,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.helper),*args],env=env or self.env,capture_output=True,timeout=12);self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));d=json.loads(p.stdout);self.assertEqual(d['ok'],expected==0)
        for marker in [b'SECRET_SENTINEL',b'example.test',b'2001:db8',b'cloudflare.dns_a.secret']:self.assertNotIn(marker,p.stdout)
        return d
    def grant(self):
        p=self.auth('preview','ddns_a');self.assertFalse(p['authorized']);self.auth('commit',p['confirmation']);return p
    def capture(self,expected=0):
        intent=self.base/'intent-out';intent.touch(mode=0o600);rfd,wfd=os.pipe()
        launch='import os,sys;os.dup2(int(sys.argv[1]),3,inheritable=True);os.dup2(int(sys.argv[2]),4,inheritable=True);os.execv(sys.argv[3],sys.argv[3:])'
        with intent.open('wb') as f:
            p=subprocess.Popen([sys.executable,'-c',launch,str(wfd),str(f.fileno()),self.busybox,'ash',str(self.helper),'snapshot'],env=self.env,pass_fds=(wfd,f.fileno()),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        os.close(wfd)
        with os.fdopen(rfd,'rb') as stream,ThreadPoolExecutor(1) as pool:
            future=pool.submit(stream.read);out,err=p.communicate(timeout=12);raw=future.result(timeout=2)
        self.assertEqual((p.returncode,err),(expected,b''),(out,err));return json.loads(out),raw,intent.read_bytes()
    def test_preview_confirm_private_snapshot_and_no_service_start(self):
        self.ordinary();p=self.grant();self.assertTrue(self.auth('check')['authorized']);out,frame,intent=self.capture();self.assertTrue(out['authorized']);self.assertIn(b'SECRET_SENTINEL',frame);self.assertNotIn(b'SECRET_SENTINEL',intent);d=json.loads(intent);self.assertEqual(d['switches'],{'ddns_a':'1'});self.assertEqual(d['revision'],p['configuration_revision']);self.assertNotIn(b"option enabled '1'",frame);self.assertEqual(self.config_files(),self.before_config);self.assertEqual(self.log(),self.before_actions);self.assertFalse(self.running())
    def test_unpublished_or_application_pending_generation_cannot_grant(self):
        self.auth('preview','ddns_a',expected=7);self.begin(0,0);self.auth('preview','ddns_a',expected=4);self.assertFalse(self.active.exists())
    def test_import_commit_without_source_projection_cannot_grant(self):
        self.commit_body(self.business);self.auth('preview','ddns_a',expected=7);self.assertFalse(self.active.exists())
    def test_preview_alone_and_wrong_or_replayed_confirmation_do_not_grant(self):
        self.ordinary();p=self.auth('preview','ddns_a');self.auth('check',expected=7);self.auth('commit','a'*32,expected=5);self.auth('commit',p['confirmation']);self.auth('commit',p['confirmation'],expected=5)
    def test_replaced_and_cancelled_previews_are_inert(self):
        self.ordinary();a=self.auth('preview','ddns_a')['confirmation'];b=self.auth('preview','ddns_a')['confirmation'];self.assertNotEqual(a,b);self.auth('commit',a,expected=5);self.auth('cancel','--confirm');self.auth('commit',b,expected=5);self.assertFalse(self.active.exists())
    def test_configuration_or_credentials_change_invalidates_pending_and_active(self):
        self.ordinary();p=self.grant();self.auth('preview','ddns_a');self.cli('credential-put','cloudflare','dns_a','secret',payload=b'NEW_TOKEN');self.auth('check',expected=7);self.capture(7);self.auth('commit',p['confirmation'],expected=5)
    def test_source_change_after_preview_prevents_confirmation_and_read(self):
        self.ordinary();p=self.auth('preview','ddns_a');self.source.write_bytes(self.source.read_bytes()+b'\n');self.auth('commit',p['confirmation'],expected=7);self.assertFalse(self.active.exists())
    def test_revoke_and_repeat_never_enable_or_start_service(self):
        self.ordinary();self.grant();self.auth('revoke','--confirm');self.auth('check',expected=7);self.capture(7);self.auth('revoke','--confirm');self.assertIn(b'\ndisabled\n',self.active.read_bytes());self.assertEqual(self.log(),self.before_actions)
    def test_later_import_requires_new_confirmation(self):
        self.ordinary();self.grant();self.plan=self.preview(self.business);self.begin(0,0);self.apply();self.auth('check',expected=7);self.assertNotIn(b"option enabled '1'",self.source.read_bytes());self.grant();self.auth('check')
    def test_expired_future_or_other_boot_preview_is_refused(self):
        self.ordinary();p=self.engine.parent/'worker-process.lua';p.write_text("if arg[1]=='now' then io.write('1000\\n');return end\n"+p.read_text());p=self.auth('preview','ddns_a');old=self.auth_pending.read_bytes();fields=old.splitlines();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.auth('commit',p['confirmation'],expected=5)
        self.boot_id.write_bytes(fields[8]+b'\n')
        for value in [b'999999999',b'0']:
            f=fields[:];f[9]=value;body=b'\n'.join(f[:-1])+b'\n';f[-1]=hashlib.sha256(body).hexdigest().encode();self.auth_pending.write_bytes(b'\n'.join(f)+b'\n');self.auth('commit',p['confirmation'],expected=5)
    def test_active_grant_is_revalidated_after_simulated_boot_change(self):
        self.ordinary();self.grant();self.boot_id.write_text('11111111-1111-1111-1111-111111111111\n');self.auth('check');self.capture()
    def test_change_of_previous_authority_invalidates_confirmation(self):
        self.ordinary();self.grant();p=self.auth('preview','ddns_a');self.auth('revoke','--confirm');self.auth('commit',p['confirmation'],expected=5);self.auth('check',expected=7)
    def test_gate_environment_and_cli_grammar_cannot_enable_authority(self):
        self.ordinary()
        for args in [[],['preview'],['preview','../bad'],['commit','bad'],['revoke'],['cancel'],['check','extra'],['snapshot','ddns_a']]:self.auth(*args,expected=2)
        for p in [self.helper,self.engine]:
            old=p.read_text();p.write_text(old.replace('ddns_authority_enabled=true','ddns_authority_enabled=false'));self.auth('preview','ddns_a',expected=2 if p==self.helper else 7,env={**self.env,'ddns_authority_enabled':'true'});p.write_text(old)
    def test_common_locks_and_dns_barrier_prevent_authority_change(self):
        import fcntl
        self.ordinary()
        for p in [self.native.lock,self.store/'.supervisor.lock']:
            with p.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.auth('preview','ddns_a',expected=4)
        j=self.store/'dns-operation';j.mkdir(mode=0o700);self.auth('preview','ddns_a',expected=4);self.assertFalse(self.active.exists())
    def test_malformed_or_linked_metadata_is_preserved(self):
        self.ordinary();self.grant();original=self.active.read_bytes();self.active.write_bytes(original+b'X');self.auth('check',expected=7);self.auth('preview','ddns_a',expected=7);self.assertEqual(self.active.read_bytes(),original+b'X');self.active.write_bytes(original);p=self.active.with_name('saved-authority');self.active.rename(p);self.active.symlink_to(p);self.auth('check',expected=7);self.assertTrue(self.active.is_symlink())
    def test_changed_source_permission_and_missing_projection_are_refused(self):
        self.ordinary();self.source.chmod(0o644);self.auth('preview','ddns_a',expected=7);self.source.chmod(0o600);p=self.store/f'gen-{self.target}/source.conf';p.rename(p.with_name('extra.conf'));self.auth('preview','ddns_a',expected=4)
    def test_unpublished_active_stage_blocks_reads_and_explicit_retry_can_finish(self):
        self.ordinary();p=self.auth('preview','ddns_a');self.fault('mv','sys.exit(1) if any(a.endswith("/.ddns-authority-next") for a in sys.argv[1:]) else None');self.auth('commit',p['confirmation'],expected=7);self.restore_tool('mv');self.assertTrue(self.auth_next.exists());self.auth('check',expected=7);self.auth('commit',p['confirmation']);self.auth('check')
    def test_sync_failure_before_publication_preserves_pending_and_denies_read(self):
        self.ordinary();p=self.auth('preview','ddns_a');self.fault('fsync','sys.exit(1) if any(a.endswith("/.ddns-authority-next") for a in sys.argv[1:]) else None');self.auth('commit',p['confirmation'],expected=7);self.restore_tool('fsync');self.auth('check',expected=7);self.assertTrue(self.auth_pending.exists());self.auth('commit',p['confirmation']);self.auth('check')
    def test_post_publish_sync_failure_requires_explicit_completion_or_resync(self):
        self.ordinary();p=self.auth('preview','ddns_a');self.fault('fsync','sys.exit(1) if any(a.endswith("/ddns-authority") for a in sys.argv[1:]) else None');self.auth('commit',p['confirmation'],expected=7);self.restore_tool('fsync');self.assertTrue(self.active.exists());self.assertTrue(self.auth_pending.exists());self.auth('commit',p['confirmation']);self.auth('check')
    def test_incomplete_grant_stage_is_not_inferred_and_revoke_can_narrow(self):
        self.ordinary();self.grant();p=self.auth('preview','ddns_a');self.auth_next.write_bytes(b'INCOMPLETE');self.auth_next.chmod(0o600);self.auth('commit',p['confirmation'],expected=7);self.auth('check',expected=7);self.auth('revoke','--confirm');self.auth('check',expected=7);self.assertFalse(self.auth_next.exists())
    def test_cancel_does_not_change_a_valid_active_grant(self):
        self.ordinary();self.grant();before=self.active.read_bytes();self.auth('preview','ddns_a');self.auth('cancel','--confirm');self.assertEqual(self.active.read_bytes(),before);self.auth('check')
    def test_snapshot_requires_private_descriptors_and_never_publicly_emits_frame(self):
        self.ordinary();self.grant();self.auth('snapshot',expected=7)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args();cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
