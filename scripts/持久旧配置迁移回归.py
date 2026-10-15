#!/usr/bin/env python3
"""Fixed-source persistent migration, only in private Linux fixture copies."""
import argparse, hashlib, json, os, signal, subprocess, unittest
from pathlib import Path
from project import ROOT
from 持久初始化回归 import Runtime as BootstrapRuntime
from 旧配置迁移回归 import LEGACY

ENGINE=ROOT/'project/core/prototype/homegate-config-prototype.sh'

class Static(unittest.TestCase):
    def test_fixed_gate_and_entry_before_open(self):
        body=ENGINE.read_text(encoding='utf-8')
        self.assertEqual(body.count('lifecycle_migration_enabled=false'),1)
        self.assertNotIn('lifecycle_migration_enabled=true',body)
        self.assertIn('migration-source-preview)',body)
        self.assertIn('migration-source-commit)',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())
        self.assertLess(body.index("fail 'Lifecycle migration is not ready'"),body.index('\nopen_store\n'))

    def test_source_recheck_after_pointer_sync_before_rename(self):
        body=ENGINE.read_text(encoding='utf-8')
        publish=body.split('publish_generation() {',1)[1].split('\nneed_initialized()',1)[0]
        self.assertLess(publish.index('synchronize candidate pointer'),publish.index('migration_source_matches'))
        self.assertLess(publish.index('migration_source_matches'),publish.index('mv -f "$scratch" "$store/current"'))
        self.assertIn('legacy_source_retained',publish)
        self.assertIn('readers_switched":false',publish)

    def test_busybox_shell_grammar(self):
        import tree_sitter,tree_sitter_bash
        body=ENGINE.read_bytes();self.assertNotIn(b'\r',body)
        tree=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language())).parse(body)
        self.assertFalse(tree.root_node.has_error)

class Runtime(BootstrapRuntime):
    def setUp(self):
        super().setUp()
        self.boot()
        self.configdir=self.etc/'config';self.configdir.mkdir(mode=0o700)
        self.source=self.configdir/'homegate';self.source.write_bytes(LEGACY.encode());self.source.chmod(0o600)
        body=self.engine.read_text(encoding='utf-8').replace('lifecycle_migration_enabled=false','lifecycle_migration_enabled=true')
        self.engine.write_text(body,encoding='utf-8')
        self.source_before=self.source.read_bytes()
        self.defaults=self.export()

    def migration_preview(self,**kwargs):return self.cli('migration-source-preview',**kwargs)
    def commit(self,token,**kwargs):return self.cli('migration-source-commit',token,**kwargs)
    def current(self):return (self.store/'current').read_bytes()
    def generation(self,n):return self.store/f'gen-{n}'
    def pending(self):return (self.store/'pending').read_bytes()
    def no_source_changes(self):self.assertEqual(self.source.read_bytes(),self.source_before)

    def test_complete_fixed_source_copy_and_single_use(self):
        plan=self.migration_preview(payload=b'not the fixed source')
        self.assertEqual(plan['operation'],'migration-source');self.assertEqual(self.current(),b'1\n')
        result=self.commit(plan['confirmation']);self.assertEqual(result['revision'],3)
        self.assertTrue(result['migration_copied']);self.assertTrue(result['legacy_source_retained'])
        self.assertFalse(result['production_ready']);self.assertFalse(result['readers_switched'])
        self.assertFalse(result['service_enabled']);self.no_source_changes()
        generation=self.generation(3)
        self.assertEqual((generation/'legacy.conf').read_bytes(),self.source_before)
        self.assertEqual((generation/'credentials/cloudflare.dns_a.secret').read_bytes(),b'SECRET_SENTINEL')
        self.assertEqual((generation/'credentials/ddns.ddns_a.url').read_bytes(),b'https://user:password@source.test/token')
        self.assertNotIn(b'private-token',self.export());self.assertNotIn(b"option enabled '1'",self.export())
        for p in [self.store,*self.store.rglob('*')]:
            self.assertEqual(p.stat().st_mode&0o777,0o700 if p.is_dir() else 0o600)
        self.commit(plan['confirmation'],expected=5);self.migration_preview(expected=4)

    def test_no_secret_hash_or_path_in_public_output(self):
        p=self.migration_preview();r=self.commit(p['confirmation'])
        output=json.dumps([p,r,self.cli('status')])+self.export().decode()
        for item in ['SECRET_SENTINEL','PRIVATE_ACCOUNT','OLD_ID','private-token',str(self.source),str(self.store),hashlib.sha256(self.source_before).hexdigest()]:
            self.assertNotIn(item,output)

    def test_four_provider_projection_preserves_exact_secrets(self):
        for provider in ['aliyun','cloudflare','dnspod','huaweicloud']:
            self.source.write_text(LEGACY.replace("provider 'cloudflare'","provider '"+provider+"'"),encoding='utf-8')
            plan=self.migration_preview();index=int(self.pending().splitlines()[3]);candidate=self.generation(index)
            self.assertEqual((candidate/'credentials'/f'{provider}.dns_a.secret').read_bytes(),b'SECRET_SENTINEL')
            self.assertNotIn('SECRET_SENTINEL',json.dumps(plan));self.cli('cancel')
        self.assertEqual(self.current(),b'1\n')

    def test_environment_cannot_enable_gate_or_redirect_source(self):
        self.engine.write_text(self.engine.read_text().replace('lifecycle_migration_enabled=true','lifecycle_migration_enabled=false'))
        self.migration_preview(expected=2,env={**self.env,'lifecycle_migration_enabled':'true','HOMEGATE_LIFECYCLE_MIGRATION_ENABLED':'1','HOMEGATE_CONFIG_PROTO_STORE':str(self.base/'decoy')})
        self.commit('a'*32,expected=2);self.no_source_changes();self.assertEqual(self.current(),b'1\n')

    def test_environment_ignored_and_lua_injection_removed(self):
        decoy=self.base/'decoy';decoy.mkdir(mode=0o700)
        self.migration_preview(env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(decoy),'IPKG_INSTROOT':str(decoy),'LUA_INIT':"error('PRIVATE_SENTINEL')"})
        self.assertEqual(list(decoy.iterdir()),[]);self.no_source_changes()

    def test_only_fixed_arguments_and_persistent_namespace(self):
        for args in [('migration-source-preview',str(self.source)),('migration-source-commit',),('migration-source-commit','x'*32),('migration-source-commit','a'*32,'extra'),('migration-preview',)]:
            self.cli(*args,expected=2)
        p=subprocess.run([self.busybox,'ash',str(self.engine),'--public-uci','migration-source-preview'],env=self.env,capture_output=True,timeout=10)
        self.assertEqual(p.returncode,2);self.no_source_changes()

    def test_changed_source_rejects_confirmation_then_new_preview_succeeds(self):
        old=self.migration_preview()['confirmation'];self.source.write_bytes(self.source_before.replace(b'OLD_ID',b'NEW_ID'))
        self.commit(old,expected=5);self.assertEqual(self.current(),b'1\n')
        new=self.migration_preview()['confirmation'];result=self.commit(new)
        self.assertEqual((self.generation(result['revision'])/'credentials/cloudflare.dns_a.key_id').read_bytes(),b'NEW_ID')

    def test_removed_or_unsafe_source_after_preview_is_preserved(self):
        token=self.migration_preview()['confirmation'];self.source.chmod(0o644);self.commit(token,expected=7)
        self.assertEqual(self.source.stat().st_mode&0o777,0o644);self.source.chmod(0o600)
        self.source.unlink();self.commit(token,expected=7);self.assertEqual(self.current(),b'1\n')

    def test_source_symbolic_and_hard_links_refused_without_following(self):
        decoy=self.base/'decoy';decoy.write_bytes(self.source_before);decoy.chmod(0o600)
        self.source.unlink();self.source.symlink_to(decoy);self.migration_preview(expected=7)
        self.assertTrue(self.source.is_symlink());self.source.unlink();os.link(decoy,self.source);self.migration_preview(expected=7)
        self.assertEqual(decoy.read_bytes(),self.source_before);self.assertEqual(self.current(),b'1\n')

    def test_config_parent_permissions_or_symlink_refused(self):
        self.configdir.chmod(0o777);self.migration_preview(expected=7);self.configdir.chmod(0o700)
        renamed=self.etc/'old-config';self.configdir.rename(renamed);self.configdir.symlink_to(renamed,target_is_directory=True)
        self.migration_preview(expected=7);self.assertTrue(self.configdir.is_symlink());self.assertEqual(self.current(),b'1\n')

    def test_unknown_oversized_and_empty_source_refused(self):
        for value in [b'',b'x'*262145,self.source_before+b" option unknown 'PRIVATE_SENTINEL'\n",self.source_before+b'\0']:
            self.source.write_bytes(value);self.migration_preview(expected=7 if len(value)==0 or len(value)>262144 else 1)
            self.assertEqual(self.current(),b'1\n');self.assertFalse((self.store/'pending').exists())

    def test_plain_commit_cannot_bypass_fixed_source_check(self):
        token=self.migration_preview()['confirmation'];self.cli('commit',token,expected=5)
        self.cli('commit-apply',token,expected=5);self.assertEqual(self.current(),b'1\n')
        self.commit(token);self.no_source_changes()

    def test_regular_import_confirmation_cannot_be_used_for_migration(self):
        token=self.preview(self.business)['confirmation'];self.commit(token,expected=5)
        self.assertEqual(self.current(),b'1\n');self.no_source_changes()

    def test_expired_boot_binding_and_cancel_keep_old_source(self):
        token=self.migration_preview()['confirmation'];self.boot_id.write_text('0'*36+'\n');self.commit(token,expected=5)
        self.boot_id.write_text(Path('/proc/sys/kernel/random/boot_id').read_text())
        self.cli('cancel');self.commit(token,expected=5);self.no_source_changes()
        self.assertEqual(self.current(),b'1\n')

    def test_modified_candidate_even_resealed_rejects_original_token(self):
        token=self.migration_preview()['confirmation'];candidate=self.generation(2)
        (candidate/'legacy.conf').write_bytes(self.source_before.replace(b'OLD_ID',b'CHANGED'))
        names=['public.conf','parent','legacy.conf']+[str(p.relative_to(candidate)) for p in sorted((candidate/'credentials').iterdir())]
        (candidate/'manifest').write_text(''.join(hashlib.sha256((candidate/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in names))
        self.commit(token,expected=5);self.assertEqual(self.current(),b'1\n');self.no_source_changes()

    def test_shared_and_supervisor_locks_block_before_capture(self):
        import fcntl
        for path in [self.native.lock,self.store/'.supervisor.lock',self.store/'.lock']:
            with path.open('rb') as fd:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.migration_preview(expected=4)
        self.assertFalse((self.store/'pending').exists());self.no_source_changes()

    def test_dns_presence_barrier_blocks_migration(self):
        path=self.store/'dns-operation';path.mkdir(mode=0o700);self.migration_preview(expected=4)
        self.assertEqual(list(path.iterdir()),[]);self.no_source_changes()

    def test_missing_runtime_lock_not_created(self):
        self.native.lock.unlink();self.migration_preview(expected=7);self.assertFalse(self.native.lock.exists());self.no_source_changes()

    def test_evolved_baseline_cannot_be_replaced_by_migration(self):
        self.commit_body(self.business);before=self.current();self.migration_preview(expected=4)
        self.assertEqual(self.current(),before);self.no_source_changes()

    def test_change_after_capture_rejected_before_preview(self):
        code="if sys.argv[-1]=="+repr(str(self.source))+":\n    import subprocess\n    from pathlib import Path\n    result=subprocess.run(["+repr(self.busybox)+",'head',*sys.argv[1:]])\n    Path(sys.argv[-1]).write_bytes("+repr(self.source_before.replace(b'OLD_ID',b'NEW_ID'))+")\n    sys.exit(result.returncode)"
        self.fault('head',code);self.migration_preview(expected=5);self.restore_tool('head')
        self.assertEqual(self.current(),b'1\n');self.assertFalse((self.store/'pending').exists())

    def test_source_change_during_pointer_fsync_rejected_before_publish(self):
        token=self.migration_preview()['confirmation']
        code="from pathlib import Path\nif len(sys.argv)==2 and Path(sys.argv[1]).name.startswith('.work.') and Path(sys.argv[1]).read_bytes()==b'3\\n':\n    Path("+repr(str(self.source))+").write_bytes("+repr(self.source_before.replace(b'OLD_ID',b'NEW_ID'))+")"
        self.fault('fsync',code);self.commit(token,expected=5);self.restore_tool('fsync')
        self.assertEqual(self.current(),b'1\n');self.assertTrue((self.generation(2)/'legacy.conf').is_file())

    def test_fsync_failure_before_pointer_preserves_preview_for_retry(self):
        token=self.migration_preview()['confirmation'];before=self.pending()
        self.fault('fsync',"if any('/gen-3/' in x and x.endswith('/legacy.conf') for x in sys.argv[1:]): sys.exit(1)")
        self.commit(token,expected=1);self.restore_tool('fsync');self.assertEqual(self.current(),b'1\n')
        self.assertEqual(self.pending(),before);self.commit(token);self.no_source_changes()

    def test_preview_sync_failure_never_returns_confirmation(self):
        self.fault('fsync',"if any(x.endswith('/pending') for x in sys.argv[1:]): sys.exit(1)")
        report=self.migration_preview(expected=7);self.assertNotIn('confirmation',report);self.restore_tool('fsync')
        self.assertEqual(self.current(),b'1\n');token=self.migration_preview()['confirmation'];self.commit(token);self.no_source_changes()

    def test_published_pointer_uncertainty_keeps_complete_backup(self):
        token=self.migration_preview()['confirmation']
        self.fault('fsync',"from pathlib import Path\nif sys.argv[1:]==["+repr(str(self.store))+"] and Path("+repr(str(self.store/'current'))+").read_bytes()==b'3\\n': sys.exit(1)")
        self.commit(token,expected=6);self.restore_tool('fsync');self.assertEqual(self.current(),b'3\n')
        self.assertEqual((self.generation(3)/'legacy.conf').read_bytes(),self.source_before)
        self.commit(token,expected=5);self.no_source_changes()

    def test_kill_before_pointer_keeps_baseline_and_recoverable_candidate(self):
        token=self.migration_preview()['confirmation']
        self.fault('mv',"if sys.argv[-1]=="+repr(str(self.store/'current'))+":\n    os.kill(os.getppid(),signal.SIGKILL)\n    sys.exit(0)")
        self.raw('migration-source-commit',token,expected=-signal.SIGKILL);self.restore_tool('mv')
        self.assertEqual(self.current(),b'1\n');self.no_source_changes()
        self.cli('writer-check',expected=7)  # Abandoned .work remains fenced.

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',action='store_true');args=parser.parse_args()
    cls=Runtime if args.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,value in cls.__dict__.items() if name.startswith('test_') and callable(value))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
