#!/usr/bin/env python3
"""Lifecycle bootstrap in copied private Linux namespaces; never a router install."""
import argparse, hashlib, json, os, re, shutil, signal, subprocess, unittest
from pathlib import Path
from project import ROOT
from 持久事务屏障回归 import Runtime as PersistentRuntime

BOOTSTRAP=ROOT/'project/core/prototype/homegate-store-bootstrap-prototype.sh'

class Static(unittest.TestCase):
    def test_gate_fixed_paths_and_no_production_install(self):
        body=BOOTSTRAP.read_text(encoding='utf-8')
        self.assertEqual(body.count('bootstrap_enabled=false'),1)
        self.assertNotIn('bootstrap_enabled=true',body)
        self.assertIn('store=/etc/homegate/transactions',body)
        self.assertIn('stage=/etc/homegate/.transactions-bootstrap',body)
        self.assertIn('unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_shell_grammar_and_no_business_or_recursive_removal(self):
        import tree_sitter,tree_sitter_bash
        body=BOOTSTRAP.read_bytes(); self.assertNotIn(b'\r',body)
        tree=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language())).parse(body)
        self.assertFalse(tree.root_node.has_error)
        nodes=[tree.root_node]
        while nodes:
            node=nodes.pop()
            self.assertNotIn(node.type,{'process_substitution','herestring_redirect','array','c_style_for_statement'})
            if node.type=='command':
                name=node.child_by_field_name('name')
                if name:
                    self.assertNotIn(body[name.start_byte:name.end_byte].decode(),{'eval','.','source','uci','curl','wget','service','nft','ip6tables','reboot','chmod','chown'})
            nodes.extend(node.named_children)
        self.assertNotRegex(body.decode(),r'rm\s+-[\w]*r')
        self.assertNotRegex(body.decode(),r'(?m)^\s*trap\s','Interrupted state must be retained')

    def test_sync_and_explicit_resume_contract(self):
        body=BOOTSTRAP.read_text()
        publication=body.rsplit('\nsync_stage\n',1)[1]
        self.assertLess(publication.index('mv "$stage" "$store"'),publication.index('Published bootstrap durability is uncertain'))
        self.assertIn('[ "$action" = resume ]',body)
        self.assertIn('check_stage\nelse',body)
        self.assertIn('existing_store\n    exit 0',body)

class Runtime(PersistentRuntime):
    # Inherit fixture utilities, not the previous stage's test collection.
    def setUp(self):
        super().setUp()
        assert self.store.resolve().is_relative_to(self.base.resolve())
        shutil.rmtree(self.store)
        self.stage=self.home/'.transactions-bootstrap'
        self.bootstrap=self.engine.parent/BOOTSTRAP.name
        wrapper=self.base/'config-transaction'
        wrapper.write_text('#!/bin/sh\nexec '+self.busybox+' ash '+str(self.engine)+' "$@"\n'); wrapper.chmod(0o700)
        body=BOOTSTRAP.read_text().replace('bootstrap_enabled=false','bootstrap_enabled=true')
        mapping={'/etc/homegate/transactions':str(self.store),'/etc/homegate/.transactions-bootstrap':str(self.stage),
                 '/etc/homegate':str(self.home),'/etc':str(self.etc),'/var/run/homegate':str(self.native.lockdir),
                 '/usr/libexec/homegate/config-transaction':str(wrapper)}
        body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
        body=body.replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
        body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))
        self.bootstrap.write_text(body,encoding='utf-8')
        self.legacy=self.etc/'legacy.conf'; self.legacy.write_bytes(b'PRIVATE_SENTINEL legacy unchanged\n'); self.legacy.chmod(0o600)

    def boot(self,*args,expected=0,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.bootstrap),*(args or ('bootstrap',))],env=env or self.env,capture_output=True,timeout=15)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr)); self.assertEqual(p.stderr,b'')
        self.assertLess(len(p.stdout),1024); self.assertNotIn(b'PRIVATE_SENTINEL',p.stdout)
        if expected>=0:
            response=json.loads(p.stdout); self.assertEqual(response['ok'],expected==0)
            return response
        return p

    def ready_stage(self):
        self.fault('mv',"sys.exit(1) if sys.argv[1:]==["+repr(str(self.stage))+','+repr(str(self.store))+"] else None")
        self.boot(expected=7); self.restore_tool('mv'); self.assertTrue(self.stage.is_dir()); self.assertFalse(self.store.exists())

    def contents(self,path=None):
        base=path or self.store
        return {str(p.relative_to(base)):(p.stat().st_mode&0o777,p.stat().st_ino,p.read_bytes() if p.is_file() else None)
                for p in base.rglob('*')}

    def test_initial_baseline_real_engine_and_all_native_routes(self):
        report=self.boot(); self.assertTrue(report['created']); self.assertFalse(report['legacy_migrated']); self.assertFalse(report['production_ready'])
        self.assertFalse(self.stage.exists()); self.assertEqual(self.cli('status')['revision'],1)
        self.assertIn(b"option enabled '0'",self.export())
        self.assertEqual(list((self.store/'gen-1/credentials').iterdir()),[])
        from 原生写入协调回归 import route_map
        for route in route_map(): self.writer(route=route)
        self.assertEqual(self.legacy.read_bytes(),b'PRIVATE_SENTINEL legacy unchanged\n')

    def test_private_permissions_and_no_identity_in_public_response(self):
        report=self.boot()
        for p in [self.store,*self.store.rglob('*')]: self.assertEqual(p.stat().st_mode&0o777,0o700 if p.is_dir() else 0o600)
        identity=(self.store/'identity').read_text().splitlines()[4]
        self.assertRegex(identity,r'^[a-f0-9]{32}$'); self.assertNotIn(identity,json.dumps(report))
        self.assertNotIn(str(self.store),json.dumps(report))

    def test_repeated_bootstrap_keeps_all_bytes_identity_and_lock_inodes(self):
        self.boot(); before=self.contents()
        for action in ['bootstrap','resume','bootstrap']: self.assertFalse(self.boot(action)['created'])
        self.assertEqual(self.contents(),before)

    def test_existing_evolved_store_is_not_reinitialized(self):
        self.boot(); self.commit_body(self.business); self.secret(b'PRIVATE_SENTINEL')
        before=self.contents(); self.assertFalse(self.boot()['created']); self.assertEqual(self.contents(),before)
        self.assertEqual(self.cli('status')['revision'],3)

    def test_gate_cannot_be_enabled_by_environment(self):
        self.bootstrap.write_text(self.bootstrap.read_text().replace('bootstrap_enabled=true','bootstrap_enabled=false'))
        self.boot(expected=2,env={**self.env,'bootstrap_enabled':'true','HOMEGATE_BOOTSTRAP_ENABLED':'1'})
        self.assertFalse(self.store.exists()); self.assertFalse(self.stage.exists())

    def test_fixed_arguments_and_environment_cannot_redirect_or_load_lua(self):
        decoy=self.base/'decoy'; decoy.mkdir(mode=0o700)
        for args in [('bootstrap',str(decoy)),('other',),('--store',str(decoy))]: self.boot(*args,expected=2)
        self.boot(env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(decoy),'IPKG_INSTROOT':str(decoy),'LUA_INIT':"error('PRIVATE_SENTINEL')"})
        self.assertEqual(list(decoy.iterdir()),[])

    def test_missing_runtime_lock_is_never_replaced(self):
        self.native.lock.unlink(); self.boot(expected=7); self.assertFalse(self.native.lock.exists()); self.assertFalse(self.store.exists())

    def test_shared_lock_busy_before_any_creation_and_released_after_success(self):
        import fcntl
        with self.native.lock.open('rb') as fd:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); self.boot(expected=4)
        self.assertFalse(self.stage.exists()); self.boot(); self.writer()

    def test_absent_parent_is_created_private_and_synchronized(self):
        self.home.rmdir(); self.boot(); self.assertEqual(self.home.stat().st_mode&0o777,0o700); self.cli('writer-check')

    def test_unsafe_parent_and_store_symlinks_are_not_changed(self):
        self.home.chmod(0o755); self.boot(expected=7); self.assertEqual(self.home.stat().st_mode&0o777,0o755); self.home.chmod(0o700)
        decoy=self.base/'decoy'; decoy.mkdir(mode=0o700); self.store.symlink_to(decoy,target_is_directory=True)
        self.boot(expected=7); self.assertTrue(self.store.is_symlink()); self.assertEqual(list(decoy.iterdir()),[])

    def test_incomplete_stage_is_preserved_and_never_published(self):
        self.stage.mkdir(mode=0o700); (self.stage/'partial').write_bytes(b'PRIVATE_SENTINEL')
        before=self.contents(self.stage)
        self.boot(expected=7); self.boot('resume',expected=7)
        self.assertEqual(self.contents(self.stage),before); self.assertFalse(self.store.exists())

    def test_complete_stage_requires_explicit_resume_then_same_identity(self):
        self.ready_stage(); identity=(self.stage/'identity').read_bytes(); before=self.contents(self.stage)
        self.boot(expected=7); self.assertEqual(self.contents(self.stage),before)
        self.boot('resume'); self.assertEqual((self.store/'identity').read_bytes(),identity); self.cli('writer-check')

    def test_stage_corruption_hidden_files_and_hardlinks_refused(self):
        self.ready_stage(); identity=(self.stage/'identity').read_bytes()
        p=self.stage/'.hidden'; p.write_bytes(b'PRIVATE_SENTINEL'); self.boot('resume',expected=7); p.unlink()
        p=self.stage/'gen-1/credentials/.hidden'; p.write_bytes(b'PRIVATE_SENTINEL'); self.boot('resume',expected=7); p.unlink()
        p=self.stage/'identity'; p.write_bytes(identity+b'\n'); self.boot('resume',expected=7); p.write_bytes(identity)
        p=self.stage/'bootstrap-receipt'; original=p.read_bytes()
        p.write_bytes(original[:-1]+b'\x00'); self.boot('resume',expected=7); p.write_bytes(original)
        p=self.stage/'gen-1/public.conf'; original=p.read_bytes()
        p.write_bytes(original[:-1]+b'\x00')
        self.boot('resume',expected=7); self.assertFalse(self.store.exists()); p.write_bytes(original)
        p=self.stage/'identity'
        alias=self.base/'identity-link'; os.link(p,alias); self.boot('resume',expected=7); alias.unlink()
        self.boot('resume')

    def test_conflicting_stage_and_store_preserved(self):
        self.boot(); before=self.contents(); self.stage.mkdir(mode=0o700)
        self.boot(expected=7); self.boot('resume',expected=7); self.assertEqual(self.contents(),before); self.assertTrue(self.stage.exists())

    def test_existing_identity_and_receipt_corruption_never_repaired(self):
        self.boot()
        for name in ['identity','bootstrap-receipt']:
            p=self.store/name; original=p.read_bytes(); p.write_bytes(b'PRIVATE_SENTINEL\n')
            self.boot(expected=7); self.assertEqual(p.read_bytes(),b'PRIVATE_SENTINEL\n'); p.write_bytes(original)
        self.boot()

    def test_missing_existing_lock_not_recreated(self):
        self.boot(); p=self.store/'.lock'; p.unlink(); self.boot(expected=7); self.assertFalse(p.exists())

    def test_active_application_and_orphan_fence_not_cleared(self):
        self.boot(); self.commit_body(self.business); self.begin(); fence=self.fence()
        self.boot(expected=4); self.assertEqual(self.fence(),fence)
        (self.store/'application').unlink(); self.boot(expected=7); self.assertEqual(self.fence(),fence)

    def test_sync_failure_before_publish_retains_stage_for_explicit_resume(self):
        self.fault('fsync',"sys.exit(1) if "+repr(str(self.stage/'bootstrap-receipt'))+" in sys.argv[1:] else None")
        self.boot(expected=7); self.assertFalse(self.store.exists()); self.assertTrue(self.stage.exists())
        self.restore_tool('fsync'); self.boot('resume'); self.cli('writer-check')

    def test_sync_failure_after_publish_retains_store_and_retry_resynchronizes(self):
        self.fault('fsync',"sys.exit(1) if sys.argv[1:]==["+repr(str(self.store))+','+repr(str(self.home))+"] else None")
        self.boot(expected=6); self.assertTrue(self.store.exists()); self.assertFalse(self.stage.exists()); before=self.contents()
        self.restore_tool('fsync'); self.assertFalse(self.boot()['created']); self.assertEqual(self.contents(),before)

    def test_kill_before_publish_preserves_sealed_stage(self):
        self.fault('mv',"if sys.argv[1:]==["+repr(str(self.stage))+','+repr(str(self.store))+"]:\n    os.kill(os.getppid(),signal.SIGKILL)\n    sys.exit(0)")
        self.boot(expected=-signal.SIGKILL); self.restore_tool('mv'); self.assertTrue(self.stage.exists()); self.assertFalse(self.store.exists())
        self.boot('resume'); self.writer()

    def test_kill_during_early_bootstrap_never_creates_ready_store(self):
        self.fault('head',"if '/dev/urandom' in sys.argv[1:]:\n    os.kill(os.getppid(),signal.SIGKILL)\n    sys.exit(0)")
        self.boot(expected=-signal.SIGKILL); self.restore_tool('head'); self.assertFalse(self.store.exists()); self.assertTrue(self.stage.exists())
        self.boot('resume',expected=7); self.assertFalse(self.store.exists())

# unittest includes inherited tests by default; run only this stage's own methods.
if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--runtime',action='store_true'); a=p.parse_args()
    cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,value in cls.__dict__.items() if name.startswith('test_') and callable(value))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
