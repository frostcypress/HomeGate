#!/usr/bin/env python3
"""Cold-start runtime preparation in private copies, never system paths."""
import argparse,json,os,subprocess,unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from project import ROOT
from 持久初始化回归 import Runtime as BootstrapRuntime
from 旧配置迁移回归 import LEGACY

PREPARE=ROOT/'project/core/prototype/homegate-lifecycle-prepare.sh'

class Static(unittest.TestCase):
    def test_gate_fixed_commands_and_no_install(self):
        body=PREPARE.read_text(encoding='utf-8')
        self.assertEqual(body.count('runtime_prepare_enabled=false'),1)
        self.assertNotIn('runtime_prepare_enabled=true',body)
        self.assertIn('prepare) bootstrap_action=bootstrap',body)
        self.assertIn('resume) bootstrap_action=resume',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())
        self.assertLess(body.index("fail 'Lifecycle preparation is not ready'"),body.index('owner=$(id -u)'))

    def test_no_destructive_cleanup_or_business(self):
        body=PREPARE.read_text(encoding='utf-8')
        self.assertIn('(set -C; : > "$lock")',body)
        self.assertIn('check_binding\nflock -n 6',body)
        self.assertIn('exec 6>&- 7>&- 8>&- 9>&-',body)
        self.assertNotRegex(body,r'(?m)^\s*(?:chmod|chown|kill|curl|wget|uci|service|reboot|eval|source)\b')
        # Cold prepare cannot delete. Explicit record apply/cancel may remove
        # only its checked context and then its empty private intent directory.
        import tree_sitter,tree_sitter_bash
        root=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language())).parse(body.encode()).root_node
        cleanup=body.index('if [ "$record_action" = apply ] || [ "$record_action" = cancel ];then')
        end=body.index('\n        record_validate || fail',cleanup)
        removals=[]
        def inspect(node):
            if node.type=='command':
                name=node.child_by_field_name('name')
                if name and name.text in [b'rm',b'rmdir']:
                    removals.append(node.text.decode())
                    self.assertGreaterEqual(node.start_byte,len(body[:cleanup].encode()))
                    self.assertLess(node.end_byte,len(body[:end].encode()))
            for child in node.named_children:inspect(child)
        inspect(root)
        self.assertEqual(removals,['rm -f "$record_path/context"','rmdir "$record_path"'])
        self.assertIn('record="$store/startup-intent";record_stage="$store/.startup-intent-next"',body)
        self.assertIn('if ! record_validate;then',body[cleanup:end])
        self.assertIn('private_dir "$record_path" && [ -z "$(ls -A "$record_path")" ]',body[cleanup:end])
        self.assertIn('startup_recheck',body[cleanup:end])
        self.assertIn('readers_switched":false',body)
        self.assertIn('production_ready":false',body)

    def test_shell_grammar(self):
        import tree_sitter,tree_sitter_bash
        body=PREPARE.read_bytes();self.assertNotIn(b'\r',body)
        tree=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language())).parse(body)
        self.assertFalse(tree.root_node.has_error)

def configure_runtime_fixture(self,extra_files=()):
    old=self.native.lockdir
    self.runtime_parent=self.native.system
    self.native.lockdir=self.runtime_parent/'homegate'
    self.native.lock=self.native.lockdir/'frontend.lock'
    for file in [self.engine,self.bootstrap,self.native.engine,self.native.boot,*extra_files]:
        file.write_text(file.read_text(encoding='utf-8').replace(str(old),str(self.native.lockdir)),encoding='utf-8')
    (old/'frontend.lock').unlink();old.rmdir()
    self.var=self.base/'var';self.var.mkdir(mode=0o700)
    self.tmp=self.base/'tmp';self.tmp.mkdir(mode=0o1777);self.tmp.chmod(0o1777)
    self.alias=self.var/'run';self.alias.symlink_to(self.runtime_parent,target_is_directory=True)
    self.prepare_script=self.engine.parent/PREPARE.name
    body=PREPARE.read_text(encoding='utf-8').replace('runtime_prepare_enabled=false','runtime_prepare_enabled=true')
    for old,value in [('var_root=/var',self.var),('tmp_root=/tmp',self.tmp),('run_alias=/var/run',self.alias),('linux_run=/run',self.runtime_parent)]:
        body=body.replace(old,old.split('=',1)[0]+'='+str(value))
    body=body.replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
    self.prepare_script.write_text(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)),encoding='utf-8')

class Runtime(BootstrapRuntime):
    def setUp(self):
        super().setUp()
        configure_runtime_fixture(self)

    def run_prepare(self,*args,expected=0,env=None):
        p=subprocess.run([self.busybox,'ash',str(self.prepare_script),*(args or ('prepare',))],env=env or self.env,capture_output=True,timeout=15)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr));self.assertEqual(p.stderr,b'')
        self.assertLess(len(p.stdout),1024);self.assertNotIn(b'PRIVATE_SENTINEL',p.stdout)
        if expected<0:return p
        r=json.loads(p.stdout);self.assertEqual(r['ok'],expected==0);return r

    def test_empty_cold_start_initializes_runtime_then_persistent_baseline(self):
        r=self.run_prepare();self.assertTrue(r['runtime_ready']);self.assertTrue(r['baseline_ready'])
        self.assertFalse(r['production_ready']);self.assertFalse(r['readers_switched'])
        self.assertEqual(self.native.lockdir.stat().st_mode&0o777,0o700)
        self.assertEqual(self.native.lock.stat().st_mode&0o777,0o600)
        self.assertEqual(self.native.lock.read_bytes(),b'');self.assertEqual(self.cli('status')['revision'],1)
        self.assertEqual(self.legacy.read_bytes(),b'PRIVATE_SENTINEL legacy unchanged\n')

    def test_repeated_prepare_preserves_runtime_and_store_inodes_and_bytes(self):
        self.run_prepare();before=self.contents();lock_inode=self.native.lock.stat().st_ino;dir_inode=self.native.lockdir.stat().st_ino
        for action in ['prepare','resume','prepare']:self.run_prepare(action)
        self.assertEqual(self.contents(),before);self.assertEqual(self.native.lock.stat().st_ino,lock_inode)
        self.assertEqual(self.native.lockdir.stat().st_ino,dir_inode);self.writer()

    def test_active_writer_is_busy_and_original_lock_remains(self):
        import fcntl
        self.run_prepare();inode=self.native.lock.stat().st_ino;before=self.contents()
        with self.native.lock.open('rb') as fd:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.run_prepare(expected=4)
        self.assertEqual(self.native.lock.stat().st_ino,inode);self.assertEqual(self.contents(),before)
        self.run_prepare()

    def test_inherited_active_writer_cannot_borrow_around_busy(self):
        import fcntl
        self.run_prepare()
        with self.native.lock.open('rb') as fd:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            launch='import os,sys; os.dup2(int(sys.argv[1]),6,inheritable=True); os.execv(sys.argv[2],sys.argv[2:])'
            p=subprocess.run([os.sys.executable,'-c',launch,str(fd.fileno()),self.busybox,'ash',str(self.prepare_script),'prepare'],pass_fds=(fd.fileno(),),env=self.env,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,4,(p.stdout,p.stderr))

    def test_concurrent_initializers_keep_one_lock_and_one_identity(self):
        def once(_):
            return subprocess.run([self.busybox,'ash',str(self.prepare_script),'prepare'],env=self.env,capture_output=True,timeout=15)
        with ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(once,range(6)))
        self.assertTrue(any(p.returncode==0 for p in results))
        for p in results:self.assertIn(p.returncode,[0,4],(p.stdout,p.stderr));self.assertEqual(p.stderr,b'')
        inode=self.native.lock.stat().st_ino;identity=(self.store/'identity').read_bytes()
        self.run_prepare();self.assertEqual(self.native.lock.stat().st_ino,inode);self.assertEqual((self.store/'identity').read_bytes(),identity)

    def test_system_var_to_tmp_layout(self):
        self.alias.unlink();self.var.rmdir();self.var.symlink_to(self.tmp,target_is_directory=True)
        runtime=self.tmp/'run';runtime.mkdir(mode=0o755)
        # Consumers follow the same physical lock as the system alias.
        for file in [self.engine,self.bootstrap,self.native.engine,self.native.boot]:
            file.write_text(file.read_text().replace(str(self.native.lockdir),str(runtime/'homegate')))
        self.run_prepare();self.assertTrue((runtime/'homegate/frontend.lock').is_file())
        self.assertFalse(self.native.lockdir.exists())

    def test_real_var_run_layout(self):
        self.alias.unlink();self.alias.mkdir(mode=0o755)
        for file in [self.engine,self.bootstrap,self.native.engine,self.native.boot]:
            file.write_text(file.read_text().replace(str(self.native.lockdir),str(self.alias/'homegate')))
        self.run_prepare();self.assertTrue((self.alias/'homegate/frontend.lock').is_file())

    def test_unsupported_alias_or_var_layout_refused(self):
        decoy=self.base/'decoy';decoy.mkdir(mode=0o700)
        self.alias.unlink();self.alias.symlink_to(decoy,target_is_directory=True);self.run_prepare(expected=7)
        self.assertEqual(list(decoy.iterdir()),[]);self.assertFalse(self.store.exists())

    def test_world_writable_runtime_parent_refused(self):
        self.runtime_parent.chmod(0o777);self.run_prepare(expected=7)
        self.assertFalse(self.native.lockdir.exists());self.assertFalse(self.store.exists());self.runtime_parent.chmod(0o700)

    def test_nonsticky_shared_tmp_parent_refused_for_runtime_alias(self):
        runtime=self.tmp/'run';runtime.mkdir(mode=0o700)
        self.alias.unlink();self.alias.symlink_to(runtime,target_is_directory=True)
        self.tmp.chmod(0o777);self.run_prepare(expected=7)
        self.assertEqual(list(runtime.iterdir()),[]);self.assertFalse(self.store.exists())
        self.tmp.chmod(0o1777)

    def test_existing_runtime_permissions_never_repaired(self):
        self.native.lockdir.mkdir(mode=0o755);self.run_prepare(expected=7)
        self.assertEqual(self.native.lockdir.stat().st_mode&0o777,0o755);self.assertFalse(self.native.lock.exists())

    def test_runtime_symlink_refused_and_target_preserved(self):
        target=self.base/'decoy';target.mkdir(mode=0o700);self.native.lockdir.symlink_to(target,target_is_directory=True)
        self.run_prepare(expected=7);self.assertEqual(list(target.iterdir()),[]);self.assertTrue(self.native.lockdir.is_symlink())

    def test_lock_symlink_hardlink_permissions_and_content_refused(self):
        self.native.lockdir.mkdir(mode=0o700);decoy=self.base/'decoy';decoy.touch(mode=0o600)
        self.native.lock.symlink_to(decoy);self.run_prepare(expected=7);self.native.lock.unlink()
        os.link(decoy,self.native.lock);self.run_prepare(expected=7);self.native.lock.unlink()
        self.native.lock.touch(mode=0o644);self.run_prepare(expected=7);self.native.lock.chmod(0o600)
        self.native.lock.write_bytes(b'PRIVATE_SENTINEL');self.run_prepare(expected=7)
        self.assertEqual(self.native.lock.read_bytes(),b'PRIVATE_SENTINEL');self.assertFalse(self.store.exists())

    def test_gate_and_extra_arguments_refuse_before_creating_anything(self):
        for args in [('prepare','extra'),('other',)]:self.run_prepare(*args,expected=2)
        self.prepare_script.write_text(self.prepare_script.read_text().replace('runtime_prepare_enabled=true','runtime_prepare_enabled=false'))
        self.run_prepare(expected=2,env={**self.env,'runtime_prepare_enabled':'true','HOMEGATE_RUNTIME_PREPARE_ENABLED':'1'})
        self.assertFalse(self.native.lockdir.exists());self.assertFalse(self.store.exists())

    def test_environment_cannot_redirect_or_inject_lua(self):
        decoy=self.base/'decoy';decoy.mkdir(mode=0o700)
        self.run_prepare(env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(decoy),'IPKG_INSTROOT':str(decoy),'LUA_INIT':"error('PRIVATE_SENTINEL')"})
        self.assertEqual(list(decoy.iterdir()),[])

    def test_unrelated_runtime_entries_not_deleted(self):
        self.native.lockdir.mkdir(mode=0o700);other=self.native.lockdir/'unrelated';other.write_bytes(b'PRIVATE_SENTINEL');other.chmod(0o600)
        self.run_prepare();self.assertEqual(other.read_bytes(),b'PRIVATE_SENTINEL')

    def test_mkdir_failure_preserves_absence(self):
        self.fault('mkdir',"if sys.argv[1:]==["+repr(str(self.native.lockdir))+"]: sys.exit(1)")
        self.run_prepare(expected=7);self.restore_tool('mkdir');self.assertFalse(self.native.lockdir.exists());self.assertFalse(self.store.exists())

    def test_lock_replacement_between_open_and_flock_refused(self):
        code="if sys.argv[1:]==['-n','6']:\n    from pathlib import Path\n    p=Path("+repr(str(self.native.lock))+")\n    p.unlink(); p.touch(mode=0o600)"
        self.fault('flock',code);self.run_prepare(expected=7);self.restore_tool('flock');self.assertFalse(self.store.exists())

    def test_bootstrap_gate_failure_preserves_created_lock_for_retry(self):
        original=self.bootstrap.read_text();self.bootstrap.write_text(original.replace('bootstrap_enabled=true','bootstrap_enabled=false'))
        self.run_prepare(expected=2);inode=self.native.lock.stat().st_ino;self.assertFalse(self.store.exists())
        self.bootstrap.write_text(original);self.run_prepare();self.assertEqual(self.native.lock.stat().st_ino,inode)

    def test_partial_persistent_stage_requires_explicit_resume(self):
        self.fault('mv',"if sys.argv[1:]==["+repr(str(self.stage))+','+repr(str(self.store))+"]: sys.exit(1)")
        self.run_prepare(expected=7);self.restore_tool('mv');self.assertTrue(self.stage.exists());inode=self.native.lock.stat().st_ino
        self.run_prepare(expected=7);self.run_prepare('resume');self.assertEqual(self.native.lock.stat().st_ino,inode)

    def test_active_persistent_barrier_is_not_cleared(self):
        self.run_prepare();self.commit_body(self.business);self.secret(b'PRIVATE_SENTINEL');self.begin()
        before=self.contents();self.run_prepare(expected=4);self.assertEqual(self.contents(),before)

    def test_published_durability_failure_propagates_then_resume(self):
        self.fault('fsync',"if sys.argv[1:]==["+repr(str(self.store))+','+repr(str(self.home))+"]: sys.exit(1)")
        self.run_prepare(expected=6);self.restore_tool('fsync');self.assertTrue((self.store/'bootstrap-pending').is_file())
        self.cli('writer-check',expected=4);self.run_prepare('resume');self.cli('writer-check')

    def test_prepared_runtime_migration_and_same_generation_private_read(self):
        self.run_prepare();configdir=self.etc/'config';configdir.mkdir(mode=0o700)
        source=configdir/'homegate';source.write_bytes(LEGACY.encode());source.chmod(0o600)
        self.engine.write_text(self.engine.read_text().replace('lifecycle_migration_enabled=false','lifecycle_migration_enabled=true'))
        token=self.cli('migration-source-preview')['confirmation'];r=self.cli('migration-source-commit',token)
        command=[self.busybox,'ash','-c','exec 3>&1; exec "$@" >/dev/null','--',self.busybox,'ash',str(self.engine),'--persistent','snapshot-read']
        p=subprocess.run(command,env=self.env,capture_output=True,timeout=10);self.assertEqual(p.returncode,0,p.stderr)
        from 私有配置读取回归 import Runtime as PrivateRuntime
        frame=PrivateRuntime.decode(self,p.stdout)
        self.assertEqual(frame[b'revision'],r['revision']);self.assertEqual(frame[b'credentials'][b'cloudflare.dns_a.secret'],b'SECRET_SENTINEL')
        self.assertEqual(source.read_bytes(),LEGACY.encode());before=self.contents();self.run_prepare();self.assertEqual(self.contents(),before)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,value in cls.__dict__.items() if name.startswith('test_') and callable(value))
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if r.wasSuccessful() else 1)
