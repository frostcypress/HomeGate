#!/usr/bin/env python3
"""Fixed persistent namespace/fences in private Linux copies; no router changes.
Real ash/flock/fsync/rename/kill/Lua51/jsonc; UCI/services remain explicit fixtures.
"""
import argparse,hashlib,json,os,re,shutil,signal,subprocess,time,unittest
from pathlib import Path
from project import ROOT
from 配置事务原型回归 import SCRIPT
from 完整配置事务回归 import Runtime as FullRuntime
from 原生写入协调回归 import Runtime as NativeRuntime,SHELL,route_map

class Static(unittest.TestCase):
    def test_fixed_gates_namespace_and_no_bootstrap(self):
        body=SCRIPT.read_text()
        self.assertEqual(body.count('persistent_namespace_enabled=false'),1)
        self.assertNotIn('persistent_namespace_enabled=true',body)
        self.assertIn('store=/etc/homegate/transactions',body)
        self.assertIn('HGSTORE1',body); self.assertIn('HGWRITEFENCE1',body)
        self.assertIn('Persistent bootstrap requires lifecycle migration',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_shell_syntax_and_guard_before_controller(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for file in [SCRIPT,SHELL]:
            self.assertNotIn(b'\r',file.read_bytes())
            self.assertFalse(parser.parse(file.read_bytes()).root_node.has_error)
        native=SHELL.read_text(); check=native.index('/usr/libexec/homegate/config-transaction --persistent writer-check')
        self.assertLess(native.index('flock -n 6'),check)
        self.assertLess(native.index('unset IPKG_INSTROOT'),check)
        self.assertLess(check,native.index('exec /usr/bin/lua'))

    def test_fence_precedes_journal_and_settlement_follows_durable_removal(self):
        body=SCRIPT.read_text()
        begin=body.split('journal_begin() {',1)[1].split('journal_need() {',1)[0]
        self.assertLess(begin.index('persistent_fence_write active'),begin.index('journal_write prepared'))
        close=body.split('journal_close() {',1)[1].split('\n}',1)[0]
        self.assertLess(close.index('rm -f "$store/application"'),close.index('Application completion durability is uncertain'))
        self.assertLess(close.index('Application completion durability is uncertain'),close.index('persistent_fence_write "settled-'))

class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FullRuntime.setUpClass.__func__(cls)
        NativeRuntime.setUpClass()

    cli=FullRuntime.cli
    export=FullRuntime.export
    preview=FullRuntime.preview
    commit_body=FullRuntime.commit_body
    secret=FullRuntime.secret
    fault=FullRuntime.fault
    restore_tool=FullRuntime.restore_tool

    def setUp(self):
        FullRuntime.setUp(self)
        self.native=NativeRuntime(); self.native.setUp()
        self.etc=self.base/'etc'; self.home=self.etc/'homegate'
        self.etc.mkdir(mode=0o700); self.home.mkdir(mode=0o700)
        target=self.home/'transactions'
        assert self.store.resolve().is_relative_to(self.base.resolve()) and target.resolve().is_relative_to(self.base.resolve())
        shutil.move(str(self.store),target); self.store=target
        self.env['HOMEGATE_CONFIG_PROTO_STORE']=str(self.store)
        fixture=self.base/'source/project/core/prototype'; shutil.copytree(SCRIPT.parent,fixture)
        backup=fixture.parent.parent/'luci/lua/luasrc/model/homegate'; backup.mkdir(parents=True)
        shutil.copy2(ROOT/'project/luci/lua/luasrc/model/homegate/backup.lua',backup/'backup.lua')
        self.engine=fixture/SCRIPT.name
        self.boot_id=self.base/'boot-id'; self.boot_id.write_text(Path('/proc/sys/kernel/random/boot_id').read_text()); self.boot_id.chmod(0o600)
        body=self.engine.read_text().replace('persistent_namespace_enabled=false','persistent_namespace_enabled=true')
        mapping={'/etc/homegate/transactions':str(self.store),'/etc/homegate':str(self.home),'/etc':str(self.etc),
                 '/var/run/homegate':str(self.native.lockdir),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body)
        body=body.replace('[ "$owner" = 0 ]','[ "$owner" = '+str(os.getuid())+' ]')
        body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))
        self.engine.write_text(body,encoding='utf-8')
        self.store_id='a'*32
        self.identity=self.store/'identity'; self.write_identity()
        native=self.native.engine.read_text()
        self.assertIn('/bin/true >/dev/null 2>&1',native)
        native=native.replace('/bin/true >/dev/null 2>&1',self.busybox+' ash '+str(self.engine)+' --persistent writer-check >/dev/null 2>&1')
        native=native.replace('PATH='+str(Path(self.busybox).parent)+':/usr/bin:/bin','PATH='+str(self.bin)+':/usr/bin:/bin')
        self.native.engine.write_text(native)

    def tearDown(self):
        if hasattr(self,'native'): self.native.tearDown()
        FullRuntime.tearDown(self)

    def write_identity(self,*,path=None,identity=None):
        payload=('\n'.join(['HGSTORE1','homegate','public-uci-v1',str(path or self.store),identity or self.store_id])+'\n').encode()
        self.identity.write_bytes(payload+hashlib.sha256(payload).hexdigest().encode()+b'\n'); self.identity.chmod(0o600)
        for path in [self.identity,self.store]:
            fd=os.open(path,os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)

    def raw(self,*args,payload=None,expected=0,env=None):
        engine=getattr(self,'engine',SCRIPT); mode='--persistent' if hasattr(self,'engine') else '--public-uci'
        result=subprocess.run([self.busybox,'ash',str(engine),mode,*args],input=payload,capture_output=True,env=env or self.env,timeout=15)
        self.assertEqual(result.returncode,expected,(args,result.stdout,result.stderr)); self.assertEqual(result.stderr,b'')
        self.assertNotIn(b'PRIVATE_SENTINEL',result.stdout); return result.stdout

    def begin(self,*,intent=False):
        self.plan=self.preview(self.business.replace(b"option https_port '443'",b"option https_port '8443'"))
        args=('commit-apply-intent',self.plan['confirmation'],'1','0') if intent else ('commit-apply',self.plan['confirmation'])
        report=self.cli(*args); self.handle=report['apply_handle']; self.target=report['revision']
        self.assertFalse(report['business_applied']); return report

    def writer(self,code=0,route='basic_apply'):
        self.native.trace.write_text('')
        result=self.native.run_request(self.native.request(route),code)
        if code: self.assertEqual(self.native.trace.read_text(),'')
        return result

    def fence(self): return (self.store/'write-fence').read_bytes()

    def test_ready_guard_is_bound_and_does_not_export_identity_or_secrets(self):
        self.secret(b'PRIVATE_SENTINEL')
        for _ in range(2):
            report=self.cli('writer-check'); self.assertTrue(report['write_ready'])
            self.assertNotIn(self.store_id,json.dumps(report)); self.assertNotIn(str(self.store),json.dumps(report))
        self.assertTrue(self.writer()['ok'])

    def test_environment_cannot_redirect_namespace_or_inject_lua(self):
        decoy=self.base/'decoy'; decoy.mkdir(mode=0o700)
        self.cli('writer-check',env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(decoy),'LUA_INIT':"error('PRIVATE_SENTINEL')"})
        self.assertEqual(list(decoy.iterdir()),[])

    def test_missing_identity_and_locks_are_never_initialized_by_request(self):
        original=self.identity.read_bytes(); self.identity.unlink(); self.writer(7); self.assertFalse(self.identity.exists())
        self.identity.write_bytes(original); self.identity.chmod(0o600)
        for name in ['.lock','.supervisor.lock']:
            p=self.store/name; p.unlink(); self.writer(7); self.assertFalse(p.exists()); p.touch(mode=0o600)
        self.cli('init',expected=2)

    def test_identity_framing_checksum_path_and_permissions_fail_closed(self):
        original=self.identity.read_bytes()
        for bad in [original+b'\n',original.replace(b'HGSTORE1',b'HGSTORE9'),original.replace(b'a'*32,b'b'*32)]:
            self.identity.write_bytes(bad); self.writer(7)
        self.write_identity(path=self.base); self.writer(7); self.write_identity()
        self.identity.chmod(0o644); self.writer(7); self.identity.chmod(0o600)
        link=self.store/'identity-link'; os.link(self.identity,link); self.writer(7); link.unlink()

    def test_private_parent_and_identity_symlink_refused(self):
        self.home.chmod(0o755); self.writer(7); self.home.chmod(0o700)
        original=self.identity.read_bytes(); self.identity.unlink(); self.identity.symlink_to(self.native.config)
        self.writer(7); self.identity.unlink(); self.identity.write_bytes(original); self.identity.chmod(0o600)

    def test_shared_flock_blocks_persistent_and_native_before_cursor(self):
        import fcntl
        with self.native.lock.open('rb') as fd:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.cli('writer-check',expected=4); self.writer(4)
        self.assertTrue(self.writer()['ok'])

    def test_active_application_blocks_all_native_routes_and_transaction_writers(self):
        self.begin(); before=self.fence(); current=(self.store/'current').read_bytes()
        for route in route_map(): self.writer(4,route)
        for args in [('writer-check',),('preview',),('cancel',),('credential-delete','cloudflare','dns_a','secret')]:
            self.cli(*args,expected=4)
        status=self.cli('status'); self.assertTrue(status['persistent_fence_pending']); self.assertEqual(status['application_phase'],'applying')
        self.assertEqual(self.fence(),before); self.assertEqual((self.store/'current').read_bytes(),current)

    def test_corrupt_application_never_loads_native_cursor(self):
        self.begin(); (self.store/'application').write_bytes(b'PRIVATE_SENTINEL\n'); self.writer(7)
        self.assertIn(b'active\n',self.fence())

    def test_worker_presence_and_unsafe_worker_fail_closed(self):
        worker=self.store/'worker'; worker.write_bytes(b'PRIVATE_SENTINEL'); worker.chmod(0o600)
        self.writer(4); worker.chmod(0o644); self.writer(7)

    def test_missing_or_foreign_fence_cannot_acknowledge_application(self):
        self.begin(); p=self.store/'write-fence'; original=p.read_bytes()
        p.unlink(); self.writer(7); self.cli('apply-finish',self.handle,'success',expected=7)
        p.write_bytes(original.replace(self.store_id.encode(),b'b'*32)); p.chmod(0o600); self.writer(7)
        p.write_bytes(original); self.write_identity(identity='b'*32); self.writer(7)

    def test_success_retains_settled_receipt_and_rechecks_before_next_writer(self):
        self.begin(); self.cli('apply-finish',self.handle,'success')
        self.assertFalse((self.store/'application').exists()); self.assertIn(b'settled-applied\n',self.fence())
        self.assertFalse(self.cli('status')['persistent_fence_pending']); self.cli('writer-check'); self.writer()
        self.begin(); self.writer(4)

    def test_restore_requires_explicit_ack_and_only_then_settles(self):
        self.begin(); self.cli('apply-finish',self.handle,'failure'); self.writer(4)
        self.cli('restore-finish',self.handle,'failure',expected=7); self.writer(4)
        self.cli('restore-finish',self.handle,'success'); self.assertIn(b'settled-restored\n',self.fence()); self.writer()
        self.cli('commit',self.plan['confirmation'],expected=5)

    def test_fence_file_sync_failure_never_publishes_journal(self):
        plan=self.preview(); self.fault('fsync','from pathlib import Path\nif Path(sys.argv[-1]).is_file() and Path(sys.argv[-1]).read_bytes().startswith(b"HGWRITEFENCE1"):\n sys.exit(1)')
        self.cli('commit-apply',plan['confirmation'],expected=7)
        self.assertFalse((self.store/'write-fence').exists()); self.assertFalse((self.store/'application').exists())
        self.assertFalse((self.store/'gen-3').exists()); self.restore_tool('fsync'); self.cli('writer-check')

    def test_fence_directory_sync_failure_retains_target_without_journal(self):
        plan=self.preview(); self.fault('fsync','from pathlib import Path\nif sys.argv[-1]=='+repr(str(self.store))+' and Path('+repr(str(self.store/'write-fence'))+').exists(): sys.exit(1)')
        self.cli('commit-apply',plan['confirmation'],expected=7); self.restore_tool('fsync')
        self.assertTrue((self.store/'gen-3/manifest').is_file()); self.assertFalse((self.store/'application').exists())
        self.writer(7); self.cli('recover-application',expected=7)

    def test_journal_removal_sync_failure_keeps_active_fence(self):
        self.begin(); self.fault('fsync','from pathlib import Path\nif sys.argv[-1]=='+repr(str(self.store))+' and not Path('+repr(str(self.store/'application'))+').exists(): sys.exit(1)')
        self.cli('apply-finish',self.handle,'success',expected=7); self.restore_tool('fsync')
        self.assertFalse((self.store/'application').exists()); self.assertIn(b'active\n',self.fence())
        self.writer(7); self.cli('preview',expected=7)

    def test_uncertain_settlement_requires_successful_sync_before_ready(self):
        self.begin(); self.fault('fsync','from pathlib import Path\np=Path('+repr(str(self.store/'write-fence'))+')\nif p.exists() and b"settled-applied\\n" in p.read_bytes(): sys.exit(1)')
        self.cli('apply-finish',self.handle,'success',expected=7); self.writer(7)
        self.assertIn(b'settled-applied\n',self.fence()); self.restore_tool('fsync'); self.cli('writer-check'); self.writer()

    def killed_begin(self,filename):
        self.plan=self.preview(); self.fault('mv','import subprocess\nif sys.argv[-1].endswith('+repr('/'+filename)+'):\n subprocess.run(['+repr(self.busybox)+',"mv",*sys.argv[1:]],check=True)\n os.kill(os.getppid(),signal.SIGKILL); sys.exit(0)')
        result=subprocess.run([self.busybox,'ash',str(self.engine),'--persistent','commit-apply',self.plan['confirmation']],env=self.env,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,-9,(result.stdout,result.stderr)); self.assertEqual(result.stdout,b''); self.assertEqual(result.stderr,b'')
        self.restore_tool('mv')

    def test_sigkill_after_fence_rename_preserves_recovery_barrier(self):
        self.killed_begin('write-fence'); self.assertTrue((self.store/'gen-3/manifest').exists()); self.writer(7)
        self.assertTrue(self.cli('status')['persistent_fence_pending']); self.cli('recover-application',expected=7)

    def test_sigkill_after_pointer_rename_recovers_with_explicit_ack(self):
        self.killed_begin('current'); self.writer(4)
        recovery=self.cli('recover-application'); self.writer(4)
        self.cli('restore-finish',recovery['restore_handle'],'success'); self.writer()

    def test_changed_boot_identity_cannot_lift_service_intent_barrier(self):
        self.begin(intent=True); self.boot_id.write_text('12345678-1234-1234-1234-123456789abc\n')
        self.writer(4); self.cli('apply-finish-intent',self.handle,'1','0',expected=7); self.writer(4)

    def test_abandoned_or_unsealed_state_requires_reconciliation(self):
        p=self.store/'.work.999999'; p.write_bytes(b'PRIVATE_SENTINEL'); p.chmod(0o600); self.writer(7); p.unlink()
        (self.store/'gen-3').mkdir(mode=0o700); self.writer(7)

    def test_original_persistent_gate_cannot_be_enabled_by_environment(self):
        result=subprocess.run([self.busybox,'ash',str(SCRIPT),'--persistent','writer-check'],capture_output=True,timeout=3,
                              env={**self.env,'persistent_namespace_enabled':'true','HOMEGATE_PERSISTENT_ENABLED':'1'})
        self.assertEqual(result.returncode,2); self.assertEqual(result.stderr,b'')
        self.assertNotIn(b'PRIVATE_SENTINEL',result.stdout)

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--runtime',action='store_true'); args=parser.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if args.runtime else Static)
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
