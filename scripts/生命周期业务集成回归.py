#!/usr/bin/env python3
"""Lifecycle/migration/private HTTPS integration against loopback TLS only."""
import argparse,json,os,shutil,subprocess,unittest
from pathlib import Path
from project import ROOT
from Cloudflare只读回归 import Runtime as CloudflareRuntime
from 生命周期准备回归 import Runtime as LifecycleRuntime,configure_runtime_fixture
from 旧配置迁移回归 import LEGACY

PROTO=ROOT/'project/core/prototype'

class Static(unittest.TestCase):
    def test_gates_and_fixed_migrated_mode(self):
        body=(PROTO/'homegate-cloudflare-read.sh').read_text(encoding='utf-8')
        self.assertEqual(body.count('dns_migrated_read_enabled=false'),1)
        self.assertIn('--migrated)',body)
        self.assertNotIn('dns_migrated_read_enabled=true',body)
        self.assertNotIn('prototype/',(ROOT/'project/core/Makefile').read_text())

    def test_bound_check_precedes_snapshot_and_http_worker(self):
        body=(PROTO/'homegate-cloudflare-read.sh').read_text(encoding='utf-8')
        self.assertLess(body.index('flock -n 6'),body.index('--persistent migration-source-reader-check'))
        self.assertLess(body.index('--persistent migration-source-reader-check'),body.index('revision=$(lua'))
        self.assertLess(body.index('--persistent migration-source-reader-check'),body.index('setsid ash'))
        engine=(PROTO/'homegate-config-prototype.sh').read_text(encoding='utf-8')
        self.assertIn('Migration reader data is not source-bound',engine)
        self.assertIn('Migration reader cannot accept a projected generation',engine)

    def test_changed_shell_grammar(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-config-prototype.sh','homegate-cloudflare-read.sh']:
            body=(PROTO/name).read_bytes();self.assertNotIn(b'\r',body);self.assertFalse(parser.parse(body).root_node.has_error)

class Runtime(CloudflareRuntime):
    run_prepare=LifecycleRuntime.run_prepare

    def setUp(self):
        super().setUp()
        assert self.store.resolve().is_relative_to(self.base.resolve()) and self.store!=self.base
        shutil.rmtree(self.store)
        configure_runtime_fixture(self,extra_files=[self.reader,self.engine.parent/'homegate-cloudflare-worker.sh',self.engine.parent/'homegate-service-observer-watchdog.sh',self.engine.parent/'cloudflare-codec.lua'])
        self.engine.write_text(self.engine.read_text().replace('lifecycle_migration_enabled=false','lifecycle_migration_enabled=true'))
        self.reader.write_text(self.reader.read_text().replace('dns_migrated_read_enabled=false','dns_migrated_read_enabled=true'))
        configdir=self.etc/'config';configdir.mkdir(mode=0o700)
        self.source=configdir/'homegate';self.source.write_bytes(LEGACY.encode());self.source.chmod(0o600)

    def migrated(self):
        self.run_prepare();token=self.cli('migration-source-preview')['confirmation']
        return self.cli('migration-source-commit',token)

    def read_migrated(self,expected=0,account='dns_a',env=None):
        p=subprocess.run([self.busybox,'ash',str(self.reader),account,'--migrated'],env=env or self.env,capture_output=True,timeout=12)
        self.assertEqual(p.returncode,expected,(p.stdout,p.stderr));self.assertEqual(p.stderr,b'')
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'PRIVATE_ACCOUNT',b'private-token',os.fsencode(self.source)]:self.assertNotIn(marker,p.stdout)
        r=json.loads(p.stdout);self.assertEqual(r['ok'],expected==0);return r

    def test_cold_start_migration_and_actual_private_tls_read(self):
        r=self.migrated();before=self.contents();source=self.source.read_bytes()
        result=self.read_migrated();self.assertEqual(result['configuration_revision'],r['revision']);self.assertTrue(result['credentials_valid'])
        self.assertEqual(self.calls,[{'method':'GET','path':'/client/v4/zones?page=1&per_page=5','authorization':'Bearer SECRET_SENTINEL'}])
        self.assertEqual(self.contents(),before);self.assertEqual(self.source.read_bytes(),source);self.unchanged()

    def test_repeat_prepare_preserves_identity_generation_and_token(self):
        self.migrated();before=self.contents();inode=self.native.lock.stat().st_ino
        for _ in range(2):self.run_prepare();self.read_migrated()
        self.assertEqual(self.contents(),before);self.assertEqual(self.native.lock.stat().st_ino,inode)
        self.assertEqual([x['authorization'] for x in self.calls],['Bearer SECRET_SENTINEL']*2)

    def test_source_change_after_confirmation_stops_before_http(self):
        self.migrated();before=self.contents();self.source.write_bytes(self.source.read_bytes().replace(b'SECRET_SENTINEL',b'NEW_TOKEN'))
        self.read_migrated(expected=7);self.assertEqual(self.calls,[]);self.assertEqual(self.contents(),before)

    def test_change_before_confirmation_requires_new_preview_and_uses_new_token(self):
        self.run_prepare();old=self.cli('migration-source-preview')['confirmation']
        self.source.write_bytes(self.source.read_bytes().replace(b'SECRET_SENTINEL',b'NEW_TOKEN'))
        self.cli('migration-source-commit',old,expected=5);self.assertEqual(self.calls,[])
        token=self.cli('migration-source-preview')['confirmation'];r=self.cli('migration-source-commit',token)
        result=self.read_migrated();self.assertEqual(result['configuration_revision'],r['revision'])
        self.assertEqual(self.calls[0]['authorization'],'Bearer NEW_TOKEN')

    def test_wrong_account_and_provider_stop_before_http(self):
        self.source.write_bytes(self.source.read_bytes().replace(b"provider 'cloudflare'",b"provider 'aliyun'"));self.migrated()
        self.read_migrated(expected=1);self.read_migrated(expected=1,account='missing');self.assertEqual(self.calls,[])

    def test_missing_credentials_stop_before_http(self):
        self.source.write_bytes(self.source.read_bytes().replace(b"secret 'SECRET_SENTINEL'",b"secret ''"));self.migrated()
        self.read_migrated(expected=1);self.assertEqual(self.calls,[])

    def test_two_accounts_only_use_selected_migrated_token(self):
        self.source.write_bytes(self.source.read_bytes()+b"\nconfig dns_account 'dns_b'\n option provider 'cloudflare'\n option secret 'SECOND_TOKEN'\n")
        self.migrated();self.read_migrated(account='dns_b');self.read_migrated()
        self.assertEqual([x['authorization'] for x in self.calls],['Bearer SECOND_TOKEN','Bearer SECRET_SENTINEL'])

    def test_gate_cannot_be_enabled_by_environment(self):
        self.migrated();self.reader.write_text(self.reader.read_text().replace('dns_migrated_read_enabled=true','dns_migrated_read_enabled=false'))
        self.read_migrated(expected=2,env={**self.env,'dns_migrated_read_enabled':'true'});self.assertEqual(self.calls,[])

    def test_unmigrated_baseline_and_later_generation_refuse_http(self):
        self.run_prepare();self.read_migrated(expected=7);self.assertEqual(self.calls,[])
        token=self.cli('migration-source-preview')['confirmation'];self.cli('migration-source-commit',token)
        self.secret(b'NEW_PRIVATE');self.read_migrated(expected=7);self.assertEqual(self.calls,[])

    def test_shared_and_supervisor_locks_block_request(self):
        import fcntl
        self.migrated()
        for path in [self.native.lock,self.store/'.supervisor.lock']:
            with path.open('rb') as fd:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.read_migrated(expected=4)
        self.assertEqual(self.calls,[])

    def test_dns_barrier_or_runtime_orphan_remains_blocking(self):
        self.migrated();journal=self.store/'dns-operation';journal.mkdir(mode=0o700)
        self.read_migrated(expected=4);journal.rmdir()
        orphan=self.native.lockdir/'.dns-check-999999';orphan.mkdir(mode=0o700)
        self.read_migrated(expected=4);self.assertTrue(orphan.exists());self.assertEqual(self.calls,[])

    def test_source_permissions_and_link_refuse_before_http(self):
        self.migrated();self.source.chmod(0o644);self.read_migrated(expected=7);self.source.chmod(0o600)
        old=self.source.with_name('old');self.source.rename(old);self.source.symlink_to(old)
        self.read_migrated(expected=7);self.assertTrue(self.source.is_symlink());self.assertEqual(self.calls,[])

    def test_supplier_error_is_redacted_and_no_state_publication(self):
        self.migrated();before=self.contents();self.http_status=403
        self.response={'success':False,'errors':[{'code':9109,'message':'SECRET_SENTINEL PRIVATE_ACCOUNT private-token'}]}
        r=self.read_migrated(expected=1);self.assertEqual(r['error_kind'],'authentication');self.assertEqual(self.contents(),before)

    def test_resealed_generation_must_still_derive_from_original_source(self):
        self.migrated();generation=self.store/'gen-3';slot=generation/'credentials/cloudflare.dns_a.secret';slot.write_bytes(b'NEW_PRIVATE')
        import hashlib
        names=['public.conf','parent','legacy.conf']+[str(p.relative_to(generation)) for p in sorted((generation/'credentials').iterdir())]
        (generation/'manifest').write_text(''.join(hashlib.sha256((generation/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names))
        self.read_migrated(expected=7);self.assertEqual(self.calls,[])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    cls=Runtime if a.runtime else Static
    suite=unittest.TestSuite(cls(name) for name,value in cls.__dict__.items() if name.startswith('test_') and callable(value))
    r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if r.wasSuccessful() else 1)
