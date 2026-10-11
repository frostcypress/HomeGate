#!/usr/bin/env python3
"""Legacy UCI migration candidate; no router paths or production reader switch."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from lupa.lua51 import LuaRuntime
from project import ROOT
from 配置预览回归 import BUSINESS, BODY, CODEC
from 完整配置事务回归 import Runtime as FullRuntime

LEGACY = ("package 'homegate'\n" + BUSINESS
          .replace(" option provider 'cloudflare'", " option provider 'cloudflare'\n"
                   " option id 'OLD_ID'\n option secret 'SECRET_SENTINEL'\n"
                   " option account_id 'PRIVATE_ACCOUNT'\n option endpoint 'https://api.test/private-token'")
          .replace(" option host 'www.example.test'", " option host 'www'\n"
                   " option source 'url'\n option url 'https://user:password@source.test/token'")
          .replace(" option certificate 'cert_a'", " option certificate 'cert_a'\n"
                   " option target 'http://user:password@192.0.2.1:8080/private-token'\n"
                   " option certificate_mode 'auto'\n option certificate_managed '1'"))


class Codec(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.codec = self.lua.execute(CODEC.read_text(encoding='utf-8'))

    def migrate(self, body=LEGACY):
        public, slots = self.codec.migration(body)
        self.assertIsInstance(public, str)
        return public, dict(slots.items())

    def reject(self, body):
        public, error = self.codec.migration(body)
        self.assertIsNone(public)
        self.assertEqual(error, 'Legacy configuration cannot be migrated safely')
        self.assertNotIn('SECRET_SENTINEL', error)

    def test_private_projection_and_shared_public_codec(self):
        public, slots = self.migrate()
        self.assertEqual(slots, {'cloudflare.dns_a.key_id':'OLD_ID',
            'cloudflare.dns_a.secret':'SECRET_SENTINEL','cloudflare.dns_a.account_id':'PRIVATE_ACCOUNT',
            'cloudflare.dns_a.endpoint':'https://api.test/private-token',
            'ddns.ddns_a.url':'https://user:password@source.test/token',
            'web.web_a.target':'http://user:password@192.0.2.1:8080/private-token'})
        for value in slots.values(): self.assertNotIn(value, public)
        self.assertEqual(self.codec.canonical(public), public)
        self.assertNotIn("option enabled '1'",public)
        self.assertIn("option host 'www.example.test'",public)
        self.assertIn("option certificate_managed '1'",public)

    def test_four_providers_empty_slots_and_exact_quote_preservation(self):
        for provider in ('aliyun','cloudflare','dnspod','huaweicloud'):
            body=LEGACY.replace("provider 'cloudflare'", "provider '"+provider+"'")
            body=body.replace("secret 'SECRET_SENTINEL'", "secret '  ab'\\''cd\\$(cmd)  '")
            body=body.replace("id 'OLD_ID'", "id ''")
            public,slots=self.migrate(body)
            self.assertEqual(slots[provider+'.dns_a.secret'],"  ab'cd\\$(cmd)  ")
            self.assertNotIn(provider+'.dns_a.key_id',slots)
            self.assertNotIn('$(cmd)',public)

    def test_legacy_certificate_domain_scalar_list_and_ambiguous_alias(self):
        for body in (LEGACY.replace('list domains','list domain'),
                     LEGACY.replace(" list domains 'example.test'\n list domains '*.example.test'",
                                    " option domain 'example.test,*.example.test'")):
            self.assertEqual(self.migrate(body)[0],self.migrate()[0])
        self.reject(LEGACY.replace("list domains 'example.test'", "option domain 'example.test'"))

    def test_raw_legacy_does_not_expand_public_import_permissions(self):
        self.assertIsNone(self.codec.parse(LEGACY)[0])
        self.reject(BODY)
        for body in (LEGACY.replace("package 'homegate'", "package 'other'"),
                     LEGACY.replace("package 'homegate'", "package 'homegate'\npackage 'homegate'")):
            self.reject(body)

    def test_unknown_duplicate_private_lists_and_bad_references_fail_closed(self):
        for body in (LEGACY+" option unknown 'SECRET_SENTINEL'\n",
                     LEGACY.replace("option id 'OLD_ID'", "option id 'OLD_ID'\n option id 'other'"),
                     LEGACY.replace("option secret", "list secret"),
                     LEGACY.replace("option account 'dns_a'", "option account 'missing'"),
                     LEGACY.replace("certificate_mode 'auto'", "certificate_mode 'shell'"),
                     LEGACY.replace("config dns_account 'dns_a'", "config dns_account")):
            self.reject(body)

    def test_limits_framing_and_no_invalid_utf8_secret_echo(self):
        for body in (LEGACY+'\x00', LEGACY+'\r', LEGACY+'#'+'x'*4096,
                     LEGACY.replace('SECRET_SENTINEL','x'*4097), LEGACY+'#\n'*8192,
                     LEGACY+'#'*(262145-len(LEGACY.encode()))):
            self.reject(body)
        raw=LuaRuntime(unpack_returned_tuples=True,encoding=None)
        codec=raw.execute(CODEC.read_bytes())
        result=codec.migration(LEGACY.encode().replace(b'SECRET_SENTINEL',b'\xffSECRET_SENTINEL'))
        self.assertIsNone(result[0]); self.assertNotIn(b'SECRET_SENTINEL',result[1])


class Runtime(unittest.TestCase):
    setUpClass = classmethod(FullRuntime.setUpClass.__func__)
    tearDown = FullRuntime.tearDown
    raw = FullRuntime.raw
    cli = FullRuntime.cli
    export = FullRuntime.export
    preview = FullRuntime.preview
    commit_body = FullRuntime.commit_body
    fault = FullRuntime.fault
    restore_tool = FullRuntime.restore_tool

    def setUp(self):
        # Reuse real filesystem/BusyBox setup, but use an untouched initial store.
        FullRuntime.setUp(self)
        self.store=self.base/'migration-store'
        self.env['HOMEGATE_CONFIG_PROTO_STORE']=str(self.store)
        self.cli('init')
        self.defaults=self.export()

    def stage(self,body=None,expected=0):
        return self.cli('migration-preview',payload=(LEGACY.encode() if body is None else body),expected=expected)

    def paths(self,revision):
        return self.store/f'gen-{revision}'

    def assert_private(self):
        for file in (self.store,*self.store.rglob('*')):
            self.assertEqual(file.stat().st_mode&0o777,0o700 if file.is_dir() else 0o600)

    def test_preview_commit_backup_and_one_time_migration(self):
        before=self.export(); plan=self.stage()
        self.assertEqual(plan['operation'],'migration')
        self.assertEqual(plan['credential_policy'],'migrate-legacy-private-fields')
        self.assertEqual(self.export(),before)
        self.assertNotIn('SECRET_SENTINEL',json.dumps(plan))
        result=self.cli('commit',plan['confirmation'])
        generation=self.paths(result['revision'])
        self.assertEqual((generation/'legacy.conf').read_bytes(),LEGACY.encode())
        self.assertEqual((generation/'credentials/cloudflare.dns_a.secret').read_bytes(),b'SECRET_SENTINEL')
        self.assertEqual((generation/'credentials/ddns.ddns_a.url').read_bytes(),b'https://user:password@source.test/token')
        self.assertNotIn(b'private-token',self.export())
        self.assert_private()
        self.cli('commit',plan['confirmation'],expected=5)
        self.stage(expected=4)

    def test_raw_input_unchanged_and_public_import_stays_closed(self):
        source=self.base/'legacy-source'
        source.write_bytes(LEGACY.encode()); source.chmod(0o600)
        before=hashlib.sha256(source.read_bytes()).hexdigest()
        self.stage(source.read_bytes())
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),before)
        self.cli('preview',payload=source.read_bytes(),expected=1)
        self.assertEqual(self.export(),self.defaults)

    def test_replacement_cancel_and_candidate_not_rollback_ancestor(self):
        first=self.stage(); second=self.stage(LEGACY.replace('OLD_ID','NEW_ID').encode())
        self.cli('commit',first['confirmation'],expected=5)
        self.cli('rollback-preview','2',expected=5)
        self.cli('cancel')
        self.cli('commit',second['confirmation'],expected=5)
        self.assertEqual(self.export(),self.defaults)

    def test_corrupted_private_source_and_resealed_candidate_rejected(self):
        for filename,value in (('credentials/cloudflare.dns_a.secret',b'CHANGED'),
                               ('legacy.conf',LEGACY.replace('OLD_ID','CHANGED').encode())):
            plan=self.stage(); stage=self.paths(max(int(p.name[4:]) for p in self.store.glob('gen-*')))
            (stage/filename).write_bytes(value)
            # Recompute the public manifest: pending's independent digest still rejects.
            names=['public.conf','parent','legacy.conf']+[str(p.relative_to(stage)).replace('\\','/') for p in sorted((stage/'credentials').iterdir())]
            (stage/'manifest').write_bytes(''.join(hashlib.sha256((stage/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in names).encode())
            self.cli('commit',plan['confirmation'],expected=5)
            self.assertEqual(self.export(),self.defaults)

    def test_private_symlink_and_hardlink_candidate_rejected(self):
        plan=self.stage(); path=self.paths(2)/'legacy.conf'
        path.unlink(); path.symlink_to(self.base/'legacy-other')
        self.cli('commit',plan['confirmation'],expected=1)
        self.assertEqual(self.export(),self.defaults)
        plan=self.stage(); path=self.paths(3)/'legacy.conf'
        outside=self.base/'legacy-other'; outside.write_bytes(path.read_bytes()); outside.chmod(0o600)
        path.unlink(); os.link(outside,path)
        self.cli('commit',plan['confirmation'],expected=1)

    def test_fsync_failure_retains_preview_and_original_backup_for_retry(self):
        plan=self.stage()
        self.fault('fsync',"if any(x.endswith('/legacy.conf') and '/gen-3/' in x for x in sys.argv[1:]): sys.exit(1)")
        self.cli('commit',plan['confirmation'],expected=1)
        self.assertEqual(self.export(),self.defaults)
        self.assertEqual((self.paths(2)/'legacy.conf').read_bytes(),LEGACY.encode())
        self.restore_tool('fsync'); self.cli('commit',plan['confirmation'])

    def test_confirm_concurrency_and_initialization_policy(self):
        plan=self.stage()
        def invoke(_):
            return subprocess.run([self.busybox,'ash',str(ROOT/'project/core/prototype/homegate-config-prototype.sh'),
                '--public-uci','commit',plan['confirmation']],capture_output=True,env=self.env,timeout=30)
        with ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(invoke,range(4)))
        self.assertEqual(sum(r.returncode==0 for r in results),1)
        self.assertTrue(all(r.returncode in (0,4,5) for r in results))
        self.stage(expected=4)
        self.assert_private()

    def test_failed_legacy_validation_retains_prior_plan(self):
        plan=self.stage()
        for body in (LEGACY.encode()+b'\x00',LEGACY.encode()+b" option unknown 'SECRET_SENTINEL'\n",b'x'*262145):
            response=self.raw('migration-preview',payload=body,expected=1)
            self.assertNotIn(b'SECRET_SENTINEL',response)
            self.assertEqual(self.export(),self.defaults)
        self.cli('commit',plan['confirmation'])

    def test_resource_url_retention_and_restore_with_credentials(self):
        report=self.cli('commit',self.stage()['confirmation']); prior=report['revision']
        public=self.export()
        self.commit_body(public.replace(b"config web_rule 'web_a'",b"config web_rule 'web_b'"))
        current=self.paths(self.cli('status')['revision'])/'credentials'
        self.assertFalse((current/'web.web_a.target').exists())
        self.assertFalse((current/'web.web_b.target').exists())
        restored=self.cli('commit',self.cli('rollback-preview',str(prior))['confirmation'])
        self.assertTrue((self.paths(restored['revision'])/'credentials/web.web_a.target').is_file())
        self.assertNotIn(b'password',self.export())

    def test_official_uci_reads_migrated_disabled_configuration(self):
        self.cli('commit',self.stage()['confirmation'])
        directory=self.base/'uci'; directory.mkdir(mode=0o700)
        config=directory/'homegate'; config.write_bytes(self.export()); config.chmod(0o600)
        uci=ROOT/'build/uci-parser/uci'
        result=subprocess.run([str(uci),'-c',str(directory),'-P',str(directory),'-q','show','homegate'],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn(b'SECRET_SENTINEL',result.stdout)
        self.assertIn(b"homegate.main.enabled='0'",result.stdout)
        self.assertIn(b"homegate.ddns_a.host='www.example.test'",result.stdout)

    def test_post_publish_failure_preserves_private_backup_and_prevents_replay(self):
        plan=self.stage()
        self.fault('fsync','if sys.argv[-1]=='+repr(str(self.store))+': sys.exit(1)')
        report=self.cli('commit',plan['confirmation'],expected=6)
        self.assertEqual(report['error'],'Published pointer durability is uncertain')
        self.assertEqual((self.paths(3)/'legacy.conf').read_bytes(),LEGACY.encode())
        self.cli('commit',plan['confirmation'],expected=5)
        self.restore_tool('fsync')
        self.cli('commit',self.cli('rollback-preview','1')['confirmation'])
        self.assertEqual(self.export(),self.defaults)

    def test_maximum_private_resources_and_long_manifest(self):
        body="config homegate 'main'\n"
        for index in range(32):
            name='dns-'+str(index)+'x'*55
            body+="config dns_account '"+name+"'\n option provider 'cloudflare'\n"
            for slot in ('id','secret','account_id','endpoint'): body+=" option "+slot+" 'PRIVATE_SENTINEL'\n"
            body+="config ddns_rule 'ddns-"+str(index)+"'\n option account '"+name+"'\n option zone 'example.test'\n option url 'PRIVATE_URL'\n"
            body+="config web_rule 'web-"+str(index)+"'\n option domain 'host"+str(index)+".example.test'\n option https '0'\n option target 'PRIVATE_TARGET'\n"
        result=self.cli('commit',self.stage(body.encode())['confirmation'])
        generation=self.paths(result['revision'])
        self.assertEqual(len(list((generation/'credentials').iterdir())),192)
        self.assertGreater((generation/'manifest').stat().st_size,20000)
        self.assertNotIn(b'PRIVATE_',self.export())
        self.assert_private()


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--runtime',action='store_true'); args=parser.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if args.runtime else Codec)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
