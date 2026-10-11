#!/usr/bin/env python3
"""Full public UCI transactions: Lua 5.1 codec, real BusyBox, real files/locks."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from project import ROOT
from 配置预览回归 import BODY, HEADER, CODEC
from 配置事务原型回归 import APPLETS, SCRIPT

ADAPTER = ROOT / 'project/core/prototype/config-codec.lua'


class Codec(unittest.TestCase):
    def setUp(self):
        from lupa.lua51 import LuaRuntime
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.codec = self.lua.execute(CODEC.read_text(encoding='utf-8'))

    def test_canonical_is_disabled_and_idempotent(self):
        body = self.codec.canonical(BODY)
        self.assertIsInstance(body, str)
        self.assertEqual(self.codec.canonical(body), body)
        self.assertNotIn("option enabled '1'", body)
        self.assertIn("config web_rule 'web_a'", body)
        self.assertIn("list domains '*.example.test'", body)

    def test_canonical_expansion_cannot_bypass_backup_limits(self):
        # Valid uploaded text expands past 256 KiB when defaults are added.
        domains=[str(i).zfill(2)+'a'*60+'.'+'b'*63+'.'+'c'*63+'.'+'d'*47+'.example.test' for i in range(30)]
        body=HEADER+"config homegate 'main'\nconfig dns_account 'dns'\n option provider 'cloudflare'\n"
        body+=''.join("config certificate 'cert_"+str(i)+"'\n option account 'dns'\n option zone 'example.test'\n"
                      +''.join(" list domains '"+d+"'\n" for d in domains) for i in range(32))
        self.assertLess(len(body.encode()),262144)
        self.assertNotIsInstance(self.codec.parse(body),tuple)
        result = self.codec.canonical(body)
        self.assertIsNone(result[0])
        self.assertIn('too large',result[1])

    def run_adapter(self, mode, files, stdin=''):
        self.lua.globals().codec = self.codec
        self.lua.globals().fixture_files = self.lua.table_from(files)
        self.lua.globals().fixture_stdin = stdin
        self.lua.globals().arg = self.lua.table_from({0:'/fixture/config-codec.lua', **{i+1:v for i,v in enumerate(mode)}})
        self.lua.execute('''
          output=''; diagnostics=''
          loadfile=function(path) assert(path:match('backup.lua$')); return function() return codec end end
          local function stream(body) return {read=function(self,n) return body:sub(1,n) end,close=function() end} end
          io={stdin=stream(fixture_stdin),open=function(path) if fixture_files[path] then return stream(fixture_files[path]) end end,
              write=function(...) for _,v in ipairs({...}) do output=output..v end end,
              stderr={write=function(self,v) diagnostics=diagnostics..v end}}
          os={exit=function() error('adapter rejected input') end}
        ''')
        self.lua.execute(ADAPTER.read_text(encoding='utf-8'))
        return self.lua.globals().output

    def test_adapter_uses_same_codec_for_diff_and_normalization(self):
        normalized = self.run_adapter(['normalize'], {}, BODY)
        expected = self.codec.canonical(BODY)
        self.assertEqual(normalized, expected)
        changed = expected.replace("option https_port '443'", "option https_port '8443'")
        rows = json.loads(self.run_adapter(['diff','before','after'], {'before':expected,'after':changed}))
        self.assertEqual(rows, [{'section':'main','kind':'homegate','field':'https_port','before':'443','after':'8443'}])

    def test_adapter_account_bindings_and_no_secret_reflection(self):
        slots = self.run_adapter(['allowed','before'], {'before':BODY}).splitlines()
        self.assertEqual(slots, [f'cloudflare.dns_a.{slot}' for slot in ('key_id','secret','account_id','endpoint')]
                         +['ddns.ddns_a.url','web.web_a.target'])
        with self.assertRaises(Exception):
            self.run_adapter(['normalize'], {}, BODY + " option secret 'SECRET_SENTINEL'\n")
        self.assertNotIn('SECRET_SENTINEL', self.lua.globals().diagnostics)
        self.assertEqual(self.lua.globals().output, '')


class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.busybox = shutil.which('busybox')
        cls.lua = shutil.which('lua5.1')
        if os.name!='posix' or not cls.busybox or not cls.lua:
            raise RuntimeError('Requires real Linux BusyBox and Lua 5.1; no simulated pass')
        available = subprocess.check_output([cls.busybox,'--list'], text=True).splitlines()
        missing = set(('ash','fsync',*APPLETS))-set(available)
        if missing:
            raise RuntimeError('Missing BusyBox applets: '+', '.join(sorted(missing)))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='homegate-config-prototype-full-',dir='/tmp')
        self.base = Path(self.temp.name)
        self.store = self.base/'store'
        self.bin = self.base/'bin'
        self.bin.mkdir(mode=0o700)
        for name in (*APPLETS,'fsync'):
            (self.bin/name).symlink_to(self.busybox)
        (self.bin/'lua').symlink_to(self.lua)
        self.env = dict(os.environ, PATH=str(self.bin), HOMEGATE_CONFIG_PROTO_STORE=str(self.store))
        self.cli('init')
        self.defaults = self.export()
        self.commit_body(BODY.encode())
        self.business = self.export()

    def tearDown(self):
        self.temp.cleanup()

    def raw(self,*args,payload=None,expected=0,env=None):
        result = subprocess.run([self.busybox,'ash',str(SCRIPT),'--public-uci',*args],
                                input=payload,capture_output=True,env=env or self.env,timeout=30)
        self.assertEqual(result.returncode,expected,(args,result.stdout,result.stderr))
        self.assertEqual(result.stderr,b'','Diagnostics must not expose uploaded data')
        self.assertLess(len(result.stdout),1048576)
        return result.stdout

    def cli(self,*args,**kwargs):
        body=json.loads(self.raw(*args,**kwargs))
        self.assertEqual(body['ok'],kwargs.get('expected',0)==0)
        self.assertTrue(body['prototype'])
        return body

    def export(self):
        return self.raw('export')

    def preview(self,body=None):
        return self.cli('preview',payload=body if body is not None else self.business)

    def commit_body(self,body):
        report=self.cli('preview',payload=body)
        return self.cli('commit',report['confirmation'])

    def secret(self,value,provider='cloudflare',account='dns_a',expected=0):
        return self.cli('credential-put',provider,account,'secret',payload=value,expected=expected)

    def secret_path(self,revision,provider='cloudflare',account='dns_a'):
        return self.store/f'gen-{revision}/credentials/{provider}.{account}.secret'

    def fault(self,name,code):
        file=self.bin/name
        file.unlink()
        file.write_text('#!'+sys.executable+'\nimport os,sys,signal\n'+code+'\n'
                        'os.execv('+repr(self.busybox)+',['+repr(name)+',*sys.argv[1:]])\n')
        file.chmod(0o700)

    def restore_tool(self,name):
        (self.bin/name).unlink()
        (self.bin/name).symlink_to(self.busybox)

    def test_full_uci_real_diff_and_single_use_confirmation(self):
        modified=self.business.replace(b"option https_port '443'",b"option https_port '8443'")
        plan=self.preview(modified)
        self.assertEqual(plan['scope'],'public-uci-v1')
        self.assertEqual(plan['changes'],[{'section':'main','kind':'homegate','field':'https_port','before':'443','after':'8443'}])
        self.assertEqual(self.export(),self.business)
        report=self.cli('commit',plan['confirmation'])
        self.assertEqual(report['revision'],3)
        self.assertEqual(report['durability'],'fsync-barriers-not-device-verified')
        self.assertIn(b"option https_port '8443'",self.export())
        self.cli('commit',plan['confirmation'],expected=5)

    def test_private_permissions_and_safe_paths(self):
        for file in (self.store,*self.store.rglob('*')):
            self.assertEqual(file.stat().st_mode&0o777,0o700 if file.is_dir() else 0o600)
        self.cli('status',env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':'/etc/homegate'},expected=2)
        result=subprocess.run([self.busybox,'ash',str(SCRIPT),'status'],env=self.env,capture_output=True,timeout=30)
        self.assertNotEqual(result.returncode,0,'Legacy mode must not read full-schema stores')
        self.cli('status',env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(self.store/'../store')},expected=2)

    def test_cancellation_replacement_and_vault_updates_invalidate(self):
        old=self.preview()['confirmation']; new=self.preview()['confirmation']
        self.cli('commit',old,expected=5)
        self.cli('cancel'); self.cli('commit',new,expected=5)
        plan=self.preview()['confirmation']; self.secret(b'PRIVATE_SENTINEL')
        self.cli('commit',plan,expected=5)
        self.assertEqual(self.export(),self.business)

    def test_secrets_never_enter_export_diff_status_or_diagnostics(self):
        secret=b'PRIVATE_SENTINEL\x00\n$(touch /tmp/not-homegate)'
        report=self.secret(secret)
        self.assertEqual(self.secret_path(3).read_bytes(),secret)
        plan=self.preview()
        self.cli('commit',plan['confirmation'])
        self.assertEqual(self.secret_path(4).read_bytes(),secret)
        for data in (json.dumps(report),json.dumps(plan),json.dumps(self.cli('status')),self.export().decode()):
            self.assertNotIn('PRIVATE_SENTINEL',data)
            self.assertNotIn(hashlib.sha256(secret).hexdigest(),data)

    def test_provider_or_account_mismatch_cannot_attach_credentials(self):
        for provider,account in [('aliyun','dns_a'),('cloudflare','not_present'),('cloudflare','../outside')]:
            self.secret(b'PRIVATE_SENTINEL',provider,account,expected=2 if '/' in account else 1)
        self.assertEqual(self.cli('status')['revision'],2)

    def test_provider_change_drops_old_credentials_and_rollback_restores(self):
        self.secret(b'OLD_PRIVATE')
        switched=self.business.replace(b"option provider 'cloudflare'",b"option provider 'aliyun'")
        self.commit_body(switched)
        self.assertEqual(list((self.store/'gen-4/credentials').iterdir()),[])
        rollback=self.cli('rollback-preview','3')
        self.cli('commit',rollback['confirmation'])
        self.assertEqual(self.secret_path(5).read_bytes(),b'OLD_PRIVATE')
        self.assertEqual(self.export(),self.business)

    def test_account_removal_drops_orphans_without_deleting_history(self):
        self.secret(b'OLD_PRIVATE')
        self.commit_body(self.defaults)
        self.assertEqual(list((self.store/'gen-4/credentials').iterdir()),[])
        self.assertEqual(self.secret_path(3).read_bytes(),b'OLD_PRIVATE')

    def test_expired_boot_mismatch_future_timestamp_and_copied_plan(self):
        original=self.preview()['confirmation']
        file=self.store/'pending'; content=file.read_text().splitlines(keepends=True)
        # Fault only the external clock source, keeping the real store/plan.
        expired=int(content[5])
        self.fault('cat','if sys.argv[-1]=="/proc/uptime":\n    print('+repr(str(expired)+'.00 0.00')+'); sys.exit(0)')
        self.cli('commit',original,expected=5)
        self.restore_tool('cat')
        plan=content.copy(); plan[4]='999999000\n'; plan[5]='999999300\n'
        file.write_text(''.join(plan)); self.cli('commit',original,expected=5)
        plan=content.copy(); plan[6]='0'*36+'\n'
        file.write_text(''.join(plan)); self.cli('commit',original,expected=5)
        other=self.base/'other'; other.mkdir(mode=0o700)
        shutil.copytree(self.store,other,dirs_exist_ok=True)
        file.write_text(''.join(content)); (other/'pending').write_text(''.join(content))
        self.cli('commit',original,env={**self.env,'HOMEGATE_CONFIG_PROTO_STORE':str(other)},expected=5)
        self.cli('commit',original)

    def test_pending_candidate_corruption_and_exact_framing(self):
        token=self.preview()['confirmation']; file=self.store/'pending'; original=file.read_bytes()
        file.write_bytes(original.replace(b"option https_port '443'",b"option https_port '8443'"))
        self.cli('commit',token,expected=5)
        for content in (original+b'\n',original[:-1],original.replace(b"'main'",b"'ma\x00in'")):
            file.write_bytes(content); self.cli('commit',token,expected=1)
        file.write_bytes(original); self.cli('commit',token)

    def test_changed_valid_generation_baseline_invalidates_preview(self):
        token=self.preview()['confirmation']; directory=self.store/'gen-2'
        public=directory/'public.conf'
        public.write_bytes(public.read_bytes().replace(b"option https_port '443'",b"option https_port '8443'"))
        hashes=[]
        for name in ('public.conf','parent'):
            hashes.append(hashlib.sha256((directory/name).read_bytes()).hexdigest()+'  '+name+'\n')
        (directory/'manifest').write_text(''.join(hashes))
        self.cli('commit',token,expected=5)
        self.assertIn(b"option https_port '8443'",self.export())

    def test_real_lock_and_concurrent_confirmation(self):
        import fcntl
        token=self.preview()['confirmation']
        with (self.store/'.lock').open('a') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.cli('commit',token,expected=4)
        def attempt(_):
            result=subprocess.run([self.busybox,'ash',str(SCRIPT),'--public-uci','commit',token],
                                  env=self.env,capture_output=True,timeout=30)
            self.assertIn(result.returncode,(0,4,5),result.stdout)
            return result.returncode
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes=list(pool.map(attempt,range(8)))
        self.assertEqual(outcomes.count(0),1)
        self.assertEqual(self.cli('status')['revision'],3)

    def test_candidate_fsync_failure_preserves_current_plan_and_retry(self):
        token=self.preview()['confirmation']; pending=(self.store/'pending').read_bytes()
        self.fault('fsync','if any(v.endswith("/gen-3/public.conf") for v in sys.argv[1:]): sys.exit(1)')
        self.cli('commit',token,expected=1)
        self.assertEqual(self.cli('status')['revision'],2)
        self.assertEqual((self.store/'pending').read_bytes(),pending)
        self.assertFalse((self.store/'gen-3').exists())
        self.restore_tool('fsync'); self.cli('commit',token)

    def test_pointer_file_fsync_and_rename_failure_preserve_old_generation(self):
        token=self.preview()['confirmation']
        self.fault('fsync','if any("/.work." in v for v in sys.argv[1:]): sys.exit(1)')
        self.cli('commit',token,expected=1)
        self.restore_tool('fsync')
        self.fault('mv','if sys.argv[-1].endswith("/current"): sys.exit(1)')
        self.cli('commit',token,expected=1)
        self.assertEqual(self.cli('status')['revision'],2)
        self.restore_tool('mv'); self.cli('commit',token)

    def test_post_publish_fsync_failure_is_uncertain_and_cannot_replay(self):
        token=self.preview()['confirmation']
        self.fault('fsync','if sys.argv[-1]=='+repr(str(self.store))+': sys.exit(1)')
        report=self.cli('commit',token,expected=6)
        self.assertIn('uncertain',report['error'])
        self.assertEqual(self.cli('status')['revision'],3)
        self.cli('commit',token,expected=5)
        self.restore_tool('fsync')
        plan=self.cli('rollback-preview','2'); self.cli('commit',plan['confirmation'])

    def test_process_kill_before_publish_leaves_unreachable_candidate(self):
        token=self.preview()['confirmation']
        self.fault('mv','if sys.argv[-1].endswith("/current"):\n    os.kill(os.getppid(),signal.SIGKILL); sys.exit(1)')
        result=subprocess.run([self.busybox,'ash',str(SCRIPT),'--public-uci','commit',token],
                              env=self.env,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,-signal.SIGKILL)
        self.assertEqual(self.cli('status')['revision'],2)
        self.cli('rollback-preview','3',expected=5)
        self.restore_tool('mv'); self.assertEqual(self.cli('commit',token)['revision'],4)
        self.cli('rollback-preview','3',expected=5)

    def test_full_schema_validation_and_input_size_failure_preserve_preview(self):
        token=self.preview()['confirmation']; pending=(self.store/'pending').read_bytes()
        for body in (self.business+b"option secret 'PRIVATE_SENTINEL'\n", b'X'*262145,
                     self.business.replace(b"'dns_a'",b"'missing'",1), self.business[:-1]):
            report=self.cli('preview',payload=body,expected=1)
            self.assertNotIn('PRIVATE_SENTINEL',json.dumps(report))
            self.assertEqual((self.store/'pending').read_bytes(),pending)
        self.cli('commit',token)

    def test_multiple_account_names_hyphens_and_secret_size_limits(self):
        body=HEADER+"config homegate 'main'\n"
        for i in range(32):
            body+=f"config dns_account 'account-{i}'\n option provider 'cloudflare'\n"
        self.commit_body(body.encode())
        # Seed a complete prior vault, then exercise the real 128-slot copy,
        # validation, manifest, file synchronization and publication path.
        directory=self.store/'gen-3'
        for i in range(32):
            for slot in ('key_id','secret','account_id','endpoint'):
                file=directory/f'credentials/cloudflare.account-{i}.{slot}'
                file.write_bytes(b'PRIVATE_FULL_VAULT'); file.chmod(0o600)
        rows=[]
        files=[directory/'public.conf',directory/'parent',*sorted((directory/'credentials').iterdir())]
        for file in files:
            rows.append(hashlib.sha256(file.read_bytes()).hexdigest()+'  '+file.relative_to(directory).as_posix()+'\n')
        (directory/'manifest').write_text(''.join(rows))
        self.assertGreater((directory/'manifest').stat().st_size,4096)
        self.cli('status')
        self.secret(b'X'*4096,account='account-31')
        self.assertEqual(len(list((self.store/'gen-4/credentials').iterdir())),128)
        self.secret(b'X'*4097,account='account-31',expected=1)
        self.secret(b'',account='account-31',expected=1)
        self.assertEqual(self.cli('status')['credential_capacity'],128)

    def test_symlink_hardlink_and_integrity_fail_closed(self):
        file=self.store/'gen-2/public.conf'; original=file.read_bytes()
        other=self.base/'outside'; other.write_bytes(b'UNCHANGED'); other.chmod(0o600)
        file.unlink(); file.symlink_to(other); self.cli('status',expected=1)
        file.unlink(); os.link(other,file); self.cli('status',expected=1)
        file.unlink(); file.write_bytes(original); file.chmod(0o600)
        file.write_bytes(original.replace(b"'443'",b"'8443'")); self.cli('status',expected=1)
        self.assertEqual(other.read_bytes(),b'UNCHANGED')

    def test_missing_fsync_cannot_publish_full_schema(self):
        token=self.preview()['confirmation']
        (self.bin/'fsync').unlink()
        self.cli('commit',token,expected=1)
        self.assertEqual(self.cli('status')['revision'],2)

    def test_official_uci_parser_reads_export_after_commit_and_rollback(self):
        executable=ROOT/'build/uci-parser/uci'
        self.assertTrue(executable.is_file(),'Official pinned UCI parser must be built; no mock fallback')
        conf=self.base/'uci'; conf.mkdir(mode=0o700)
        save=self.base/'uci-save'; save.mkdir(mode=0o700)
        file=conf/'homegate'
        def inspect(body):
            file.write_bytes(body)
            result=subprocess.run([str(executable),'-c',str(conf),'-P',str(save),'-q','show','homegate'],
                                  capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stderr,b'')
            return result.stdout
        quoted=self.business.replace(b"option name 'DNS ",b"option name 'Alice'\\''s DNS ",1)
        self.commit_body(quoted)
        shown=inspect(self.export())
        for name,kind in [('main','homegate'),('dns_a','dns_account'),('ddns_a','ddns_rule'),
                          ('cert_a','certificate'),('web_a','web_rule'),('host_a','wol_host')]:
            self.assertIn(('homegate.'+name+'='+kind+'\n').encode(),shown)
        self.assertIn(b"homegate.dns_a.name='Alice'\\''s DNS ",shown)
        self.assertNotIn(b"enabled='1'",shown)
        plan=self.cli('rollback-preview','2'); self.cli('commit',plan['confirmation'])
        self.assertEqual(inspect(self.export()),inspect(self.business))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',action='store_true')
    args=parser.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if args.runtime else Codec)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
