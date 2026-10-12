#!/usr/bin/env python3
"""Private frame parser and inherited-pipe reads under the real store flock."""
import argparse
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import sys
import unittest
from project import ROOT
from 配置预览回归 import BODY, CODEC
from 完整配置事务回归 import Runtime as FullRuntime
from 配置事务原型回归 import SCRIPT

READER=ROOT/'project/core/prototype/private-snapshot.lua'

class Codec(unittest.TestCase):
    def setUp(self):
        from lupa.lua51 import LuaRuntime
        self.lua=LuaRuntime(unpack_returned_tuples=True,encoding=None)
        self.codec=self.lua.execute(CODEC.read_bytes())
        self.reader=self.lua.execute(READER.read_bytes())
        self.public=self.codec.canonical(BODY.encode())

    def frame(self,slots=None,public=None,revision=b'3',count=None):
        public=self.public if public is None else public
        slots=[] if slots is None else slots
        return b'HGPRIVATE1\n'+revision+b'\n'+str(len(public)).encode()+b'\n'+str(len(slots) if count is None else count).encode()+b'\n'+public+b''.join(str(len(k)).encode()+b'\n'+str(len(v)).encode()+b'\n'+k+v for k,v in slots)+b'END\n'

    def parse(self,body): return self.reader.parse(body,self.codec)
    def reject(self,body):
        result=self.parse(body)
        self.assertEqual(result,(None,b'Invalid private configuration snapshot'))

    def test_binary_secret_and_public_configuration_share_revision(self):
        value=b'PRIVATE_SENTINEL\x00\xff\nEND\n$(false)'
        result=self.parse(self.frame([(b'cloudflare.dns_a.secret',value)]))
        self.assertEqual(result[b'revision'],3)
        self.assertEqual(result[b'credentials'][b'cloudflare.dns_a.secret'],value)
        self.assertEqual(result[b'configuration'][1][b'name'],b'main')

    def test_every_truncation_and_trailing_bytes_are_rejected(self):
        body=self.frame([(b'ddns.ddns_a.url',b'PRIVATE_SENTINEL')])
        for end in range(len(body)): self.reject(body[:end])
        self.reject(body+b'PRIVATE_SENTINEL')

    def test_unknown_duplicate_and_unsorted_slots_are_rejected(self):
        for slots in [[(b'cloudflare.missing.secret',b'x')],[(b'aliyun.dns_a.secret',b'x')],
                      [(b'cloudflare.dns_a.secret',b'x')]*2,
                      [(b'web.web_a.target',b'x'),(b'ddns.ddns_a.url',b'x')]]:
            self.reject(self.frame(slots))

    def test_numbers_counts_and_sizes_fail_closed(self):
        for revision in [b'0',b'33',b'03',b'1\r',b'-1',b'99999999']:
            self.reject(self.frame(revision=revision))
        for count in [1,193]: self.reject(self.frame(count=count))
        self.reject(self.frame([(b'cloudflare.dns_a.secret',b'')]))
        self.reject(self.frame([(b'cloudflare.dns_a.secret',b'x'*4097)]))
        self.reject(b'x'*(1114112+1))

    def test_private_or_noncanonical_public_config_is_rejected(self):
        self.reject(self.frame(public=self.public+b" option secret 'PRIVATE_SENTINEL'\n"))
        self.reject(self.frame(public=self.public.replace(b"option enabled '0'",b"option enabled '1'")))
        self.reject(self.frame(public=BODY.encode()))

    def test_reader_bounds_input_and_masks_stream_failure(self):
        self.lua.globals().frame=self.frame()
        stream=self.lua.execute(b'return {read=function(self,n) assert(n==1114113); return frame end}')
        self.assertEqual(self.reader.read(stream,self.codec)[b'revision'],3)
        stream=self.lua.execute(b'return {read=function() error("PRIVATE_SENTINEL") end}')
        self.assertEqual(self.reader.read(stream,self.codec),(None,b'Invalid private configuration snapshot'))

class Runtime(unittest.TestCase):
    setUpClass=classmethod(FullRuntime.setUpClass.__func__)
    setUp=FullRuntime.setUp
    tearDown=FullRuntime.tearDown
    raw=FullRuntime.raw
    cli=FullRuntime.cli
    export=FullRuntime.export
    commit_body=FullRuntime.commit_body
    secret=FullRuntime.secret
    secret_path=FullRuntime.secret_path
    fault=FullRuntime.fault
    restore_tool=FullRuntime.restore_tool
    preview=FullRuntime.preview

    def snapshot(self,expected=0):
        read_fd,write_fd=os.pipe()
        launcher='import os,sys; fd=int(sys.argv[1]); os.dup2(fd,3,inheritable=True); os.close(fd) if fd!=3 else None; os.execv(sys.argv[2],sys.argv[2:])'
        try:
            process=subprocess.Popen([sys.executable,'-c',launcher,str(write_fd),self.busybox,'ash',str(SCRIPT),'--public-uci','snapshot-read'],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env,pass_fds=(write_fd,))
        finally: os.close(write_fd)
        with os.fdopen(read_fd,'rb') as stream,ThreadPoolExecutor(max_workers=1) as pool:
            private=pool.submit(stream.read)
            stdout,stderr=process.communicate(timeout=30)
            frame=private.result(timeout=10)
        self.assertEqual(process.returncode,expected,(stdout,stderr))
        self.assertEqual(stderr,b'')
        self.assertLess(len(stdout),1024)
        if expected: self.assertEqual(frame,b'')
        return json.loads(stdout),frame

    def decode(self,frame):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(unpack_returned_tuples=True,encoding=None)
        return lua.execute(READER.read_bytes()).parse(frame,lua.execute(CODEC.read_bytes()))

    def test_empty_and_binary_vault_never_use_public_stdout(self):
        report,frame=self.snapshot()
        self.assertEqual(report['revision'],2)
        self.assertEqual(len(list(self.decode(frame)[b'credentials'].items())),0)
        value=b'PRIVATE_SENTINEL\x00\xff\nEND\n'
        self.secret(value)
        report,frame=self.snapshot()
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(report))
        decoded=self.decode(frame)
        self.assertEqual(decoded[b'revision'],report['revision'])
        self.assertEqual(decoded[b'credentials'][b'cloudflare.dns_a.secret'],value)
        self.assertNotIn(b'PRIVATE_SENTINEL',self.export())

    def test_missing_pipe_regular_file_and_extra_arguments_are_rejected(self):
        self.cli('snapshot-read',expected=2)
        file=self.base/'wrong-destination'; file.write_bytes(b'unchanged')
        with file.open('r+b') as stream:
            launcher='import os,sys; os.dup2(int(sys.argv[1]),3,inheritable=True); os.execv(sys.argv[2],sys.argv[2:])'
            result=subprocess.run([sys.executable,'-c',launcher,str(stream.fileno()),self.busybox,'ash',str(SCRIPT),'--public-uci','snapshot-read'],
                env=self.env,capture_output=True,pass_fds=(stream.fileno(),),timeout=30)
        self.assertEqual(result.returncode,2)
        self.assertEqual(file.read_bytes(),b'unchanged')
        self.cli('snapshot-read','cloudflare',expected=2)

    def test_shared_flock_prevents_overlapping_writer(self):
        import fcntl
        with (self.store/'.lock').open('rb') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.snapshot(expected=4)
            self.secret(b'PRIVATE_SENTINEL',expected=4)
        self.assertEqual(self.snapshot()[0]['revision'],2)

    def test_corrupt_and_linked_credentials_fail_before_private_delivery(self):
        self.secret(b'PRIVATE_SENTINEL')
        path=self.secret_path(3); path.write_bytes(b'CORRUPTED_SENTINEL')
        self.snapshot(expected=1)
        path.write_bytes(b'PRIVATE_SENTINEL')
        target=self.base/'linked'; target.write_bytes(b'PRIVATE_SENTINEL'); target.chmod(0o600)
        path.unlink(); path.symlink_to(target)
        self.snapshot(expected=1)

    def test_rollback_and_provider_change_use_only_current_generation(self):
        self.secret(b'OLD_PRIVATE')
        self.commit_body(self.export().replace(b"option provider 'cloudflare'",b"option provider 'aliyun'"))
        self.assertEqual(len(list(self.decode(self.snapshot()[1])[b'credentials'].items())),0)
        self.cli('commit',self.cli('rollback-preview','3')['confirmation'])
        data=self.decode(self.snapshot()[1])
        self.assertEqual(data[b'revision'],5)
        self.assertEqual(data[b'credentials'][b'cloudflare.dns_a.secret'],b'OLD_PRIVATE')

    def test_incomplete_transport_has_no_valid_snapshot(self):
        self.secret(b'PRIVATE_SENTINEL')
        self.fault('lua','if "snapshot" in sys.argv: sys.exit(1)')
        self.snapshot(expected=1)
        # Lua is the actual Lua 5.1 interpreter, not a BusyBox applet.
        (self.bin/'lua').unlink()
        (self.bin/'lua').symlink_to(self.lua)
        frame=self.snapshot()[1]
        self.assertIsNone(self.decode(frame[:-1])[0])

    def test_busy_reader_does_not_consume_pending_confirmation(self):
        plan=self.preview()
        self.snapshot()
        self.cli('commit',plan['confirmation'])
        self.assertEqual(self.snapshot()[0]['revision'],3)

    def test_maximum_frame_and_slow_consumer_hold_writer_lock(self):
        # Prepare a sealed maximum vault fixture without consuming the
        # prototype's bounded 32-generation history with 192 individual puts.
        body="config homegate 'main'\n"
        names=[]
        for i in range(32):
            body+="config dns_account 'dns_"+str(i)+"'\n option provider 'cloudflare'\n"
            body+="config ddns_rule 'ddns_"+str(i)+"'\n option account 'dns_"+str(i)+"'\n option zone 'example.test'\n"
            body+="config web_rule 'web_"+str(i)+"'\n option domain 'host"+str(i)+".example.test'\n option https '0'\n"
            names += ['cloudflare.dns_'+str(i)+'.'+slot for slot in ('key_id','secret','account_id','endpoint')]
            names += ['ddns.ddns_'+str(i)+'.url','web.web_'+str(i)+'.target']
        from 配置预览回归 import HEADER
        self.commit_body((HEADER+body).encode())
        generation=self.store/'gen-3'
        for name in names:
            path=generation/'credentials'/name
            path.write_bytes(b'PRIVATE_SENTINEL'+b'\x00'*(4096-16))
            path.chmod(0o600)
        paths=[generation/'public.conf',generation/'parent',*sorted((generation/'credentials').iterdir())]
        (generation/'manifest').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path.relative_to(generation))+'\n' for path in paths))
        read_fd,write_fd=os.pipe()
        launcher='import os,sys; os.dup2(int(sys.argv[1]),3,inheritable=True); os.execv(sys.argv[2],sys.argv[2:])'
        process=subprocess.Popen([sys.executable,'-c',launcher,str(write_fd),self.busybox,'ash',str(SCRIPT),'--public-uci','snapshot-read'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env,pass_fds=(write_fd,))
        os.close(write_fd)
        try:
            with os.fdopen(read_fd,'rb') as stream:
                prefix=stream.read(11)
                self.assertEqual(prefix,b'HGPRIVATE1\n')
                self.assertIsNone(process.poll())
                self.secret(b'NEW_PRIVATE',expected=4)
                frame=prefix+stream.read()
            stdout,stderr=process.communicate(timeout=30)
            self.assertEqual(process.returncode,0,(stdout,stderr))
            self.assertEqual(stderr,b'')
            decoded=self.decode(frame)
            self.assertEqual(decoded[b'revision'],3)
            self.assertEqual(len(list(decoded[b'credentials'].items())),192)
            self.assertGreater(len(frame),786432)
            self.assertLess(len(frame),1114112)
            self.assertNotIn(b'PRIVATE_SENTINEL',stdout)
            self.assertEqual(self.cli('status')['revision'],3)
        finally:
            if process.poll() is None: process.kill(); process.wait()

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--runtime',action='store_true'); args=parser.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if args.runtime else Codec))
    raise SystemExit(not result.wasSuccessful())
