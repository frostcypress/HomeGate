#!/usr/bin/env python3
"""Exercise the real version supervisor, including timeout and process cleanup."""
from pathlib import Path
import os,signal,subprocess,tempfile,time,unittest
ROOT=Path(__file__).resolve().parents[1]
FIXTURE=r'''
#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv){
 const char *mode=getenv("PROBE_MODE"),*trace=getenv("PROBE_TRACE");
 if(argc!=2||strcmp(argv[1],getenv("PROBE_ARG")))return 90;
 FILE *f=fopen(trace,"w");if(!f)return 91;fprintf(f,"%ld\n",(long)getpid());fclose(f);
 /* A broken supervisor must fail a bounded test, never leave infinite fixtures. */
 alarm(25);
 if(!strcmp(mode,"fail"))return 42;
 if(!strcmp(mode,"signal")){raise(SIGUSR1);return 92;}
 if(!strcmp(mode,"fork-exit")||!strcmp(mode,"fork-hang")){
  pid_t child=fork();if(child<0)return 93;
  if(!child){alarm(25);signal(SIGTERM,SIG_IGN);for(;;)pause();}
  f=fopen(trace,"a");if(!f)return 94;fprintf(f,"%ld\n",(long)child);fclose(f);
  if(!strcmp(mode,"fork-exit"))return 0;
  signal(SIGTERM,SIG_IGN);for(;;)pause();
 }
 return 0;
}
'''

class Supervisor(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(prefix='homegate-probe-regression-');cls.base=Path(cls.temp.name)
  cls.launcher=cls.base/'probe-run';fixture=cls.base/'fixture.c';fixture.write_text(FIXTURE)
  for src,out in [(ROOT/'scripts/native-component-probe.c',cls.launcher),(fixture,cls.base/'fixture')]:
   subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',str(src),'-o',str(out)],capture_output=True,check=True,timeout=30)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def setUp(self):
  self.case=self.base/self._testMethodName;self.case.mkdir();self.trace=self.case/'trace'
  for n in ['nginx','wol-send']:(self.case/n).symlink_to(self.base/'fixture')
 def env(self,mode='normal',arg='-V'):return {**os.environ,'PROBE_MODE':mode,'PROBE_ARG':arg,'PROBE_TRACE':str(self.trace)}
 def run_helper(self,mode='normal',args=('--nginx',),arg='-V',**kwargs):
  return subprocess.run([str(self.launcher),*args],cwd=self.case,env=self.env(mode,arg),capture_output=True,timeout=18,**kwargs)
 def assert_gone(self,pids):
  for pid in pids:
   p=Path('/proc')/pid/'stat'
   for _ in range(100):
    try:state=p.read_text().rsplit(')',1)[1].split()[0]
    except (FileNotFoundError,ProcessLookupError):break
    if state in ['Z','X']:break
    time.sleep(.01)
   else:self.fail('Owned child remains running: '+pid)
 def test_nginx_exact_version_argument(self):self.assertEqual(self.run_helper().returncode,0)
 def test_wol_exact_version_argument(self):self.assertEqual(self.run_helper(args=('--wol',),arg='--version').returncode,0)
 def test_preserves_failure_code(self):self.assertEqual(self.run_helper(mode='fail').returncode,42)
 def test_preserves_signal_code(self):self.assertEqual(self.run_helper(mode='signal').returncode,128+signal.SIGUSR1)
 def test_refuses_every_other_invocation(self):
  for args in [(),('--nginx','extra'),('--command',),('/bin/sh',)]:
   with self.subTest(args=args):self.assertEqual(self.run_helper(args=args).returncode,2);self.assertFalse(self.trace.exists())
 def test_exec_failure_is_explicit(self):
  (self.case/'nginx').unlink();r=self.run_helper();self.assertEqual(r.returncode,127);self.assertIn(b'component exec',r.stderr)
 def test_ten_second_limit_kills_owned_process_group(self):
  start=time.monotonic();r=self.run_helper(mode='fork-hang');elapsed=time.monotonic()-start
  self.assertEqual(r.returncode,124);self.assertGreaterEqual(elapsed,9.8);self.assertLess(elapsed,17.5)
  self.assertIn(b'timed out (10s)',r.stderr);self.assert_gone(self.trace.read_text().splitlines())
 def test_direct_exit_also_cleans_descendants_before_reap(self):
  self.assertEqual(self.run_helper(mode='fork-exit').returncode,0);self.assert_gone(self.trace.read_text().splitlines())
 def test_interrupt_cleans_children(self):
  p=subprocess.Popen([str(self.launcher),'--nginx'],cwd=self.case,env=self.env('fork-hang'),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   deadline=time.monotonic()+3
   while time.monotonic()<deadline:
    if self.trace.exists() and len(self.trace.read_text().splitlines())==2:break
    time.sleep(.01)
   else:self.fail('Fixture failed to enter owned process group')
   p.send_signal(signal.SIGTERM);p.communicate(timeout=5);self.assertEqual(p.returncode,143);self.assert_gone(self.trace.read_text().splitlines())
  finally:
   if p.poll() is None:p.kill();p.communicate(timeout=5)
 def test_ignored_SIGCHLD_cannot_auto_reap_owned_child(self):
  r=self.run_helper(preexec_fn=lambda:signal.signal(signal.SIGCHLD,signal.SIG_IGN));self.assertEqual(r.returncode,0)

if __name__=='__main__':
 if os.getuid()==0:raise SystemExit('Run with the existing non-root test UID')
 unittest.main()
