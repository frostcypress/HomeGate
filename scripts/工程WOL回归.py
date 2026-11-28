#!/usr/bin/env python3
"""Actual installed CLI/LuCI and C transport, captured at external syscalls.
No CAP_NET_RAW is added; physical network/target wake remains unverified.
"""
import argparse,hashlib,importlib.util,json,os,shutil,struct,subprocess,sys,time,unittest
from pathlib import Path
from project import ROOT
spec=importlib.util.spec_from_file_location('engineering_web',ROOT/'scripts/工程网页回归.py');web=importlib.util.module_from_spec(spec);spec.loader.exec_module(web)
rpc,luci,STATE=web.rpc,web.luci,web.STATE
WOL=ROOT/'build/wol';FIXTURE=ROOT/'build/wol-fixture'
def setup_state(s):
 web.setup_state(s)
 for name in ['br-lan','eth1','eth2']:(s/'wol-sys-net'/name).mkdir(parents=True)
 (s/'wol-sys-net/br-lan/brif').mkdir()
 for name in ['eth2','eth1']:(s/'wol-sys-net/br-lan/brif'/name).touch()
 (s/'libexec/homegate-wol').mkdir()
 (s/'libexec/homegate-wol/send').write_text('#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\np=Path("/teststate/wol-mode")\nos.environ["HOMEGATE_WOL_FIXTURE_MODE"]=p.read_text() if p.exists() else "ok"\nos.environ["LD_PRELOAD"]='+repr(str(FIXTURE/'transport.so'))+'\nos.execv('+repr(str(WOL/'send'))+',["send",*sys.argv[1:]])\n')
 (s/'libexec/homegate-wol/send').chmod(0o755)
class Wake(web.Web):
 def cli(self,*args,ok=True):
  p=subprocess.run(['/usr/bin/homegate-engineering',*args],capture_output=True,timeout=12)
  self.assertEqual(p.returncode==0,ok,(args,p.returncode,p.stdout[:500],p.stderr[:200]));return json.loads(p.stdout)
 def cgi_action(self,action,s,fields=None,write=True,expected=200):
  data=dict(fields or {});data.update({'token':s[1]} if write else {})
  status,_,raw=self.cgi(web.BASE+'/configuration_api/'+action,cookie=s[0],verb='POST' if write else 'GET',fields=data)
  self.assertEqual(status,expected,raw[:600]);return json.loads(raw)
 def configured(self):
  s=self.login();self.cfg('prepare',s)
  for action,fields in [('preview_wol_host',{'id':'wake_a','name':'Wake host','mac':'c8-7f-54-53-6b-80'}),('preview_wol_settings',{'interface':'br-lan','selected_host':'wake_a'})]:
   p=self.cfg(action,s,**fields);self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
  return s
 def packets(self):
  p=STATE/'wol-wire.bin';raw=p.read_bytes() if p.exists() else b'';out=[]
  while raw:
   self.assertGreaterEqual(len(raw),12);self.assertEqual(raw[:4],b'WOL1');kind,index,n=raw[4],raw[5],int.from_bytes(raw[6:8],'big');dst=raw[8:12];self.assertGreaterEqual(len(raw),n+12);packet=raw[12:12+n];raw=raw[12+n:];out.append((kind,index,dst,packet))
  return out
 def verify_packets(self,d,mac='C8:7F:54:53:6B:80',clear=True):
  frames=self.packets();self.assertEqual(sum(k==1 for k,_,_,_ in frames),d['raw_sent']);self.assertEqual(sum(k==2 for k,_,_,_ in frames),d['udp_sent'])
  target=bytes.fromhex(mac.replace(':',''));payload=b'\xff'*6+target*16
  for kind,index,dst,packet in frames:
   if kind==1:self.assertEqual(packet[:6],b'\xff'*6);self.assertEqual(packet[6:12],bytes([0,17,34,51,68,index]));self.assertEqual(packet[12:14],b'\x08\x42');self.assertEqual(packet[14:],payload)
   else:self.assertIn(dst,[bytes([192,0,2,255]),b'\xff'*4]);self.assertEqual(packet,payload)
  self.assertFalse(d['device_wake_verified'])
  print('WOL_CAPTURE',json.dumps({'raw':d['raw_sent'],'udp':d['udp_sent'],'records':len(frames),'records_sha256':hashlib.sha256((STATE/'wol-wire.bin').read_bytes() if (STATE/'wol-wire.bin').exists() else b'').hexdigest(),'real_network':False}),flush=True)
  if clear:(STATE/'wol-wire.bin').unlink(missing_ok=True)
 def test_saved(self):
  s=self.configured();d=self.cgi_action('wol_status',s,write=False)['report'];self.assertEqual(d['selected_host'],'wake_a');self.assertEqual(d['hosts'][0]['mac'],'C8:7F:54:53:6B:80')
  self.assertFalse((STATE/'wol-wire.bin').exists());d=self.cgi_action('wol_send',s,{'id':'wake_a','consent':'1'})['report'];self.assertEqual((d['raw_sent'],d['udp_sent'],d['interfaces']),(9,6,['br-lan','eth1','eth2']));self.verify_packets(d)
  self.verify_packets(self.cli('wol','wake_a','--confirm'));self.verify_unchanged()
  p=self.cfg('preview_wol_settings',s,interface='eth1',selected_host='wake_a');self.cfg('apply',s,confirmation=p['report']['confirmation'],consent='1')
  d=self.cli('wol','','C8:7F:54:53:6B:80','--confirm');self.assertEqual(d['interface'],'eth1');self.verify_packets(d)
 def test_direct(self):
  # No prepare/store/config requirements on this explicit direct command.
  source=Path('/etc/config/homegate_engineering');source.write_text('INVALID_OTHER_BUSINESS\n')
  d=self.cli('wol','eth1','c87f.5453.6b80','--confirm');self.assertEqual((d['raw_sent'],d['udp_sent'],d['interfaces']),(3,6,['eth1']));self.verify_packets(d)
  s=self.login();d=self.cgi_action('wol_direct',s,{'interface':'eth1','mac':'C8:7F:54:53:6B:80','consent':'1'})['report'];self.assertEqual((d['raw_sent'],d['udp_sent']),(3,6));self.verify_packets(d)
  d=self.cli('wol','','c8:7f:54:53:6b:80','--confirm');self.assertEqual(d['interface'],'br-lan');self.verify_packets(d);self.verify_unchanged()
 def test_failures(self):
  s=self.configured()
  for mode,raw,udp in [('raw-fail',0,6),('udp-fail',9,0),('partial',3,6),('all-fail',0,0),('short',0,0)]:
   (STATE/'wol-mode').write_text(mode);d=self.cli('wol','wake_a','--confirm',ok=raw+udp>0);self.assertEqual((d['raw_sent'],d['udp_sent']),(raw,udp));self.assertTrue(d['warnings']);self.verify_packets(d)
  self.verify_unchanged()
 def test_security(self):
  s=self.configured();base=web.BASE+'/configuration_api/wol_send'
  for verb,fields,expected in [('GET',{'id':'wake_a','consent':'1'},405),('POST',{'id':'wake_a','consent':'1','token':'bad'},403)]:
   status,_,_=self.cgi(base,cookie=s[0],verb=verb,fields=fields);self.assertEqual(status,expected)
  for args in [('wol','wake_a'),('wol','eth1;id','C8:7F:54:53:6B:80','--confirm'),('wol','eth1','bad','--confirm'),('wol','absent','C8:7F:54:53:6B:80','--confirm')]:self.cli(*args,ok=False)
  self.assertFalse((STATE/'wol-wire.bin').exists());work=Path('/var/run/homegate-engineering/wol');target=STATE/'untouched';target.write_text('KEEP');(work/'plan.json').unlink();(work/'plan.json').symlink_to(target)
  self.cli('wol','eth1','C8:7F:54:53:6B:80','--confirm',ok=False);self.assertEqual(target.read_text(),'KEEP');self.verify_unchanged()
 def test_bounds(self):
  self.configured();(STATE/'wol-mode').write_text('hold');start=time.monotonic();d=self.cli('wol','wake_a','--confirm',ok=False);self.assertLess(time.monotonic()-start,8);self.assertEqual(d['effect'],'unknown');self.assertNotIn('raw_sent',d);self.assertFalse((STATE/'wol-wire.bin').exists())
  caps=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
  for name in ['CapEff','CapPrm','CapBnd']:self.assertEqual(int(caps[name].strip(),16),0)
  self.verify_unchanged()
def main():
 global WOL,FIXTURE
 p=argparse.ArgumentParser();p.add_argument('--runtime-dir',type=Path,default=ROOT/'build/rpcd');p.add_argument('--http-runtime-dir',type=Path,default=ROOT/'build/uhttpd');p.add_argument('--luci-runtime-dir',type=Path,default=ROOT/'build/luci');p.add_argument('--wol-runtime-dir',type=Path,default=WOL);p.add_argument('--wol-fixture-dir',type=Path,default=FIXTURE);p.add_argument('--inside-net');p.add_argument('--inside-uid');p.add_argument('--group',choices=['saved','direct','failures','security','bounds']);a=p.parse_args()
 WOL=a.wol_runtime_dir.resolve();FIXTURE=a.wol_fixture_dir.resolve();rpc.WORK,luci.HTTP,luci.LUA=a.runtime_dir.resolve(),a.http_runtime_dir.resolve(),a.luci_runtime_dir.resolve();luci.BASE,luci.PAGE=web.BASE,web.PAGE
 if a.inside_net:
  rpc.OUTER_NET,rpc.OUTER_UID=a.inside_net,a.inside_uid;return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([Wake('test_'+a.group)])).wasSuccessful() else 1
 spec=importlib.util.spec_from_file_location('wol_runtime',ROOT/'scripts/prepare-wol.py');runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime);runtime.validate(WOL)
 d=json.loads((FIXTURE/'metadata.json').read_text());assert d['source_sha256']==hashlib.sha256((ROOT/'scripts/wol-syscall-fixture.c').read_bytes()).hexdigest() and d['library_sha256']==hashlib.sha256((FIXTURE/'transport.so').read_bytes()).hexdigest()
 for group in [a.group] if a.group else ['saved','direct','failures','security','bounds']:
  result=rpc.isolated(rpc.WORK,guest_script=Path(__file__).resolve(),extra_ro=(luci.HTTP,luci.LUA,WOL,FIXTURE),extra_mounts=lambda s:((Path('/usr/bin'),'/fixture-host-bin'),(s/'usr-bin','/usr/bin'),(s/'controllers',luci.LUA/'prefix/lib/lua/luci/controller'),(s/'models',luci.LUA/'prefix/lib/lua/luci/model'),(s/'libexec','/usr/libexec'),(s/'tools','/usr/sbin'),(s/'curl-fixture','/usr/bin/curl'),(s/'wol-sys-net','/sys/class/net')),extra_rw_mounts=lambda s:((s/'etc/homegate-engineering','/etc/homegate-engineering'),(s/'etc/config','/etc/config')),state_setup=setup_state,guest_args=['--http-runtime-dir',str(luci.HTTP),'--luci-runtime-dir',str(luci.LUA),'--wol-runtime-dir',str(WOL),'--wol-fixture-dir',str(FIXTURE),'--group',group])
  if result:return result
 return 0
if __name__=='__main__':sys.exit(main())
