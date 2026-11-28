#!/usr/bin/env python3
"""Installed-provider selection and refusal before native lifecycle writes."""
from pathlib import Path
import copy,importlib.util,json,os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('install_plan',ROOT/'scripts/native-install-plan.py');plan=importlib.util.module_from_spec(spec);spec.loader.exec_module(plan)
VERSION='1.3.0-r174'
def row(name,depends='',version='1',provides='',conflicts=''):
 return {'Package':name,'Version':version,'Architecture':'all','Status':'install ok installed','Depends':depends,'Provides':provides,'Conflicts':conflicts}
def candidates():
 return [row('homegate-core','libc, homegate-nginx, homegate-wol',VERSION,conflicts='homegate'),row('luci-app-homegate','homegate-core (= '+VERSION+')',VERSION),row('luci-i18n-homegate-zh-cn','homegate-core (= '+VERSION+'), luci-app-homegate (= '+VERSION+')',VERSION),row('homegate-nginx','libc'),row('homegate-wol','libc')]
def inventory():
 return {'architectures':['all','aarch64_cortex-a53'],'installed':{'libc':row('libc')},'commands':{n:'/bin/'+n for n in plan.TOOLS},'files':{n:'present' for n in plan.FRAMEWORK}}
class Providers(unittest.TestCase):
 def assess(self,c=None,i=None):return plan.assess(c or candidates(),i or inventory(),VERSION,lambda a,o,b:a==b)
 def codes(self,r):return {x['code'] for x in r['issues']}
 def test_reuses_installed_without_SDK_replacement(self):
  r=self.assess();self.assertTrue(r['declared_provider_set_closed']);self.assertEqual(r['selected_providers']['libc']['origin'],'reuse-installed');self.assertEqual(r['automatic_additional_packages'],[]);self.assertFalse(r['deployable']);self.assertFalse(r['target_verified'])
 def test_unique_versioned_virtual_provider(self):
  c=candidates();c[0]['Depends']+=', ip6tables (= 2)';i=inventory();i['installed']['legacy-fw']=row('legacy-fw',provides='ip6tables (= 2)')
  r=self.assess(c,i);self.assertTrue(r['declared_provider_set_closed']);self.assertIn('legacy-fw',r['selected_providers'])
 def test_unversioned_virtual_never_claims_required_version(self):
  c=candidates();c[0]['Depends']+=', alias (= 1)';i=inventory();i['installed']['provider']=row('provider',provides='alias')
  self.assertIn('provider-version-unsatisfied',self.codes(self.assess(c,i)))
 def test_ambiguous_virtual_is_not_guessed(self):
  c=candidates();c[0]['Depends']+=', alias';i=inventory()
  for n in ['first','second']:i['installed'][n]=row(n,provides='alias')
  self.assertIn('ambiguous-installed-provider',self.codes(self.assess(c,i)))
 def test_missing_dependencies_are_reported_never_downloaded(self):
  c=candidates();c[0]['Depends']+=', absent';r=self.assess(c);self.assertIn('missing-installed-provider',self.codes(r));self.assertEqual(r['kernel_modules_to_install'],[])
 def test_missing_command_and_framework_block(self):
  i=inventory();i['commands']['fsync']='missing';i['files']['/lib/functions/procd.sh']='missing';codes=self.codes(self.assess(i=i));self.assertIn('required-command-missing',codes);self.assertIn('required-framework-missing',codes)
 def test_old_products_and_unconfigured_provider_refused(self):
  c=candidates();c[0]['Version']='1.3.0-r168';i=inventory();i['installed']['libc']['Status']='install ok unpacked';codes=self.codes(self.assess(c,i));self.assertIn('candidate-source-version-stale',codes);self.assertIn('installed-package-not-configured',codes)
 def test_legacy_conflict_requires_coordinated_transition(self):
  i=inventory();i['installed']['homegate']=row('homegate',version='1.3.1-1');self.assertIn('legacy-transition-required',self.codes(self.assess(i=i)))
 def test_transitive_installed_versions_checked(self):
  i=inventory();i['installed']['libc']['Depends']='base (= 2)';i['installed']['base']=row('base',version='1');self.assertIn('provider-version-unsatisfied',self.codes(self.assess(i=i)))
 def test_real_opkg_user_and_hold_flags_are_installed(self):
  for flag in ['ok','user','hold']:
   i=inventory();i['installed']['libc']['Status']='install '+flag+' installed';r=self.assess(i=i)
   self.assertTrue(r['declared_provider_set_closed']);self.assertEqual(r['selected_providers']['libc']['installed_status'],'install '+flag+' installed');self.assertEqual(r['system_packages_to_replace'],[])
 def test_unknown_flags_or_pending_removal_do_not_authorize_reuse(self):
  for status in ['install nonsense installed','install ok unpacked','deinstall user installed']:
   i=inventory();i['installed']['libc']['Status']=status;self.assertIn('installed-package-not-configured',self.codes(self.assess(i=i)))
 def test_underscore_package_and_dependency_are_preserved(self):
  p=plan.package_fields('Package: kmod-pcie_mhi\nVersion: 1\nArchitecture: all\nDepends: wififw_mount_script (= 1)')
  self.assertEqual(p['Package'],'kmod-pcie_mhi');self.assertEqual(plan.dependency(p['Depends']),('wififw_mount_script','=','1'))
  i=inventory();i['installed']['libc']['Depends']='wififw_mount_script (= 1)';i['installed']['wififw_mount_script']=row('wififw_mount_script');self.assertTrue(self.assess(i=i)['declared_provider_set_closed'])
 def test_held_wrong_version_is_not_replaced(self):
  i=inventory();i['installed']['libc']['Status']='install hold installed';c=candidates();c[0]['Depends']='libc (= 2)';r=self.assess(c,i)
  self.assertIn('provider-version-unsatisfied',self.codes(r));self.assertEqual(r['system_packages_to_replace'],[])
 def test_duplicate_and_secret_metadata_fields_refused(self):
  for raw in ['Package: a\nPackage: a\nVersion: 1\nArchitecture: all','Package: a\nVersion: 1\nArchitecture: all\nConffiles: PRIVATE','Package: a\nVersion: invalid version\nArchitecture: all']:
   with self.assertRaises(ValueError):plan.package_fields(raw)
 def test_malformed_inventory_cannot_be_empty_ready(self):
  for text in ['','x'*(plan.LIMIT+1),'[native_install_inventory]\n\0','[commands]\n[commands]\n']:
   with self.assertRaises(ValueError):plan.load_inventory(text)

@unittest.skipUnless(os.name=='posix','Existing Linux shell')
class ReadOnlyAndLifecycle(unittest.TestCase):
 def test_collector_filters_metadata_without_mutations(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);release=root/'release';release.write_text('fixture\n')
   body=(ROOT/'scripts/native-install-inventory.sh').read_text().replace('/etc/openwrt_release',str(release))
   prefix='''opkg(){ case "$1" in print-architecture) printf 'arch all 1\\n';;status) printf 'Package: libc\\nVersion: 1\\nArchitecture: all\\nStatus: install ok installed\\nDescription: PRIVATE_DESCRIPTION\\nConffiles:\\n /etc/config/private PRIVATE_HASH\\n\\n';;*) return 99;;esac; }
command(){ [ "$1" = -v ] || return 99;printf '/bin/fixture-%s\\n' "$2"; }
'''
   before={p.name:p.read_bytes() for p in root.iterdir()};r=subprocess.run(['sh'],input=(prefix+body).encode(),capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
   self.assertNotIn(b'PRIVATE',r.stdout);i=plan.load_inventory(r.stdout.decode());self.assertEqual(i['installed']['libc']['Version'],'1');self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir()})
 def guard(self,transition=False,offline=False,missing='fsync'):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);tools=root/'tools';tools.mkdir();trace=root/'mutations'
   for name in ['id','stat','fsync','flock','lua','sha256sum','opkg','mkdir','mv','rm','sleep','cat']:
    if name==missing:continue
    p=tools/name;p.write_text('#!/bin/sh\n'+('echo 0\n' if name=='id' else 'printf attempted > "'+str(trace)+'"\nexit 99\n'));p.chmod(0o755)
   script=ROOT/'packaging/production'/('native-transition.sh' if transition else 'native-package.sh');body=script.read_text()
   body=body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(tools)).replace('/usr/lib/opkg/info',str(root/'info')).replace('/etc/.homegate-transition',str(root/'transition')).replace('/etc/homegate',str(root/'data'))
   env={**os.environ,'IPKG_INSTROOT':str(root/'offline') if offline else ''}
   r=subprocess.run(['/bin/sh','-s','--',*(['prepare','--confirm'] if transition else ['preinst'])],input=body.encode(),env=env,capture_output=True,timeout=10)
   self.assertFalse(trace.exists());self.assertFalse((root/'data').exists());self.assertFalse((root/'transition').exists());return r
 def test_preinst_missing_fsync_refuses_before_writes(self):
  r=self.guard();self.assertEqual(r.returncode,7);self.assertIn(b'prerequisite missing: fsync',r.stderr)
 def test_transition_missing_fsync_refuses_before_writes(self):
  r=self.guard(transition=True);self.assertEqual(r.returncode,7);self.assertIn(b'prerequisite missing: fsync',r.stderr)
 def test_preinst_missing_flock_refuses_before_writes(self):
  r=self.guard(missing='flock');self.assertEqual(r.returncode,7);self.assertIn(b'prerequisite missing: flock',r.stderr)
 def test_transition_missing_flock_refuses_before_writes(self):
  r=self.guard(transition=True,missing='flock');self.assertEqual(r.returncode,7);self.assertIn(b'prerequisite missing: flock',r.stderr)
 def test_offline_preinst_preserves_no_activation(self):self.assertEqual(self.guard(offline=True).returncode,0)

if __name__=='__main__':unittest.main()
