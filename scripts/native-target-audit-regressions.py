#!/usr/bin/env python3
"""Target triage must not confuse package labels, ELF identity or approval."""
from pathlib import Path
import copy,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('target_audit',ROOT/'scripts/native-target-audit.py');audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
TARGET={'schema':1,'id':'fixture-target','architecture':'aarch64_cortex-a53','verified':False,'abi':None,'sdk':{'url':None,'sha256':None}}
CANDIDATE={'schema':1,'sdk':{'version':'24.10.6'},'QWRT_runtime_ABI_verified':False}
CLOSURE={'packages':[{'name':'kernel','version':'6.6.133~sdk-r1','depends':'libc'},{'name':'kmod-fixture','version':'1','depends':'kernel (=6.6.133~sdk)'},{'name':'libc','version':'1.2.5-r4','depends':''},{'name':'libopenssl3','version':'3.0.19-r1','depends':''},{'name':'homegate-nginx','version':'1','depends':'libc, libopenssl3'}]}
INVENTORY='[kernel]\nLinux 5.4.213\n[dependency_packages]\nkernel - 5.4.213-1-target\nlibc - 1.1.24-2\nlibopenssl3 - 1.1.1w-1\n'
class TargetAudit(unittest.TestCase):
    def assess(self,text=INVENTORY,target=TARGET,closure=CLOSURE):return audit.assess(target,CANDIDATE,closure,audit.load_inventory(text))
    def test_kernel_and_misleading_OpenSSL_label_block(self):
        r=self.assess();codes={x['code'] for x in r['issues']};self.assertIn('kernel-version-mismatch',codes);self.assertIn('openssl-package-name-ambiguous',codes);self.assertIn('target-SDK-not-pinned',codes);self.assertFalse(r['deployable'])
    def test_matching_base_kernel_never_establishes_hash_ABI(self):
        text=INVENTORY.replace('5.4.213','6.6.133');codes={x['code'] for x in self.assess(text)['issues']};self.assertNotIn('kernel-version-mismatch',codes);self.assertIn('kernel-ABI-hash-unverified',codes)
    def test_flags_and_package_name_do_not_authorize(self):
        target=copy.deepcopy(TARGET);target.update(verified=True,abi='self-claimed');target['sdk']={'url':'https://fixture.invalid/sdk','sha256':'a'*64}
        r=self.assess(target=target);self.assertFalse(r['target_verified']);self.assertFalse(r['release_authorized']);self.assertFalse(r['deployable'])
    def test_user_SDK_series_follows_package_format(self):
        target=copy.deepcopy(TARGET);target['package_format']='ipk';self.assertNotIn('SDK-series-selection-mismatch',{x['code'] for x in self.assess(target=target)['issues']})
        target['package_format']='apk';self.assertIn('SDK-series-selection-mismatch',{x['code'] for x in self.assess(target=target)['issues']})
        candidate=copy.deepcopy(CANDIDATE);candidate['sdk']['version']='25.12.0'
        r=audit.assess(target,candidate,CLOSURE,audit.load_inventory(INVENTORY));self.assertEqual(r['user_selected_SDK_series'],'25.12');self.assertNotIn('SDK-series-selection-mismatch',{x['code'] for x in r['issues']});self.assertFalse(r['deployable'])
    def test_duplicate_and_oversized_inputs_refused(self):
        for raw in [INVENTORY+'libc - different\n',INVENTORY+'\0', 'a'*(audit.MAX_BYTES+1),'x'*8193]:
            with self.subTest(length=len(raw)):
                with self.assertRaises(ValueError):audit.load_inventory(raw)
        with self.assertRaises(ValueError):audit.merge([audit.load_inventory(INVENTORY),audit.load_inventory(INVENTORY.replace('5.4.213','6.6.133'))])
        with self.assertRaises(ValueError):self.assess(closure={'packages':CLOSURE['packages']*2})
    def test_absent_or_changed_ELF_is_not_evidence(self):
        r=self.assess(INVENTORY+'[elf:/lib/libc.so]\nstate=missing\n');self.assertIn('actual-ELF-evidence-missing',{x['code'] for x in r['issues']})
        text=INVENTORY+'[elf:/usr/lib/libcrypto.so.3]\nstate=present\nelf_header_hex=unavailable\nidentity_before=1:2\nidentity_after=1:3\n'
        codes={x['code'] for x in self.assess(text)['issues']};self.assertIn('ELF-changed-during-observation',codes);self.assertIn('TLS-SONAME-evidence-missing',codes)
    def test_wrong_machine_and_invalid_header_refused(self):
        header=bytearray(64);header[:6]=b'\x7fELF\x02\x01';header[18:20]=(62).to_bytes(2,'little')
        def r(value):return {x['code'] for x in self.assess(INVENTORY+'[elf:/lib/libc.so]\nstate=present\nelf_header_hex='+value+'\n')['issues']}
        self.assertIn('ELF-machine-mismatch',r(header.hex()));self.assertIn('ELF-header-invalid',r('00'));header[18:20]=(183).to_bytes(2,'little');self.assertNotIn('ELF-machine-mismatch',r(header.hex()))
    def test_cli_is_read_only_and_returns_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);paths=[]
            for name,obj in [('target',TARGET),('candidate',CANDIDATE),('closure',CLOSURE)]:
                p=root/(name+'.json');p.write_text(json.dumps(obj));paths.extend(['--'+name,str(p)])
            inventory=root/'inventory.txt';inventory.write_text(INVENTORY);before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}
            run=subprocess.run([sys.executable,str(ROOT/'scripts/native-target-audit.py'),*paths,'--inventory',str(inventory)],capture_output=True,timeout=10)
            self.assertEqual(run.returncode,2);report=json.loads(run.stdout);self.assertFalse(report['deployable']);self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()})
    @unittest.skipUnless(os.name=='posix' and shutil.which('sh'),'POSIX shell required')
    def test_collector_source_mapped_read_only_and_output_bounds(self):
        # External package/readelf fixtures plus mapped public paths only.
        # This is a collector model, never a claim of device/ABI acceptance.
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);release=root/'release';release.write_text("DISTRIB_ID='Fixture'\nDISTRIB_ARCH='aarch64_cortex-a53'\nSECRET_SHOULD_NOT_EXPORT=keep\n")
            library=root/'public-lib';header=bytearray(64);header[:7]=b'\x7fELF\x02\x01\x01';header[18:20]=(183).to_bytes(2,'little');library.write_bytes(header)
            text=(ROOT/'scripts/核实原生ABI.sh').read_text();text=text.replace('/etc/openwrt_release',str(release))
            import re
            text=re.sub(r'for path in .*?;do','for path in '+str(library)+';do',text,count=1)
            prefix="""opkg(){ case "$1" in print-architecture) printf 'arch all 1\\narch aarch64_cortex-a53 10\\n';;list-installed) printf 'kernel - 5.4.213\\nlibc - 1.1.24-2\\nsecret-package - KEEP\\n';;*) return 9;;esac; }
uname(){ printf 'Linux 5.4.213\\n'; }
readelf(){ case "$1" in -h) printf '  Machine: AArch64\\n';;-d) awk 'BEGIN {for(i=1;i<=1000;i++)print "0x (SONAME) Library soname: [libfixture.so]"}';;*) awk 'BEGIN {for(i=1;i<=1000;i++)print "X509_check_ip"}';;esac; }
"""
            before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()};run=subprocess.run(['sh'],input=(prefix+text).encode(),capture_output=True,timeout=10);self.assertEqual(run.returncode,0,run.stderr)
            output=run.stdout.decode();self.assertNotIn('SECRET_SHOULD_NOT_EXPORT',output);self.assertNotIn('secret-package',output);self.assertEqual(output.count('(SONAME)'),64);self.assertEqual(output.count('X509_check_ip'),24);self.assertIn('acceptance=false',output);self.assertIn(header.hex(),output)
            self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()})
    @unittest.skipUnless(os.name=='posix' and shutil.which('sh') and not Path('/etc/openwrt_release').exists(),'Non-OpenWrt host guard')
    def test_collector_refuses_non_target_before_inventory(self):
        p=subprocess.run(['sh',str(ROOT/'scripts/核实原生ABI.sh')],capture_output=True,timeout=10);self.assertEqual(p.returncode,2);self.assertIn(b'status=target-required',p.stdout);self.assertNotIn(b'[dependency_packages]',p.stdout)
if __name__=='__main__':unittest.main()
