from pathlib import Path
import argparse,hashlib,importlib.util,io,json,os,re,shutil,stat,subprocess,tarfile
from project import ROOT,identity
from engineering_runtime import payload,web_payload,SCOPE

parser=argparse.ArgumentParser(description='Inspect and execute the exact installed bytes of isolated engineering IPKs')
parser.add_argument('--packages',type=Path,required=True)
parser.add_argument('--root-dir',type=Path,required=True)
parser.add_argument('--report',type=Path,required=True)
args=parser.parse_args()
source=ROOT;output=args.packages;root=args.root_dir
assert os.getuid()==0 and not root.exists()
spec=importlib.util.spec_from_file_location('packages',source/'scripts/检查三包.py')
packages=importlib.util.module_from_spec(spec);spec.loader.exec_module(packages)
files=sorted(output.glob('*.ipk'));assert len(files)==3
packages.inspect(output,'homegate-engineering',identity()['normalized'],'ipk','all')
root.mkdir(mode=0o700)
allowed={
 'homegate-engineering-core':['usr/bin/homegate-engineering','usr/libexec/homegate-engineering/','usr/share/licenses/homegate-engineering/','usr/share/doc/homegate-engineering/','etc/config/homegate_engineering','etc/init.d/homegate-engineering','etc/hotplug.d/iface/95-homegate-engineering'],
 'luci-app-homegate-engineering':['usr/lib/lua/luci/controller/homegate_engineering.lua','usr/lib/lua/luci/controller/homegate_engineering_ddns.lua','usr/lib/lua/luci/view/homegate_engineering/','usr/lib/lua/luci/model/homegate_engineering/','www/luci-static/resources/homegate-engineering/'],
 'luci-i18n-homegate-engineering-zh-cn':['usr/lib/lua/luci/i18n/homegate_engineering.zh-cn.lmo'],
}
payload_hashes={};inspected=[];control_files={}
for file in files:
 info=packages.metadata(file,'ipk');assert info['name'] in allowed
 blob=file.read_bytes()
 if blob.startswith(b'!<arch>\n'):
  members=packages.ar_members(blob);data=[v for k,v in members.items() if k.startswith('data.tar.')];assert len(data)==1;data=data[0]
  control=[v for k,v in members.items() if k.startswith('control.tar.')];assert len(control)==1;control=control[0]
 else:data=packages.tar_member(blob,'data.tar.gz');control=packages.tar_member(blob,'control.tar.gz')
 with tarfile.open(fileobj=io.BytesIO(control),mode='r:*') as archive:
  control_files[info['name']]={entry.name.removeprefix('./'):archive.extractfile(entry).read() for entry in archive if entry.isfile()}
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as archive:
  for entry in archive:
   name=entry.name.removeprefix('./').rstrip('/')
   if name in ('','.'):continue
   assert not name.startswith('/') and '..' not in Path(name).parts
   assert entry.isfile() or entry.isdir(),('nonregular payload',name)
   if entry.isfile():
    assert any(name==p or (p.endswith('/') and name.startswith(p)) for p in allowed[info['name']]),name
    raw=archive.extractfile(entry).read();assert not raw.startswith(b'\x7fELF'),name
    payload_hashes[name]=hashlib.sha256(raw).hexdigest()
  archive.extractall(root,filter='data')
 inspected.append({'name':info['name'],'payload_files':sum(1 for n in payload_hashes if any(n==p or (p.endswith('/') and n.startswith(p)) for p in allowed[info['name']]))})

expected={
 'usr/bin/homegate-engineering':source/'packaging/engineering/files/homegate-engineering',
 'usr/libexec/homegate-engineering/engineering.lua':source/'packaging/engineering/files/engineering.lua',
 'usr/share/doc/homegate-engineering/README.md':source/'packaging/engineering/README.md',
 'usr/share/licenses/homegate-engineering/LICENSE':source/'LICENSE',
 'usr/lib/lua/luci/controller/homegate_engineering.lua':source/'packaging/engineering/files/controller.lua',
 'usr/lib/lua/luci/view/homegate_engineering/overview.htm':source/'packaging/engineering/files/overview.htm',
 'etc/config/homegate_engineering':source/'packaging/engineering/files/homegate_engineering.config',
 'etc/init.d/homegate-engineering':source/'packaging/engineering/files/homegate-engineering.init',
 'etc/hotplug.d/iface/95-homegate-engineering':source/'packaging/engineering/files/95-homegate-engineering',
}
for name in ['ddns-control.sh','apply-handle.lua','service-disabled','config-web.sh','config-web.lua','schedule-control.sh']:
 expected['usr/libexec/homegate-engineering/'+name]=source/'packaging/engineering/files'/name
generated=payload(source)
expected_lmo=root/'expected-translation.lmo'
subprocess.run(['python3',str(source/'project/luci/common/tools/po2lmo.py'),str(source/'packaging/engineering/po/zh_Hans/engineering.po'),str(expected_lmo)],check=True)
expected['usr/lib/lua/luci/i18n/homegate_engineering.zh-cn.lmo']=expected_lmo
expected_hashes={name:hashlib.sha256(file.read_bytes()).hexdigest() for name,file in expected.items()}
expected_hashes.update({'usr/libexec/homegate-engineering/'+name:hashlib.sha256(raw).hexdigest() for name,raw in generated.items()})
expected_hashes.update({name:hashlib.sha256(raw).hexdigest() for name,raw in web_payload(source).items()})
assert set(payload_hashes)==set(expected_hashes),(set(payload_hashes)-set(expected_hashes),set(expected_hashes)-set(payload_hashes))
for name,file in expected.items():assert payload_hashes[name]==hashlib.sha256(file.read_bytes()).hexdigest(),('payload differs from current source',name)
assert all(payload_hashes[name]==digest for name,digest in expected_hashes.items())
assert (root/'etc/config/homegate_engineering').stat().st_mode&0o777==0o600

def copy_runtime(binary,destination=None):
 dest=root/(destination or str(binary).lstrip('/'));dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(binary,dest);dest.chmod(0o755)
 process=subprocess.run(['ldd',str(binary)],capture_output=True,text=True)
 if process.returncode and 'not a dynamic executable' not in process.stderr+process.stdout:raise RuntimeError(process.stderr+process.stdout)
 for name in re.findall(r'(?:=>\s+)?(/[^\s()]+)',process.stdout):
  dep=Path(name);target=root/str(dep).lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
  if not target.exists():shutil.copyfile(dep,target);target.chmod(0o755)

busybox=Path('/var/tmp/homegate-newhost-r79-20261023/source/build/busybox-runtime/busybox-1.33.2/busybox')
copy_runtime(busybox,'bin/busybox');(root/'bin/sh').symlink_to('busybox');(root/'bin/id').symlink_to('busybox');(root/'bin/ash').symlink_to('busybox')
copy_runtime(Path('/usr/bin/lua5.1'));(root/'usr/bin/lua').symlink_to('lua5.1')
sentinels={'etc/config/homegate':b'OLD-CONFIG-PRIVATE-SENTINEL','usr/bin/homegate':b'OLD-PRODUCTION-KEEP','etc/init.d/homegate':b'OLD-SERVICE-KEEP'}
for name,raw in sentinels.items():
 p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
tests=[]
(root/'dev').mkdir();os.mknod(root/'dev/null',stat.S_IFCHR|0o666,os.makedev(1,3))

# Execute the SDK-generated control wrappers against a fixed dispatch-boundary
# fixture. This is not an opkg installation or a claim about target firmware.
core='homegate-engineering-core';hooks=control_files[core]
assert b'default_postinst' in hooks['postinst'] and b'default_prerm' in hooks['prerm']
assert b'schedule-quiescent' in hooks['prerm-pkg'] and b'rm -' not in hooks['prerm-pkg']
info=root/'usr/lib/opkg/info';info.mkdir(parents=True)
for name in ['postinst','prerm','prerm-pkg']:
 p=info/(core+'.'+name);p.write_bytes(hooks[name]);p.chmod(0o755)
lib=root/'lib/functions.sh';lib.parent.mkdir(exist_ok=True)
lib.write_text('''default_postinst() {
 /etc/init.d/homegate-engineering enable >/dev/null 2>&1 || :
 /etc/init.d/homegate-engineering start >/dev/null 2>&1 || :
 return 0
}
default_prerm() {
 ( . /usr/lib/opkg/info/homegate-engineering-core.prerm-pkg ); code=$?
 /etc/init.d/homegate-engineering stop >/dev/null 2>&1 || :
 return "$code"
}
''')
for action in ['boot','start']:
 p=subprocess.run(['chroot',str(root),'/etc/init.d/homegate-engineering',action],capture_output=True,timeout=10)
 assert (p.returncode,p.stdout,p.stderr)==(0,b'',b'')
 assert not (root/'var/run/homegate-engineering').exists() and not (root/'etc/homegate-engineering').exists()
tests.append('installed-init-boot-and-unconfirmed-start-do-not-dispatch')
for action in ['postinst','prerm']:
 p=subprocess.run(['chroot',str(root),'/bin/sh','/usr/lib/opkg/info/'+core+'.'+action],capture_output=True,timeout=10)
 assert (p.returncode,p.stdout,p.stderr)==(0,b'',b''),(action,p.stdout,p.stderr)
 assert not (root/'var/run/homegate-engineering').exists() and not (root/'etc/homegate-engineering').exists()
tests.append('actual-SDK-control-wrappers-no-implicit-activation')
def command(label,args,expected=0,data=b''):
 p=subprocess.run(['chroot',str(root),'/usr/bin/homegate-engineering',*args],input=data,capture_output=True,timeout=15,
                  env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
 assert (p.returncode,p.stderr)==(expected,b''),(label,p.stdout,p.stderr)
 assert len(p.stdout)<=8192
 for secret in [b'PRIVATE_SENTINEL',b'SECRET_SENTINEL',b'127.0.0.1',b'example.test']:assert secret not in p.stdout,(label,secret)
 result=json.loads(p.stdout);assert result['ok']==(expected==0)
 assert result['write_ready'] is False and result['effect']=='none'
 tests.append(label);return p.stdout,result

raw='''config homegate 'main'
 option enabled '1'
config dns_account 'dns_a'
 option provider 'cloudflare'
 option secret 'PRIVATE_SENTINEL'
config ddns_rule 'ddns_a'
 option enabled '1'
 option account 'dns_a'
 option zone 'example.test'
 option host 'www.example.test'
config certificate 'cert_a'
 option source 'acme'
 option account 'dns_a'
 option zone 'example.test'
 list domains '*.example.test'
config web_rule 'web_a'
 option enabled '1'
 option domain 'www.example.test'
 option certificate 'cert_a'
 option target 'https://127.0.0.1:8443/'
config wol_host 'host_a'
 option mac 'AA-BB-CC-DD-EE-FF'
'''
version_raw,version=command('installed-version',['version']);assert version['version']==identity()['normalized'] and version['scope']==SCOPE and not version['production_ready']
dns_raw,dns=command('installed-provider-catalog',['dns-provider-catalog']);assert [p['name'] for p in dns['providers']]==['aliyun','cloudflare','dnspod','huaweicloud']
ca_raw,ca=command('installed-CA-catalog',['acme-ca-catalog']);assert ca['cas'][0]['name']=='letsencrypt'
_,valid=command('installed-full-configuration-validation',['check-stdin'],data=raw.encode());assert valid['sections']==dict.fromkeys(['homegate','dns_account','ddns_rule','certificate','web_rule','wol_host'],1)
command('invalid-switch-refused',['check-stdin'],1,raw.replace("option enabled '1'","option enabled '2'",1).encode())
command('invalid-Web-target-refused',['check-stdin'],1,raw.replace('https://127.0.0.1:8443/','ftp://PRIVATE_SENTINEL/').encode())
command('oversized-input-refused',['check-stdin'],1,b'A'*262145)
command('unsupported-action-refused',['daemon'],2)
command('extra-path-argument-refused',['check-stdin','/etc/config/homegate'],2)
command('empty-input-refused',['check-stdin'],1)

lua='/usr/bin/lua'
controller='/usr/lib/lua/luci/controller/homegate_engineering.lua'
code="assert(loadfile('"+controller+"'))"
subprocess.run(['chroot',str(root),lua,'-e',code],check=True,capture_output=True,timeout=15);tests.append('installed-controller-Lua51-syntax')

parsers=list(Path('/var/tmp/homegate-luci-r84-runtime').rglob('parser.so'));assert parsers,'existing real LuCI template parser required'
parser=parsers[0];copy_runtime(parser,'usr/lib/lua/5.1/luci/template/parser.so')
template='/usr/lib/lua/luci/view/homegate_engineering/overview.htm'
render="""package.cpath='/usr/lib/lua/5.1/?.so'
local parser=require('luci.template.parser')
local f,e=parser.parse('"""+template+"""');assert(type(f)=='function',e)
local out={};local env={backend_available=true,version='1.3.0-r137',providers={{name='cf',display_name='<script>alert(1)</script>'}},cas={{display_name="Let's Encrypt"}}}
env.write=function(v)out[#out+1]=tostring(v or '')end
env.include=function(v)assert(v=='header' or v=='footer')end
env.translate=function(v)return v end
env.url=function(v)return '/'..v end
env.pcdata=function(v)return tostring(v):gsub('&','&amp;'):gsub('<','&lt;'):gsub('>','&gt;'):gsub('"','&quot;')end
setmetatable(env,{__index=_G});setfenv(f,env);f()
local html=table.concat(out);assert(not html:find('<script>',1,true));assert(html:find('&lt;script&gt;',1,true));assert(html:find('1.3.0-r137',1,true))
"""
result=subprocess.run(['chroot',str(root),lua,'-'],input=render.encode(),capture_output=True,timeout=15)
assert result.returncode==0,(result.stdout,result.stderr);tests.append('installed-template-real-parser-and-escaping')
lmo=(root/'usr/lib/lua/luci/i18n/homegate_engineering.zh-cn.lmo').read_bytes()
assert '工程验证'.encode() in lmo and len(lmo)>200;tests.append('compiled-Chinese-catalog-present')
for name,digest in payload_hashes.items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest,name
for name,content in sentinels.items():assert (root/name).read_bytes()==content,name
record={'privacy':'local-only','date':'2026-10-27','version':identity()['normalized'],'package_payload_files':len(payload_hashes),
        'packages':inspected,'test_count':len(tests),'tests':tests,'all_passed':True,'host_runtime_chroot':str(root),
        'SDK_target_ELF_in_payload':False,'installed_bytes_unchanged':True,'old_config_binary_and_service_sentinels_unchanged':True,
        'target_router_installed':False,'QWRT_runtime_ABI_verified':False,'real_LuCI_template_parser_used':str(parser),
        'real_LuCI_HTTP_or_device_acceptance':False,'payload_file_sha256':payload_hashes}
record['SDK_hooks_dispatch_boundary_fixture']=True
record['control_hook_SHA256']={p:{n:hashlib.sha256(v).hexdigest() for n,v in c.items() if n in ['postinst','prerm','prerm-pkg']} for p,c in control_files.items()}
args.report.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'all_passed':True,'tests':len(tests),'payload_files':len(payload_hashes),'old_data_unchanged':True}))
