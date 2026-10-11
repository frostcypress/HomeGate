#!/usr/bin/env python3
"""Build standalone ARM64 offline test programs; devices need no Go toolchain."""
import argparse,gzip,hashlib,os,re,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def build(out,go):
    env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='arm64',GOARM64='v8.0')
    packages=subprocess.check_output([go,'list','-mod=vendor','./internal/...'],cwd=ROOT/'project/core/src',env=env,text=True).splitlines()
    tests=out/'offline-tests';tests.mkdir(parents=True,exist_ok=True)
    expected=set()
    with tempfile.TemporaryDirectory(prefix='homegate-offline-build-') as temp:
        for package in packages:
            name=package.rsplit('/',1)[1];binary=Path(temp)/(name+'.test')
            subprocess.run([go,'test','-mod=vendor','-c','-trimpath','-buildvcs=false','-ldflags=-s -w','-o',str(binary),package],cwd=ROOT/'project/core/src',env=env,check=True)
            blob=binary.read_bytes();assert blob[:6]==b'\x7fELF\x02\x01' and int.from_bytes(blob[18:20],'little')==183
            target=tests/(name+'.test.gz');target.write_bytes(gzip.compress(blob,mtime=0));expected.add(target.name)
    for stale in tests.glob('*.test.gz'):
        if stale.name not in expected:stale.unlink()
    text=(ROOT/'homegate-version.mk').read_text(encoding='utf-8');version=re.search(r'^HOMEGATE_VERSION:=(.+)$',text,re.M)[1]+'-'+re.search(r'^HOMEGATE_RELEASE:=(.+)$',text,re.M)[1]
    script=(ROOT/'scripts/offline-verify.sh').read_text(encoding='utf-8')
    script=re.sub(r'EXPECTED_VERSION=\$\{HOMEGATE_VERIFY_EXPECTED_VERSION:-[^}]+\}',lambda _: 'EXPECTED_VERSION=${HOMEGATE_VERIFY_EXPECTED_VERSION:-'+version+'}',script)
    (out/'offline-verify.sh').write_text(script,newline='\n')
    (out/'arm64-profile.sh').write_bytes((ROOT/'scripts/arm64-profile.sh').read_bytes())
    (out/'offline-tests.SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  offline-tests/'+f.name+'\n' for f in sorted(tests.glob('*.gz'))),newline='\n')
    print('Built ARM64 offline tests:',len(expected))
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,default=ROOT/'dist/verification');parser.add_argument('--go',default='go');args=parser.parse_args();build(args.out.resolve(),args.go)
