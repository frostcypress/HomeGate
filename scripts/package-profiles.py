#!/usr/bin/env python3
"""Central ARM64 package metadata; labels must match the firmware APK database."""
import json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROFILE=json.loads((ROOT/'packaging/arm64-profiles.json').read_text(encoding='utf-8'))
ARCHITECTURES=tuple(PROFILE['package_architectures'])
assert PROFILE['goarch']=='arm64' and PROFILE['goarm64']=='v8.0'
assert len(ARCHITECTURES)==len(set(ARCHITECTURES)) and all(re.fullmatch(r'aarch64(?:_[a-z0-9-]+)?',v) for v in ARCHITECTURES)
def sync():
 p=ROOT/'scripts/arm64-profile.sh';s=p.read_text(encoding='utf-8');s,n=re.subn(r'case "\$1" in [^\n]+return 0;;',lambda m:'case "$1" in '+'|'.join(ARCHITECTURES)+') return 0;;',s,count=1);assert n==1
 s,n=re.subn(r'^hg_architectures\(\).+$',lambda m:"hg_architectures() { printf '%s\\n' '"+' '.join(ARCHITECTURES)+"'; }",s,count=1,flags=re.M);assert n==1;p.write_text(s,encoding='utf-8',newline='\n')
if __name__=='__main__':
 import sys
 if '--list' in sys.argv:print(' '.join(ARCHITECTURES))
 else:sync()
