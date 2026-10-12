#!/usr/bin/env python3
"""Build the unchanged official LuCI jsonc Lua 5.1 binding for Linux tests."""
import hashlib
import subprocess
import urllib.request
from project import ROOT

COMMIT='e4c46338b196e486a88b1a75b78e283708c82bc4'
SHA256='95f84989937c965bb4c8e1e43df8601fc4588812a6a8ef24a5f474a617f7a5f0'
if __name__=='__main__':
    data=urllib.request.urlopen('https://raw.githubusercontent.com/openwrt/luci/'+COMMIT+'/libs/luci-lib-jsonc/src/jsonc.c',timeout=30).read(65537)
    if len(data)>65536 or hashlib.sha256(data).hexdigest()!=SHA256:
        raise ValueError('Official LuCI jsonc source checksum/size mismatch')
    output=ROOT/'build/service-observer'; (output/'luci').mkdir(parents=True,exist_ok=True)
    source=output/'jsonc.c'; source.write_bytes(data)
    subprocess.run(['gcc','-O2','-Wall','-Werror','-fPIC','-shared','-I/usr/include/lua5.1',str(source),
                    '-ljson-c','-llua5.1','-o',str(output/'luci/jsonc.so')],check=True,timeout=60)
    print('Official LuCI jsonc binding built:',COMMIT,SHA256)
