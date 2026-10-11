#!/usr/bin/env python3
"""Build the official 2019 UCI text parser/CLI for host interoperability tests."""
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import urllib.request
from project import ROOT

COMMIT='415f9e48436d29f612348f58f546b3ad8d74ac38'
SHA256='4adce41d0f93e71f3564b8f4f7dd91c11d68da0a33b3f198a652d1312680a3d4'

if __name__=='__main__':
    url='https://codeload.github.com/openwrt/uci/tar.gz/'+COMMIT
    data=urllib.request.urlopen(url,timeout=30).read(4*1024*1024+1)
    if len(data)>4*1024*1024 or hashlib.sha256(data).hexdigest()!=SHA256:
        raise ValueError('Official UCI archive checksum/size mismatch')
    output=ROOT/'build/uci-parser'
    output.mkdir(parents=True,exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        for item in archive.getmembers():
            path=Path(item.name)
            target=(output/path).resolve()
            if path.is_absolute() or not target.is_relative_to(output.resolve()) or not (item.isfile() or item.isdir()) or item.size>1024*1024:
                raise ValueError('Unsafe UCI archive entry')
        archive.extractall(output,filter='data')
    source=output/('uci-'+COMMIT)
    # The upstream template enables no macros with both debug options OFF.
    # Build unchanged text parser sources; blob/JSON and Lua binding excluded.
    template=(source/'uci_config.h.in').read_text()
    assert template.strip().splitlines()==['#cmakedefine UCI_DEBUG 1','#cmakedefine UCI_DEBUG_TYPECAST 1']
    (source/'uci_config.h').write_text('/* upstream debug options disabled */\n')
    subprocess.run(['gcc','-O2','-Wall','-Werror','-std=gnu99','-DUCI_PREFIX="'+str(source)+'"',
                    '-I'+str(source),*(str(source/name) for name in ('cli.c','libuci.c','file.c','util.c','delta.c','parse.c')),
                    '-o',str(output/'uci')],check=True,timeout=60)
    print('Official UCI parser built:',COMMIT,SHA256)
