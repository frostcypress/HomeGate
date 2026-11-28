#!/usr/bin/env python3
"""Fetch the unchanged host BusyBox archive through two bounded HTTPS sources."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from project import ROOT

SHA='6843ba7977081e735fa0fdb05893e3c002c8c5ad7c9c80da206e603cc0ac47e7'
LIMIT=4194304
ARCHIVE=ROOT/'build/busybox-runtime/busybox-1.33.2.tar.bz2'
URLS=('https://sources.openwrt.org/busybox-1.33.2.tar.bz2',
      'https://busybox.net/downloads/busybox-1.33.2.tar.bz2')

def valid(path):
    if path.is_symlink() or not path.is_file():return False
    with path.open('rb') as f:data=f.read(LIMIT+1)
    return len(data)<=LIMIT and hashlib.sha256(data).hexdigest()==SHA

def prepare():
    if ARCHIVE.is_symlink():return 1
    if valid(ARCHIVE):
        print('Pinned BusyBox 1.33.2 archive reused after SHA256 verification')
        return 0
    ARCHIVE.parent.mkdir(parents=True,exist_ok=True)
    for url in URLS:
        fd,name=tempfile.mkstemp(prefix='.busybox-download-',dir=ARCHIVE.parent)
        os.close(fd);pending=Path(name)
        try:
            try:
                result=subprocess.run(['curl','--silent','--show-error','--fail','--location',
                    '--proto','=https','--proto-redir','=https','--connect-timeout','15','--max-time','45',
                    '--max-filesize',str(LIMIT),'--output',str(pending),url],timeout=50,check=False)
            except (subprocess.TimeoutExpired,OSError):
                print('Pinned BusyBox source unavailable; trying remaining source',file=sys.stderr)
                continue
            if result.returncode or not valid(pending):
                print('Pinned BusyBox source failed transport, size or SHA256 verification',file=sys.stderr)
                continue
            os.replace(pending,ARCHIVE)
            print('Pinned BusyBox 1.33.2 archive verified:',SHA)
            return 0
        finally:pending.unlink(missing_ok=True)
    print('No verified BusyBox archive; dependency preparation refused',file=sys.stderr)
    return 1

if __name__=='__main__':
    if len(sys.argv)!=1:raise SystemExit(2)
    raise SystemExit(prepare())
