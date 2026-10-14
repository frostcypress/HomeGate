#!/usr/bin/env python3
"""Build unchanged official curl 7.83.1 CLI for isolated host HTTPS tests."""
import hashlib,io,subprocess,tarfile,urllib.request
from pathlib import Path
from project import ROOT
SHA='2cb9c2356e7263a1272fd1435ef7cdebf2cd21400ec287b068396deb705c22c4'
if __name__=='__main__':
 data=urllib.request.urlopen('https://curl.se/download/curl-7.83.1.tar.xz',timeout=60).read(4194305)
 assert len(data)<=4194304 and hashlib.sha256(data).hexdigest()==SHA,'Curl archive size/SHA mismatch'
 output=ROOT/'build/curl-runtime';output.mkdir(parents=True,exist_ok=True)
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:xz') as archive:
  for item in archive.getmembers():
   dest=(output/item.name).resolve()
   assert dest.is_relative_to(output.resolve()) and (item.isfile() or item.isdir()) and item.size<=8388608,'Unsafe official archive entry'
  archive.extractall(output,filter='data')
 source=output/'curl-7.83.1'
 subprocess.run(['./configure','--with-openssl','--disable-shared','--enable-static','--disable-manual','--without-libidn2','--without-libpsl','--without-brotli','--without-zstd','--without-zlib','--without-libssh2','--without-nghttp2','--disable-ldap','--disable-ldaps','--disable-rtsp','--disable-dict','--disable-telnet','--disable-tftp','--disable-pop3','--disable-imap','--disable-smtp','--disable-gopher','--disable-mqtt'],cwd=source,check=True,timeout=180)
 subprocess.run(['make','-j2'],cwd=source,check=True,timeout=240)
 version=subprocess.check_output([str(source/'src/curl'),'--version'],text=True)
 assert version.startswith('curl 7.83.1 '),version
 print('Official host curl 7.83.1 built; not a target SDK/ABI check:',SHA,version)
