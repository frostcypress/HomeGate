#!/usr/bin/env python3
"""Real APK3 lifecycle selection in a temporary package database; no product hooks."""
from pathlib import Path
import subprocess,tempfile,os
apk=os.environ.get('HOMEGATE_APK_TOOL','apk')
with tempfile.TemporaryDirectory(prefix='hg-apk-manager-') as temp:
 root=Path(temp);stage=root/'files';stage.mkdir();(stage/'fixture').write_text('isolated lifecycle trace')
 trace=root/'trace';scripts=[]
 (root/'db/etc/apk').mkdir(parents=True);(root/'cache').mkdir()
 (root/'db/etc/apk/cache').symlink_to(root/'cache')
 for phase in ['pre-install','post-install','pre-upgrade','post-upgrade','pre-deinstall','post-deinstall']:
  script=root/phase;script.write_text('#!/bin/sh\necho '+phase+' >>'+str(trace)+'\n');scripts+=['--script',phase+':'+str(script)]
 for version in ['1-r1','1-r2']:
  subprocess.run([apk,'mkpkg','--files',str(stage),'--output',str(root/('hg-lifecycle-fixture-'+version+'.apk')),'--info','name:hg-lifecycle-fixture','--info','version:'+version,'--info','arch:x86_64',*scripts],check=True)
 subprocess.run([apk,'--allow-untrusted','mkndx','--pkgname-spec','${name}-${version}.apk','--output',str(root/'packages.adb'),*map(str,root.glob('*.apk'))],check=True)
 (root/'x86_64').mkdir()
 for package in root.glob('*.apk'):(root/'x86_64'/package.name).write_bytes(package.read_bytes())
 common=[apk,'--root',str(root/'db'),'--arch','x86_64','--allow-untrusted','--force-no-chroot','--force-non-repository','--repository',str(root/'packages.adb')]
 subprocess.run([*common,'add','--initdb',str(root/'hg-lifecycle-fixture-1-r1.apk')],check=True)
 subprocess.run([*common,'add',str(root/'hg-lifecycle-fixture-1-r2.apk')],check=True)
 subprocess.run([*common,'fix','--reinstall','hg-lifecycle-fixture'],check=True)
 subprocess.run([*common,'del','hg-lifecycle-fixture'],check=True)
 actual=trace.read_text(encoding='utf-8').splitlines()
 expected=['pre-install','post-install','pre-upgrade','post-upgrade','pre-upgrade','post-upgrade','pre-deinstall','post-deinstall']
 assert actual==expected,(actual,expected)
 print('PASS APK 3.0.5 actual-manager fresh/upgrade/reinstall/removal hook selection',actual)
