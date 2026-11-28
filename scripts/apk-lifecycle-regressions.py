#!/usr/bin/env python3
"""Exercise real lifecycle shell hooks against isolated init/UCI/proc fixtures."""
from pathlib import Path
import os, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[1]
HOOKS=ROOT/'packaging/apk-hooks'
with tempfile.TemporaryDirectory() as work:
    work=Path(work);bin_=work/'bin';bin_.mkdir();proc=work/'proc';proc.mkdir()
    init=work/'init';init.write_text('''#!/bin/sh
case "$1" in
 enabled) test "$(cat "$TEST_ROOT/enabled")" = 1;;
 enable) echo 1 >"$TEST_ROOT/enabled";;
 disable) echo 0 >"$TEST_ROOT/enabled";;
 start|reload) echo 1 >"$TEST_ROOT/running";;
 stop) echo 0 >"$TEST_ROOT/running";;
 *) exit 1;;
esac
''',newline='\n');init.chmod(0o755)
    uci=bin_/'uci';uci.write_text('#!/bin/sh\nif [ "$2" = get ]; then cat "$TEST_ROOT/desired"; fi\n',newline='\n');uci.chmod(0o755)
    config=work/'config';config.write_text('persistent configuration\n')
    env=dict(os.environ,PATH=str(bin_)+os.pathsep+os.environ['PATH'],TEST_ROOT=str(work),HOMEGATE_PACKAGE_INIT=str(init),HOMEGATE_PACKAGE_CONFIG_FILE=str(config),HOMEGATE_PACKAGE_UPGRADE_STATE=str(work/'state'),HOMEGATE_PACKAGE_PROC=str(proc))
    def hook(name):subprocess.run(['sh',str(HOOKS/name)],env=env,check=True)
    count=0
    for enabled in (0,1):
        for running in (0,1):
            for process in proc.glob('*'): (process/'cmdline').unlink();process.rmdir()
            (proc/'11').mkdir();(proc/'11/cmdline').write_bytes(b'/usr/bin/homegate\0web-job\0test\0')
            if running:(proc/'12').mkdir();(proc/'12/cmdline').write_bytes(b'/usr/bin/homegate\0daemon\0')
            (work/'enabled').write_text(str(enabled));(work/'running').write_text(str(running));(work/'desired').write_text(str(1-enabled))
            hook('core-pre-upgrade');assert (work/'running').read_text(encoding='utf-8').strip()=='0'
            hook('core-post-install')
            assert (work/'enabled').read_text(encoding='utf-8').strip()==str(enabled)
            assert (work/'running').read_text(encoding='utf-8').strip()==str(running)
            assert config.read_text(encoding='utf-8')=='persistent configuration\n'
            assert not (work/'state').exists();count+=1
    for desired in (0,1):
        (work/'desired').write_text(str(desired));hook('core-post-install')
        assert (work/'enabled').read_text(encoding='utf-8').strip()==str(desired)
        assert (work/'running').read_text(encoding='utf-8').strip()==str(desired);count+=1
    hook('core-pre-deinstall');assert (work/'enabled').read_text(encoding='utf-8').strip()=='0';assert (work/'running').read_text(encoding='utf-8').strip()=='0';count+=1
    for hookfile in HOOKS.iterdir():subprocess.run(['sh','-n',str(hookfile)],check=True)
print('APK hook fixtures: PASS',count,'cases; no router files modified')
