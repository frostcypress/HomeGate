#!/usr/bin/env python3
"""Check automatic reporting and failure exits with isolated command fixtures."""
from pathlib import Path
import tempfile,os,subprocess,gzip,hashlib,shutil
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    root=Path(temp);tools=root/'bin';tools.mkdir()
    commands={
      'homegate': '''case "$1" in version) printf '{"version":"%s"}\\n' "${TEST_RELEASE:-1.3.0-11}";; *) echo '{"ok":true,"fixture":true}';; esac''',
      'apk': '''case "$1" in --print-arch) echo "${TEST_ARCH:-aarch64_cortex-a53}";; list) echo "$3-1.3.0-r11 ${TEST_ARCH:-aarch64_cortex-a53} {homegate} [installed]";; *) exit 1;; esac''',
      'uname': 'echo aarch64', 'ubus': 'echo fixture-homegate-RPC-methods', 'uci':'exit 0', 'ip':'exit 0', 'ip6tables':'exit 0'}
    for name,body in commands.items():
        f=tools/name;f.write_text('#!/bin/sh\n'+body+'\n',newline='\n');f.chmod(0o755)
    suite=root/'suite';suite.mkdir();(suite/'offline-tests').mkdir()
    shutil.copy2(ROOT/'scripts/offline-verify.sh',suite/'offline-verify.sh')
    shutil.copy2(ROOT/'scripts/arm64-profile.sh',suite/'arm64-profile.sh')
    configured=root/'arch';env_paths={'HOMEGATE_APK_ARCH_FILE':str(configured),'HOMEGATE_RELEASE_FILE':str(root/'missing-release')}
    # Model a test binary using the default access recorder. Even an inherited
    # live path must be overridden only for the isolated child, never inventory.
    program=b'#!/bin/sh\n[ -n "${HOMEGATE_ACCESS_RECENT:-}" ] || exit 1\nprintf "fixture-access-record\\n" >"$HOMEGATE_ACCESS_RECENT"\necho "PRIVATE_TEST_ACCESS_PATH=$HOMEGATE_ACCESS_RECENT"\n'
    compressed=suite/'offline-tests/proxy.test.gz';compressed.write_bytes(gzip.compress(program,mtime=0))
    (suite/'offline-tests.SHA256SUMS').write_text(hashlib.sha256(compressed.read_bytes()).hexdigest()+'  offline-tests/proxy.test.gz\n')
    sentinel=root/'live-access.json';sentinel.write_text('live sentinel must be unchanged\n')
    env=dict(os.environ,PATH=str(tools)+':'+os.environ['PATH'],HOMEGATE_ACCESS_RECENT=str(sentinel))
    env.update(env_paths)
    for name,release,arch,expected in [('positive','1.3.0-11','aarch64_cortex-a53',0),('generic-apk','1.3.0-11','aarch64',0),('generic-profile','1.3.0-11','aarch64_generic',0),('a72-profile','1.3.0-11','aarch64_cortex-a72',0),('old-version','1.2.3-2','aarch64_cortex-a53',1),('wrong-arch','1.3.0-11','x86_64',1)]:
        configured.write_text((arch if name != 'wrong-arch' else 'aarch64_cortex-a53')+'\n')
        env.update(TEST_RELEASE=release,TEST_ARCH=(arch if name != 'wrong-arch' else 'aarch64_cortex-a53'),HOMEGATE_VERIFY_EXPECTED_ARCH=arch,HOMEGATE_VERIFY_OUT=str(root/name))
        result=subprocess.run(['sh',str(suite/'offline-verify.sh')],env=env,capture_output=True,text=True)
        assert result.returncode==expected,(name,result.stdout,result.stderr)
        log=(root/name/'verification.log').read_text(encoding='utf-8');assert 'SKIP real DNS writes/' in log and 'RESULT failed='+str(expected) in log
        assert Path(str(root/name)+'.tar.gz').is_file()
        assert sentinel.read_text(encoding='utf-8')=='live sentinel must be unchanged\n', 'test touched inherited live recorder'
        private_line=(root/name/'isolated-core-proxy.log').read_text(encoding='utf-8').strip()
        assert private_line.startswith('PRIVATE_TEST_ACCESS_PATH=/tmp/homegate-verify-private-'), private_line
        assert not Path(private_line.split('=',1)[1]).exists(), 'private recorder was not cleaned'

        print('PASS offline-verifier '+name)
