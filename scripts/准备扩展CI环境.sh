#!/bin/sh
# Pinned headless test dependencies, copied from the existing source CI recipe.
set -eu
sudo apt-get update
sudo apt-get install --no-install-recommends -y build-essential lua5.1 liblua5.1-0-dev libjson-c-dev libssl-dev
mkdir -p build/busybox-runtime
python3 scripts/准备BusyBox归档.py
printf '%s  %s\n' 6843ba7977081e735fa0fdb05893e3c002c8c5ad7c9c80da206e603cc0ac47e7 \
  build/busybox-runtime/busybox-1.33.2.tar.bz2 | sha256sum -c -
tar -xjf build/busybox-runtime/busybox-1.33.2.tar.bz2 -C build/busybox-runtime
make -C build/busybox-runtime/busybox-1.33.2 allnoconfig
python3 - <<'PY'
from pathlib import Path
import re
file = Path('build/busybox-runtime/busybox-1.33.2/.config')
body = file.read_text()
required = ['BUSYBOX', 'ASH', 'ASH_OPTIMIZE_FOR_SIZE', 'ASH_PRINTF', 'ASH_TEST',
            'FEATURE_SH_MATH', 'EXPR', 'STAT', 'FEATURE_STAT_FORMAT', 'FLOCK',
            'TR', 'MKDIR', 'MV', 'RM', 'ID', 'DIRNAME', 'CAT', 'CP',
            'RMDIR', 'SHA256SUM', 'HEAD', 'FEATURE_FANCY_HEAD', 'FSYNC',
            'SETSID', 'SLEEP', 'FEATURE_FANCY_SLEEP', 'FLOAT_DURATION', 'MKFIFO', 'LS', 'KILL']
for name in required:
    pattern = r'^# CONFIG_' + name + r' is not set$'
    body, count = re.subn(pattern, 'CONFIG_' + name + '=y', body, flags=re.M)
    if count == 0:
        assert re.search(r'^CONFIG_' + name + r'=y$', body, re.M), 'Unknown or unavailable BusyBox option: ' + name
file.write_text(body)
PY
make -C build/busybox-runtime/busybox-1.33.2 oldconfig < /dev/null
make -C build/busybox-runtime/busybox-1.33.2 -j2
build/busybox-runtime/busybox-1.33.2/busybox --list
build/busybox-runtime/busybox-1.33.2/busybox sleep 0.001
echo "$PWD/build/busybox-runtime/busybox-1.33.2" >> "$GITHUB_PATH"
python3 -m venv build/verify-venv
build/verify-venv/bin/python -m pip install 'lupa==2.8' 'tree-sitter==0.25.2' 'tree-sitter-bash==0.25.1'
python3 scripts/准备UCI解析回归.py
python3 scripts/准备服务采样回归.py
python3 scripts/准备curl回归.py
