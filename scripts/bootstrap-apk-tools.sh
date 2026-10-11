#!/bin/sh
set -eu
# Same upstream commit as OpenWrt 25.12 apk 3.0.5; no rolling edge binary URL.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK="$ROOT/build/apk-tools"
ARCHIVE="$ROOT/build/apk-tools-source.tar.gz"
mkdir -p "$ROOT/build"
if [ ! -f "$ARCHIVE" ]; then
 curl -fL --retry 3 'https://codeload.github.com/alpinelinux/apk-tools/tar.gz/b5a31c0d865342ad80be10d68f1bb3d3ad9b0866' -o "$ARCHIVE"
fi
printf '%s  %s\n' '598056e338fa96af030b0f6f2127cc7df151e6f078b0e44a5cae95cc4bba1f79' "$ARCHIVE" | sha256sum -c -
mkdir -p "$WORK"
tar -xzf "$ARCHIVE" -C "$WORK" --strip-components=1
if [ ! -f "$WORK/out/build.ninja" ]; then
 meson setup "$WORK/out" "$WORK" -Ddocs=disabled -Dtests=disabled -Dcrypto_backend=openssl -Durl_backend=wget -Dzstd=disabled -Dpython=disabled -Dlua_version=5.1
fi
ninja -C "$WORK/out"
TOOL="$WORK/out/src/apk"
[ -x "$TOOL" ] || TOOL="$WORK/out/apk"
test -x "$TOOL"
printf '%s\n' "$TOOL" >"$ROOT/build/apk-tools-path.txt"
