#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK="$ROOT/build/ucode"
mkdir -p "$WORK/source"
ARCHIVE="$WORK/source.tar.gz"
[ -f "$ARCHIVE" ] || curl -fL --retry 3 'https://codeload.github.com/jow-/ucode/tar.gz/85922056ef7abeace3cca3ab28bc1ac2d88e31b1' -o "$ARCHIVE"
printf '%s  %s\n' '54dda1e8a2757710c285659e42336f5054f1825f20d01a4016245bbf877f6da7' "$ARCHIVE" | sha256sum -c -
tar -xzf "$ARCHIVE" -C "$WORK/source" --strip-components=1
cmake -S "$WORK/source" -B "$WORK/out" -DUBUS_SUPPORT=OFF -DUCI_SUPPORT=OFF -DULOOP_SUPPORT=OFF -DNL80211_SUPPORT=OFF -DRESOLV_SUPPORT=OFF -DRTNL_SUPPORT=OFF -DDEBUG_SUPPORT=OFF -DLOG_SUPPORT=OFF -DDIGEST_SUPPORT=OFF -DSOCKET_SUPPORT=OFF
cmake --build "$WORK/out" -j2
"$WORK/out/ucode" -L "$WORK/out/*.so" -c -o "$WORK/homegate.uc" "$ROOT/project/luci/js/root/usr/share/rpcd/ucode/homegate"
echo 'OpenWrt 25.12 ucode compile: PASS'
