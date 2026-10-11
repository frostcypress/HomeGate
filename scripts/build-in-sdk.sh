#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 /path/to/openwrt-sdk" >&2
	exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SDK=$(cd "$1" && pwd)

"$ROOT/scripts/stage-into-sdk.sh" "$SDK"
cd "$SDK"

make defconfig
make package/homegate/clean V=s
make package/homegate/compile V=s
make package/luci-app-homegate/clean V=s
make package/luci-app-homegate/compile V=s

CORE_VERSION=$(sed -n 's/^HOMEGATE_VERSION:=//p' "$ROOT/homegate-version.mk" | head -n1)
CORE_RELEASE=$(sed -n 's/^HOMEGATE_RELEASE:=//p' "$ROOT/homegate-version.mk" | head -n1)
LUCI_VERSION="$CORE_VERSION"
LUCI_RELEASE="$CORE_RELEASE"
find bin -type f \( \
	-name "homegate_${CORE_VERSION}-${CORE_RELEASE}_*.ipk" -o \
	-name "luci-app-homegate_${LUCI_VERSION}-${LUCI_RELEASE}_*.ipk" -o \
	-name "luci-i18n-homegate-zh-cn_${LUCI_VERSION}-${LUCI_RELEASE}_*.ipk" \
\) -print | sort
