#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 /path/to/openwrt-sdk" >&2
	exit 2
fi

SDK=$(cd "$1" && pwd)
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 "$ROOT/scripts/project.py" --check >/dev/null

[ -f "$SDK/rules.mk" ] || { echo "not an OpenWrt SDK/Buildroot: $SDK" >&2; exit 1; }
[ -f "$SDK/include/package.mk" ] || { echo "package.mk missing: $SDK" >&2; exit 1; }
[ "${HOMEGATE_ALLOW_LEGACY_GO:-0}" = "1" ] || { echo 'Legacy Go reference staging requires HOMEGATE_ALLOW_LEGACY_GO=1' >&2; exit 2; }
[ ! -e "$SDK/package/homegate" ] && [ ! -e "$SDK/package/luci-app-homegate" ] || { echo 'Refusing to overwrite existing SDK packages' >&2; exit 2; }
cp -a "$ROOT/project/core" "$SDK/package/homegate"
cp -a "$ROOT/project/luci" "$SDK/package/luci-app-homegate"
cp -a "$ROOT/LICENSE" "$SDK/LICENSE"
cp -a "$ROOT/homegate-version.mk" "$SDK/homegate-version.mk"

CORE_VERSION=$(sed -n 's/^HOMEGATE_VERSION:=//p' "$ROOT/homegate-version.mk" | head -n1)
CORE_RELEASE=$(sed -n 's/^HOMEGATE_RELEASE:=//p' "$ROOT/homegate-version.mk" | head -n1)
LUCI_VERSION="$CORE_VERSION"
LUCI_RELEASE="$CORE_RELEASE"
echo "staged HomeGate Core ${CORE_VERSION}-${CORE_RELEASE} + LuCI/i18n ${LUCI_VERSION}-${LUCI_RELEASE} into $SDK/package"
echo "next: make defconfig"
echo "then: make package/homegate/compile V=s"
echo "and:  make package/luci-app-homegate/compile V=s"
