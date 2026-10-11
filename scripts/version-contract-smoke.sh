#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION_FILE="$ROOT/homegate-version.mk"
CORE_MF="$ROOT/project/core/Makefile"
LUCI_MF="$ROOT/project/luci/Makefile"
CTRL="$ROOT/project/luci/lua/luasrc/controller/homegate.lua"
CFG="$ROOT/project/core/files/etc/config/homegate"
MAIN="$ROOT/project/core/src/cmd/homegate/main.go"

VERSION=$(sed -n 's/^HOMEGATE_VERSION:=//p' "$VERSION_FILE" | head -n1)
RELEASE=$(sed -n 's/^HOMEGATE_RELEASE:=//p' "$VERSION_FILE" | head -n1)
[ -n "$VERSION" ] && [ -n "$RELEASE" ] || { echo 'missing unified version source' >&2; exit 1; }

for mf in "$CORE_MF" "$LUCI_MF"; do
  grep -Fq 'include $(TOPDIR)/homegate-version.mk' "$mf"
  grep -Fq 'PKG_VERSION:=$(HOMEGATE_VERSION)' "$mf"
  grep -Fq 'PKG_RELEASE:=$(HOMEGATE_RELEASE)' "$mf"
done
grep -Fq 'PKG_PO_VERSION:=$(PKG_VERSION)-$(PKG_RELEASE)' "$LUCI_MF"

# No package-local product version literals may diverge from the authoritative file.
! grep -Eq '^PKG_VERSION:=[0-9]' "$CORE_MF"
! grep -Eq '^PKG_VERSION:=[0-9]' "$LUCI_MF"
! grep -Eq '^PKG_RELEASE:=[0-9]' "$CORE_MF"
! grep -Eq '^PKG_RELEASE:=[0-9]' "$LUCI_MF"

# Runtime and default UCI version are generated from the same source at build time.
grep -Fq 'var version = "dev"' "$MAIN"
grep -Fq -- '-X main.version=$(PKG_VERSION)-$(PKG_RELEASE)' "$CORE_MF"
grep -Fq "option version '@HOMEGATE_VERSION@'" "$CFG"
grep -Fq "sed 's/@HOMEGATE_VERSION@/\$(PKG_VERSION)-\$(PKG_RELEASE)/g'" "$CORE_MF"

# LuCI displays the product version from the installed Core package and config reset
# uses that product value instead of introducing another hard-coded version.
grep -Fq 'product = product_version' "$CTRL"
grep -Fq 'local product_version = core_version' "$CTRL"
grep -Fq 'local v = package_info().product' "$CTRL"
! grep -Eq 'version = "[0-9]+\.[0-9]+\.[0-9]+"' "$CTRL"

# SDK staging/build scripts must copy/read the authoritative version file.
grep -Fq 'cp -a "$ROOT/homegate-version.mk" "$SDK/homegate-version.mk"' "$ROOT/scripts/stage-into-sdk.sh"
for script in "$ROOT/scripts/stage-into-sdk.sh" "$ROOT/scripts/build-in-sdk.sh" "$ROOT/scripts/build-legacy-ipk.sh"; do
  grep -Fq 'HOMEGATE_VERSION:=' "$script"
  grep -Fq 'HOMEGATE_RELEASE:=' "$script"
done

# Optionally prove the compiled CLI receives exactly the same product version.
# Host CI/release validation leaves this enabled; static-only callers may set 0.
if [ "${HOMEGATE_VERSION_CONTRACT_BUILD:-1}" = "1" ]; then
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT INT TERM
  (
    cd "$ROOT/project/core/src"
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$VERSION-$RELEASE" -o "$TMP/homegate" ./cmd/homegate
  )
  OUT=$($TMP/homegate version)
  printf '%s\n' "$OUT" | grep -Fq '"version":"'"$VERSION-$RELEASE"'"'
fi

printf 'unified version contract: PASS (%s-%s for Core/LuCI/i18n)\n' "$VERSION" "$RELEASE"
