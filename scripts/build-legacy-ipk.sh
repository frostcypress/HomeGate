#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PKG_VERSION=$(sed -n 's/^HOMEGATE_VERSION:=//p' "$ROOT/homegate-version.mk" | head -n1)
PKG_RELEASE=$(sed -n 's/^HOMEGATE_RELEASE:=//p' "$ROOT/homegate-version.mk" | head -n1)
[ -n "$PKG_VERSION" ] && [ -n "$PKG_RELEASE" ] || exit 1
# Compatibility entry point: no old IPK directory is needed.
exec python3 "$ROOT/scripts/build-release.py" --out "${1:-$ROOT/dist}"
