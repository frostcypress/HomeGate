#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 2 ]; then printf '%s\n' 'Usage: sh scripts/check-rpcd.sh [RPC-runtime-directory] [ucode-runtime-directory]' >&2; exit 2; fi
WORK="${1:-$ROOT/build/rpcd}"
NATIVE="${2:-$ROOT/build/ucode}"
WORK=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$WORK")
NATIVE=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$NATIVE")
python3 "$ROOT/scripts/prepare-ucode.py" --runtime-dir "$NATIVE"
python3 "$ROOT/scripts/prepare-rpcd.py" --runtime-dir "$WORK" --ucode-runtime-dir "$NATIVE"
python3 "$ROOT/scripts/rpcd-ddns-regressions.py" --runtime-dir "$WORK"
echo 'Pinned host rpcd/ubus: isolated loading, arguments and session ACL checks passed; HTTP and target not tested'
