#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 3 ]; then printf '%s\n' 'Usage: sh scripts/check-http.sh [HTTP-runtime-directory] [RPC-runtime-directory] [ucode-runtime-directory]' >&2; exit 2; fi
HTTP="${1:-$ROOT/build/uhttpd}"
RPC="${2:-$ROOT/build/rpcd}"
NATIVE="${3:-$ROOT/build/ucode}"
HTTP=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$HTTP")
RPC=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$RPC")
NATIVE=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$NATIVE")
python3 "$ROOT/scripts/prepare-ucode.py" --runtime-dir "$NATIVE"
python3 "$ROOT/scripts/prepare-rpcd.py" --runtime-dir "$RPC" --ucode-runtime-dir "$NATIVE"
python3 "$ROOT/scripts/prepare-uhttpd.py" --runtime-dir "$HTTP" --rpc-runtime-dir "$RPC"
python3 "$ROOT/scripts/http-ddns-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP"
echo 'Pinned isolated HTTP: 10 HTTP authorization and 8 retained RPC checks passed; TLS, Lua/LuCI and target not tested'
