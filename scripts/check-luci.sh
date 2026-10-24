#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 4 ]; then printf '%s\n' 'Usage: sh scripts/check-luci.sh [LuCI-runtime] [HTTP-runtime] [RPC-runtime] [ucode-runtime]' >&2; exit 2; fi
LUA="${1:-$ROOT/build/luci}"
HTTP="${2:-$ROOT/build/uhttpd}"
RPC="${3:-$ROOT/build/rpcd}"
NATIVE="${4:-$ROOT/build/ucode}"
LUA=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$LUA")
HTTP=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$HTTP")
RPC=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$RPC")
NATIVE=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$NATIVE")
python3 "$ROOT/scripts/prepare-ucode.py" --runtime-dir "$NATIVE"
python3 "$ROOT/scripts/prepare-rpcd.py" --runtime-dir "$RPC" --ucode-runtime-dir "$NATIVE"
python3 "$ROOT/scripts/prepare-uhttpd.py" --runtime-dir "$HTTP" --rpc-runtime-dir "$RPC"
python3 "$ROOT/scripts/prepare-luci.py" --runtime-dir "$LUA" --rpc-runtime-dir "$RPC"
python3 "$ROOT/scripts/luci-ddns-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
echo 'Pinned Lua LuCI host: 11 real CGI/session/POST/CSRF and private transport checks passed; target and TLS not tested'
python3 "$ROOT/scripts/luci-ddns-read-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
echo 'Pinned Lua LuCI to real Shell DDNS status/jobs: 9 private read-only checks passed; no provider operation or target acceptance'
python3 "$ROOT/scripts/rpc-ddns-read-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
echo 'Pinned HTTP/rpcd ucode to real Shell DDNS status/jobs: 11 private ACL/read-only checks passed; no provider operation or target acceptance'
