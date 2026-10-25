#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
usage() { printf '%s\n' 'Usage: sh scripts/check-ddns-authority.sh [--group all|authority|tasks|receipts] [LuCI-runtime] [HTTP-runtime] [RPC-runtime] [ucode-runtime]' >&2; exit 2; }
GROUP=all
case "${1-}" in
  --group) [ "$#" -ge 2 ] || usage; GROUP=$2; shift 2;;
  --*) usage;;
esac
case "$GROUP" in all|authority|tasks|receipts) ;; *) usage;; esac
[ "$#" -le 4 ] || usage
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
case "$GROUP" in
  all|authority)
    python3 "$ROOT/scripts/luci-ddns-authority-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned Lua LuCI to real Shell DDNS authority: 8 private preview/commit/revoke checks passed; no DNS action or production installation'
    python3 "$ROOT/scripts/rpc-ddns-authority-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned HTTP/rpcd to real Shell DDNS authority: 11 private scope/ACL/write checks passed; no DNS action or production installation'
    ;;
esac
case "$GROUP" in
  all|tasks)
    python3 "$ROOT/scripts/luci-ddns-jobs-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned Lua LuCI to real retained Shell jobs: 7 private admission/replay/interruption checks passed; no provider dispatch'
    python3 "$ROOT/scripts/rpc-ddns-jobs-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned HTTP/rpcd to real retained Shell jobs: 10 private admission/ACL/replay checks passed; no provider dispatch'
    python3 "$ROOT/scripts/luci-ddns-maintenance-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned Lua LuCI explicit task maintenance: 8 private known-none/consent/barrier checks passed; confirmed receipt archive not tested'
    python3 "$ROOT/scripts/rpc-ddns-maintenance-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned HTTP/rpcd explicit task maintenance: 11 private known-none/ACL/consent checks passed; confirmed receipt archive not tested'
    ;;
esac
case "$GROUP" in
  all|receipts)
    python3 "$ROOT/scripts/luci-ddns-provider-jobs-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned curl/TLS provider tasks: 4 private result/original-receipt checks passed; no public DNS or production installation'
    python3 "$ROOT/scripts/luci-ddns-archive-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned Lua confirmed task archive: 6 private source/fresh-consent/recovery checks passed; no public DNS or archive retirement'
    python3 "$ROOT/scripts/rpc-ddns-archive-regressions.py" --runtime-dir "$RPC" --http-runtime-dir "$HTTP" --luci-runtime-dir "$LUA"
    echo 'Pinned HTTP/rpcd confirmed task archive: 10 private original-receipt/ACL/consent checks passed; no public DNS or archive retirement'
    ;;
esac
