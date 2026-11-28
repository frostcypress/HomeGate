#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 1 ]; then printf '%s\n' 'Usage: sh scripts/check-ucode.sh [existing-or-new-runtime-directory]' >&2; exit 2; fi
WORK="${1:-$ROOT/build/ucode}"
WORK=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$WORK")
python3 "$ROOT/scripts/prepare-ucode.py" --runtime-dir "$WORK"
"$WORK/out/ucode" -L "$WORK/out/*.so" -c -o "$WORK/homegate.uc" "$ROOT/project/luci/js/root/usr/share/rpcd/ucode/homegate"
python3 "$ROOT/scripts/ucode-ddns-regressions.py" --runtime-dir "$WORK"
echo 'Pinned host ucode: production compile and gate-closed DDNS candidate checks passed; rpcd and target not tested'
