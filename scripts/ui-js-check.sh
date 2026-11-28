#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APP="$ROOT/project/luci/lua/luasrc/view/homegate"
OUT="$ROOT/build/ui-js-check"
rm -rf "$OUT"
mkdir -p "$OUT"

if ! command -v node >/dev/null 2>&1; then
    echo "template JavaScript syntax: SKIP (node not installed)"
    exit 0
fi

python3 - "$APP" "$OUT" <<'PY'
from pathlib import Path
import re, sys
app=Path(sys.argv[1]); out=Path(sys.argv[2])
for p in sorted(app.glob('*.htm')):
    text=p.read_text()
    blocks=re.findall(r'<script type="text/javascript">(.*?)</script>', text, re.S)
    if not blocks:
        continue
    js='\n'.join(blocks)
    # LuCI template expressions are inside JavaScript string literals in these templates;
    # replace the complete tag only, preserving the surrounding quote delimiters.
    js=re.sub(r'<%.*?%>', 'TEMPLATE', js, flags=re.S)
    (out/(p.stem+'.js')).write_text(js)
PY

count=0
for js in "$OUT"/*.js; do
    [ -f "$js" ] || continue
    node --check "$js" >/dev/null
    count=$((count+1))
done
[ "$count" -eq 5 ]
echo "template JavaScript syntax: PASS ($count templates)"
