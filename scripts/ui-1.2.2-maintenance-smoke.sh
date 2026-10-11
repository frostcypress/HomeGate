#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APP="$ROOT/project/luci"
MAINT="$APP/lua/luasrc/view/homegate/maintenance.htm"
COMMON="$APP/lua/luasrc/view/homegate/common.htm"

# 1.2.2 log UI contract: one raw log viewport only. There is no Raw/Time
# selector and no frontend Time View translation/rendering path.
[ "$(grep -c 'id="hg-maintenance-log" class="hg-log hg-log-large"' "$MAINT" || true)" -eq 1 ]
! grep -q 'hg-maintenance-time-log' "$MAINT"
! grep -q 'hg-log-raw-view-button' "$MAINT"
! grep -q 'hg-log-time-view-button' "$MAINT"
! grep -q '<%:Raw Log%>' "$MAINT"
! grep -q '<%:Time View%>' "$MAINT"
! grep -q 'hgMaintenanceLogView' "$MAINT"
! grep -q 'hgMaintenanceSetLogView' "$MAINT"
! grep -q 'hgMaintenanceRenderTimeView' "$MAINT"
! grep -q 'hgMaintenanceTranslatedMessage' "$MAINT"
! grep -q 'api/log_events' "$MAINT"
grep -q "api/logs" "$MAINT"

# Refresh / Clear Log / Download Diagnostic remain below the raw log box.
raw_line=$(grep -n 'id="hg-maintenance-log"' "$MAINT" | head -n1 | cut -d: -f1)
actions_line=$(grep -n 'hg-log-actions hg-log-actions-inline hg-log-actions-below' "$MAINT" | head -n1 | cut -d: -f1)
[ -n "$raw_line" ] && [ -n "$actions_line" ] && [ "$actions_line" -gt "$raw_line" ]
grep -Fq '.hg-log-actions-below { margin-top: var(--hg-log-action-gap); }' "$COMMON"
grep -q 'hgMaintenanceRefreshLog()' "$MAINT"
grep -q "log_clear')%>" "$MAINT"
grep -q "diagnostic_download')%>" "$MAINT"

# Preserve the accepted taller/symmetric log layout and plugin-wide button-state guard.
grep -Fq '.hg-log-large { height: 380px; min-height: 380px; max-height: 560px; }' "$COMMON"
grep -Fq 'html.hg-theme-design .hg-maintenance-log-card .hg-log-actions { margin-top: var(--hg-log-action-gap); }' "$COMMON"
grep -Fq 'transform: none !important; translate: none !important; scale: 1 !important;' "$COMMON"
grep -Fq 'box-shadow: none !important;' "$COMMON"
! grep -Fq 'box-shadow: inset' "$COMMON"
! grep -q 'hg-log-view-button' "$COMMON"

# Full-plugin static button geometry audit remains mandatory.
python3 - "$APP/lua/luasrc/view/homegate" <<'PY2'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
for p in root.glob('*.htm'):
    s=p.read_text()
    for m in re.finditer(r'<button\b([^>]*)>', s, re.I|re.S):
        tag=m.group(0)
        cm=re.search(r'class="([^"]*)"', tag)
        classes=(cm.group(1).split() if cm else [])
        if 'cbi-button' not in classes:
            raise SystemExit(f'button without cbi-button geometry foundation: {p.name}: {tag[:160]}')
        if not any(c in classes for c in ('hg-btn-4','cbi-button-apply','cbi-button-save','cbi-button-reset')):
            raise SystemExit(f'button without HomeGate size tier: {p.name}: {tag[:160]}')
print('HomeGate button-state geometry audit: PASS')
PY2

echo 'HomeGate 1.2.2 raw-only maintenance UI smoke: PASS'
