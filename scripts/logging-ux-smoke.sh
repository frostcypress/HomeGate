#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

# Core structured-event contract remains available for machine/diagnostic consumers;
# raw /var/log/homegate.log remains the source of truth.
grep -q 'case "log-events"' project/core/src/cmd/homegate/main.go
grep -q 'Phase: "log-events"' project/core/src/internal/logger/events.go
grep -q 'Raw.*json:"raw"' project/core/src/internal/logger/events.go
grep -q 'Sanitize(raw)' project/core/src/internal/logger/events.go

MAINT=project/luci/lua/luasrc/view/homegate/maintenance.htm

# 1.2.2 LuCI contract: one raw log view only, no Raw/Time switch and no
# frontend translation layer. Refresh loads the raw-log endpoint directly.
grep -q 'id="hg-maintenance-log" class="hg-log hg-log-large"' "$MAINT"
[ "$(grep -c 'id="hg-maintenance-log" class="hg-log hg-log-large"' "$MAINT" || true)" -eq 1 ]
! grep -q 'hg-maintenance-time-log' "$MAINT"
! grep -q '<%:Raw Log%>' "$MAINT"
! grep -q '<%:Time View%>' "$MAINT"
! grep -q 'hgMaintenanceLogView' "$MAINT"
! grep -q 'hgMaintenanceTranslatedMessage' "$MAINT"
! grep -q 'hgMaintenanceRenderTimeView' "$MAINT"
! grep -q 'api/log_events' "$MAINT"
grep -q 'hg-log-actions-below' "$MAINT"
! grep -q 'data-filter=' "$MAINT"
! grep -q 'hg-log-filters' "$MAINT"
! grep -q '<%:Technical Details%>' "$MAINT"
! grep -q 'hg-log-event-detail' "$MAINT"

grep -q "api/logs" "$MAINT"
grep -q 'diagnostic_download' "$MAINT"
grep -q "log_clear')%>" "$MAINT"

# Diagnostic bundle must still carry raw log, never replace it with summaries.
grep -q 'tail -n 300 /var/log/homegate.log' project/luci/lua/luasrc/controller/homegate.lua

# Focused tests cover user classification, newest-line retention and redaction.
(cd project/core/src && go test ./internal/logger -run 'Test(ParseEvent|ReadEvents)' -count=1)

echo 'HomeGate 1.2.2 raw-only logging UX contract smoke: PASS'
