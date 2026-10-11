#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APP="$ROOT/project/luci"
PUB="$APP/lua/luasrc/view/homegate/public.htm"
MAINT="$APP/lua/luasrc/view/homegate/maintenance.htm"
COMMON="$APP/lua/luasrc/view/homegate/common.htm"

# Tall Public Service editor must stay inside the viewport. Only the form body scrolls;
# the Cancel/Confirm footer remains outside the scrolling viewport.
grep -q 'class="hg-modal hg-public-service-modal"' "$PUB"
grep -q 'class="hg-public-service-scroll" id="hg-public-service-scroll"' "$PUB"
grep -q 'class="hg-modal-actions hg-public-service-footer"' "$PUB"
grep -Fq '.hg-public-service-modal > .hg-public-service-footer { flex: 0 0 auto; }' "$COMMON"

# Current maintenance log UI keeps one raw log and compact actions below it.
grep -q 'hg-log-actions hg-log-actions-inline' "$MAINT"
grep -q 'id="hg-maintenance-log" class="hg-log hg-log-large"' "$MAINT"
! grep -q 'hg-log-raw-view-button' "$MAINT"
! grep -q 'hg-log-time-view-button' "$MAINT"
! grep -q 'hg-maintenance-time-log' "$MAINT"
grep -q "log_clear')%>" "$MAINT"
grep -q "diagnostic_download')%>" "$MAINT"
! grep -q 'data-filter=' "$MAINT"
! grep -q '<%:Uninstall HomeGate%>' "$MAINT"
! grep -q 'action_uninstall' "$APP/lua/luasrc/controller/homegate.lua"

echo 'HomeGate 1.2.1 maintenance/public UI smoke: PASS'
