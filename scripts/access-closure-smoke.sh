#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ACCESS="$ROOT/project/core/src/internal/access/access.go"
APP="$ROOT/project/core/src/internal/app/app.go"
PUBLIC="$ROOT/project/luci/lua/luasrc/view/homegate/public.htm"
CTRL="$ROOT/project/luci/lua/luasrc/controller/homegate.lua"
CFG="$ROOT/project/core/src/internal/config/config.go"

# Recent Access actions are exact /32 or /128 one-click overrides; advanced Add Rule may still accept CIDR.
grep -Fq "ip.indexOf(':')>=0?ip+'/128':ip+'/32'" "$PUBLIC"
grep -Fq "hgPublicAccessHasExactIp('deny',ip)" "$PUBLIC"
grep -Fq "hgPublicAccessHasExactIp('allow',ip)" "$PUBLIC"
grep -Fq "Deny Access" "$PUBLIC"
grep -Fq "Allow Access" "$PUBLIC"
grep -Fq "Delete All" "$PUBLIC"
grep -Fq "hg-public-access-action-delete" "$PUBLIC"
! grep -Fq "<%:Clear Record%>" "$PUBLIC"
! grep -Fq "Already Allowed" "$PUBLIC"

# UI is a source summary; region is merged into source and timestamps retain full local date/seconds.
grep -Fq 'hgPublicAccessSummaries' "$PUBLIC"
grep -Fq "d.getFullYear()+'/'+(d.getMonth()+1)+'/'+d.getDate()" "$PUBLIC"
grep -Fq 'Access Status' "$PUBLIC"
grep -Fq 'Delete All' "$PUBLIC"
grep -Fq "+' · '+ip" "$PUBLIC"

# Empty allow-list-only mode is a legal fail-closed policy, not a save validation error.
! grep -Fq 'access restriction requires an allowed IP/network or allowed region' "$CFG"
! grep -Fq 'access restriction requires an allowed IP/network or allowed region' "$ACCESS"
! grep -Fq 'Access restriction requires an allowed IP/network or region' "$CTRL"
grep -Fq 'TestManualOnlyModeEmptyFailClosed' "$ROOT/project/core/src/internal/access/access_test.go"
grep -Fq 'TestParseAccessRestrictionAllowsEmptyManualFailClosed' "$ROOT/project/core/src/internal/config/config_test.go"

# Explicit deny is persistent and highest priority, even when scope is No Restriction.
grep -Fq 'AccessDeny' "$CFG"
grep -Fq 'denyMatcher' "$ACCESS"
grep -Fq 'Reason: "manual-deny"' "$ACCESS"
grep -Fq 'Explicit deny is the highest-priority override, including No Restriction' "$ACCESS"
grep -Fq 'DenyPrefixes' "$ACCESS"

# Public delete is one step: deleting a recent row clears its exact allow/deny override
# plus the runtime observation; Delete All clears all manual rules and all observations
# while leaving Access Scope itself untouched. Legacy clear endpoints remain internal-compatible.
grep -Fq 'ClearRecentEntry' "$ACCESS"
grep -Fq 'access-clear-entry' "$ROOT/project/core/src/cmd/homegate/main.go"
python3 - "$CTRL" <<'PY'
import sys
s=open(sys.argv[1],encoding='utf-8').read()
a=s.index('function action_access_delete_entry()')
b=s.index('function action_access_delete_rule()',a)
entry=s[a:b]
assert 'remove_access_ip(cur:get("homegate", "main", "access_allow") or "", ip)' in entry
assert 'remove_access_ip(cur:get("homegate", "main", "access_deny") or "", ip)' in entry
assert 'action_core("access-clear-entry " .. ip .. " " .. host)' in entry
all_start=s.index('function action_access_delete_all()')
all_end=s.index('function action_maintenance()',all_start)
delete_all=s[all_start:all_end]
assert 'cur:set("homegate", "main", "access_allow", "")' in delete_all
assert 'cur:set("homegate", "main", "access_deny", "")' in delete_all
assert 'action_core("access-clear-all")' in delete_all
assert 'access_region' not in delete_all
PY

# Region enable/save validates or refreshes cache before UCI access state is committed.
python3 - "$CTRL" <<'PY'
import sys
s=open(sys.argv[1],encoding='utf-8').read()
a=s.index('if access_enabled and access_region ~= "" and not action_core("access-update " .. access_region) then')
b=s.index('cur:set("homegate", "main", "access_enabled"',a)
assert a < b
assert 'action_core("access-refresh " .. region)' in s
PY

# Core runtime summary carries current-policy annotation and Geo display metadata.
grep -Fq 'CurrentAllowed' "$ACCESS"
grep -Fq 'CurrentReason' "$ACCESS"
grep -Fq 'AnnotateRecentCurrent' "$ACCESS"
grep -Fq 'summarizeEvents' "$ACCESS"
grep -Fq 'AnnotateRecentGeo' "$ACCESS"
grep -Fq '"FOREIGN"' "$ACCESS"
grep -Fq '"UNKNOWN"' "$ACCESS"

# Region cache contract: dual-stack validation, atomic replacement, stale fallback.
grep -Fq 'downloaded region list is not dual-stack' "$ACCESS"
grep -Fq 'Source: "stale-cache"' "$ACCESS"
grep -Fq 'f.Sync()' "$ACCESS"
grep -Fq 'os.Rename(tmp, path)' "$ACCESS"
grep -Fq 'CacheValid' "$ACCESS"
grep -Fq 'CacheStale' "$ACCESS"

# Daemon startup/reload recovery remains intact.
grep -Fq 'prepareAccessRegion(ctx, cfg, log, "startup")' "$APP"
grep -Fq 'prepareAccessRegion(ctx, next, log, "reload")' "$APP"
grep -Fq 'access.LoadPolicy(cfg.Main, m.homeDir)' "$ROOT/project/core/src/internal/proxy/proxy.go"

printf '%s\n' 'Access closure contract smoke: PASS'
