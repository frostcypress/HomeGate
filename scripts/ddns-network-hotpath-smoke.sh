#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$ROOT/project/core/src"
go test ./internal/ddns -count=1 -run '^(TestSyncAllResolvesWANOncePerCycle|TestSyncAllDoesNotResolveWANForIneligibleRules|TestSyncAllSharesWANFailureWithinCycle|TestSyncRuleStillResolvesWANPerManualCall)$'
go test ./internal/network -count=1 -run '^(TestResolveWANSkipsUbusWhenDefaultRouteOwnsPublicIPv6|TestResolveWANUsesUbusWhenDefaultRouteDoesNotOwnPublicIPv6|TestResolveQWRTPPPoE)$'

# Lock the intended hot-path shape: one lazy WAN snapshot per SyncAll cycle,
# while single-rule sync keeps the direct resolver path.
grep -q 'wanResolved bool' "$ROOT/project/core/src/internal/ddns/service.go"
grep -q 'return s.syncRule(ctx, cfg, rule, s.resolveWAN)' "$ROOT/project/core/src/internal/ddns/service.go"
grep -q 'defaultOwnsPublic' "$ROOT/project/core/src/internal/network/resolver.go"
grep -q 'if !defaultOwnsPublic' "$ROOT/project/core/src/internal/network/resolver.go"

echo "ddns/network hotpath smoke: PASS"
