#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# Stage 5 Round 2 contract: common-runtime health keeps the established
# desired-state meaning, while daemon identity and proxy listener truth must
# not be derived from a reusable PID or a stale proxy.json alone.
grep -q 'ProcessStartTicks uint64' "$ROOT/project/core/src/internal/runtime/state.go"
grep -q 'process_start_ticks,omitempty' "$ROOT/project/core/src/internal/runtime/state.go"
grep -q 'actual != state.ProcessStartTicks' "$ROOT/project/core/src/internal/runtime/state.go"
grep -q 'proxy.json is daemon-owned runtime state' "$ROOT/project/core/src/internal/app/app.go"
grep -q '!probe.Running' "$ROOT/project/core/src/internal/app/app.go"

cd "$ROOT/project/core/src"
go test ./internal/runtime ./internal/status ./internal/app \
  -run 'Test(StoreLifecycle|ProbeRejectsReusedPIDByProcessStartTicks|ProbeAcceptsMatchingProcessStartTicks|ProbeKeepsLegacyPIDOnlyStateCompatible|Semantics|ProxyStatusDoesNotTrustStaleListenerSnapshotWhenDaemonStopped|ProxyStatusFailsClosedWhenRuntimeIdentityCannotBeProbed)$'

echo "Stage 5 status truth smoke: PASS"
