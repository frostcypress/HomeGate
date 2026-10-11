#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CORE="$ROOT/project/core/src"

# Stage 5 Round 5 contract: a transient WAN/public-IPv6 startup gap keeps the
# daemon alive for the existing bounded recovery loop, while a permanent
# firewall runtime failure fails startup and releases runtime/proxy ownership.
grep -q 'if firewall.Retryable(fwErr)' "$CORE/internal/app/app.go"
grep -q 'firewall startup apply:' "$CORE/internal/app/app.go"
grep -q 'proxy cleanup after firewall startup failure' "$CORE/internal/app/app.go"

cd "$CORE"
go test ./internal/firewall ./internal/app \
  -run 'Test(WANNotReadyIsRetryable|PermanentIPTablesFailureIsNotRetryable|PermanentFirewallStartupFailureIsFailFastAndReleasesRuntime|RetryableWANStartupFailureKeepsDaemonForBoundedRecovery)$'

echo "Stage 5 firewall startup contract smoke: PASS"
