#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CORE="$ROOT/project/core/src"

# Stage 5 Round 4 contract: only one daemon may own runtime state, and an
# initial Proxy bind/apply failure must fail startup instead of leaving a
# long-lived half-started process behind.
grep -q 'ErrDaemonAlreadyRunning' "$CORE/internal/runtime/lock.go"
grep -q 'LOCK_EX|syscall.LOCK_NB' "$CORE/internal/runtime/lock.go"
grep -q 'AcquireDaemonLock(a.DaemonLockPath)' "$CORE/internal/app/app.go"
grep -q 'return fmt.Errorf("proxy startup apply: %w", proxyErr)' "$CORE/internal/app/app.go"

cd "$CORE"
go test ./internal/runtime ./internal/app \
  -run 'Test(DaemonLockRejectsConcurrentOwnerAndReleases|RunDaemonRejectsSecondOwnerBeforeConfigOrRuntimeMutation|RunDaemonProxyStartupFailureIsFailFastAndClearsRuntime)$'

echo "Stage 5 daemon startup ownership smoke: PASS"
