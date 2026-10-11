#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APP="$ROOT/project/core/src/internal/app/app.go"
CFG="$ROOT/project/core/src/internal/config/manager.go"
PROXY="$ROOT/project/core/src/internal/proxy/proxy.go"

# Daemon reload must load a candidate without publishing Config.Current first.
grep -Fq 'a.Config.LoadCandidate(ctx)' "$APP"
grep -Fq 'a.Config.Commit(next)' "$APP"
grep -Fq 'proxyManager.PrepareGeneration' "$APP"
grep -Fq 'proxyManager.CommitPrepared' "$APP"
grep -Fq 'RefreshAccessPolicyGeneration' "$APP"

# Proxy Apply is prepare/commit based; the historical side-effecting reconcile
# helpers must not return as an alternate runtime mutation path.
grep -Fq 'func (m *Manager) prepareHTTPS' "$PROXY"
grep -Fq 'func (m *Manager) prepareHTTP' "$PROXY"
grep -Fq 'runtimeGeneration' "$PROXY"
! grep -Fq 'func (m *Manager) reconcileHTTPS' "$PROXY"
! grep -Fq 'func (m *Manager) reconcileHTTP' "$PROXY"

grep -Fq 'func (m *Manager) LoadCandidate' "$CFG"
grep -Fq 'func (m *Manager) Commit' "$CFG"

cd "$ROOT/project/core/src"
go test ./internal/config -run 'TestManagerCandidateDoesNotPublishUntilCommit|TestManagerKeepsLastGoodSnapshotOnReloadError'
go test ./internal/proxy -run 'TestReloadFailureKeepsOldRouteAndAccessPolicy|TestStaleGenerationCannotOverwriteAccessPolicy|TestHTTPPortReloadFailureKeepsOldListener'
go test ./internal/app -run 'TestDaemonGeneration|TestReconcileRuntimeCandidate|TestReconcileProxyCandidate'

echo 'core runtime transaction smoke: PASS'
