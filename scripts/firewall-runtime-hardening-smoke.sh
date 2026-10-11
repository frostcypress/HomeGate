#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$ROOT/project/core/src"
go test ./internal/firewall -count=1 -run '^(TestCleanupTreatsLegacyMissingHomeGateJumpTargetAsAbsent|TestCleanupAcceptsQWRTLegacyAlreadyAbsentChains|TestCleanupReportsRealHookFailureAndDoesNotFlushReferencedChain|TestApplyReportsOriginalAndCleanupFailure|TestStatusWriteFailureIsSeparatedFromRuntimeFailure|TestWANNotReadyIsRetryable|TestPermanentIPTablesFailureIsNotRetryable)$'
go test ./internal/app -count=1 -run '^(TestReconcileRuntimeCandidateFirewallRejectKeepsConfigAndProxyOld|TestReconcileRuntimeCandidateReportsFirewallRestoreFailure|TestReconcileProxyCandidateRejectKeepsConfigCurrent|TestReconcileProxyCandidateCommitsAfterProxyAccepts)$'
go test ./internal/runtimefile -count=1

grep -Fq 'proxyManager.PrepareGeneration' "$ROOT/project/core/src/internal/app/app.go"
grep -Fq 'proxyManager.CommitPrepared' "$ROOT/project/core/src/internal/app/app.go"
grep -Fq 'a.Firewall.Apply(ctx, a.Version, current)' "$ROOT/project/core/src/internal/app/app.go"
grep -Fq 'RuntimeFailed' "$ROOT/project/core/src/internal/firewall/firewall.go"
grep -Fq 'runtimefile.WriteJSONAtomic' "$ROOT/project/core/src/internal/firewall/firewall.go"
grep -Fq 'runtimefile.WriteJSONAtomic' "$ROOT/project/core/src/internal/proxy/proxy.go"
! grep -Fq 'os.WriteFile(path, append(b' "$ROOT/project/core/src/internal/firewall/firewall.go"
! grep -Fq 'os.WriteFile(path, append(b' "$ROOT/project/core/src/internal/proxy/proxy.go"

echo 'firewall/runtime hardening smoke: PASS'
