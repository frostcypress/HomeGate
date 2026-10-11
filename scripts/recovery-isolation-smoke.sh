#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT/project/core/src"

go test ./internal/recovery -count=1
go test ./internal/ddns -run 'Test(WANFailureIsRetryableNetworkUnavailable|CanceledWANFailureIsNotRetryable|InvalidRuleIsPermanentInvalidRequest)$' -count=1
go test ./internal/app -run 'Test(ClassifyDDNSRecoveryPrefersRetryableFailure|DaemonDDNSTemporaryFailureRetriesAndRecovers|DaemonDDNSPermanentFailureRequiresUserActionWithoutRetry|ClassifyACMERecoveryPermanentTakesPrecedence|DaemonACMETemporaryFailureRetriesAndRecovers|DaemonACMEPermanentFailureRequiresUserActionWithoutRetry|DaemonAccessStaleCacheFailureRetriesAndRecovers|DaemonWorkerPanicIsolatedAndRecovered|DaemonACMEWorkerPanicIsolatedAndRecovered|DaemonAccessWorkerPanicIsolatedAndRecovered)$' -count=1
go test ./internal/acme -run 'TestIssueErrorClassifiesNetworkFailureAsRetryable$' -count=1
go test ./internal/proxy -run 'TestUnexpectedListenerFailurePublishesAndCanRecover$' -count=1

grep -q 'case "recovery-status"' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'EventDDNSRetry' "$ROOT/project/core/src/internal/scheduler/queue.go"
grep -q 'EventACMERetry' "$ROOT/project/core/src/internal/scheduler/queue.go"
grep -q 'EventAccessRetry' "$ROOT/project/core/src/internal/scheduler/queue.go"
grep -q 'EventProxyRetry' "$ROOT/project/core/src/internal/scheduler/queue.go"
grep -q 'DDNS recovery scheduled' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'ACME recovery scheduled' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'Access recovery scheduled' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'Proxy recovery scheduled' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'background worker panic isolated' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'listener stopped unexpectedly' "$ROOT/project/core/src/internal/proxy/proxy.go"
grep -q 'recovery.StateRequiresUserAction' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'recovery.StateRetrying' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'recovery.StateDegraded' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'ErrorNetworkUnavailable' "$ROOT/project/core/src/internal/ddns/service.go"
grep -q '5 \* time.Second' "$ROOT/project/core/src/internal/app/app.go"
grep -q '120 \* time.Second' "$ROOT/project/core/src/internal/app/app.go"

echo 'recovery/isolation smoke PASS'
