#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT/project/core/src"

go test ./internal/app -run 'TestDaemonGeneration(AdvanceCancelsOldWork|CommitRejectsStaleWork|CommitLinearizesWithAdvance|StopRejectsCommit)$' -count=1
go test ./internal/acme -run '^TestIssueStaleGenerationDoesNotPublishCertificate$' -count=1

grep -q 'generation.Commit(work.Generation' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'svc.Commit = func' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'return generation.Commit(work.Generation, fn)' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'Commit.*func(func() error)' "$ROOT/project/core/src/internal/acme/service.go"

# Manual actions remain direct synchronous CLI calls; they are deliberately not
# routed through the daemon scheduler in Stage 8.
grep -q 'a.SyncDDNS(ctx' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'a.RenewCertificate(ctx' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'a.RefreshAccessRegion(ctx' "$ROOT/project/core/src/cmd/homegate/main.go"

# Distinct events must retain independent queue identity/order.
go test ./internal/scheduler -run 'TestQueue(PreservesDistinctOrder|DeduplicatesSameKind)$' -count=1

echo 'generation/order smoke PASS'
