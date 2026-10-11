#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$ROOT/project/core/src"
go test ./internal/acme -run 'Test(IssueDNS01AndExactCleanup|IssueDoesNotPublishGeneratedKeyForMismatchedCertificate|IssuePreservesExistingPairWhenIssuedCertificateMismatches|PublishCertificatePairRollsBackGeneratedKeyWhenCertificatePublishFails|CertificateRenewalLockHonorsContext|RenewDueUsesIndependentTimeoutPerCertificate|RenewDueRechecksFreshnessAfterWaitingForLock|IssueFailurePopulatesRenewError|CanceledLockWaitDoesNotWriteRenewFailure)$'

grep -Eq 'IssueTimeout[[:space:]]+time.Duration' "$ROOT/project/core/src/internal/acme/service.go"
grep -q 'acquireCertificateLock' "$ROOT/project/core/src/internal/acme/service.go"
grep -q 'RenewError.*renew_error' "$ROOT/project/core/src/internal/acme/service.go"
grep -q 'publishCertificatePair' "$ROOT/project/core/src/internal/acme/service.go"
grep -q 'syscall.Flock' "$ROOT/project/core/src/internal/acme/lock.go"
grep -q 'tls.X509KeyPair' "$ROOT/project/core/src/internal/acme/certificate.go"
grep -q 'automatic renewal failed' "$ROOT/project/core/src/internal/app/app.go"

echo "ACME robustness smoke: PASS"
