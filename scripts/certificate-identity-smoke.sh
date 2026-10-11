#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT/project/core/src"

go test ./internal/certstore -run 'TestValidatePEMIdentities' -count=1
go test ./internal/acme -run 'TestStatusReportsCertificateIdentityValidity|TestPublishCertificatePairRejectsIdentityMismatchBeforeMutation|TestIssueDNS01AndExactCleanup' -count=1

grep -q 'ValidatePEMIdentities(chain, expectedDomains)' "$ROOT/project/core/src/internal/acme/certificate.go"
grep -q 'IdentityValid.*identity_valid' "$ROOT/project/core/src/internal/acme/service.go"
grep -q 'IdentityError.*identity_error' "$ROOT/project/core/src/internal/acme/service.go"

echo 'Certificate identity validation smoke: PASS'
