#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$ROOT/project/core/src"
go test ./internal/proxy -count=1 -run '^(TestGetCertificateLoadsR6CompatiblePaths|TestGetCertificateCachesUnchangedPair|TestGetCertificateReloadsAfterAtomicRotation|TestDeniedLogMapIsBounded)$'

# Keep the request-time TLS path on stat/cache lookup rather than returning to
# unconditional PEM/key parsing on every ClientHello.
grep -q 'certCache' "$ROOT/project/core/src/internal/proxy/proxy.go"
grep -q 'sameCertificateFile' "$ROOT/project/core/src/internal/proxy/proxy.go"
grep -q 'denyLogMaxEntries = 1024' "$ROOT/project/core/src/internal/proxy/proxy.go"
grep -q 'denyRing' "$ROOT/project/core/src/internal/proxy/proxy.go"

echo "proxy hotpath smoke: PASS"
