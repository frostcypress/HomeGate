#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$ROOT/project/core/src"
go test ./internal/certstore ./internal/proxy -run 'Test(MatchesPatternSingleLabelWildcard|ResolvePrefersExactOverWildcard|ResolveValidatesExplicitReference|NewRejectsDuplicateEnabledPattern|BuildRoutesCertificateSelectionPrefersExactOverWildcard|BuildRoutesRejectsInvalidExplicitCertificateReference|BuildRoutesRejectsAmbiguousEnabledCertificatePattern)$' -count=1

grep -q 'internal/certstore' "$ROOT/project/core/src/internal/proxy/proxy.go"
! grep -q '^func certMatches' "$ROOT/project/core/src/internal/proxy/proxy.go"
grep -q 'certificates.Resolve' "$ROOT/project/core/src/internal/proxy/proxy.go"
grep -q 'MatchesPattern(name, d)' "$ROOT/project/core/src/internal/proxy/proxy.go"

echo "certificate store selection smoke: PASS"
