#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT/project/core/src"
go test ./internal/access -count=1 -run '^(TestLoadPolicyReusesParsedRegionSnapshotUntilFileChanges|TestWriteRegionCacheInvalidatesParsedSnapshot|TestBuildStatusWarmsPolicyRegionSnapshot|TestLoadPolicyRejectsSameMetadataAtomicReplacement|TestGeoResolverReusesParsedRegionMatcher)$'
echo "access region parsed-cache smoke: PASS"
