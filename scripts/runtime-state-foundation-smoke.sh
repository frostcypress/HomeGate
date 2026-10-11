#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$ROOT/project/core/src"
go test ./internal/runtime ./internal/runtimefile ./internal/ddns ./internal/access ./internal/logger \
  -run 'TestStoreLifecycle|TestStoreConcurrentWritesUseIndependentTempFiles|TestRecorderDoesNotResurrectRowsAfterExternalClear|TestWriteRegionCacheConcurrentWritersDoNotShareTempFile|TestConcurrentTrimUsesIndependentTempFiles' \
  -count=1

# Runtime JSON/state writers share the 4G unique-temp atomic contract.
grep -q 'runtimefile.WriteJSONAtomic(s.path(), report, 0o644)' "$ROOT/project/core/src/internal/ddns/state.go"
grep -q 'runtimefile.WriteJSONAtomic(s.path(), state, 0o644)' "$ROOT/project/core/src/internal/runtime/state.go"
grep -q 'runtimefile.WriteJSONAtomic(r.Path, report, 0o600)' "$ROOT/project/core/src/internal/access/access.go"

# Access recent mutations have one cross-process sidecar lock and reload the
# in-memory snapshot when the atomic file identity changes.
grep -q 'func lockRecentFile' "$ROOT/project/core/src/internal/access/access.go"
grep -q 'os.SameFile' "$ROOT/project/core/src/internal/access/access.go"
grep -q 'defer unlock()' "$ROOT/project/core/src/internal/access/access.go"

# No production writer may go back to one shared <final>.tmp pathname.
if grep -RIn 'tmp := .*+ "\.tmp"' "$ROOT/project/core/src/internal" --include='*.go' | grep -v '_test.go'; then
  echo 'fixed shared temp filename found in production Core' >&2
  exit 1
fi

# Persistent/cache writers that stream content still use unique same-dir temps.
grep -q 'os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-\*")' "$ROOT/project/core/src/internal/access/access.go"
grep -q 'os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-\*")' "$ROOT/project/core/src/internal/logger/logger.go"

echo 'Stage 5 Round 1 runtime-state foundation smoke: PASS'
