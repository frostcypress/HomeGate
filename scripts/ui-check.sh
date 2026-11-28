#!/bin/sh
# Current static contracts. Browser suites additionally cover all retained UI behavior.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 "$ROOT/scripts/frontend-source-regressions.py"
