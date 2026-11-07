#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
find scripts project/core/prototype packaging -type f -name '*.sh' \
    -exec sh -c 'for file do sh -n "$file" || exit; done' sh {} +
sh -n packaging/production/homegate.init
sh -n packaging/production/95-homegate
exec make check
