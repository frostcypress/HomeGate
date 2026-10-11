#!/bin/sh
set -eu
BIN=${1:?usage: access-recent-hotpath-smoke.sh /path/to/homegate}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/home/access/regions"
mkfifo "$TMP/home/access/regions/CN.cidr"
cat > "$TMP/access.json" <<'JSON'
{"api_version":1,"ok":true,"phase":"access","entries":[{"time":"2026-09-09T05:01:27Z","ip":"2001:db8::1","host":"vault.example.com","allowed":false,"reason":"manual-deny","policy_mode":"manual","geo":"CN","current_allowed":false,"current_reason":"manual-deny","current_policy_mode":"manual","count":29}]}
JSON
# A legacy access-recent implementation that reparses Geo cache files blocks on
# the FIFO above. The current implementation must only read access.json.
HOMEGATE_HOME_DIR="$TMP/home" HOMEGATE_ACCESS_RECENT="$TMP/access.json" \
  timeout 2 "$BIN" access-recent > "$TMP/out.json"
grep -Fq '"geo":"CN"' "$TMP/out.json"
grep -Fq '"current_reason":"manual-deny"' "$TMP/out.json"
echo "access-recent hot-path smoke: PASS"
