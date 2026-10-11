#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CTRL="$ROOT/project/luci/lua/luasrc/controller/homegate.lua"
VIEW="$ROOT/project/luci/lua/luasrc/view/homegate/public.htm"
CORE="$ROOT/project/core/src/cmd/homegate/main.go"
DDNS="$ROOT/project/core/src/internal/ddns/service.go"

# Public-service Delete is staged in the page model. It never submits the old
# immediate service_delete action; Save & Apply owns provider/local cleanup.
grep -Fq 'function hgPublicDeleteNeedsConfirmation' "$VIEW"
grep -Fq 'function hgPublicDelete(i)' "$VIEW"
! grep -Fq "op:'service_delete'" "$VIEW"
grep -Fq 'hgPublicRows.splice(i,1)' "$VIEW"
grep -Fq 'Public service deletion requires Save & Apply' "$CTRL"

# Core still has the machine-readable exact DDNS deletion command used by the
# Save & Apply lifecycle.
grep -Fq 'ddns-delete <rule-id>' "$CORE"
grep -Fq 'case "ddns-delete"' "$CORE"
grep -Fq 'provider.Delete(ctx, rule.Zone, rule.Host, rule.Type, "")' "$DDNS"

python3 - "$CTRL" <<'PY'
import sys
s=open(sys.argv[1],encoding='utf-8').read()
a=s.index('function action_public_apply()')
b=s.index('\ncleanup_certificate_files = function',a)
blk=s[a:b]
assert 'if (#removed_web > 0 or #removed_ddns > 0) and mode ~= "apply" then' in blk
assert 'Public service deletion requires Save & Apply' in blk
remote=blk.index('action_core("ddns-delete " .. id)')
local=blk.index('cur:delete("homegate", id)', remote)
assert remote < local
assert 'certificate_use_count(cur, cert_id) == 0' in blk
assert 'ddns_group_count(cur, pair.account, pair.zone, "") == 0' in blk
assert 'delete_orphan_zone_certificates(cur, pair.account, pair.zone, deleted_cert_ids)' in blk
assert 'account_use_count(cur, account_id) == 0' in blk
assert blk.index('commit(cur)') < blk.index('cleanup_certificate_files(id)')
assert 'if mode == "apply" then' in blk and 'apply_homegate()' in blk
PY

printf '%s\n' 'service delete lifecycle smoke: PASS'
