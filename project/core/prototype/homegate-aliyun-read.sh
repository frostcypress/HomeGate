#!/bin/sh
# Fixed read-only entry; coordinator retains the existing common lock protocol.
set -u
aliyun_entry_enabled=false
aliyun_records_enabled=false
aliyun_reconcile_enabled=false
aliyun_receipt_enabled=false
aliyun_settlement_enabled=false
aliyun_retention_enabled=false
aliyun_terminal_repair_enabled=false
aliyun_orphan_collection_enabled=false
aliyun_checkpoint_repair_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"Aliyun reader is unavailable"}\n';exit 2; }
[ "$aliyun_entry_enabled" = true ] || fail
[ "${2:-}" != --records ] || [ "$aliyun_records_enabled" = true ] || fail
if [ "$#" -eq 4 ]; then
    [ "$aliyun_reconcile_enabled" = true ] && [ "$4" = --confirm ] || fail
    case "$2" in
        --reconcile) ;;
        --reconcile-receipt) [ "$aliyun_receipt_enabled" = true ] || fail;;
        --collect-receipt|--retire-archive|--repair-terminal|--collect-orphan|--repair-checkpoint)
            [ "$aliyun_receipt_enabled" = true ] && [ "$aliyun_settlement_enabled" = true ] || fail
            case "$2" in
                --retire-archive) [ "$aliyun_retention_enabled" = true ] || fail;;
                --repair-terminal) [ "$aliyun_terminal_repair_enabled" = true ] || fail;;
                --collect-orphan) [ "$aliyun_orphan_collection_enabled" = true ] || fail;;
                --repair-checkpoint) [ "$aliyun_checkpoint_repair_enabled" = true ] || fail;;
            esac;;
        *) fail;;
    esac
else
    [ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && { [ "$2" = --zones ] || [ "$2" = --migrated ] || [ "$2" = --records ]; }; } || fail
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
exec ash "$dir/homegate-cloudflare-read.sh" --aliyun-internal "$@"
