#!/bin/sh
# Fixed read-only entry; coordinator retains the existing common lock protocol.
set -u
huaweicloud_entry_enabled=false
huaweicloud_records_enabled=false
huaweicloud_reconcile_enabled=false
huaweicloud_receipt_enabled=false
huaweicloud_settlement_enabled=false
huaweicloud_retention_enabled=false
huaweicloud_terminal_repair_enabled=false
huaweicloud_orphan_collection_enabled=false
huaweicloud_checkpoint_repair_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"Huawei Cloud reader is unavailable"}\n';exit 2; }
[ "$huaweicloud_entry_enabled" = true ] || fail
[ "${2:-}" != --records ] || [ "$huaweicloud_records_enabled" = true ] || fail
if [ "$#" -eq 4 ]; then
    [ "$huaweicloud_reconcile_enabled" = true ] && [ "$4" = --confirm ] || fail
    case "$2" in
        --reconcile) ;;
        --reconcile-receipt) [ "$huaweicloud_receipt_enabled" = true ] || fail;;
        --collect-receipt|--retire-archive|--repair-terminal|--collect-orphan|--repair-checkpoint)
            [ "$huaweicloud_receipt_enabled" = true ] && [ "$huaweicloud_settlement_enabled" = true ] || fail
            case "$2" in
                --retire-archive) [ "$huaweicloud_retention_enabled" = true ] || fail;;
                --repair-terminal) [ "$huaweicloud_terminal_repair_enabled" = true ] || fail;;
                --collect-orphan) [ "$huaweicloud_orphan_collection_enabled" = true ] || fail;;
                --repair-checkpoint) [ "$huaweicloud_checkpoint_repair_enabled" = true ] || fail;;
            esac;;
        *) fail;;
    esac
else
    [ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && { [ "$2" = --zones ] || [ "$2" = --records ]; }; } || fail
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
exec ash "$dir/homegate-cloudflare-read.sh" --huaweicloud-internal "$@"
