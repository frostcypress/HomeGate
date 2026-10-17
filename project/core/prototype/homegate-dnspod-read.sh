#!/bin/sh
# Fixed read-only entry; coordinator retains the existing common lock protocol.
set -u
dnspod_entry_enabled=false
dnspod_records_enabled=false
dnspod_reconcile_enabled=false
dnspod_receipt_enabled=false
dnspod_settlement_enabled=false
dnspod_retention_enabled=false
dnspod_terminal_repair_enabled=false
dnspod_orphan_collection_enabled=false
dnspod_checkpoint_repair_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"DNSPod reader is unavailable"}\n';exit 2; }
[ "$dnspod_entry_enabled" = true ] || fail
[ "${2:-}" != --records ] || [ "$dnspod_records_enabled" = true ] || fail
if [ "$#" -eq 4 ]; then
    [ "$dnspod_reconcile_enabled" = true ] && [ "$4" = --confirm ] || fail
    case "$2" in
        --reconcile) ;;
        --reconcile-receipt) [ "$dnspod_receipt_enabled" = true ] || fail;;
        --collect-receipt|--retire-archive|--repair-terminal|--collect-orphan|--repair-checkpoint)
            [ "$dnspod_receipt_enabled" = true ] && [ "$dnspod_settlement_enabled" = true ] || fail
            case "$2" in
                --retire-archive) [ "$dnspod_retention_enabled" = true ] || fail;;
                --repair-terminal) [ "$dnspod_terminal_repair_enabled" = true ] || fail;;
                --collect-orphan) [ "$dnspod_orphan_collection_enabled" = true ] || fail;;
                --repair-checkpoint) [ "$dnspod_checkpoint_repair_enabled" = true ] || fail;;
            esac;;
        *) fail;;
    esac
else
    [ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && { [ "$2" = --zones ] || [ "$2" = --records ]; }; } || fail
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
exec ash "$dir/homegate-cloudflare-read.sh" --dnspod-internal "$@"
