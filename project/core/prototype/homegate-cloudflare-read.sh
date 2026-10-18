#!/bin/sh
# Fixed private DNS coordinator. Not installed; both production gates closed.
set -u
umask 077
export LC_ALL=C
dns_read_enabled=false
ddns_sync_enabled=false
ddns_work_enabled=false
ddns_runtime_enabled=false
ddns_closeout_enabled=false
aliyun_read_enabled=false
dnspod_read_enabled=false
huaweicloud_read_enabled=false
huaweicloud_records_enabled=false
huaweicloud_reconcile_enabled=false
huaweicloud_receipt_enabled=false
huaweicloud_settlement_enabled=false
huaweicloud_retention_enabled=false
huaweicloud_terminal_repair_enabled=false
huaweicloud_orphan_collection_enabled=false
huaweicloud_checkpoint_repair_enabled=false
dnspod_records_enabled=false
dnspod_reconcile_enabled=false
dnspod_receipt_enabled=false
dnspod_settlement_enabled=false
dnspod_retention_enabled=false
dnspod_terminal_repair_enabled=false
dnspod_orphan_collection_enabled=false
dnspod_checkpoint_repair_enabled=false
aliyun_records_enabled=false
aliyun_reconcile_enabled=false
aliyun_receipt_enabled=false
aliyun_settlement_enabled=false
aliyun_retention_enabled=false
aliyun_terminal_repair_enabled=false
aliyun_orphan_collection_enabled=false
aliyun_checkpoint_repair_enabled=false
dns_migrated_read_enabled=false
dns_records_enabled=false
dns_reconcile_enabled=false
dns_receipt_enabled=false
dns_settlement_enabled=false
dns_retention_enabled=false
dns_terminal_repair_enabled=false
dns_checkpoint_repair_enabled=false
dns_orphan_collection_enabled=false
persistent_reconcile=false
effect=none
fail() {
    if [ "${mode:-check}" = records ]; then
        required=false;[ "$effect" != unknown ] || required=true
        operation_error="Cloudflare operation is unavailable"
        [ "${provider:-cloudflare}" != aliyun ] || operation_error="Aliyun operation is unavailable"
        [ "${provider:-cloudflare}" != dnspod ] || operation_error="DNSPod operation is unavailable"
        [ "${provider:-cloudflare}" != huaweicloud ] || operation_error="Huawei Cloud operation is unavailable"
        printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","effect":"%s","reconciliation_required":%s,"error":"%s"}\n' "$effect" "$required" "$operation_error"
    elif [ "${provider:-cloudflare}" = aliyun ]; then printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"Aliyun reader is unavailable"}\n'
    elif [ "${provider:-cloudflare}" = huaweicloud ]; then printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"Huawei Cloud reader is unavailable"}\n'
    elif [ "${provider:-cloudflare}" = dnspod ]; then printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"DNSPod reader is unavailable"}\n'
    else printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"Cloudflare reader is unavailable"}\n'; fi
    exit "${1:-7}"
}
[ "$dns_read_enabled" = true ] || fail 2
provider=cloudflare
ddns_dispatch=false;runtime_dispatch=false;runtime_recovery=false;runtime_closeout=false
case "${1:-}" in
    --runtime-collect-orphan-internal|--runtime-collect-receipt-internal|--runtime-retire-archive-internal)
        [ "$ddns_runtime_enabled" = true ] && [ "$ddns_closeout_enabled" = true ] && [ "$#" -eq 5 ] && [ "$5" = --confirm ] || fail 2
        runtime_closeout=true
        case "$1" in --runtime-collect-orphan-internal) maintenance=--collect-orphan;; --runtime-collect-receipt-internal) maintenance=--collect-receipt;; --runtime-retire-archive-internal) maintenance=--retire-archive;; esac
        case "$2" in cloudflare) set -- "$3" "$maintenance" "$4" --confirm;; aliyun|dnspod|huaweicloud) set -- --"$2"-internal "$3" "$maintenance" "$4" --confirm;; *) fail 2;; esac;;
esac
if [ "${1:-}" = --runtime-reconcile-internal ]; then
    [ "$ddns_runtime_enabled" = true ] && [ "$#" -eq 5 ] && [ "$5" = --confirm ] || fail 2
    runtime_recovery=true
    case "$2" in cloudflare) set -- "$3" --reconcile-receipt "$4" --confirm;; aliyun|dnspod|huaweicloud) set -- --"$2"-internal "$3" --reconcile-receipt "$4" --confirm;; *) fail 2;; esac
fi
if [ "${1:-}" = --ddns-runtime-sync-internal ]; then
    [ "$ddns_runtime_enabled" = true ] || fail 2;runtime_dispatch=true;shift;set -- --ddns-sync-internal "$@"
fi
if [ "${1:-}" = --ddns-sync-internal ]; then
    [ "$ddns_sync_enabled" = true ] && [ "$ddns_work_enabled" = true ] && [ "$#" -eq 5 ] && [ "$4" = --records ] || fail 2
    ddns_job=$5
    case "$ddns_job" in ''|0*|*[!0-9]*) fail 2;; esac
    [ "${#ddns_job}" -le 9 ] && [ "$ddns_job" -ge 2 ] || fail 2
    ddns_dispatch=true
    case "$2" in
        cloudflare) set -- "$3" --records;;
        aliyun) set -- --aliyun-internal "$3" --records;;
        dnspod) set -- --dnspod-internal "$3" --records;;
        huaweicloud) set -- --huaweicloud-internal "$3" --records;;
        *) fail 2;;
    esac
fi
if [ "${1:-}" = --aliyun-internal ]; then
    [ "$aliyun_read_enabled" = true ] || fail 2
    provider=aliyun;shift
elif [ "${1:-}" = --huaweicloud-internal ]; then
    provider=huaweicloud;[ "$huaweicloud_read_enabled" = true ] || fail 2;shift
    [ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && { [ "$2" = --zones ] || [ "$2" = --records ]; }; } || { [ "$#" -eq 4 ] && { [ "$2" = --reconcile ] || [ "$2" = --reconcile-receipt ] || [ "$2" = --collect-receipt ] || [ "$2" = --retire-archive ] || [ "$2" = --repair-terminal ] || [ "$2" = --collect-orphan ] || [ "$2" = --repair-checkpoint ]; } && [ "$4" = --confirm ]; } || fail 2
elif [ "${1:-}" = --dnspod-internal ]; then
    provider=dnspod;[ "$dnspod_read_enabled" = true ] || fail 2;shift
    [ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && { [ "$2" = --zones ] || [ "$2" = --records ]; }; } || { [ "$#" -eq 4 ] && { [ "$2" = --reconcile ] || [ "$2" = --reconcile-receipt ] || [ "$2" = --collect-receipt ] || [ "$2" = --retire-archive ] || [ "$2" = --repair-terminal ] || [ "$2" = --collect-orphan ] || [ "$2" = --repair-checkpoint ]; } && [ "$4" = --confirm ]; } || fail 2
fi
[ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && { [ "$2" = --zones ] || [ "$2" = --records ] || [ "$2" = --migrated ]; }; } || { [ "$#" -eq 4 ] && { [ "$2" = --reconcile ] || [ "$2" = --reconcile-receipt ] || [ "$2" = --collect-receipt ] || [ "$2" = --retire-archive ] || [ "$2" = --repair-terminal ] || [ "$2" = --repair-checkpoint ] || [ "$2" = --collect-orphan ]; } && [ "$4" = --confirm ]; } || fail 2
account=$1
mode=check; codec=cloudflare-codec.lua
migrated_read=false
if [ "$#" -eq 2 ]; then
    case "$2" in --zones) mode=zones; codec=cloudflare-zones.lua;;
        --migrated) [ "$dns_migrated_read_enabled" = true ] || fail 2;migrated_read=true;;
        --records) mode=records;codec=cloudflare-records.lua;[ "$dns_records_enabled" = true ] || fail 2;; esac
fi
if [ "$#" -eq 4 ]; then
    mode=reconcile;codec=cloudflare-records.lua
    [ "$dns_records_enabled" = true ] && [ "$dns_reconcile_enabled" = true ] || fail 2
    old_job=$3
    case "$old_job" in ''|0*|*[!0-9]*) fail 2;; esac
    [ "${#old_job}" -le 9 ] && [ "$old_job" -ge 2 ] || fail 2
    old_work=/var/run/homegate/.dns-check-$old_job
    if [ "$provider" = aliyun ]; then
        [ "$aliyun_reconcile_enabled" = true ] || fail 2
        case "$2" in
            --reconcile) ;;
            --reconcile-receipt) [ "$aliyun_receipt_enabled" = true ] || fail 2;persistent_reconcile=true;;
            --collect-receipt|--retire-archive|--repair-terminal|--collect-orphan|--repair-checkpoint)
                [ "$aliyun_receipt_enabled" = true ] && [ "$aliyun_settlement_enabled" = true ] || fail 2
                case "$2" in
                    --collect-receipt) mode=collect;;
                    --retire-archive) [ "$aliyun_retention_enabled" = true ] || fail 2;mode=retire;;
                    --repair-terminal) [ "$aliyun_terminal_repair_enabled" = true ] || fail 2;mode=repair;;
                    --collect-orphan) [ "$aliyun_orphan_collection_enabled" = true ] || fail 2;mode=orphan;;
                    --repair-checkpoint) [ "$aliyun_checkpoint_repair_enabled" = true ] || fail 2;mode=checkpoint;;
                esac;;
            *) fail 2;;
        esac
    elif [ "$provider" = huaweicloud ]; then
        [ "$huaweicloud_reconcile_enabled" = true ] || fail 2
        case "$2" in
            --reconcile) ;;
            --reconcile-receipt) [ "$huaweicloud_receipt_enabled" = true ] || fail 2;persistent_reconcile=true;;
            --collect-receipt|--retire-archive|--repair-terminal|--collect-orphan|--repair-checkpoint)
                [ "$huaweicloud_receipt_enabled" = true ] && [ "$huaweicloud_settlement_enabled" = true ] || fail 2
                case "$2" in
                    --collect-receipt) mode=collect;;
                    --retire-archive) [ "$huaweicloud_retention_enabled" = true ] || fail 2;mode=retire;;
                    --repair-terminal) [ "$huaweicloud_terminal_repair_enabled" = true ] || fail 2;mode=repair;;
                    --collect-orphan) [ "$huaweicloud_orphan_collection_enabled" = true ] || fail 2;mode=orphan;;
                    --repair-checkpoint) [ "$huaweicloud_checkpoint_repair_enabled" = true ] || fail 2;mode=checkpoint;;
                esac;;
            *) fail 2;;
        esac
    elif [ "$provider" = dnspod ]; then
        [ "$dnspod_reconcile_enabled" = true ] || fail 2
        case "$2" in
            --reconcile) ;;
            --reconcile-receipt) [ "$dnspod_receipt_enabled" = true ] || fail 2;persistent_reconcile=true;;
            --collect-receipt|--retire-archive|--repair-terminal|--collect-orphan|--repair-checkpoint)
                [ "$dnspod_receipt_enabled" = true ] && [ "$dnspod_settlement_enabled" = true ] || fail 2
                case "$2" in
                    --collect-receipt) mode=collect;;
                    --retire-archive) [ "$dnspod_retention_enabled" = true ] || fail 2;mode=retire;;
                    --repair-terminal) [ "$dnspod_terminal_repair_enabled" = true ] || fail 2;mode=repair;;
                    --collect-orphan) [ "$dnspod_orphan_collection_enabled" = true ] || fail 2;mode=orphan;;
                    --repair-checkpoint) [ "$dnspod_checkpoint_repair_enabled" = true ] || fail 2;mode=checkpoint;;
                esac;;
            *) fail 2;;
        esac
    elif [ "$2" != --reconcile ]; then
        [ "$dns_receipt_enabled" = true ] && [ "$dns_settlement_enabled" = true ] || fail 2
        case "$2" in
            --collect-receipt) mode=collect;;
            --retire-archive) [ "$dns_retention_enabled" = true ] || fail 2;mode=retire;;
            --repair-terminal) [ "$dns_terminal_repair_enabled" = true ] || fail 2;mode=repair;;
            --repair-checkpoint) [ "$dns_checkpoint_repair_enabled" = true ] || fail 2;mode=checkpoint;;
            --collect-orphan) [ "$dns_orphan_collection_enabled" = true ] || fail 2;mode=orphan;;
            *) persistent_reconcile=true;;
        esac
    fi
fi
watchdog_mode=--cloudflare-check
if [ "$provider" = aliyun ]; then
    case "$mode" in check|zones) ;; collect|retire|repair|orphan|checkpoint) [ "$aliyun_settlement_enabled" = true ] && [ "$aliyun_receipt_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; reconcile) [ "$aliyun_reconcile_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; records) [ "$aliyun_records_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; *) fail 2;; esac
    [ "$dns_migrated_read_enabled" = true ] || fail 2;migrated_read=true
    codec=aliyun-reader.lua;watchdog_mode=--aliyun-check
elif [ "$provider" = dnspod ]; then
    case "$mode" in check|zones) ;; records) [ "$dnspod_records_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; reconcile) [ "$dnspod_reconcile_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; collect|retire|repair|orphan|checkpoint) [ "$dnspod_settlement_enabled" = true ] && [ "$dnspod_receipt_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; *) fail 2;; esac
    [ "$dns_migrated_read_enabled" = true ] || fail 2;migrated_read=true
    codec=dnspod-reader.lua;watchdog_mode=--dnspod-check
elif [ "$provider" = huaweicloud ]; then
    case "$mode" in check|zones) ;; records) [ "$huaweicloud_records_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; reconcile) [ "$huaweicloud_records_enabled" = true ] && [ "$huaweicloud_reconcile_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; collect|retire|repair|orphan|checkpoint) [ "$huaweicloud_settlement_enabled" = true ] && [ "$huaweicloud_receipt_enabled" = true ] && [ "$dns_receipt_enabled" = false ] || fail 2;; *) fail 2;;esac
    [ "$dns_migrated_read_enabled" = true ] || fail 2;migrated_read=true
    codec=huaweicloud-reader.lua;watchdog_mode=--huaweicloud-check
fi
if [ "$ddns_dispatch" = true ]; then
    [ "$mode" = records ] && [ "$dns_migrated_read_enabled" = true ] || fail 2
    migrated_read=true
    case "$provider" in
        cloudflare) [ "$dns_receipt_enabled" = true ] && [ "$dns_settlement_enabled" = true ] || fail 2;;
        aliyun) [ "$aliyun_receipt_enabled" = true ] && [ "$aliyun_settlement_enabled" = true ] || fail 2;;
        dnspod) [ "$dnspod_receipt_enabled" = true ] && [ "$dnspod_settlement_enabled" = true ] || fail 2;;
        huaweicloud) [ "$huaweicloud_receipt_enabled" = true ] && [ "$huaweicloud_settlement_enabled" = true ] || fail 2;;
    esac
fi
case "$account" in ''|*[!a-zA-Z0-9_-]*) fail 2;; esac
[ "${#account}" -le 64 ] || fail 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
[ "$(id -u)" = 0 ] || fail
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1" 2>/dev/null)" = 0:600:1 ]; }
private_dir /var/run/homegate && private_dir /etc/homegate/transactions || fail
private_file /var/run/homegate/frontend.lock && private_file /etc/homegate/transactions/.supervisor.lock || fail
if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/6 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' /var/run/homegate/frontend.lock)" ]; then
    exec 6>>/var/run/homegate/frontend.lock || fail
fi
flock -n 6 || fail 4
if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/7 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' /etc/homegate/transactions/.supervisor.lock)" ]; then
    exec 7>>/etc/homegate/transactions/.supervisor.lock || fail
fi
flock -n 7 || fail 4
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
if [ "$ddns_dispatch" = true ]; then
    info=$(lua "$dir/worker-process.lua" info "$$" none 2>/dev/null) || fail
    old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
    [ "$#" -eq 6 ] && [ "$2" = "$ddns_job" ] || fail
fi
check_command=writer-check;snapshot_command=snapshot-read
if { [ "$mode" = reconcile ] || [ "$mode" = collect ] || [ "$mode" = retire ] || [ "$mode" = repair ] || [ "$mode" = checkpoint ] || [ "$mode" = orphan ]; } && [ "$dns_receipt_enabled" = true ]; then check_command=dns-recovery-check;snapshot_command=dns-recovery-snapshot-read; fi
if { [ "$provider" = aliyun ] || [ "$provider" = dnspod ] || [ "$provider" = huaweicloud ]; } && { [ "$mode" = reconcile ] || [ "$mode" = collect ] || [ "$mode" = retire ] || [ "$mode" = repair ] || [ "$mode" = orphan ] || [ "$mode" = checkpoint ]; }; then check_command=dns-recovery-check;snapshot_command=migration-source-recovery-snapshot-read;migrated_read=false;fi
if [ "$runtime_dispatch" = true ]; then migrated_read=false;snapshot_command=runtime-ddns-snapshot-read;fi
if [ "$runtime_recovery" = true ]; then
    [ "$mode" = reconcile ] && [ "$persistent_reconcile" = true ] || fail 2
    check_command=dns-recovery-check;snapshot_command=runtime-ddns-recovery-snapshot-read;migrated_read=false
fi
if [ "$runtime_closeout" = true ]; then
    check_command=dns-recovery-check;snapshot_command=runtime-ddns-recovery-snapshot-read;migrated_read=false
fi
ash "$dir/homegate-config-prototype.sh" --persistent "$check_command" >/dev/null 2>&1
state=$?; case "$state" in 0) ;; 4) fail 4;; *) fail;; esac
if [ "$migrated_read" = true ]; then
    ash "$dir/homegate-config-prototype.sh" --persistent migration-source-reader-check >/dev/null 2>&1
    state=$?;case "$state" in 0) ;; 4) fail 4;; *) fail;; esac
fi
revision=$(lua "$dir/cloudflare-codec.lua" context < /etc/homegate/transactions/current 2>/dev/null) || fail
if [ "$runtime_closeout" = true ]; then
    case "$mode" in orphan|collect|retire) ;; *) fail 2;; esac
    # Bind the ordinary source even for archive retirement, which otherwise
    # deliberately validates historical evidence without current credentials.
    ready=$(ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-sync.lua" source "$revision" 3>&- 4>&- 5>&- 8>&- 9>&- 2>/dev/null) || fail
    [ "$ready" = HGDDNSSOURCE1 ] || fail
    # The outer DDNS evidence must be explicitly collected first. Never clear
    # a provider fence while another outer request remains unresolved.
    for outer in /var/run/homegate/.ddns-plan-*; do
        [ ! -e "$outer" ] && [ ! -L "$outer" ] || fail 4
    done
fi
if [ "$ddns_dispatch" = true ]; then
    work_check=check;[ "$runtime_dispatch" != true ] || work_check=check-runtime
    ddns_rule=$(ash "$dir/homegate-ddns-work.sh" "$work_check" "$ddns_job" "$revision" "$provider" "$account" 2>/dev/null) || fail
    if [ "$runtime_dispatch" = true ]; then ash "$dir/homegate-ddns-authority.sh" check-rule "$ddns_rule" >/dev/null 2>/dev/null || fail;fi
fi
# Never silently collect an orphan request or unlink possibly live files.
for orphan in /var/run/homegate/.dns-check-*; do
    if [ "$mode" = reconcile ] && [ "$orphan" = "$old_work" ]; then continue; fi
    if { [ "$mode" = repair ] || [ "$mode" = checkpoint ] || [ "$mode" = orphan ]; } && [ "$orphan" = "$old_work" ]; then private_dir "$orphan" || fail 4;continue;fi
    [ ! -e "$orphan" ] && [ ! -L "$orphan" ] || fail 4
done
if [ "$mode" = orphan ]; then
    if [ "$provider" = aliyun ]; then
        ash "$dir/homegate-dns-orphan.sh" --aliyun-internal collect-orphan "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = dnspod ]; then
        ash "$dir/homegate-dns-orphan.sh" --dnspod-internal collect-orphan "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = huaweicloud ]; then
        ash "$dir/homegate-dns-orphan.sh" --huaweicloud-internal collect-orphan "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    else
    ash "$dir/homegate-dns-orphan.sh" collect-orphan "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    fi
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-orphan-collection","orphan_collected":true,"write_ready":false}\n'
    exit 0
fi
if [ "$mode" = checkpoint ]; then
    if [ "$provider" = aliyun ]; then
        ash "$dir/homegate-dns-checkpoint-repair.sh" --aliyun-internal repair-checkpoint "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = dnspod ]; then
        ash "$dir/homegate-dns-checkpoint-repair.sh" --dnspod-internal repair-checkpoint "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = huaweicloud ]; then
        ash "$dir/homegate-dns-checkpoint-repair.sh" --huaweicloud-internal repair-checkpoint "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    else
    ash "$dir/homegate-dns-checkpoint-repair.sh" repair-checkpoint "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    fi
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-checkpoint-repair","checkpoint_repaired":true,"write_ready":false}\n'
    exit 0
fi
if [ "$mode" = repair ]; then
    if [ "$provider" = aliyun ]; then
        ash "$dir/homegate-dns-recovery.sh" --aliyun-internal repair-terminal "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = dnspod ]; then
        ash "$dir/homegate-dns-recovery.sh" --dnspod-internal repair-terminal "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = huaweicloud ]; then
        ash "$dir/homegate-dns-recovery.sh" --huaweicloud-internal repair-terminal "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    else
    ash "$dir/homegate-dns-recovery.sh" repair-terminal "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    fi
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-terminal-repair","terminal_repaired":true,"write_ready":false}\n'
    exit 0
fi
if [ "$mode" = retire ]; then
    if [ "$provider" = aliyun ]; then
        ash "$dir/homegate-dns-retention.sh" --aliyun-internal retire "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = dnspod ]; then
        ash "$dir/homegate-dns-retention.sh" --dnspod-internal retire "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = huaweicloud ]; then
        ash "$dir/homegate-dns-retention.sh" --huaweicloud-internal retire "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    else
    ash "$dir/homegate-dns-retention.sh" retire "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    fi
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-archive-retention","retired":true,"write_ready":false}\n'
    exit 0
fi
if [ "$mode" = collect ]; then
    if [ "$provider" = aliyun ]; then
        ash "$dir/homegate-dns-recovery.sh" --aliyun-internal collect "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = huaweicloud ]; then
        ash "$dir/homegate-dns-recovery.sh" --huaweicloud-internal collect "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    elif [ "$provider" = dnspod ]; then
        ash "$dir/homegate-dns-recovery.sh" --dnspod-internal collect "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    else
    ash "$dir/homegate-dns-recovery.sh" collect "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    fi
    ready=true;[ "$runtime_closeout" != true ] || ready=false
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-receipt-collection","archived":true,"write_ready":%s}\n' "$ready"
    exit 0
fi
if [ "$mode" = reconcile ] && [ "$persistent_reconcile" = false ]; then
    private_dir "$old_work" || fail
    for slot in request result zones state input context attempt; do private_file "$old_work/$slot" || fail; done
    marker=HGCFATTEMPT1;marker_size=13
    [ "$provider" != aliyun ] || { marker=HGALIATTEMPT1;marker_size=14; }
    [ "$provider" != dnspod ] || { marker=HGDNPATTEMPT1;marker_size=14; }
    [ "$provider" != huaweicloud ] || { marker=HGHWATTEMPT1;marker_size=13; }
    [ "$(cat "$old_work/attempt" 2>/dev/null)" = "$marker" ] || fail
    [ "$(stat -c '%s' "$old_work/attempt" 2>/dev/null)" = "$marker_size" ] || fail
fi
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 2>/dev/null) || fail
job=$$
[ "$ddns_dispatch" != true ] || job=$ddns_job
work=/var/run/homegate/.dns-check-$job
mkdir "$work" 2>/dev/null || fail
(set -C; : > "$work/request" && : > "$work/result" && : > "$work/zones" && : > "$work/state") 2>/dev/null || fail
private_dir "$work" && private_file "$work/request" && private_file "$work/result" || fail
if [ "$provider" != cloudflare ]; then
    (set -C; : > "$work/sign-input" && : > "$work/sign-output") 2>/dev/null || fail
fi
if [ "$mode" = records ] || [ "$mode" = reconcile ]; then
    (set -C; : > "$work/input" && : > "$work/context" && : > "$work/attempt") 2>/dev/null || fail
    # Original operation input has a separate inherited reader. The watchdog
    # bounds its consumption; the private snapshot remains on FD0.
    if [ "$mode" = records ]; then exec 4<&0 || fail
    elif [ "$persistent_reconcile" = true ]; then
        if [ "$provider" = aliyun ]; then
            if [ "$aliyun_settlement_enabled" = true ]; then
                ash "$dir/homegate-dns-recovery.sh" --aliyun-internal load "$account" "$revision" "$old_job" 5>"$work/context" >/dev/null 2>/dev/null || fail
            else
            ash "$dir/homegate-dns-receipt.sh" --aliyun-internal load "$account" "$revision" "$old_job" 5>"$work/context" >/dev/null 2>/dev/null || fail
            fi
        elif [ "$provider" = huaweicloud ]; then
            if [ "$huaweicloud_settlement_enabled" = true ]; then
            ash "$dir/homegate-dns-recovery.sh" --huaweicloud-internal load "$account" "$revision" "$old_job" 5>"$work/context" >/dev/null 2>/dev/null || fail
            else
            ash "$dir/homegate-dns-receipt.sh" --huaweicloud-internal load "$account" "$revision" "$old_job" 5>"$work/context" >/dev/null 2>/dev/null || fail
            fi
        elif [ "$provider" = dnspod ]; then
            if [ "$dnspod_settlement_enabled" = true ]; then
                ash "$dir/homegate-dns-recovery.sh" --dnspod-internal load "$account" "$revision" "$old_job" 5>"$work/context" >/dev/null 2>/dev/null || fail
            else
            ash "$dir/homegate-dns-receipt.sh" --dnspod-internal load "$account" "$revision" "$old_job" 5>"$work/context" >/dev/null 2>/dev/null || fail
            fi
        else
        ash "$dir/homegate-dns-recovery.sh" load "$account" "$revision" "$old_job" 5>"$work/context" >/dev/null 2>/dev/null || fail
        fi
    else
        [ "$(stat -c '%s' "$old_work/context" 2>/dev/null)" -le 8388608 ] || fail
        cat "$old_work/context" > "$work/context" || fail
    fi
fi
result=0
# Only the private frame uses FD3; engine's public receipt goes to /dev/null.
# The independent consumer watchdog retains FD6/7, but not the configuration lock.
ash "$dir/homegate-config-prototype.sh" --persistent "$snapshot_command" 3>&1 8>&- 9>&- >/dev/null 2>/dev/null |
    setsid ash "$dir/homegate-service-observer-watchdog.sh" "$watchdog_mode" "$ticket" "$account" "$revision" "$job" "$mode" 3>"$work/result" 8>&- 9>&- >/dev/null 2>/dev/null || result=$?
exec 4>&-
if [ "$mode" = records ] && [ -s "$work/attempt" ]; then effect=unknown; fi
# The whole pipeline has ended. Unknown descendants retain the watchdog locks;
# the same-session watchdog must prove quiescence before returning success.
if [ "$result" -eq 0 ] || [ "$result" -eq 1 ]; then
    result_mode=result
    if [ "$mode" = records ] || [ "$mode" = reconcile ]; then exec 9<"$work/attempt" || fail; fi
    [ "$mode" != reconcile ] || result_mode=reconcile-result
    if [ "$provider" != cloudflare ]; then
    lua "$dir/$codec" "$result_mode" "$account" "$revision" "$result" "$mode" < "$work/result" 2>/dev/null > "$work/zones" || result=7
    else
    lua "$dir/$codec" "$result_mode" "$account" "$revision" "$result" < "$work/result" 2>/dev/null > "$work/zones" || result=7
    fi
    exec 9<&-
fi
# Persist the already canonical success receipt only after the supervised family
# is quiet. A settlement failure retains both durable and same-boot barriers.
if [ "$mode" = records ] && [ "$dns_receipt_enabled" = true ] && [ "$dns_settlement_enabled" = true ] && [ "$effect" = unknown ] && [ "$result" -eq 0 ]; then
    ash "$dir/homegate-dns-recovery.sh" settle "$account" "$revision" "$job" >/dev/null 2>/dev/null || result=7
fi
if [ "$provider:$mode" = aliyun:records ] && [ "$aliyun_receipt_enabled" = true ] && [ "$aliyun_settlement_enabled" = true ] && [ "$effect" = unknown ] && [ "$result" -eq 0 ]; then
    ash "$dir/homegate-dns-recovery.sh" --aliyun-internal settle "$account" "$revision" "$job" >/dev/null 2>/dev/null || result=7
fi
if [ "$provider:$mode" = dnspod:records ] && [ "$dnspod_receipt_enabled" = true ] && [ "$dnspod_settlement_enabled" = true ] && [ "$effect" = unknown ] && [ "$result" -eq 0 ]; then
    ash "$dir/homegate-dns-recovery.sh" --dnspod-internal settle "$account" "$revision" "$job" >/dev/null 2>/dev/null || result=7
fi
if [ "$provider:$mode" = huaweicloud:records ] && [ "$huaweicloud_receipt_enabled" = true ] && [ "$huaweicloud_settlement_enabled" = true ] && [ "$effect" = unknown ] && [ "$result" -eq 0 ]; then
    ash "$dir/homegate-dns-recovery.sh" --huaweicloud-internal settle "$account" "$revision" "$job" >/dev/null 2>/dev/null || result=7
fi
# Delete only this invocation's allocated slots, after the pipeline is quiet.
case "$result" in 0|1) exec 5<"$work/zones" || fail;; esac
if [ "$mode" = records ] && [ "$effect" = unknown ] && [ "$result" -ne 0 ]; then
    # Keep only this job's private same-boot evidence. DNS orphan guard blocks
    # another request until explicit reconciliation (not implemented/installed).
    case "$result" in 1) cat <&5 || fail; exec 5<&-; exit 1;; *) fail;; esac
fi
if [ "$mode" = records ] || [ "$mode" = reconcile ]; then rm -f "$work/input" "$work/context" "$work/attempt" 2>/dev/null || fail; fi
if [ "$provider" != cloudflare ]; then rm -f "$work/sign-input" "$work/sign-output" 2>/dev/null || fail; fi
rm -f "$work/request" "$work/result" "$work/zones" "$work/state" 2>/dev/null && rmdir "$work" 2>/dev/null || fail
case "$result" in 0|1) cat <&5 || fail; exec 5<&-; exit "$result";; *) fail;; esac
