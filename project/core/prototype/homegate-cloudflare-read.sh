#!/bin/sh
# Fixed private DNS coordinator. Not installed; both production gates closed.
set -u
umask 077
export LC_ALL=C
dns_read_enabled=false
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
        printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","effect":"%s","reconciliation_required":%s,"error":"Cloudflare operation is unavailable"}\n' "$effect" "$required"
    else printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"Cloudflare reader is unavailable"}\n'; fi
    exit "${1:-7}"
}
[ "$dns_read_enabled" = true ] || fail 2
[ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && { [ "$2" = --zones ] || [ "$2" = --records ]; }; } || { [ "$#" -eq 4 ] && { [ "$2" = --reconcile ] || [ "$2" = --reconcile-receipt ] || [ "$2" = --collect-receipt ] || [ "$2" = --retire-archive ] || [ "$2" = --repair-terminal ] || [ "$2" = --repair-checkpoint ] || [ "$2" = --collect-orphan ]; } && [ "$4" = --confirm ]; } || fail 2
account=$1
mode=check; codec=cloudflare-codec.lua
if [ "$#" -eq 2 ]; then
    case "$2" in --zones) mode=zones; codec=cloudflare-zones.lua;;
        --records) mode=records;codec=cloudflare-records.lua;[ "$dns_records_enabled" = true ] || fail 2;; esac
fi
if [ "$#" -eq 4 ]; then
    mode=reconcile;codec=cloudflare-records.lua
    [ "$dns_records_enabled" = true ] && [ "$dns_reconcile_enabled" = true ] || fail 2
    old_job=$3
    case "$old_job" in ''|0*|*[!0-9]*) fail 2;; esac
    [ "${#old_job}" -le 9 ] && [ "$old_job" -ge 2 ] || fail 2
    old_work=/var/run/homegate/.dns-check-$old_job
    if [ "$2" != --reconcile ]; then
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
exec 7>>/etc/homegate/transactions/.supervisor.lock || fail
flock -n 7 || fail 4
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
check_command=writer-check;snapshot_command=snapshot-read
if { [ "$mode" = reconcile ] || [ "$mode" = collect ] || [ "$mode" = retire ] || [ "$mode" = repair ] || [ "$mode" = checkpoint ] || [ "$mode" = orphan ]; } && [ "$dns_receipt_enabled" = true ]; then check_command=dns-recovery-check;snapshot_command=dns-recovery-snapshot-read; fi
ash "$dir/homegate-config-prototype.sh" --persistent "$check_command" >/dev/null 2>&1
state=$?; case "$state" in 0) ;; 4) fail 4;; *) fail;; esac
revision=$(lua "$dir/cloudflare-codec.lua" context < /etc/homegate/transactions/current 2>/dev/null) || fail
# Never silently collect an orphan request or unlink possibly live files.
for orphan in /var/run/homegate/.dns-check-*; do
    if [ "$mode" = reconcile ] && [ "$orphan" = "$old_work" ]; then continue; fi
    if { [ "$mode" = repair ] || [ "$mode" = checkpoint ] || [ "$mode" = orphan ]; } && [ "$orphan" = "$old_work" ]; then private_dir "$orphan" || fail 4;continue;fi
    [ ! -e "$orphan" ] && [ ! -L "$orphan" ] || fail 4
done
if [ "$mode" = orphan ]; then
    ash "$dir/homegate-dns-orphan.sh" collect-orphan "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-orphan-collection","orphan_collected":true,"write_ready":false}\n'
    exit 0
fi
if [ "$mode" = checkpoint ]; then
    ash "$dir/homegate-dns-checkpoint-repair.sh" repair-checkpoint "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-checkpoint-repair","checkpoint_repaired":true,"write_ready":false}\n'
    exit 0
fi
if [ "$mode" = repair ]; then
    ash "$dir/homegate-dns-recovery.sh" repair-terminal "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-terminal-repair","terminal_repaired":true,"write_ready":false}\n'
    exit 0
fi
if [ "$mode" = retire ]; then
    ash "$dir/homegate-dns-retention.sh" retire "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-archive-retention","retired":true,"write_ready":false}\n'
    exit 0
fi
if [ "$mode" = collect ]; then
    ash "$dir/homegate-dns-recovery.sh" collect "$account" "$revision" "$old_job" >/dev/null 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-receipt-collection","archived":true,"write_ready":true}\n'
    exit 0
fi
if [ "$mode" = reconcile ] && [ "$persistent_reconcile" = false ]; then
    private_dir "$old_work" || fail
    for slot in request result zones state input context attempt; do private_file "$old_work/$slot" || fail; done
    [ "$(cat "$old_work/attempt" 2>/dev/null)" = HGCFATTEMPT1 ] || fail
    [ "$(stat -c '%s' "$old_work/attempt" 2>/dev/null)" = 13 ] || fail
fi
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 2>/dev/null) || fail
job=$$
work=/var/run/homegate/.dns-check-$job
mkdir "$work" 2>/dev/null || fail
(set -C; : > "$work/request" && : > "$work/result" && : > "$work/zones" && : > "$work/state") 2>/dev/null || fail
private_dir "$work" && private_file "$work/request" && private_file "$work/result" || fail
if [ "$mode" = records ] || [ "$mode" = reconcile ]; then
    (set -C; : > "$work/input" && : > "$work/context" && : > "$work/attempt") 2>/dev/null || fail
    # Original operation input has a separate inherited reader. The watchdog
    # bounds its consumption; the private snapshot remains on FD0.
    if [ "$mode" = records ]; then exec 4<&0 || fail
    elif [ "$persistent_reconcile" = true ]; then
        ash "$dir/homegate-dns-recovery.sh" load "$account" "$revision" "$old_job" 5>"$work/context" >/dev/null 2>/dev/null || fail
    else
        [ "$(stat -c '%s' "$old_work/context" 2>/dev/null)" -le 8388608 ] || fail
        cat "$old_work/context" > "$work/context" || fail
    fi
fi
result=0
# Only the private frame uses FD3; engine's public receipt goes to /dev/null.
# The independent consumer watchdog retains FD6/7, but not the configuration lock.
ash "$dir/homegate-config-prototype.sh" --persistent "$snapshot_command" 3>&1 8>&- 9>&- >/dev/null 2>/dev/null |
    setsid ash "$dir/homegate-service-observer-watchdog.sh" --cloudflare-check "$ticket" "$account" "$revision" "$job" "$mode" 3>"$work/result" 8>&- 9>&- >/dev/null 2>/dev/null || result=$?
exec 4>&-
if [ "$mode" = records ] && [ -s "$work/attempt" ]; then effect=unknown; fi
# The whole pipeline has ended. Unknown descendants retain the watchdog locks;
# the same-session watchdog must prove quiescence before returning success.
if [ "$result" -eq 0 ] || [ "$result" -eq 1 ]; then
    result_mode=result
    if [ "$mode" = records ] || [ "$mode" = reconcile ]; then exec 9<"$work/attempt" || fail; fi
    [ "$mode" != reconcile ] || result_mode=reconcile-result
    lua "$dir/$codec" "$result_mode" "$account" "$revision" "$result" < "$work/result" 2>/dev/null > "$work/zones" || result=7
    exec 9<&-
fi
# Persist the already canonical success receipt only after the supervised family
# is quiet. A settlement failure retains both durable and same-boot barriers.
if [ "$mode" = records ] && [ "$dns_receipt_enabled" = true ] && [ "$dns_settlement_enabled" = true ] && [ "$effect" = unknown ] && [ "$result" -eq 0 ]; then
    ash "$dir/homegate-dns-recovery.sh" settle "$account" "$revision" "$job" >/dev/null 2>/dev/null || result=7
fi
# Delete only this invocation's allocated slots, after the pipeline is quiet.
case "$result" in 0|1) exec 5<"$work/zones" || fail;; esac
if [ "$mode" = records ] && [ "$effect" = unknown ] && [ "$result" -ne 0 ]; then
    # Keep only this job's private same-boot evidence. DNS orphan guard blocks
    # another request until explicit reconciliation (not implemented/installed).
    case "$result" in 1) cat <&5 || fail; exec 5<&-; exit 1;; *) fail;; esac
fi
if [ "$mode" = records ] || [ "$mode" = reconcile ]; then rm -f "$work/input" "$work/context" "$work/attempt" 2>/dev/null || fail; fi
rm -f "$work/request" "$work/result" "$work/zones" "$work/state" 2>/dev/null && rmdir "$work" 2>/dev/null || fail
case "$result" in 0|1) cat <&5 || fail; exec 5<&-; exit "$result";; *) fail;; esac
