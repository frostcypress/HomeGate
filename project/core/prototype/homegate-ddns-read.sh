#!/bin/sh
# Fixed private DDNS preflight entry. Rule selection only; no caller address/URL.
set -u
umask 077
export LC_ALL=C
ddns_plan_enabled=false
ddns_sync_enabled=false
ddns_work_enabled=false
ddns_runtime_enabled=false
ddns_batch_enabled=false
if [ "${1:-}" = --collect-work ]; then
    [ "$ddns_work_enabled" = true ] && [ "$#" -eq 3 ] && [ "$3" = --confirm ] || exit 2
    dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
    exec ash "$dir/homegate-ddns-work.sh" collect "$2" --confirm
fi
runtime=false;batch=false
if [ "${1:-}" = --runtime-batch-internal ]; then
    [ "$ddns_batch_enabled" = true ] && [ "$#" -eq 4 ] && [ "$4" = --confirm ] || exit 2
    batch=true;batch_parent=$3
    case "$batch_parent" in ''|0*|*[!0-9]*) exit 2;; esac
    [ "${#batch_parent}" -le 9 ] && [ "$batch_parent" -ge 2 ] || exit 2
    set -- --runtime-sync "$2" --confirm
fi
if [ "${1:-}" = --runtime ] || [ "${1:-}" = --runtime-sync ]; then
    [ "$ddns_runtime_enabled" = true ] || exit 2
    runtime=true
    if [ "$1" = --runtime-sync ]; then shift;set -- --sync "$@";else shift;fi
fi
sync=false;effect=none
fail() { phase=ddns-plan;[ "$sync" != true ] || phase=ddns-sync;required=false;[ "$effect" != unknown ] || required=true;printf '{"api_version":1,"prototype":true,"ok":false,"phase":"%s","effect":"%s","reconciliation_required":%s,"error":"DDNS operation is unavailable"}\n' "$phase" "$effect" "$required";exit "${1:-7}"; }
if [ "${1:-}" = --sync ]; then
    sync=true
    [ "$ddns_sync_enabled" = true ] && [ "$ddns_work_enabled" = true ] && [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2
    set -- "$2"
fi
[ "$ddns_plan_enabled" = true ] && [ "$#" -le 1 ] || fail 2
[ "$runtime" != true ] || [ "$#" -eq 1 ] || fail 2
rule=${1:-}
if [ "$#" -eq 1 ]; then case "$rule" in ''|*[!a-zA-Z0-9_-]*) fail 2;; esac;[ "${#rule}" -le 64 ] || fail 2;fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
[ "$(id -u)" = 0 ] || fail
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
run=/var/run/homegate;store=/etc/homegate/transactions
private_dir "$run" && private_dir "$store" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
for fd in 6 7; do
    lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
    if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ]; then
        case "$fd" in 6) exec 6>>"$lock" || fail;; 7) exec 7>>"$lock" || fail;; esac
    fi
    flock -n "$fd" || fail 4
done
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
if [ "$batch" = true ]; then
    [ -f /proc/self/fd/5 ] && [ "$(stat -Lc '%u:%a:%h' /proc/self/fd/5)" = 0:600:0 ] && [ "$(stat -Lc %s /proc/self/fd/5)" -le 524288 ] || fail
    [ "$(stat -Lc '%d:%i' /proc/self/fd/5)" = "$(stat -Lc '%d:%i' /proc/$batch_parent/fd/5 2>/dev/null)" ] || fail
    batch_context=$(lua "$dir/homegate-ddns-batch.lua" parent read "$$" "$rule" "$batch_parent" 2>/dev/null) || fail
fi
ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null
state=$?;case "$state" in 0) ;; 4) fail 4;; *) fail;; esac
for orphan in "$run/".dns-check-* "$run/".ddns-plan-*; do [ ! -e "$orphan" ] && [ ! -L "$orphan" ] || fail 4;done
if [ "$runtime" = true ]; then ash "$dir/homegate-ddns-authority.sh" check-rule "$rule" >/dev/null 2>/dev/null || fail;fi
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null) || fail
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 2>/dev/null) || fail
job=$$;work=$run/.ddns-plan-$job
mkdir "$work" 2>/dev/null || fail
(set -C; : > "$work/result" && : > "$work/public" && : > "$work/plan" && : > "$work/intent") 2>/dev/null || fail
private_dir "$work" && private_file "$work/result" && private_file "$work/public" && private_file "$work/plan" && private_file "$work/intent" || fail
if [ "$sync" = true ]; then
    (set -C; : > "$work/input" && : > "$work/provider") 2>/dev/null || fail
    private_file "$work/input" && private_file "$work/provider" || fail
fi
snapshot() {
    if [ "$runtime" = true ]; then ash "$dir/homegate-ddns-authority.sh" snapshot-rule "$rule";else ash "$dir/homegate-config-prototype.sh" --persistent ddns-plan-snapshot-read;fi
}
result=0
if [ "$batch" = true ]; then
    identity=$(sha256sum "$store/identity") || fail;identity=${identity%% *}
    generation=$(sha256sum "$store/gen-$revision/manifest") || fail;generation=${generation%% *}
    grant=$(sha256sum "$store/ddns-authority") || fail;grant=${grant%% *};boot=$(cat /proc/sys/kernel/random/boot_id) || fail
    snapshot 3>&1 4>"$work/intent" 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-batch.lua" slice "$revision" "$rule" "$identity" "$generation" "$grant" "$boot" "$batch_context" 3>"$work/result" 4>"$work/plan" 8<"$work/intent" 9>&- 2>/dev/null || result=$?
    exec 5<&-
else
snapshot 3>&1 4>"$work/intent" 8>&- 9>&- >/dev/null 2>/dev/null |
    setsid ash "$dir/homegate-service-observer-watchdog.sh" --ddns-plan "$ticket" "$revision" "$job" "$rule" 3>"$work/result" 8>&- 9>&- >/dev/null 2>/dev/null || result=$?
fi
case "$result" in 0|1)
    lua "$dir/homegate-ddns-plan.lua" result "$revision" "$rule" "$result" < "$work/result" > "$work/public" 2>/dev/null || fail
    if [ "$sync" = true ] && [ "$result" = 0 ]; then
        # Regenerate source proof and intent under the same retained locks.
        target=$(snapshot 3>&1 4>"$work/intent" 8>&- 9>&- >/dev/null 2>/dev/null |
            lua "$dir/homegate-ddns-sync.lua" dispatch "$revision" "$rule" 4>"$work/input" 5<"$work/plan" 8<"$work/intent" 9<"$work/result" 2>/dev/null) || fail
        if [ "$target" != disabled ]; then
        provider=${target%%:*};account=${target#*:}
        case "$provider" in cloudflare|aliyun|dnspod|huaweicloud) ;; *) fail;; esac
        case "$account" in ''|*[!a-zA-Z0-9_-]*) fail;; esac
        [ "${#account}" -le 64 ] || fail
        bind=bind;dispatch=--ddns-sync-internal
        if [ "$runtime" = true ]; then bind=bind-runtime;dispatch=--ddns-runtime-sync-internal;fi
        ash "$dir/homegate-ddns-work.sh" "$bind" "$job" "$revision" "$rule" "$provider" "$account" >/dev/null 2>/dev/null || fail
        effect=unknown;result=0
        cat < "$work/input" 5>&- 6>&- 7>&- 8>&- 9>&- |
            ash "$dir/homegate-cloudflare-read.sh" "$dispatch" "$provider" "$account" --records "$job" > "$work/provider" 8>&- 9>&- 2>/dev/null || result=$?
        case "$result" in
            0|1)
                if private_file "$store/dns-operation/terminal"; then exec 9<"$store/dns-operation/terminal" || fail;else exec 9</dev/null;fi
                lua "$dir/homegate-ddns-sync.lua" result "$revision" "$rule" "$provider" "$account" "$result" < "$work/provider" > "$work/public" 2>/dev/null || fail
                exec 9<&-;;
            2|4) effect=none;fail "$result";;
            *) fail;;
        esac
        # Provider canonical failures after an attempt must retain the outer fence.
        if [ "$result" != 0 ] && { [ -e "$store/dns-operation" ] || [ -L "$store/dns-operation" ]; }; then cat "$work/public";exit "$result";fi
        fi
    fi
    exec 5<"$work/public" || fail
    if [ "$sync" = true ]; then rm -f "$work/input" "$work/provider" "$work/binding" || fail;fi
    rm -f "$work/result" "$work/public" "$work/plan" "$work/intent" && rmdir "$work" || fail
    cat <&5;exec 5<&-;exit "$result";;
    *) fail;;
esac
