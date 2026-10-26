#!/bin/sh
# Fixed recovery observation only. Never retries, cleans or removes old evidence.
set -u
umask 077
export LC_ALL=C
recovery_status_enabled=false
ddns_recovery_read_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"recovery","effect":"none","write_ready":false,"error":"Recovery diagnostic refused"}\n';exit "${1:-7}"; }
[ "$#" -eq 0 ] && [ "$recovery_status_enabled" = true ] || fail 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE HOMEGATE_RECOVERY_STATUS HOMEGATE_RUNTIME_STATE HOMEGATE_HOME_DIR
exec 2>/dev/null
[ "$(id -u)" = 0 ] || fail
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
run=/var/run/homegate;store=/etc/homegate/transactions
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir "$run" && private_dir "$store" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" && private_file "$store/.lock" || fail
exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock" || fail
flock -n 6 && flock -n 7 || fail 4
locks_match() {
    for fd in 6 7; do
        lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
        [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] || return 1
    done
}
locks_match || fail 4
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || fail
private_file "$store/identity" && [ "$(stat -c %s "$store/identity")" -le 512 ] && private_dir "$store/gen-$revision" && private_file "$store/gen-$revision/manifest" && [ "$(stat -c %s "$store/gen-$revision/manifest")" -le 65536 ] || fail
job=$$;work=$run/.recovery-read-$job
binding() {
    idsum=$(sha256sum "$store/identity") || return 1;idsum=${idsum%% *}
    gensum=$(sha256sum "$store/gen-$revision/manifest") || return 1;gensum=${gensum%% *}
    state=0;ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || state=$?
    case "$state" in 0) writer=clear;; 4) writer=pending;; *) writer=unavailable;; esac
    orphan=0;count=0
    for p in "$run/".dns-check-* "$run/".ddns-plan-* "$run/".network-read-* "$run/".health-read-* "$run/".recovery-read-* "$run/ddns-schedule" "$run/.ddns-recovery-next" "$run/.ddns-recovery-pending"; do
        [ "$p" != "$work" ] || continue
        exists "$p" || continue
        orphan=1;count=$((count+1));[ "$count" -le 256 ] || { writer=unavailable;break; }
    done
    if exists "$run/ddns-state"; then
        if private_dir "$run/ddns-state"; then
            for p in "$run/ddns-state/".*.next "$run/ddns-state/".*.result; do exists "$p" && orphan=1;done
        else orphan=1;fi
    fi
    printf '%s:%s:%s:%s\n' "$idsum" "$gensum" "$writer" "$orphan"
}
snapshot() { ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null; }
token=$(binding) || fail
ddns_proof=
ddns_inspect() { ash "$dir/homegate-ddns-recovery.sh" inspect-internal 3>&- 4>&- 5>&- 8>&- 9>&- 2>/dev/null || printf 'unavailable\n'; }
if [ "$ddns_recovery_read_enabled" = true ]; then ddns_proof=$(ddns_inspect);fi
context=$(snapshot | lua "$dir/homegate-recovery.lua" context "$revision" "$token" ${ddns_proof:+"$ddns_proof"} 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-) || fail
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
mkdir "$work" || fail
(set -C; : > "$work/result" && : > "$work/public") || fail
private_dir "$work" && private_file "$work/result" && private_file "$work/public" || fail
snapshot | setsid ash "$dir/homegate-service-observer-watchdog.sh" --recovery-status "$ticket" "$revision" "$job" "$token" ${ddns_proof:+"$ddns_proof"} 3>"$work/result" 8>&- 9>&- >/dev/null 2>/dev/null || fail
locks_match || fail 4
[ "$(binding)" = "$token" ] || fail
if [ "$ddns_recovery_read_enabled" = true ]; then [ "$(ddns_inspect)" = "$ddns_proof" ] || fail;fi
[ "$(snapshot | lua "$dir/homegate-recovery.lua" context "$revision" "$token" ${ddns_proof:+"$ddns_proof"} 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-)" = "$context" ] || fail
lua "$dir/homegate-recovery.lua" result "$revision" "$context" < "$work/result" > "$work/public" || fail
private_file "$work/public" && [ -s "$work/public" ] && [ "$(stat -c %s "$work/public")" -le 8192 ] || fail
lua "$dir/homegate-recovery.lua" result "$revision" "$context" < "$work/public" >/dev/null || fail
exec 5<"$work/public" || fail
rm -f "$work/result" "$work/public" && rmdir "$work" || fail
cat <&5;exec 5<&-
exit 0
