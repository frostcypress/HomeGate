#!/bin/sh
# Candidate status/check: locked configuration plus bounded fixed runtime probe.
set -u
umask 077
export LC_ALL=C
health_status_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"common-runtime","effect":"none","write_ready":false,"error":"Health diagnostic refused"}\n';exit "${1:-7}"; }
[ "$#" -eq 1 ] && [ "$health_status_enabled" = true ] || fail 2
action=$1;case "$action" in status|check) ;; *) fail 2;; esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE HOMEGATE_RUNTIME_STATE HOMEGATE_HOME_DIR
exec 2>/dev/null
[ "$(id -u)" = 0 ] || fail
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
run=/var/run/homegate;store=/etc/homegate/transactions
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
private_dir "$run" && private_dir "$store" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock" || fail
flock -n 6 && flock -n 7 || fail 4
locks_match() {
    for fd in 6 7; do
        lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
        [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] || return 1
    done
}
locks_match || fail 4
ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null
state=$?;[ "$state" != 4 ] || fail 4
for old in "$run/".health-read-*; do [ ! -e "$old" ] && [ ! -L "$old" ] || fail 4;done
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || fail
snapshot() { ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null; }
configuration() { snapshot | lua "$dir/homegate-health.lua" configuration "$revision" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; }
context=$(configuration) || fail
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
job=$$;work=$run/.health-read-$job
mkdir "$work" || fail
(set -C; : > "$work/result" && : > "$work/public") || fail
private_dir "$work" && private_file "$work/result" && private_file "$work/public" || fail
snapshot | setsid ash "$dir/homegate-service-observer-watchdog.sh" --health-status "$ticket" "$revision" "$job" 3>"$work/result" 8>&- 9>&- >/dev/null 2>/dev/null || fail
locks_match || fail 4
[ "$(configuration)" = "$context" ] || fail
result=0
lua "$dir/homegate-health.lua" result "$revision" "$action" "$context" < "$work/result" > "$work/public" || result=$?
case "$result" in 0|1) ;; *) fail;; esac
private_file "$work/public" && [ -s "$work/public" ] && [ "$(stat -c %s "$work/public")" -le 8192 ] || fail
# Check the bytes actually stored, including a partial/failed final write.
verified=0
lua "$dir/homegate-health.lua" result "$revision" "$action" "$context" < "$work/public" >/dev/null || verified=$?
[ "$verified" -eq "$result" ] || fail
exec 5<"$work/public" || fail
rm -f "$work/result" "$work/public" && rmdir "$work" || fail
cat <&5;exec 5<&-
exit "$result"
