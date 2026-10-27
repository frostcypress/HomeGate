#!/bin/sh
# One explicit finite session; no respawn, PID signalling or implicit reaping.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 2>/dev/null
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-schedule","effect":"none","write_ready":false,"error":"Schedule control unavailable; inspect retained state"}\n';exit "${1:-7}"; }
[ "$(id -u)" = 0 ] && [ "$#" -ge 1 ] || fail 2
base=/usr/libexec/homegate-engineering/project/core/prototype
case "$1" in
 status|quiescent) [ "$#" -eq 1 ] || fail 2;exec ash "$base/homegate-ddns-schedule.sh" "$1";;
 stop|reap) [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;exec ash "$base/homegate-ddns-schedule.sh" "$@";;
 event) [ "$#" -eq 4 ] || fail 2;exec ash "$base/homegate-ddns-schedule.sh" "$@";;
 start) [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
 *) fail 2;;
esac
run=/var/run/homegate-engineering
[ -d "$run" ] && [ ! -L "$run" ] && [ "$(stat -c '%u:%a' "$run")" = 0:700 ] || fail
lock=$run/ddns-launch.lock
if [ ! -e "$lock" ] && [ ! -L "$lock" ];then (set -C; : > "$lock") || fail;fi
[ -f "$lock" ] && [ ! -L "$lock" ] && [ "$(stat -c '%u:%a:%h:%s' "$lock")" = 0:600:1:0 ] || fail
exec 5>>"$lock" || fail
flock -n 5 && [ "$(stat -Lc '%d:%i' /proc/self/fd/5)" = "$(stat -c '%d:%i' "$lock")" ] || fail 4
[ ! -e "$run/ddns-schedule" ] && [ ! -L "$run/ddns-schedule" ] || fail 4
ash "$base/homegate-ddns-schedule.sh" quiescent >/dev/null || fail 4
# Child performs the original authorization/generation/lock binding and owns
# the retained lease. Its stdout is disconnected from HTTP before admission.
setsid ash "$base/homegate-ddns-schedule.sh" run --confirm 5>&- </dev/null >/dev/null 2>&1 &
attempt=0
while [ "$attempt" -lt 70 ];do
    if [ -f "$run/ddns-schedule/report" ];then
        result=$(ash "$base/homegate-ddns-schedule.sh" status) || fail
        printf '%s\n' "$result";exit 0
    fi
    attempt=$((attempt+1));sleep 0.1 || fail
done
fail
