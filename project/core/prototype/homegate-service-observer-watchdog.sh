#!/bin/sh
# A read-only observer session: a fixed five-second deadline survives caller loss.
set -u
umask 077
export LC_ALL=C
[ "$#" -eq 1 ] && [ "${#1}" -eq 32 ] || exit 1
case "$1" in *[!0-9a-f]*) exit 1;; esac
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
process="$dir/worker-process.lua"
info=$(lua "$process" info "$$" "$1" 2>/dev/null) || exit 1
old_ifs=$IFS; IFS=:; set -- $info; IFS=$old_ifs
[ "$#" -eq 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] && [ "$6" = 1 ] || exit 1
sleep 0.001 >/dev/null 2>&1 || exit 1
kill -0 "$$" >/dev/null 2>&1 || exit 1
# Missing executables/modules are unknown, never "disabled" or "stopped".
[ -f /etc/init.d/homegate ] && [ ! -L /etc/init.d/homegate ] && [ -x /etc/init.d/homegate ] &&
    [ -x /etc/rc.common ] && [ -x /sbin/ubus ] && [ "$(id -u)" = 0 ] || exit 1
stop_requested=false
trap 'stop_requested=true' TERM INT
now=$(lua "$process" now 2>/dev/null) || exit 1
deadline=$((now + 5))
stop_family() {
    # Signal only this still-running session leader's own process group.
    kill -TERM "-$$" 2>/dev/null || :
    sleep 1
    kill -KILL "-$$" 2>/dev/null
    exit 1
}
lua "$dir/homegate-service-observer.lua" 7>&- 8>&- 9>&- >/dev/null 2>&1 &
worker=$!
while :; do
    info=$(lua "$process" info "$worker" none 2>/dev/null) || stop_family
    case "$info" in ''|Z:*|X:*) break;; esac
    [ "$stop_requested" = false ] || stop_family
    now=$(lua "$process" now 2>/dev/null) || stop_family
    [ "$now" -lt "$deadline" ] || stop_family
    sleep 0.05 2>/dev/null || stop_family
done
[ "$stop_requested" = false ] || stop_family
result=0; wait "$worker" || result=$?
members=$(lua "$process" group "$$" "$$" 2>/dev/null) || stop_family
[ "$members" = 0 ] || stop_family
sleep 0.05 2>/dev/null || stop_family
members=$(lua "$process" group "$$" "$$" 2>/dev/null) || stop_family
[ "$members" = 0 ] || stop_family
exit "$result"
