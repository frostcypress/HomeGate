#!/bin/sh
# Explicit metadata closeout only; no DNS operation, cache reset or retry.
set -u
umask 077
export LC_ALL=C
ddns_recovery_read_enabled=false
ddns_recovery_repair_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-summary-repair","effect":"none","write_ready":false,"business_recovered":false,"error":"Summary request refused"}\n';exit "${1:-7}"; }
action=${1:-}
case "$action" in
    check) [ "$#" -eq 1 ] && [ "$ddns_recovery_read_enabled" = true ] || fail 2;;
    finish) [ "$#" -eq 3 ] && [ "$3" = --confirm ] && [ "$ddns_recovery_repair_enabled" = true ] || fail 2
        case "$2" in ''|*[!0-9a-f]*) fail 2;; esac;[ "${#2}" -eq 64 ] || fail 2;;
    *) fail 2;;
esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 2>/dev/null 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
[ "$(id -u)" = 0 ] || fail
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
run=/var/run/homegate;store=/etc/homegate/transactions
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
private_dir "$run" && private_dir "$store" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock" || fail
flock -n 6 && flock -n 7 || fail 4
if [ "$action" = check ]; then
    result=$(ash "$dir/homegate-ddns-recovery.sh" repair-check-internal) || fail "$?"
else
    result=$(ash "$dir/homegate-ddns-recovery.sh" repair-finish-internal "$2" --confirm) || fail "$?"
fi
printf '%s\n' "$result"
