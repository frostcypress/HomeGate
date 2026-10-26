#!/bin/sh
# Internal published-configuration validator, not the public health-check CLI.
set -u
umask 077
export LC_ALL=C
configuration_validation_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"configuration-validation","effect":"none","write_ready":false,"error":"Configuration validation refused"}\n';exit "${1:-7}"; }
[ "$#" -eq 0 ] && [ "$configuration_validation_enabled" = true ] || fail 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
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
state=$?;case "$state" in 0) ;; 4) fail 4;; *) fail;; esac
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || fail
snapshot() { ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null; }
validate() { snapshot | lua "$dir/homegate-configuration.lua" validate "$revision" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; }
# Pure bounded reads, no external commands in Lua and no private scratch files.
result=0;report=$(validate) || result=$?
case "$result" in 0|1) [ -n "$report" ] || fail;; *) fail;; esac
locks_match || fail 4
again_result=0;again=$(validate) || again_result=$?
[ "$again_result" -eq "$result" ] && [ "$again" = "$report" ] || fail
locks_match || fail 4
printf '%s\n' "$report"
exit "$result"
