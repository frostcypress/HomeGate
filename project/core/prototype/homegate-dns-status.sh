#!/bin/sh
# Source-bound account validation using the existing read-only provider family.
set -u
umask 077
export LC_ALL=C
dns_status_cli_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","effect":"none","write_ready":false,"error":"DNS status request refused"}\n';exit "${1:-7}"; }
[ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && [ "$2" = --zones ]; } || fail 2
zones=false;error_mode=error;result_mode=result
if [ "$#" -eq 2 ]; then zones=true;error_mode=zones-error;result_mode=zones-result;fi
account=$1
case "$account" in ''|*[!a-zA-Z0-9_-]*) fail 2;; esac
[ "${#account}" -le 64 ] || fail 2
[ "$dns_status_cli_enabled" = true ] || fail 2
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
lua "$dir/homegate-dns-status.lua" identity "$revision" "$account" >/dev/null || fail
select_provider() {
    ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-dns-status.lua" select "$revision" "$account" 3>&- 4>&- 5>&- 8>&- 9>&-
}
provider=$(select_provider) || fail
case "$provider" in
    not_found|unsupported) lua "$dir/homegate-dns-status.lua" "$error_mode" "$revision" "$account" "$provider" || fail;exit 1;;
    cloudflare|aliyun|dnspod|huaweicloud) ;;
    *) fail;;
esac
# Keep FD6/7 throughout selection, the supervised request and final source check.
# The fixed coordinator validates its inherited locks and the same private source.
if [ "$zones" = true ]; then
    raw=$(ash "$dir/homegate-cloudflare-read.sh" --runtime-zones-internal "$provider" "$account")
else
    raw=$(ash "$dir/homegate-cloudflare-read.sh" --runtime-check-internal "$provider" "$account")
fi
state=$?;case "$state" in 0|1) ;; 4) fail 4;; *) fail;; esac
locks_match || fail 4
[ "$(select_provider)" = "$provider" ] || fail
report=$(printf '%s\n' "$raw" | lua "$dir/homegate-dns-status.lua" "$result_mode" "$revision" "$account" "$provider" "$state" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-) || fail
printf '%s\n' "$report"
exit "$state"
