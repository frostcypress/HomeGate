#!/bin/sh
# Fixed source-bound network diagnostic; no service control or provider access.
set -u
umask 077
export LC_ALL=C
network_resolve_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"network-resolver","effect":"none","write_ready":false,"error":"Network diagnostic refused"}\n';exit "${1:-7}"; }
[ "$#" -eq 0 ] && [ "$network_resolve_enabled" = true ] || fail 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE HOMEGATE_SYS_CLASS_NET
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
for old in "$run/".network-read-*; do [ ! -e "$old" ] && [ ! -L "$old" ] || fail 4;done
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || fail
lua "$dir/homegate-network.lua" identity "$revision" >/dev/null || fail
snapshot() { ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null; }
bridge=$(snapshot | lua "$dir/homegate-network.lua" bridge "$revision" 3>&- 4>&- 5>&- 8>&- 9>&-) || fail
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
job=$$;work=$run/.network-read-$job
mkdir "$work" || fail
(set -C; : > "$work/result" && : > "$work/public" && : > "$work/lan") || fail
private_dir "$work" && private_file "$work/result" && private_file "$work/public" && private_file "$work/lan" || fail
result=0
snapshot | setsid ash "$dir/homegate-service-observer-watchdog.sh" --network-resolve "$ticket" "$revision" "$job" "$bridge" 3>"$work/result" 8>&- 9>&- >/dev/null 2>/dev/null || result=$?
[ "$result" -eq 0 ] || fail
locks_match || fail 4
[ "$(snapshot | lua "$dir/homegate-network.lua" source "$revision" "$bridge" 3>&- 4>&- 5>&- 8>&- 9>&-)" = HGNETWORKSOURCE1 ] || fail
lua "$dir/homegate-network.lua" result "$revision" "$bridge" "$result" < "$work/result" > "$work/public" || fail
exec 5<"$work/public" || fail
rm -f "$work/result" "$work/public" "$work/lan" && rmdir "$work" || fail
cat <&5;exec 5<&-
exit 0
