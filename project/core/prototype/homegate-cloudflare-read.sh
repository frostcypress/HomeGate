#!/bin/sh
# Fixed read-only business coordinator. Not installed; no DNS record mutation.
set -u
umask 077
export LC_ALL=C
dns_read_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"dns-provider","error":"Cloudflare reader is unavailable"}\n'; exit "${1:-7}"; }
[ "$dns_read_enabled" = true ] || fail 2
[ "$#" -eq 1 ] || { [ "$#" -eq 2 ] && [ "$2" = --zones ]; } || fail 2
account=$1
mode=check; codec=cloudflare-codec.lua
if [ "$#" -eq 2 ]; then mode=zones; codec=cloudflare-zones.lua; fi
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
ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>&1
state=$?; case "$state" in 0) ;; 4) fail 4;; *) fail;; esac
revision=$(lua "$dir/cloudflare-codec.lua" context < /etc/homegate/transactions/current 2>/dev/null) || fail
# Never silently collect an orphan request or unlink possibly live files.
for orphan in /var/run/homegate/.dns-check-*; do
    [ ! -e "$orphan" ] && [ ! -L "$orphan" ] || fail 4
done
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 2>/dev/null) || fail
job=$$
work=/var/run/homegate/.dns-check-$job
mkdir "$work" 2>/dev/null || fail
(set -C; : > "$work/request" && : > "$work/result" && : > "$work/zones" && : > "$work/state") 2>/dev/null || fail
private_dir "$work" && private_file "$work/request" && private_file "$work/result" || fail
result=0
# Only the private frame uses FD3; engine's public receipt goes to /dev/null.
# The independent consumer watchdog retains FD6/7, but not the configuration lock.
ash "$dir/homegate-config-prototype.sh" --persistent snapshot-read 3>&1 8>&- 9>&- >/dev/null 2>/dev/null |
    setsid ash "$dir/homegate-service-observer-watchdog.sh" --cloudflare-check "$ticket" "$account" "$revision" "$job" "$mode" 3>"$work/result" 8>&- 9>&- >/dev/null 2>/dev/null || result=$?
# The whole pipeline has ended. Unknown descendants retain the watchdog locks;
# the same-session watchdog must prove quiescence before returning success.
if [ "$result" -eq 0 ] || [ "$result" -eq 1 ]; then
    lua "$dir/$codec" result "$account" "$revision" "$result" < "$work/result" 2>/dev/null > "$work/zones" || result=7
fi
# Delete only this invocation's allocated slots, after the pipeline is quiet.
case "$result" in 0|1) exec 5<"$work/zones" || fail;; esac
rm -f "$work/request" "$work/result" "$work/zones" "$work/state" 2>/dev/null && rmdir "$work" 2>/dev/null || fail
case "$result" in 0|1) cat <&5 || fail; exec 5<&-; exit "$result";; *) fail;; esac
