#!/bin/sh
# Fixed native writer adapter, intentionally not installed or production-enabled.
set -u
umask 077
export LC_ALL=C
native_dispatch_enabled=false
fail() {
    printf '{"api_version":1,"ok":false,"error":"Native writer request refused"}\n'
    exit "${1:-2}"
}
[ "$native_dispatch_enabled" = true ] || fail
[ "$#" -eq 1 ] || fail
owner=$(id -u) || fail
[ "$owner" = 0 ] || fail
case "$1" in /tmp/homegate-luci-*/request) ;; *) fail;; esac
request=$1
request_dir=${request%/request}
id=${request_dir#/tmp/homegate-luci-}
[ "${#id}" -eq 32 ] || fail
case "$id" in *[!0-9a-f]*) fail;; esac
[ -d /tmp ] && [ ! -L /tmp ] || fail
[ -d "$request_dir" ] && [ ! -L "$request_dir" ] &&
    [ "$(stat -c '%u:%a' "$request_dir" 2>/dev/null)" = "$owner:700" ] || fail
[ -f "$request" ] && [ ! -L "$request" ] &&
    [ "$(stat -c '%u:%a:%h' "$request" 2>/dev/null)" = "$owner:600:1" ] || fail
size=$(stat -c %s "$request" 2>/dev/null) || fail
case "$size" in ''|*[!0-9]*) fail;; esac
[ "$size" -gt 0 ] && [ "$size" -le 2097152 ] || fail
# The existing lock must already have been initialized by the migration owner.
# Never chmod, unlink or replace a possibly live lock from a web request.
lock_dir=/var/run/homegate
lock=$lock_dir/frontend.lock
[ -d "$lock_dir" ] && [ ! -L "$lock_dir" ] &&
    [ "$(stat -c '%u:%a' "$lock_dir" 2>/dev/null)" = "$owner:700" ] || fail 7
[ -f "$lock" ] && [ ! -L "$lock" ] &&
    [ "$(stat -c '%u:%a:%h' "$lock" 2>/dev/null)" = "$owner:600:1" ] || fail 7
exec 6>>"$lock" || fail 7
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/6)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] || fail 7
flock -n 6 || fail 4
# Configuration cursors and controller code are loaded only after this point.
# Keep the inherited lock in the Lua owner; its synchronous core calls close 6.
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
exec /usr/bin/lua /usr/libexec/homegate/frontend-write.lua "$request"
