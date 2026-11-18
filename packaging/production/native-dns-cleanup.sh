#!/bin/sh
# Reset and live removal share the exact configured DDNS deletion scope.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-

base=/usr/libexec/homegate
dir=$base/project/core/prototype
run=/var/run/homegate
store=/etc/homegate/transactions
source=/etc/config/homegate
fail() { printf 'HomeGate DNS cleanup: %s\n' "$1" >&2; exit 7; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
rules() { lua "$base/native-cli.lua" ids ddns_rule < "$source"; }

[ "$(id -u)" = 0 ] && [ "${1:-}" = --confirm ] && [ "$#" -le 2 ] || fail arguments
private_file "$source" || fail local_configuration
selected=$(rules) || fail configured_ddns
[ -n "$selected" ] || exit 0

# Fully stopped also means the previous scheduler lease is no longer active.
ash "$base/native-service.sh" reap --confirm >/dev/null || fail service_quiescence
owner=$run/native-service.lock
if [ ! -e "$owner" ] && [ ! -L "$owner" ]; then
    (set -C; : > "$owner") || fail coordinator_lock
fi
for path in "$owner" "$run/frontend.lock" "$store/.supervisor.lock"; do
    private_file "$path" && [ ! -s "$path" ] || fail lock_file
done
exec 8<>"$owner" 6<>"$run/frontend.lock" 7<>"$store/.supervisor.lock"
for pair in "8:$owner" "6:$run/frontend.lock" "7:$store/.supervisor.lock"; do
    fd=${pair%%:*};path=${pair#*:}
    flock -n "$fd" &&
        [ "$(stat -Lc '%d:%i' "/proc/self/fd/$fd")" = "$(stat -c '%d:%i' "$path")" ] ||
        fail service_or_config_busy
done
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || fail revision
[ "$revision" = "${2:-$revision}" ] || fail revision_changed
selected=$(rules) || fail configured_ddns

# Check every account before deleting any record. Retried deletions can return
# unchanged for records that are already absent.
for rule in $selected; do
    ash "$dir/homegate-ddns-authority.sh" cleanup-check-rule "$rule" >/dev/null || fail "credentials:$rule"
done
for rule in $selected; do
    if ! ash "$dir/homegate-ddns-read.sh" --runtime-cleanup-delete "$rule" --confirm; then
        fail "record:$rule"
    fi
done
