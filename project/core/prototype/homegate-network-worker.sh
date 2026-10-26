#!/bin/sh
# Read-only network/sysfs worker inside the existing supervised session.
set -u
umask 077
export LC_ALL=C
network_resolve_enabled=false
[ "$network_resolve_enabled" = true ] && [ "$#" -eq 3 ] || exit 2
revision=$1;job=$2;bridge=$3
case "$revision:$job" in *[!0-9:]*) exit 2;; esac
[ "$revision" -ge 1 ] && [ "$revision" -le 32 ] && [ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || exit 2
case "$bridge" in ''|.|..|*[!a-zA-Z0-9_.:-]*) exit 2;; esac
[ "${#bridge}" -le 32 ] && [ -p /proc/self/fd/0 ] || exit 1
work=/var/run/homegate/.network-read-$job
[ -d "$work" ] && [ ! -L "$work" ] && [ "$(stat -c '%u:%a' "$work")" = 0:700 ] || exit 1
for name in result public lan; do
    [ -f "$work/$name" ] && [ ! -L "$work/$name" ] && [ "$(stat -c '%u:%a:%h' "$work/$name")" = 0:600:1 ] || exit 1
done
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$work/result")" ] || exit 1
sys_root=/sys/class/net
capture_lan() {
    [ -d "$sys_root/$bridge" ] && [ -x "$sys_root/$bridge" ] || return 1
    printf 'HGLAN1\nok\n'
    if [ -e "$sys_root/$bridge/brif" ] || [ -L "$sys_root/$bridge/brif" ]; then
        [ -d "$sys_root/$bridge/brif" ] && [ -r "$sys_root/$bridge/brif" ] && [ -x "$sys_root/$bridge/brif" ] || return 1
        count=0
        for path in "$sys_root/$bridge/brif/"* "$sys_root/$bridge/brif/".[!.]* "$sys_root/$bridge/brif/"..?*; do
            [ -e "$path" ] || [ -L "$path" ] || continue
            name=${path##*/}
            case "$name" in ''|.|..|*[!a-zA-Z0-9_.:-]*) return 1;; esac
            [ "${#name}" -le 32 ] || return 1
            count=$((count + 1));[ "$count" -le 1024 ] || return 1
            printf '%s\n' "$name"
        done
    fi
    printf 'END\n'
}
capture_lan > "$work/lan" || printf 'HGLAN1\nunavailable\nEND\n' > "$work/lan" || exit 1
exec 4<"$work/lan" 5<&- 6>&- 7>&- 8>&- 9>&- || exit 1
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
exec lua "$dir/homegate-network.lua" run "$revision" "$bridge"
