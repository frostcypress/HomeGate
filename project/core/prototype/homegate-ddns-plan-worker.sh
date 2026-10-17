#!/bin/sh
# Fixed worker: read-only preflight, no provider calls or persistent publication.
set -u
umask 077
export LC_ALL=C
ddns_plan_enabled=false
[ "$ddns_plan_enabled" = true ] && [ "$#" -eq 3 ] || exit 2
revision=$1;job=$2;rule=$3
case "$revision:$job" in *[!0-9:]*) exit 2;; esac
[ "$revision" -ge 1 ] && [ "$revision" -le 32 ] && [ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || exit 2
case "$rule" in *[!a-zA-Z0-9_-]*) exit 2;; esac
[ "${#rule}" -le 64 ] && [ -p /proc/self/fd/0 ] || exit 1
work=/var/run/homegate/.ddns-plan-$job
[ -d "$work" ] && [ ! -L "$work" ] && [ "$(stat -c '%u:%a' "$work")" = 0:700 ] || exit 1
for name in result public plan intent; do
    [ -f "$work/$name" ] && [ ! -L "$work/$name" ] && [ "$(stat -c '%u:%a:%h' "$work/$name")" = 0:600:1 ] || exit 1
done
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$work/result")" ] || exit 1
exec 4>>"$work/plan" 5<"$work/intent" 6>&- 7>&- 8>&- 9>&- || exit 1
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
exec lua "$dir/homegate-ddns-plan.lua" run "$revision" "$rule"
