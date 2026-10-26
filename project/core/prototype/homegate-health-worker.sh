#!/bin/sh
# Fixed runtime file descriptor; no arbitrary PID/path or service operation.
set -u
umask 077
export LC_ALL=C
health_status_enabled=false
[ "$health_status_enabled" = true ] && [ "$#" -eq 2 ] || exit 2
revision=$1;job=$2
case "$revision:$job" in *[!0-9:]*) exit 2;; esac
[ "$revision" -ge 1 ] && [ "$revision" -le 32 ] && [ "${#job}" -le 9 ] && [ "$job" -ge 2 ] && [ -p /proc/self/fd/0 ] || exit 1
work=/var/run/homegate/.health-read-$job
[ -d "$work" ] && [ ! -L "$work" ] && [ "$(stat -c '%u:%a' "$work")" = 0:700 ] || exit 1
for name in result public; do
    [ -f "$work/$name" ] && [ ! -L "$work/$name" ] && [ "$(stat -c '%u:%a:%h' "$work/$name")" = 0:600:1 ] || exit 1
done
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$work/result")" ] || exit 1
runtime=/var/run/homegate/runtime.json
runtime_mode=invalid
exec 4<&- 5<&- 6>&- 7>&- 8>&- 9>&-
if [ ! -e "$runtime" ] && [ ! -L "$runtime" ]; then runtime_mode=absent
elif [ -f "$runtime" ] && [ ! -L "$runtime" ]; then
    case "$(stat -c '%u:%a:%h' "$runtime")" in 0:600:1|0:644:1)
        if [ "$(stat -c %s "$runtime")" -le 4096 ] && exec 4<"$runtime"; then
            runtime_identity=$(stat -Lc '%d:%i:%u:%a:%h:%s' /proc/self/fd/4) || exit 1
            [ "$runtime_identity" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$runtime")" ] || exit 1
            runtime_mode=present
        fi;;
    esac
fi
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
lua "$dir/homegate-health.lua" run "$revision" "$runtime_mode" || exit 1
case "$runtime_mode" in
    absent) [ ! -e "$runtime" ] && [ ! -L "$runtime" ] || exit 1;;
    present) [ -f "$runtime" ] && [ ! -L "$runtime" ] &&
        [ "$runtime_identity" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$runtime")" ] || exit 1;;
esac
exit 0
