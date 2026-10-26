#!/bin/sh
# Fixed runtime file descriptor; no arbitrary PID/path or service operation.
set -u
umask 077
export LC_ALL=C
recovery_status_enabled=false
ddns_recovery_read_enabled=false
[ "$recovery_status_enabled" = true ] && { [ "$#" -eq 3 ] || { [ "$#" -eq 4 ] && [ "$ddns_recovery_read_enabled" = true ]; }; } || exit 2
revision=$1;job=$2;token=$3
ddns_proof=${4:-}
case "$revision:$job" in *[!0-9:]*) exit 2;; esac
[ "$revision" -ge 1 ] && [ "$revision" -le 32 ] && [ "${#job}" -le 9 ] && [ "$job" -ge 2 ] && [ -p /proc/self/fd/0 ] || exit 1
work=/var/run/homegate/.recovery-read-$job
[ -d "$work" ] && [ ! -L "$work" ] && [ "$(stat -c '%u:%a' "$work")" = 0:700 ] || exit 1
for name in result public; do
    [ -f "$work/$name" ] && [ ! -L "$work/$name" ] && [ "$(stat -c '%u:%a:%h' "$work/$name")" = 0:600:1 ] || exit 1
done
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$work/result")" ] || exit 1
runtime=/var/run/homegate/recovery.json
runtime_mode=invalid
exec 4<&- 5<&- 6>&- 7>&- 8>&- 9>&-
if [ ! -e "$runtime" ] && [ ! -L "$runtime" ]; then runtime_mode=absent
elif [ -f "$runtime" ] && [ ! -L "$runtime" ]; then
    case "$(stat -c '%u:%a:%h' "$runtime")" in 0:600:1|0:644:1)
        if [ "$(stat -c %s "$runtime")" -le 65536 ] && exec 4<"$runtime"; then
            runtime_identity=$(stat -Lc '%d:%i:%u:%a:%h:%s' /proc/self/fd/4) || exit 1
            [ "$runtime_identity" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$runtime")" ] || exit 1
            runtime_mode=present
        fi;;
    esac
fi
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
if [ -n "$ddns_proof" ]; then
    ddns_record=/var/run/homegate/ddns-recovery.json;ddns_mode=invalid
    if [ -e /var/run/homegate/.ddns-recovery-next ] || [ -L /var/run/homegate/.ddns-recovery-next ] ||
       [ -e /var/run/homegate/.ddns-recovery-pending ] || [ -L /var/run/homegate/.ddns-recovery-pending ]; then ddns_mode=pending
    elif [ ! -e "$ddns_record" ] && [ ! -L "$ddns_record" ]; then ddns_mode=absent
    elif [ -f "$ddns_record" ] && [ ! -L "$ddns_record" ] && [ "$(stat -c '%u:%a:%h' "$ddns_record")" = 0:600:1 ] && [ "$(stat -c %s "$ddns_record")" -le 8192 ]; then
        exec 5<"$ddns_record" || exit 1
        ddns_identity=$(stat -Lc '%d:%i:%u:%a:%h:%s' /proc/self/fd/5) || exit 1
        [ "$ddns_identity" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$ddns_record")" ] || exit 1
        ddns_mode=present
    fi
    lua "$dir/homegate-recovery.lua" run "$revision" "$runtime_mode" "$token" "$ddns_proof" "$ddns_mode" || exit 1
    if [ "$ddns_mode" = present ]; then
        [ -f "$ddns_record" ] && [ ! -L "$ddns_record" ] && [ "$ddns_identity" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$ddns_record")" ] || exit 1
    fi
else lua "$dir/homegate-recovery.lua" run "$revision" "$runtime_mode" "$token" || exit 1;fi
case "$runtime_mode" in
    absent) [ ! -e "$runtime" ] && [ ! -L "$runtime" ] || exit 1;;
    present) [ -f "$runtime" ] && [ ! -L "$runtime" ] &&
        [ "$runtime_identity" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$runtime")" ] || exit 1;;
esac
exit 0
