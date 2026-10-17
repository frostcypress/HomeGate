#!/bin/sh
# Only the fixed watchdog invokes this reader with inherited private pipes.
set -u
umask 077
export LC_ALL=C
huaweicloud_read_enabled=false
huaweicloud_records_enabled=false
huaweicloud_reconcile_enabled=false
huaweicloud_receipt_enabled=false
[ "$huaweicloud_read_enabled" = true ] && [ "$#" -eq 4 ] || exit 2
account=$1;revision=$2;job=$3;mode=$4
case "$account" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
[ "${#account}" -le 64 ] || exit 2
case "$revision:$job" in *[!0-9:]*) exit 2;; esac
[ "$revision" -ge 1 ] && [ "$revision" -le 32 ] && [ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || exit 2
case "$mode" in check|zones) ;; records) [ "$huaweicloud_records_enabled" = true ] || exit 2;; reconcile) [ "$huaweicloud_records_enabled" = true ] && [ "$huaweicloud_reconcile_enabled" = true ] || exit 2;; *) exit 2;; esac
[ -p /proc/self/fd/0 ] || exit 1
work=/var/run/homegate/.dns-check-$job
[ -d "$work" ] && [ ! -L "$work" ] && [ "$(stat -c '%u:%a' "$work")" = 0:700 ] || exit 1
for slot in request result zones state sign-input sign-output; do
    [ -f "$work/$slot" ] && [ ! -L "$work/$slot" ] && [ "$(stat -c '%u:%a:%h' "$work/$slot")" = 0:600:1 ] || exit 1
done
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$work/result")" ] || exit 1
for tool in /usr/bin/curl /usr/bin/openssl; do
    [ -f "$tool" ] && [ ! -L "$tool" ] && [ -x "$tool" ] || exit 1
    case "$(stat -c '%u:%a:%h' "$tool")" in 0:700:1|0:755:1) ;; *) exit 1;; esac
done
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
if [ "$huaweicloud_receipt_enabled" = true ]; then
    for pair in '6:/var/run/homegate/frontend.lock' '7:/etc/homegate/transactions/.supervisor.lock'; do
        fd=${pair%%:*};lock=${pair#*:}
        [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] && flock -n "$fd" || exit 1
    done
else exec 6>&- 7>&-;fi
if [ "$mode" = records ] || [ "$mode" = reconcile ]; then
    [ "$mode" != records ] || [ -p /proc/self/fd/4 ] || exit 1
    for slot in input context attempt; do
        [ -f "$work/$slot" ] && [ ! -L "$work/$slot" ] && [ "$(stat -c '%u:%a:%h' "$work/$slot")" = 0:600:1 ] || exit 1
    done
    if [ "$mode" = records ]; then exec 5<&4 || exit 1
    else exec 5<"$work/context" || exit 1;fi
fi
exec 4>>"$work/request" 8>>"$work/sign-input" 9>>"$work/sign-output" || exit 1
[ "$mode:$huaweicloud_receipt_enabled" != records:true ] || mode=records-durable
exec lua "$dir/huaweicloud-reader.lua" run "$account" "$revision" "$mode" "$job"
