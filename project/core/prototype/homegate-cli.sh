#!/bin/sh
# Candidate Shell CLI only. The production recipe and old Go CLI are unchanged.
set -u
umask 077
export LC_ALL=C
native_cli_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"native-cli","effect":"none","write_ready":false,"error":"Native CLI request refused"}\n';exit "${1:-7}"; }
action=${1:-};rule=
case "$action" in
    ddns-status|ddns-sync) [ "$#" -ge 1 ] && [ "$#" -le 2 ] || fail 2
        if [ "$#" -eq 2 ]; then rule=$2;case "$rule" in ''|*[!a-zA-Z0-9_-]*) fail 2;; esac;[ "${#rule}" -le 64 ] || fail 2;fi;;
    schedule-status|schedule-quiescent|lifecycle-prepare|lifecycle-resume) [ "$#" -eq 1 ] || fail 2;;
    schedule-run|schedule-stop|schedule-reap) [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
    *) fail 2;;
esac
case "$action" in schedule-status|schedule-stop|schedule-reap|schedule-quiescent) ;; *) [ "$native_cli_enabled" = true ] || fail 2;; esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 2>/dev/null
[ "$(id -u)" = 0 ] || fail
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
# Every public entry discards caller descriptors, especially borrowed locks and
# internal plan frames. The fixed helper obtains and validates its own locks.
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
case "$action" in
    schedule-status) exec ash "$dir/homegate-ddns-schedule.sh" status;;
    schedule-quiescent) exec ash "$dir/homegate-ddns-schedule.sh" quiescent;;
    schedule-run) exec ash "$dir/homegate-ddns-schedule.sh" run --confirm;;
    schedule-stop) exec ash "$dir/homegate-ddns-schedule.sh" stop --confirm;;
    schedule-reap) exec ash "$dir/homegate-ddns-schedule.sh" reap --confirm;;
    lifecycle-prepare) exec ash "$dir/homegate-lifecycle-prepare.sh" prepare;;
    lifecycle-resume) exec ash "$dir/homegate-lifecycle-prepare.sh" resume;;
    ddns-sync)
        if [ -n "$rule" ]; then exec ash "$dir/homegate-ddns-state.sh" sync "$rule" --confirm;fi
        exec ash "$dir/homegate-ddns-batch.sh" sync --confirm;;
esac
run=/var/run/homegate;store=/etc/homegate/transactions
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
private_dir "$run" && private_dir "$store" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock" || fail
flock -n 6 && flock -n 7 || fail 4
for fd in 6 7; do
    lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
    [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] || fail 4
done
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null) || fail
names=$(ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 >/dev/null 2>/dev/null |
    lua "$dir/homegate-ddns-cli.lua" names "$revision" "$rule" 3>&- 2>/dev/null) || fail
rows=
for rule in $names; do
    row=$(ash "$dir/homegate-ddns-state.sh" status "$rule" 2>/dev/null |
        lua "$dir/homegate-ddns-batch.lua" row "$revision" "$rule" 0 2>/dev/null) || fail
    rows=${rows:+$rows,}$row
done
# Publish no partial prefix if any row was unavailable or corrupt.
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-status","configuration_revision":%s,"effect":"none","write_ready":false,"rules":[%s]}\n' "$revision" "$rows"
