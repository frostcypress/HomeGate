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
    dns-provider-catalog|acme-ca-catalog) [ "$#" -eq 1 ] || fail 2;;
    network-resolve|status|check|recovery-status|recovery-summary-check) [ "$#" -eq 1 ] || fail 2;;
    recovery-summary-finish) [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2
        case "$2" in ''|*[!0-9a-f]*) fail 2;; esac;[ "${#2}" -eq 64 ] || fail 2;;
    dns-provider-status|dns-zones) [ "$#" -eq 2 ] || fail 2
        case "$2" in ''|*[!a-zA-Z0-9_-]*) fail 2;; esac
        [ "${#2}" -le 64 ] || fail 2;;
    schedule-status|schedule-quiescent|lifecycle-prepare|lifecycle-resume|lifecycle-startup|lifecycle-source-intent) [ "$#" -eq 1 ] || fail 2;;
    lifecycle-intent-check) [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2
        case "$2" in enabled|disabled) ;; *) fail 2;; esac;;
    lifecycle-intent-record) [ "$#" -eq 4 ] && [ "$4" = --confirm ] || fail 2
        case "$2" in save|resume|check) ;; *) fail 2;; esac
        case "$3" in enabled|disabled) ;; *) fail 2;; esac;;
    schedule-run|schedule-stop|schedule-reap) [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
    *) fail 2;;
esac
case "$action" in dns-provider-catalog|acme-ca-catalog|schedule-status|schedule-stop|schedule-reap|schedule-quiescent) ;; *) [ "$native_cli_enabled" = true ] || fail 2;; esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 2>/dev/null
[ "$(id -u)" = 0 ] || fail
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
# Every public entry discards caller descriptors, especially borrowed locks and
# internal plan frames. The fixed helper obtains and validates its own locks.
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
case "$action" in
    dns-provider-catalog|acme-ca-catalog)
        catalog=$(lua "$dir/homegate-cli-catalog.lua" "$action") || fail
        printf '%s\n' "$catalog"; exit 0;;
    dns-provider-status) exec ash "$dir/homegate-dns-status.sh" "$2";;
    dns-zones) exec ash "$dir/homegate-dns-status.sh" "$2" --zones;;
    network-resolve) exec ash "$dir/homegate-network-read.sh";;
    status|check) exec ash "$dir/homegate-health-read.sh" "$action";;
    recovery-status) exec ash "$dir/homegate-recovery-read.sh";;
    recovery-summary-check) exec ash "$dir/homegate-ddns-recovery-control.sh" check;;
    recovery-summary-finish) exec ash "$dir/homegate-ddns-recovery-control.sh" finish "$2" --confirm;;
    schedule-status) exec ash "$dir/homegate-ddns-schedule.sh" status;;
    schedule-quiescent) exec ash "$dir/homegate-ddns-schedule.sh" quiescent;;
    schedule-run) exec ash "$dir/homegate-ddns-schedule.sh" run --confirm;;
    schedule-stop) exec ash "$dir/homegate-ddns-schedule.sh" stop --confirm;;
    schedule-reap) exec ash "$dir/homegate-ddns-schedule.sh" reap --confirm;;
    lifecycle-prepare) exec ash "$dir/homegate-lifecycle-prepare.sh" prepare;;
    lifecycle-resume) exec ash "$dir/homegate-lifecycle-prepare.sh" resume;;
    lifecycle-startup) exec ash "$dir/homegate-lifecycle-prepare.sh" startup;;
    lifecycle-source-intent) exec ash "$dir/homegate-lifecycle-prepare.sh" intent;;
    lifecycle-intent-check) exec ash "$dir/homegate-lifecycle-prepare.sh" intent-check "$2" --confirm;;
    lifecycle-intent-record) exec ash "$dir/homegate-lifecycle-prepare.sh" "record-$2" "$3" --confirm;;
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
        lua "$dir/homegate-ddns-batch.lua" row-observed "$revision" "$rule" 0 2>/dev/null) || fail
    rows=${rows:+$rows,}$row
done
# Publish no partial prefix if any row was unavailable or corrupt.
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-status","configuration_revision":%s,"effect":"none","write_ready":false,"rules":[%s]}\n' "$revision" "$rows"
