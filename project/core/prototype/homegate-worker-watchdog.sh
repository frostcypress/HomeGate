#!/bin/sh
# Fixed isolated worker family. Its own session leader enforces the deadline
# even when the outer supervisor is killed. No signals to recorded foreign PIDs.
set -u
umask 077
export LC_ALL=C
persistent_worker_enabled=false
persistent_mode=false
engine_mode=--public-uci
if [ "${1:-}" = --persistent ]; then
    shift; [ "$persistent_worker_enabled" = true ] || exit 2
    persistent_mode=true; engine_mode=--persistent
    PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
    unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE HOMEGATE_WORKER_PROTO_TIMEOUT
fi
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
store=${HOMEGATE_CONFIG_PROTO_STORE:-}
[ "$persistent_mode" = false ] || store=/etc/homegate/transactions
role=${1:-}; token=${2:-}; budget=${3:-}
case "$role" in apply|restore) ;; *) exit 1;; esac
case "$token" in *[!0-9a-f]*) exit 1;; esac
[ "${#token}" -eq 32 ] && [ "$#" -eq 3 ] || exit 1
case "$budget" in [1-9]|[12][0-9]|30) ;; *) exit 1;; esac
process="$dir/worker-process.lua"
info=$(lua "$process" info "$$" "$token") || exit 1
old_ifs=$IFS; IFS=:; set -- $info; IFS=$old_ifs
[ "$#" -eq 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] && [ "$6" = 1 ] || exit 1
IFS= read -r start || exit 1
[ "$start" = START ] || exit 1
stop_requested=false
trap 'stop_requested=true' TERM INT
exec 4<> "$store/worker-data" || exit 1
if [ "$persistent_mode" = true ]; then
    lua "$dir/homegate-worker-prototype.lua" --persistent "$role" "$token" <"$store/worker-data" 4>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
else
    lua "$dir/homegate-worker-prototype.lua" "$role" "$token" <"$store/worker-data" 4>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
fi
worker_pid=$!
case "$role" in apply) snapshot_command=apply-snapshot-read;; restore) snapshot_command=restore-snapshot-read;; esac
produce_snapshot() {
    # Busy (4) occurs before any private frame bytes are written. Retain the
    # FIFO writer across retries so the consumer cannot mistake a busy reader
    # for EOF. The independent watchdog bounds and stops this whole family.
    while :; do
        result=0
        ash "$dir/homegate-config-prototype.sh" "$engine_mode" "$snapshot_command" "$token" || result=$?
        [ "$result" -eq 4 ] || return "$result"
        sleep 0.05 2>/dev/null || return 1
    done
}
produce_snapshot 3>&4 4>&- 8>&- 9>&- </dev/null >/dev/null 2>&1 &
producer_pid=$!
exec 4>&-
now=$(lua "$process" now) || exit 1
deadline=$((now + budget))
running() {
    state=$(lua "$process" info "$1" none) || return 0
    [ -n "$state" ] || return 1
    old_ifs=$IFS; IFS=:; set -- $state; IFS=$old_ifs
    [ "$#" -eq 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] || return 1
    case "$1" in Z|X) return 1;; esac
    return 0
}
stop_family() {
    printf '%s\n' "$1" > "$store/worker-reason"
    # $$ is this still-running session leader, never a stale recorded PID.
    kill -TERM "-$$" 2>/dev/null || :
    sleep 1
    kill -KILL "-$$" 2>/dev/null
    exit 1
}
while running "$worker_pid" || running "$producer_pid"; do
    if [ -e "$store/worker-stop" ]; then
        stop=$(cat "$store/worker-stop") || stop_family inspection
        [ "$stop" != "$token" ] || stop_requested=true
    fi
    [ "$stop_requested" = false ] || stop_family stop
    now=$(lua "$process" now) || stop_family inspection
    [ "$now" -lt "$deadline" ] || stop_family timeout
    sleep 0.05 2>/dev/null || stop_family inspection
done
worker_rc=0; producer_rc=0
wait "$worker_pid" || worker_rc=$?
wait "$producer_pid" || producer_rc=$?
members=$(lua "$process" group "$$" "$$") || stop_family inspection
[ "$members" = 0 ] || stop_family descendants
if [ "$worker_rc" -ne 0 ]; then printf '%s\n' worker-exit > "$store/worker-reason"; exit 1; fi
if [ "$producer_rc" -ne 0 ]; then printf '%s\n' producer-exit > "$store/worker-reason"; exit 1; fi
exit 0
