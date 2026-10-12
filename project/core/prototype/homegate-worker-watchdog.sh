#!/bin/sh
# Fixed isolated worker family. Its own session leader enforces the deadline
# even when the outer supervisor is killed. No signals to recorded foreign PIDs.
set -u
umask 077
export LC_ALL=C
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
store=${HOMEGATE_CONFIG_PROTO_STORE:-}
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
exec 6<> "$store/worker-data" || exit 1
lua "$dir/homegate-worker-prototype.lua" "$role" "$token" <"$store/worker-data" 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
worker_pid=$!
case "$role" in apply) snapshot_command=apply-snapshot-read;; restore) snapshot_command=restore-snapshot-read;; esac
ash "$dir/homegate-config-prototype.sh" --public-uci "$snapshot_command" "$token" 3>&6 6>&- 8>&- 9>&- </dev/null >/dev/null 2>&1 &
producer_pid=$!
exec 6>&-
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
[ "$worker_rc" -eq 0 ] && [ "$producer_rc" -eq 0 ]
