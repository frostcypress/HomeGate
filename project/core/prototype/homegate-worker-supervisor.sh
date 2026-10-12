#!/bin/sh
# Isolated fixed worker supervisor. Never installs or controls real services.
set -u
umask 077
export LC_ALL=C
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
engine="$dir/homegate-config-prototype.sh"
process="$dir/worker-process.lua"
store=${HOMEGATE_CONFIG_PROTO_STORE:-}
interrupted=0
control_open=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"worker-supervision","error":"%s"}\n' "$1"; exit "${2:-7}"; }
trap 'interrupted=143' TERM
trap 'interrupted=130' INT
trap 'exec 5>&- 2>/dev/null || :' EXIT
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ]; }
private_fifo() { [ -p "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ]; }
validate_store_path() {
    case "$store" in /tmp/homegate-config-prototype-*) ;; *) fail 'Invalid isolated worker store' 2;; esac
    walk=; old_ifs=$IFS; IFS=/; set -f
    for component in $store; do
        case "$component" in '') continue;; .|..) fail 'Invalid isolated worker store' 2;; esac
        walk="$walk/$component"
        [ ! -L "$walk" ] || fail 'Invalid isolated worker store' 2
        if [ "$walk" != /tmp ]; then
            [ -d "$walk" ] && [ "$(stat -c '%u:%a' "$walk" 2>/dev/null)" = "$owner:700" ] || fail 'Invalid isolated worker store' 2
        fi
    done
    IFS=$old_ifs; set +f
    if [ -e "$store/worker" ] || [ -L "$store/worker" ]; then
        private_file "$store/worker" && [ "$(stat -c %s "$store/worker")" -le 512 ] || fail 'Invalid isolated worker store' 2
    fi
}
validate_configuration() {
    rc=0; ash "$engine" --public-uci status >/dev/null 2>&1 || rc=$?
    case "$rc" in 0) ;; 4) fail 'Configuration busy' 4;; *) fail 'Invalid isolated worker store' 2;; esac
}
digits() { case "$1" in ''|*[!0-9]*) return 1;; esac; [ "${#1}" -le "$2" ]; }
token_valid() { [ "${#1}" -eq 32 ] || return 1; case "$1" in *[!0-9a-f]*) return 1;; esac; }
now() { moment=$(lua "$process" now 2>/dev/null) || fail 'Unable to read worker deadline'; }
metadata() {
    info=$(lua "$process" info "$1" "$2" 2>/dev/null) || fail 'Unable to inspect worker identity'
    state=; parent=; group=; session=; birth=; matched=
    [ -n "$info" ] || return
    old_ifs=$IFS; IFS=:; set -- $info; IFS=$old_ifs
    [ "$#" -eq 6 ] || fail 'Invalid worker metadata'
    state=$1; parent=$2; group=$3; session=$4; birth=$5; matched=$6
}
members() { count=$(lua "$process" group "$1" 0 2>/dev/null) || fail 'Unable to confirm worker quiescence'; }
check_slots() {
    for slot in runtime worker-stop worker-reason; do
        file="$store/$slot"
        if [ -e "$file" ] || [ -L "$file" ]; then
            private_file "$file" && [ "$(stat -c %s "$file")" -le 256 ] || fail 'Unsafe worker state'
        fi
    done
    for slot in worker-start worker-data; do
        file="$store/$slot"
        if [ -e "$file" ] || [ -L "$file" ]; then private_fifo "$file" || fail 'Unsafe worker pipe'; fi
    done
}
clean_slots() {
    check_slots
    rm -f "$store/worker-start" "$store/worker-data" "$store/worker-stop" "$store/worker-reason" || fail 'Unable to close worker pipes'
}
lease_read() {
    private_file "$store/worker" && [ "$(stat -c %s "$store/worker")" -le 512 ] || fail 'Unsafe worker lease'
    body=$(cat "$store/worker") || fail 'Unable to read worker lease'
    [ "$(stat -c %s "$store/worker")" -eq "$((${#body} + 1))" ] || fail 'Invalid worker lease framing'
    exec 4<"$store/worker" || fail 'Unable to read worker lease'
    IFS= read -r format <&4 && IFS= read -r lease_boot <&4 && IFS= read -r lease_store <&4 &&
        IFS= read -r owner_pid <&4 && IFS= read -r owner_birth <&4 && IFS= read -r watchdog_pid <&4 &&
        IFS= read -r watchdog_birth <&4 && IFS= read -r lease_role <&4 && IFS= read -r lease_token <&4 &&
        IFS= read -r lease_budget <&4 || fail 'Incomplete worker lease'
    if IFS= read -r extra <&4; then fail 'Unexpected worker lease data'; fi
    exec 4<&-
    [ "$format" = HGWORKER1 ] && [ "$lease_store" = "$store_digest" ] || fail 'Worker lease belongs to another store'
    [ "${#lease_boot}" -eq 36 ] || fail 'Invalid worker boot identity'
    case "$lease_boot" in *[!0-9a-f-]*) fail 'Invalid worker boot identity';; esac
    digits "$owner_pid" 9 && digits "$watchdog_pid" 9 && digits "$owner_birth" 20 && digits "$watchdog_birth" 20 || fail 'Invalid worker process identity'
    case "$owner_pid:$watchdog_pid" in 0*|*:0*) fail 'Invalid worker process identity';; esac
    [ "$owner_pid" -gt 1 ] && [ "$watchdog_pid" -gt 1 ] || fail 'Invalid worker process identity'
    token_valid "$lease_token" || fail 'Invalid worker handle'
    case "$lease_role" in apply|restore) ;; *) fail 'Invalid worker role';; esac
    case "$lease_budget" in [1-9]|[12][0-9]|30) ;; *) fail 'Invalid worker budget';; esac
    expected=$(printf '%s\n' HGWORKER1 "$lease_boot" "$lease_store" "$owner_pid" "$owner_birth" "$watchdog_pid" "$watchdog_birth" "$lease_role" "$lease_token" "$lease_budget")
    [ "$body" = "$expected" ] || fail 'Invalid worker lease framing'
}
lease_remove() {
    rm -f "$store/worker" || fail 'Unable to close worker lease'
    fsync "$store" 2>/dev/null || fail 'Worker lease closure is uncertain'
}
request_stop() {
    file="$store/worker-stop"
    if [ -e "$file" ] || [ -L "$file" ]; then private_file "$file" || fail 'Unsafe worker stop request'; fi
    printf '%s\n' "$lease_token" > "$file" || fail 'Unable to request worker stop'
}
orphan_quiescence() {
    lease_read
    if [ "$lease_boot" = "$boot" ]; then
        metadata "$owner_pid" none
        if [ "$birth" = "$owner_birth" ]; then case "$state" in ''|Z|X) ;; *) fail 'Worker supervisor is active' 4;; esac; fi
        metadata "$watchdog_pid" "$lease_token"
        if [ "$birth" = "$watchdog_birth" ] && [ "$group" = "$watchdog_pid" ] && [ "$session" = "$watchdog_pid" ] && [ "$matched" = 1 ]; then
            # Ask the original session leader to stop its OWN group. Never
            # signal a PID/group obtained from stale persistent metadata.
            request_stop
        fi
        now; end_wait=$((moment + 4))
        while :; do
            members "$watchdog_pid"; [ "$count" != 0 ] || break
            now; [ "$moment" -lt "$end_wait" ] || fail 'Orphan worker quiescence is unproven'
            sleep 0.05 2>/dev/null || fail 'Worker pacing is unavailable'
        done
    fi
    # A changed boot cannot contain the old kernel processes; no old PID is
    # signalled. Production cold-start intent restoration is still unverified.
}
run_job() {
    role=$1; handle=$2
    case "$role" in apply) authorize=apply-authorize;; restore) authorize=restore-authorize;; esac
    authorization=$(ash "$engine" --public-uci "$authorize" "$handle" 2>/dev/null) || fail 'Worker context is not authorized' 5
    revision=$(printf '%s\n' "$authorization" | lua "$process" revision 2>/dev/null) || fail 'Invalid worker context'
    clean_slots
    mkfifo "$store/worker-start" "$store/worker-data" || fail 'Unable to create private worker pipes'
    exec 5<> "$store/worker-start" || fail 'Unable to open worker startup gate'
    control_open=true
    setsid ash "$dir/homegate-worker-watchdog.sh" "$role" "$handle" "$budget" <"$store/worker-start" 5>&- 8>&- 9>&- >/dev/null 2>&1 &
    child=$!
    now; start_deadline=$((moment + 2))
    while :; do
        metadata "$child" "$handle"
        if [ "$group" = "$child" ] && [ "$session" = "$child" ] && [ "$matched" = 1 ]; then break; fi
        now; [ "$moment" -lt "$start_deadline" ] || fail 'Worker session startup is unproven'
        sleep 0.05 2>/dev/null || fail 'Worker pacing is unavailable'
    done
    child_birth=$birth
    metadata "$$" none; own_birth=$birth
    temporary="$store/.worker.$$"
    (set -C; : > "$temporary") 2>/dev/null || fail 'Unable to allocate worker lease'
    printf '%s\n' HGWORKER1 "$boot" "$store_digest" "$$" "$own_birth" "$child" "$child_birth" "$role" "$handle" "$budget" > "$temporary" || fail 'Unable to write worker lease'
    fsync "$temporary" 2>/dev/null || fail 'Unable to synchronize worker lease'
    mv -f "$temporary" "$store/worker" || fail 'Unable to publish worker lease'
    fsync "$store" 2>/dev/null || fail 'Worker startup durability is uncertain'
    lease_token=$handle
    printf '%s\n' START >&5 || fail 'Unable to release worker startup gate'
    exec 5>&-
    control_open=false
    now; final_deadline=$((moment + budget + 3))
    while :; do
        [ "$interrupted" -eq 0 ] || request_stop
        metadata "$child" "$handle"
        case "$state" in ''|Z|X) break;; esac
        [ "$birth" = "$child_birth" ] || break
        now; [ "$moment" -lt "$final_deadline" ] || fail 'Worker completion is unproven'
        sleep 0.05 2>/dev/null || fail 'Worker pacing is unavailable'
    done
    child_rc=0; wait "$child" || child_rc=$?
    # The leader may reach Z before all members finish handling group KILL.
    # Keep the lease and barrier while waiting within the existing deadline.
    while :; do
        members "$child"; [ "$count" != 0 ] || break
        now; [ "$moment" -lt "$final_deadline" ] || fail 'Worker descendants remain active'
        sleep 0.05 2>/dev/null || fail 'Worker pacing is unavailable'
    done
    # A second scan catches ordinary fork/exit transitions before ACK.
    sleep 0.05 2>/dev/null || fail 'Worker pacing is unavailable'
    members "$child"; [ "$count" = 0 ] || fail 'Worker descendants remain active'
    lease_remove
    check_slots
    timed_out=false
    if [ -f "$store/worker-reason" ]; then reason=$(cat "$store/worker-reason"); [ "$reason" != timeout ] || timed_out=true; fi
    clean_slots
    [ "$interrupted" -eq 0 ] || fail 'Worker supervision interrupted; recovery required' "$interrupted"
    [ "$child_rc" -eq 0 ] || return 1
    private_file "$store/runtime" && lua "$process" receipt "$store" "$revision" "$role" 2>/dev/null || return 1
    fsync "$store/runtime" "$store" 2>/dev/null || return 1
    return 0
}
case "${1:-}" in
    run-apply) [ "$#" -eq 2 ] && token_valid "$2" || fail 'Expected internal worker handle' 2; command=run-apply; handle=$2;;
    recover) [ "$#" -eq 1 ] || fail 'Unexpected supervisor arguments' 2; command=recover;;
    *) fail 'Unsupported supervisor command' 2;;
esac
budget=${HOMEGATE_WORKER_PROTO_TIMEOUT:-30}
case "$budget" in [1-9]|[12][0-9]|30) ;; *) fail 'Worker timeout must be 1 to 30 seconds' 2;; esac
sleep 0.001 >/dev/null 2>&1 || fail 'Worker pacing is unavailable' 2
command -v kill >/dev/null 2>&1 || fail 'Worker signalling is unavailable' 2
owner=$(id -u) || fail 'Unable to identify worker owner'
validate_store_path
# A blocked snapshot producer can still own the configuration flock after
# outer SIGKILL. Recovery must prove the family quiet before taking that lock.
[ "$command" = recover ] || validate_configuration
boot=$(cat /proc/sys/kernel/random/boot_id) || fail 'Unable to read worker boot identity'
store_digest=$(printf '%s\n' "$store" | sha256sum); store_digest=${store_digest%% *}
for file in "$store/.recovery.lock" "$store/.supervisor.lock"; do
    if [ ! -e "$file" ] && [ ! -L "$file" ]; then (set -C; : > "$file") 2>/dev/null || :; fi
    private_file "$file" || fail 'Unsafe worker control lock'
done
exec 8>>"$store/.recovery.lock" || fail 'Unable to open worker recovery lock'
flock -n 8 || fail 'Another supervisor is active' 4
stale=false
if [ -e "$store/worker" ] || [ -L "$store/worker" ]; then
    [ "$command" = recover ] || fail 'Unfinished worker requires explicit recovery' 4
    orphan_quiescence; stale=true
fi
exec 7>>"$store/.supervisor.lock" || fail 'Unable to open worker supervisor lock'
flock -n 7 || fail 'Worker group has not released its control lock' 4
[ "$stale" = false ] || lease_remove
[ "$command" != recover ] || validate_configuration
if [ "$command" = run-apply ]; then
    if run_job apply "$handle"; then
        ash "$engine" --public-uci apply-finish "$handle" success >/dev/null 2>&1 || fail 'Application acknowledgement is uncertain'
        printf '{"api_version":1,"prototype":true,"ok":true,"scope":"isolated-worker-receipt","applied":true}\n'
        exit 0
    fi
    apply_timed_out=$timed_out
    ash "$engine" --public-uci apply-finish "$handle" failure >/dev/null 2>&1 || fail 'Baseline restoration could not begin'
else
    result=$(ash "$engine" --public-uci recover-application 2>/dev/null) || fail 'Application recovery could not begin'
    handle=$(printf '%s\n' "$result" | lua "$process" ticket 2>/dev/null) || fail 'Invalid recovery context'
    if [ "$handle" = completed ]; then
        clean_slots
        printf '{"api_version":1,"prototype":true,"ok":true,"scope":"isolated-worker-receipt","recovery_closed":true}\n'
        exit 0
    fi
fi
if run_job restore "$handle"; then
    ash "$engine" --public-uci restore-finish "$handle" success >/dev/null 2>&1 || fail 'Restoration acknowledgement is uncertain'
    if [ "$command" = run-apply ]; then
        printf '{"api_version":1,"prototype":true,"ok":false,"scope":"isolated-worker-receipt","baseline_restored":true,"application_pending":false,"timed_out":%s}\n' "$apply_timed_out"
        exit 8
    fi
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"isolated-worker-receipt","baseline_restored":true}\n'
    exit 0
fi
ash "$engine" --public-uci restore-finish "$handle" failure >/dev/null 2>&1 || :
fail 'Baseline worker restoration remains incomplete'
