#!/bin/sh
# Confirmed terminal only. Delete seven fixed volatile files, never DNS evidence.
set -u
umask 077
export LC_ALL=C
dns_orphan_collection_enabled=false
[ "$dns_orphan_collection_enabled" = true ] && [ "$#" -eq 4 ] && [ "$1" = collect-orphan ] || exit 2
account=$2;revision=$3;job=$4
case "$account" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
[ "${#account}" -le 64 ] || exit 2
case "$revision" in ''|0*|*[!0-9]*) exit 2;; esac
[ "${#revision}" -le 2 ] && [ "$revision" -le 32 ] || exit 2
case "$job" in ''|0*|*[!0-9]*) exit 2;; esac
[ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || exit 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
owner=$(id -u) || exit 1
[ "$owner" = 0 ] || exit 1
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1" 2>/dev/null)" = "$owner:600:1" ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ]; }
hex() { [ "${#1}" -eq 64 ] || return 1;case "$1" in *[!0-9a-f]*) return 1;; esac; }
store=/etc/homegate/transactions;run=/var/run/homegate
journal=$store/dns-operation;work=$run/.dns-check-$job
plan=$journal/orphan-plan;next=$journal/.orphan-plan
private_dir "$store" && private_dir "$run" && private_file "$store/identity" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || exit 1
for fd in 6 7; do
    target=$run/frontend.lock;[ "$fd" != 7 ] || target=$store/.supervisor.lock
    [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$target")" ] || exit 1
    flock -n "$fd" || exit 1
done
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
# The existing independent watchdog retains these locks until its family is
# quiet. Also refuse any live/reused coordinator PID; never signal old PIDs.
quiet() {
    info=$(lua "$dir/worker-process.lua" info "$job" none 2>/dev/null) || return 1
    case "$info" in '') [ ! -e "/proc/$job" ] && [ ! -L "/proc/$job" ] || return 1;; Z:*|X:*) ;; *) return 1;; esac
}
quiet || exit 1
ash "$dir/homegate-dns-recovery.sh" orphan-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
hash "$store/identity" || exit 1;identity_hash=$sum
hash "$journal/terminal-meta" || exit 1;terminal_binding=$sum
exec 8<"$journal/terminal-meta" || exit 1
IFS= read -r ignored <&8 && IFS= read -r ignored <&8 && IFS= read -r ignored <&8 && IFS= read -r original_boot <&8 || exit 1
exec 8<&-
boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || exit 1
plan_body() {
    printf '%s\n' HGCFOrphan1 homegate "$identity_hash" "$original_boot" "$revision" "$account" "$job" "$terminal_binding" "$inode" "$h_request" "$h_result" "$h_zones" "$h_state" "$h_input" "$h_context" "$h_attempt"
}
plan_read() {
    private_file "$1" && [ "$(stat -c %s "$1")" -le 2048 ] || return 1
    exec 8<"$1" || return 1
    IFS= read -r format <&8 && IFS= read -r slug <&8 && IFS= read -r p_identity <&8 && IFS= read -r p_boot <&8 &&
        IFS= read -r p_revision <&8 && IFS= read -r p_account <&8 && IFS= read -r p_job <&8 && IFS= read -r p_binding <&8 &&
        IFS= read -r inode <&8 && IFS= read -r h_request <&8 && IFS= read -r h_result <&8 && IFS= read -r h_zones <&8 &&
        IFS= read -r h_state <&8 && IFS= read -r h_input <&8 && IFS= read -r h_context <&8 && IFS= read -r h_attempt <&8 && IFS= read -r checksum <&8 || return 1
    if IFS= read -r extra <&8; then return 1;fi
    exec 8<&-
    [ "$format:$slug:$p_identity:$p_boot:$p_revision:$p_account:$p_job:$p_binding" = "HGCFOrphan1:homegate:$identity_hash:$original_boot:$revision:$account:$job:$terminal_binding" ] || return 1
    for value in "$h_request" "$h_result" "$h_zones" "$h_state" "$h_input" "$h_context" "$h_attempt"; do hex "$value" || return 1;done
    case "$inode" in ''|*[!0-9:]*|:*|*:|*:*:*) return 1;; esac
    case "$inode" in *:*) ;; *) return 1;; esac
    frame=$(plan_body) || return 1;digest=$(printf '%s\n' "$frame" | sha256sum) || return 1
    expected=$(printf '%s\n' "$frame" "${digest%% *}") || return 1
    [ "$(stat -c %s "$1")" -eq "$((${#expected} + 1))" ] && [ "$(cat "$1")" = "$expected" ]
}
member() {
    case "$1" in
        request) limit=32768;expected_hash=${h_request:-};;
        result) limit=4096;expected_hash=${h_result:-};;
        zones) limit=4096;expected_hash=${h_zones:-};;
        state) limit=65536;expected_hash=${h_state:-};;
        input) limit=4096;expected_hash=${h_input:-};;
        context) limit=8388608;expected_hash=${h_context:-};;
        attempt) limit=13;expected_hash=${h_attempt:-};;
        *) return 1;;
    esac
    private_file "$work/$1" && [ "$(stat -c %s "$work/$1")" -le "$limit" ] || return 1
    hash "$work/$1" || return 1
    [ -z "$expected_hash" ] || [ "$sum" = "$expected_hash" ]
}
preflight() {
    private_dir "$work" && [ "$boot" = "$original_boot" ] || return 1
    [ -z "${inode:-}" ] || [ "$(stat -c '%d:%i' "$work")" = "$inode" ] || return 1
    for entry in "$work/"* "$work/".[!.]* "$work/"..?*; do
        exists "$entry" || continue
        case "$entry" in "$work/request"|"$work/result"|"$work/zones"|"$work/state"|"$work/input"|"$work/context"|"$work/attempt") ;; *) return 1;; esac
    done
    for name in request result zones state input context attempt; do
        if [ "$1" = full ] || exists "$work/$name"; then member "$name" || return 1;fi
    done
}
bound_full() {
    preflight full || return 1
    [ "$(stat -c %s "$work/attempt")" = 13 ] && [ "$(cat "$work/attempt")" = HGCFATTEMPT1 ] || return 1
    hash "$journal/terminal" || return 1;success_hash=$sum
    hash "$work/zones" && [ "$sum" = "$success_hash" ] || return 1
    active=$(cat "$journal/current") || return 1
    ready=$(ash "$dir/homegate-config-prototype.sh" --persistent dns-recovery-snapshot-read 3>&1 5<&- 8<&- 9<&- >/dev/null 2>/dev/null |
        lua "$dir/cloudflare-records.lua" receipt-orphan "$account" "$revision" 8<"$journal/slot-$active/context" 9<"$work/context" 5<"$work/input" 3>&- 4>&- 2>/dev/null) || return 1
    [ "$ready" = HGCFOBOUND1 ]
}
if exists "$plan" && exists "$next"; then exit 1;fi
if exists "$plan"; then
    plan_read "$plan" || exit 1
elif exists "$next"; then
    plan_read "$next" && bound_full || exit 1
    fsync "$next" "$journal" "$store" 2>/dev/null && mv "$next" "$plan" || exit 1
elif exists "$work"; then
    bound_full || exit 1
    inode=$(stat -c '%d:%i' "$work") || exit 1
    hash "$work/request" || exit 1;h_request=$sum
    hash "$work/result" || exit 1;h_result=$sum
    hash "$work/zones" || exit 1;h_zones=$sum
    hash "$work/state" || exit 1;h_state=$sum
    hash "$work/input" || exit 1;h_input=$sum
    hash "$work/context" || exit 1;h_context=$sum
    hash "$work/attempt" || exit 1;h_attempt=$sum
    (set -C; : > "$next") 2>/dev/null || exit 1
    frame=$(plan_body) || exit 1;digest=$(printf '%s\n' "$frame" | sha256sum) || exit 1
    printf '%s\n' "$frame" "${digest%% *}" > "$next" || exit 1
    plan_read "$next" && fsync "$next" "$journal" "$store" 2>/dev/null && mv "$next" "$plan" || exit 1
else
    # No volatile directory to remove. Keep the validated active DNS journal.
    fsync "$journal" "$store" "$run" 2>/dev/null || exit 1
    exit 0
fi
plan_read "$plan" && fsync "$plan" "$journal" "$store" 2>/dev/null || exit 1
if exists "$work"; then
    preflight remaining && quiet || exit 1
    # Whole-tree preflight precedes removal. Missing members are accepted only
    # with the previously validated plan; no recursive delete or new path.
    for name in request result zones state input context attempt; do
        if exists "$work/$name"; then
            member "$name" && rm -f "$work/$name" 2>/dev/null && fsync "$work" 2>/dev/null || exit 1
        fi
    done
    rmdir "$work" && fsync "$run" 2>/dev/null || exit 1
fi
# The original durable terminal/checkpoints remain intact throughout. Even an
# uncertain plan removal cannot release the active journal's writer fence.
fsync "$run" "$journal" "$store" 2>/dev/null && rm -f "$plan" 2>/dev/null && fsync "$journal" "$store" 2>/dev/null || exit 1
exit 0
