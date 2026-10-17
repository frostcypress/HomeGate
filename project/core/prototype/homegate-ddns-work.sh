#!/bin/sh
# Bound confirmed outer-work collection only; no provider calls or recursive purge.
set -u
umask 077
export LC_ALL=C
ddns_work_enabled=false
ddns_runtime_enabled=false
action=${1:-};job=${2:-}
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-work","effect":"unknown","write_ready":false,"error":"DDNS work evidence is unavailable"}\n';exit "${1:-7}"; }
[ "$ddns_work_enabled" = true ] || fail 2
case "$job" in ''|0*|*[!0-9]*) fail 2;; esac
[ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || fail 2
runtime=false;format=HGDDNSWORK1
case "$action" in bind-runtime|check-runtime) [ "$ddns_runtime_enabled" = true ] || fail 2;runtime=true;format=HGDDNSWORK2;action=${action%-runtime};; esac
case "$action" in bind) [ "$#" -eq 6 ] || fail 2;revision=$3;rule=$4;provider=$5;account=$6;; check) [ "$#" -eq 5 ] || fail 2;want_revision=$3;want_provider=$4;want_account=$5;; collect) [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2;; *) fail 2;; esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
owner=$(id -u) || fail
[ "$owner" = 0 ] || fail
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};hex "$sum"; }
hex() { [ "${#1}" -eq 64 ] || return 1;case "$1" in *[!0-9a-f]*) return 1;; esac; }
id() { [ -n "$1" ] && [ "${#1}" -le 64 ] || return 1;case "$1" in *[!a-zA-Z0-9_-]*) return 1;; esac; }
store=/etc/homegate/transactions;run=/var/run/homegate
work=$run/.ddns-plan-$job;plan=$run/.ddns-collect-$job;next=$plan.next
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
private_dir "$store" && private_dir "$run" && private_file "$store/identity" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
for fd in 6 7; do
    lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
    if [ "$action" = collect ]; then
        case "$fd" in 6) exec 6>>"$lock" || fail;; 7) exec 7>>"$lock" || fail;; esac
    fi
    [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] && flock -n "$fd" || fail 4
done
binding_body() { printf '%s\n' "$format" "$identity" "$boot" "$revision" "$rule" "$provider" "$account" "$job" "$birth" "$inode" "$generation" "$h_plan" "$h_intent" "$h_result" "$h_input"; }
collection_body() { printf '%s\n' HGDDNSCOLLECT1 "$terminal_binding" "$h_provider" "$h_public";binding_body; }
framed() { frame=$($1) || return 1;digest=$(printf '%s\n' "$frame" | sha256sum) || return 1;printf '%s\n' "$frame" "${digest%% *}"; }
read_fields() {
    IFS= read -r format <&8 && IFS= read -r identity <&8 && IFS= read -r boot <&8 && IFS= read -r revision <&8 &&
        IFS= read -r rule <&8 && IFS= read -r provider <&8 && IFS= read -r account <&8 && IFS= read -r stored_job <&8 &&
        IFS= read -r birth <&8 && IFS= read -r inode <&8 && IFS= read -r generation <&8 && IFS= read -r h_plan <&8 &&
        IFS= read -r h_intent <&8 && IFS= read -r h_result <&8 && IFS= read -r h_input <&8 || return 1
    [ "$stored_job" = "$job" ] || return 1
    case "$format" in HGDDNSWORK1) ;; HGDDNSWORK2) [ "$ddns_runtime_enabled" = true ] || return 1;; *) return 1;; esac
    id "$rule" && id "$account" || return 1
    case "$provider" in cloudflare|aliyun|dnspod|huaweicloud) ;; *) return 1;; esac
    case "$revision" in ''|0*|*[!0-9]*) return 1;; esac
    [ "${#revision}" -le 2 ] && [ "$revision" -le 32 ] || return 1
    case "$birth" in ''|*[!0-9]*) return 1;; esac
    [ "${#birth}" -le 20 ] && [ "${#inode}" -le 48 ] && [ "${#boot}" -eq 36 ] || return 1
    case "$inode" in ''|*[!0-9:]*|:*|*:|*:*:*) return 1;; esac
    case "$inode" in *:*) ;; *) return 1;; esac
    case "$boot" in *[!0-9a-f-]*) return 1;; esac
    for value in "$identity" "$generation" "$h_plan" "$h_intent" "$h_result" "$h_input"; do hex "$value" || return 1;done
}
read_record() {
    private_file "$1" && [ "$(stat -c %s "$1")" -le 2048 ] || return 1
    exec 8<"$1" || return 1
    if [ "$2" = collection ]; then
        IFS= read -r p_format <&8 && [ "$p_format" = HGDDNSCOLLECT1 ] && IFS= read -r terminal_binding <&8 &&
            IFS= read -r h_provider <&8 && IFS= read -r h_public <&8 || return 1
        hex "$terminal_binding" && hex "$h_provider" && hex "$h_public" || return 1
    fi
    read_fields && IFS= read -r checksum <&8 || return 1
    if IFS= read -r extra <&8; then return 1;fi
    exec 8<&-
    kind=binding_body;[ "$2" != collection ] || kind=collection_body
    expected=$(framed "$kind") || return 1
    [ "$(stat -c %s "$1")" -eq "$((${#expected}+1))" ] && [ "$(cat "$1")" = "$expected" ]
}
identity_check() {
    [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ] && hash "$store/identity" && [ "$sum" = "$identity" ] || return 1
    hash "$store/gen-$revision/manifest" && [ "$sum" = "$generation" ] || return 1
    [ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null)" = "$revision" ]
}
member() {
    case "$1" in
        binding) limit=2048;expected=$(framed binding_body) || return 1;private_file "$work/binding" && [ "$(stat -c %s "$work/binding")" -eq "$((${#expected}+1))" ] && [ "$(cat "$work/binding")" = "$expected" ];return;;
        plan) limit=262144;want=$h_plan;; intent) limit=65536;want=$h_intent;; result) limit=65536;want=$h_result;; input) limit=4096;want=$h_input;;
        provider) limit=4096;want=${h_provider:-};; public) limit=65536;want=${h_public:-};; *) return 1;;
    esac
    private_file "$work/$1" && [ "$(stat -c %s "$work/$1")" -le "$limit" ] && hash "$work/$1" || return 1
    [ -z "$want" ] || [ "$sum" = "$want" ]
}
preflight() {
    private_dir "$work" && [ "$(stat -c '%d:%i' "$work")" = "$inode" ] || return 1
    for entry in "$work/"* "$work/".[!.]* "$work/"..?*; do
        exists "$entry" || continue
        case "$entry" in "$work/binding"|"$work/plan"|"$work/intent"|"$work/result"|"$work/input"|"$work/provider"|"$work/public") ;; *) return 1;; esac
    done
    for name in binding plan intent result input provider public; do
        if [ "$1" = full ] || exists "$work/$name"; then member "$name" || return 1;fi
    done
}
source_mode() {
    source_command=migration-source-recovery-snapshot-read;bound_mode=work-bound
    if [ "$format" = HGDDNSWORK2 ]; then source_command=runtime-ddns-recovery-snapshot-read;bound_mode=work-bound-runtime;fi
}
source_bound() {
    source_mode
    private_file "$store/dns-operation/current" || return 1
    active=$(cat "$store/dns-operation/current") || return 1;case "$active" in 1|2) ;; *) return 1;; esac
    ready=$(ash "$dir/homegate-config-prototype.sh" --persistent "$source_command" 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-sync.lua" "$bound_mode" "$revision" "$rule" 3<"$store/dns-operation/slot-$active/context" 4<"$work/input" 5<"$work/plan" 8<"$work/intent" 9<"$work/result" 2>/dev/null) || return 1
    [ "$ready" = HGDDNSBOUND1 ]
}
source_check() {
    source_mode
    ready=$(ash "$dir/homegate-config-prototype.sh" --persistent "$source_command" 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-sync.lua" work-source "$revision" "$rule" 3>&- 4>&- 5>&- 8>&- 9>&- 2>/dev/null) || return 1
    [ "$ready" = HGDDNSSOURCE1 ]
}
quiet() {
    info=$(lua "$dir/worker-process.lua" info "$job" none 2>/dev/null) || return 1
    case "$info" in '') [ ! -e "/proc/$job" ] && [ ! -L "/proc/$job" ];; Z:*|X:*) ;; *) return 1;; esac
}
terminal_check() {
    case "$provider" in cloudflare) set -- ;; aliyun) set -- --aliyun-internal;; dnspod) set -- --dnspod-internal;; huaweicloud) set -- --huaweicloud-internal;; esac
    ash "$dir/homegate-dns-recovery.sh" "$@" orphan-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || return 1
    hash "$store/dns-operation/terminal-meta" || return 1
    [ -z "${terminal_binding:-}" ] || [ "$sum" = "$terminal_binding" ] || return 1
    terminal_binding=$sum
}
if [ "$action" = bind ]; then
    id "$rule" && id "$account" && private_dir "$work" || fail
    ! exists "$plan" && ! exists "$next" || fail
    case "$provider" in cloudflare|aliyun|dnspod|huaweicloud) ;; *) fail;; esac
    case "$revision" in ''|0*|*[!0-9]*) fail;; esac
    [ "${#revision}" -le 2 ] && [ "$revision" -le 32 ] || fail
    exists "$work/binding" && fail
    info=$(lua "$dir/worker-process.lua" info "$job" none 2>/dev/null) || fail
    old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
    [ "$#" -eq 6 ] && [ "$1" != Z ] && [ "$1" != X ] || fail;birth=$5
    boot=$(cat /proc/sys/kernel/random/boot_id) || fail
    hash "$store/identity" || fail;identity=$sum
    hash "$store/gen-$revision/manifest" || fail;generation=$sum
    inode=$(stat -c '%d:%i' "$work") || fail
    hash "$work/plan" || fail;h_plan=$sum;hash "$work/intent" || fail;h_intent=$sum
    hash "$work/result" || fail;h_result=$sum;hash "$work/input" || fail;h_input=$sum
    for name in plan intent result input provider public; do member "$name" || fail;done
    identity_check || fail
    (set -C; : > "$work/.binding") 2>/dev/null || fail
    framed binding_body > "$work/.binding" || fail
    read_record "$work/.binding" binding && fsync "$work/.binding" "$work" 2>/dev/null && mv "$work/.binding" "$work/binding" && fsync "$work" 2>/dev/null || fail
    exit 0
fi
if [ "$action" = check ]; then
    read_record "$work/binding" binding && identity_check && preflight full || fail
    [ "$revision:$provider:$account" = "$want_revision:$want_provider:$want_account" ] || fail
    if [ "$runtime" = true ]; then [ "$format" = HGDDNSWORK2 ] || fail;else [ "$format" = HGDDNSWORK1 ] || fail;fi
    info=$(lua "$dir/worker-process.lua" info "$job" none 2>/dev/null) || fail
    old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
    [ "$#" -eq 6 ] && [ "$1" != Z ] && [ "$1" != X ] && [ "$5" = "$birth" ] || fail
    printf '%s\n' "$rule"
    exit 0
fi
quiet || fail 4
if exists "$plan" && exists "$next"; then fail;fi
if exists "$plan"; then
    read_record "$plan" collection && identity_check && terminal_check || fail
elif exists "$next"; then
    read_record "$next" collection && identity_check && terminal_check && preflight full && source_bound || fail
    fsync "$next" "$run" 2>/dev/null && mv "$next" "$plan" || fail
else
    read_record "$work/binding" binding && identity_check && preflight full && source_bound && terminal_check || fail
    # Both the selected request and the original canonical success must match.
    ready=$(lua "$dir/homegate-ddns-sync.lua" result "$revision" "$rule" "$provider" "$account" 0 < "$work/provider" 9<"$store/dns-operation/terminal" 2>/dev/null) || fail
    hash "$work/provider" || fail;h_provider=$sum;hash "$work/public" || fail;h_public=$sum
    (set -C; : > "$next") 2>/dev/null || fail
    framed collection_body > "$next" || fail
    read_record "$next" collection && fsync "$next" "$run" 2>/dev/null && mv "$next" "$plan" || fail
fi
read_record "$plan" collection && identity_check && source_check && terminal_check && fsync "$plan" "$run" 2>/dev/null || fail
if exists "$work"; then
    preflight remaining && quiet || fail
    for name in provider public input plan intent result binding; do
        if exists "$work/$name"; then member "$name" && rm -f "$work/$name" && fsync "$work" 2>/dev/null || fail;fi
    done
    rmdir "$work" && fsync "$run" 2>/dev/null || fail
fi
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-work","outer_collected":true,"effect":"none","write_ready":false}\n'
