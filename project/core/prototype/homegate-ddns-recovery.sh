#!/bin/sh
# Source-bound DDNS contribution only; global recovery.json is never replaced.
set -u
umask 077
export LC_ALL=C
ddns_recovery_publish_enabled=false
ddns_recovery_read_enabled=false
ddns_recovery_repair_enabled=false
fail() { exit "${1:-7}"; }
mode=${1:-};confirmation=${2:-}
case "$mode" in publish-internal) [ "$#" -eq 1 ] && [ "$ddns_recovery_publish_enabled" = true ] || fail 2;;
    inspect-internal|repair-check-internal) [ "$#" -eq 1 ] && [ "$ddns_recovery_read_enabled" = true ] || fail 2;;
    repair-finish-internal) [ "$#" -eq 3 ] && [ "$3" = --confirm ] && [ "$ddns_recovery_repair_enabled" = true ] || fail 2
        case "$confirmation" in ''|*[!0-9a-f]*) fail 2;; esac;[ "${#confirmation}" -eq 64 ] || fail 2;;
    *) fail 2;; esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 2>/dev/null 3>&- 4>&- 5>&- 8>&- 9>&-
[ "$(id -u)" = 0 ] || fail
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
run=/var/run/homegate;store=/etc/homegate/transactions
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir "$run" && private_dir "$store" || fail
locks_match() {
    for fd in 6 7; do
        lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
        private_file "$lock" && [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] && flock -n "$fd" || return 1
    done
}
locks_match || fail 4
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || fail
private_file "$store/identity" && private_dir "$store/gen-$revision" && private_file "$store/gen-$revision/manifest" || fail
identity=$(sha256sum "$store/identity") || fail;identity=${identity%% *}
generation=$(sha256sum "$store/gen-$revision/manifest") || fail;generation=${generation%% *}
boot=$(cat /proc/sys/kernel/random/boot_id) || fail
. "$dir/ddns-recovery-files.sh"
collect() {
    cache=$(ddns_cache_status) || return 1
    sample_now=$(lua "$dir/worker-process.lua" now) || return 1
    ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-recovery.lua" inputs "$revision" "$identity" "$generation" "$boot" "$cache" "$sample_now" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
}
input=$(collect) || fail
digest=$(printf '%s\n' "$input" | sha256sum) || fail;digest=${digest%% *}
if [ "$mode" = inspect-internal ]; then printf '%s:%s\n' "$digest" "$boot";exit 0;fi
record=$run/ddns-recovery.json;next=$run/.ddns-recovery-next;pending=$run/.ddns-recovery-pending
# Only the three fixed metadata paths participate. A token binds bytes and
# inode/owner/mode/link/size stamps, including both common lock descriptions.
file_stamp() {
    if ! exists "$1"; then printf absent;return;fi
    private_file "$1" && [ "$(stat -c %s "$1")" -le "$2" ] || return 1
    before=$(stat -c '%d:%i:%u:%a:%h:%s' "$1") || return 1
    sum=$(sha256sum "$1") || return 1;sum=${sum%% *}
    [ "$before" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$1")" ] && private_file "$1" || return 1
    printf '%s:%s' "$before" "$sum"
}
context_same() {
    locks_match && [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ] &&
    [ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current")" = "$revision" ] &&
    [ "$(sha256sum "$store/identity")" = "$identity  $store/identity" ] &&
    [ "$(sha256sum "$store/gen-$revision/manifest")" = "$generation  $store/gen-$revision/manifest" ] &&
    [ "$(collect)" = "$input" ]
}
capture_files() {
    ps=$(file_stamp "$pending" 2048) && ns=$(file_stamp "$next" 8192) && rs=$(file_stamp "$record" 8192) || return 1
    ls=$(stat -c '%d:%i:%u:%a:%h:%s' "$run/frontend.lock" "$store/.supervisor.lock") || return 1
    printf '%s\n' "$ps" "$ns" "$rs" "$ls"
}
check_repair() {
    stage=unverifiable;reason=unverifiable;ready=false;required=true;token=
    frame=$(capture_files) || return 0
    if ! exists "$pending"; then
        if ! exists "$next"; then stage=clean;reason=none;required=false;fi
        return 0
    fi
    expected=$(lua "$dir/homegate-ddns-recovery.lua" marker-current "$revision" "$identity" "$generation" "$boot" "$digest" < "$pending") || return 0
    if exists "$next"; then
        [ "$(sha256sum "$next")" = "$expected  $next" ] &&
            lua "$dir/homegate-ddns-recovery.lua" validate "$revision" "$identity" "$generation" "$boot" "$digest" < "$next" || return 0
        if exists "$record"; then lua "$dir/homegate-ddns-recovery.lua" owned "$identity" < "$record" || return 0;fi
        stage=staged
    else
        exists "$record" && [ "$(sha256sum "$record")" = "$expected  $record" ] &&
            lua "$dir/homegate-ddns-recovery.lua" validate "$revision" "$identity" "$generation" "$boot" "$digest" < "$record" || return 0
        stage=published
    fi
    context_same && [ "$(capture_files)" = "$frame" ] || { stage=unverifiable;return 0; }
    token=$(printf '%s\n' HGDDNSREPAIR1 "$revision" "$identity" "$generation" "$boot" "$digest" "$stage" "$frame" | sha256sum) || fail
    token=${token%% *};ready=true;reason=none
}
repair_json() {
    printf '{"api_version":1,"prototype":true,"phase":"ddns-summary-repair","ok":true,"repair_required":%s,"finish_ready":%s,"stage":"%s","reason":"%s","effect":"none","write_ready":false,"business_recovered":false,"metadata_changed":%s' "$required" "$ready" "$stage" "$reason" "$1"
    if [ -n "$token" ]; then printf ',"confirmation":"%s"' "$token";fi
    printf '}\n'
}
case "$mode" in repair-check-internal|repair-finish-internal)
    check_repair
    if [ "$mode" = repair-check-internal ]; then repair_json false;exit 0;fi
    [ "$ready" = true ] && [ "$confirmation" = "$token" ] || fail 4
    marker=$(cat "$pending") || fail
    marker_stamp=$(file_stamp "$pending" 2048) || fail
    context_same && [ "$(capture_files)" = "$frame" ] || fail 4
    if [ "$stage" = staged ]; then
        fsync "$next" "$pending" "$run" || fail
        context_same && [ "$(capture_files)" = "$frame" ] || fail 4
        mv -f "$next" "$record" || fail
    fi
    fsync "$record" "$pending" "$run" || fail
    context_same && [ "$(file_stamp "$pending" 2048)" = "$marker_stamp" ] && [ "$(cat "$pending")" = "$marker" ] &&
        private_file "$record" && [ "$(sha256sum "$record")" = "$expected  $record" ] && ! exists "$next" || fail
    rm -f "$pending" || fail
    fsync "$run" || { (set -C; printf '%s\n' "$marker" > "$pending") 2>/dev/null || :;fail; }
    stage=finished;reason=none;required=false;ready=false;token=;repair_json true;exit 0;;
esac
! exists "$next" && ! exists "$pending" || fail 4
if exists "$record"; then private_file "$record" && [ "$(stat -c %s "$record")" -le 8192 ] &&
    lua "$dir/homegate-ddns-recovery.lua" owned "$identity" < "$record" || fail 4;fi
now=$(lua "$dir/worker-process.lua" now) || fail
candidate=$(printf '%s\n' "$input" | lua "$dir/homegate-ddns-recovery.lua" build "$digest" "$now" 6>&- 7>&-) || fail
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
candidate_hash=$(printf '%s\n' "$candidate" | sha256sum) || fail;candidate_hash=${candidate_hash%% *}
marker=$(lua "$dir/homegate-ddns-recovery.lua" pending "$revision" "$identity" "$generation" "$boot" "$digest" "$candidate_hash" "$ticket") || fail
(set -C; printf '%s\n' "$marker" > "$pending") || fail
private_file "$pending" || fail
(set -C; printf '%s\n' "$candidate" > "$next") || fail
private_file "$next" && [ "$(stat -c %s "$next")" -le 8192 ] || fail
lua "$dir/homegate-ddns-recovery.lua" validate "$revision" "$identity" "$generation" "$boot" "$digest" < "$next" 6>&- 7>&- || fail
fsync "$next" "$pending" "$run" || fail
locks_match || fail 4
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ] && [ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current")" = "$revision" ] || fail
[ "$(sha256sum "$store/identity")" = "$identity  $store/identity" ] && [ "$(sha256sum "$store/gen-$revision/manifest")" = "$generation  $store/gen-$revision/manifest" ] || fail
[ "$(collect)" = "$input" ] || fail
mv -f "$next" "$record" && fsync "$record" "$run" || fail
private_file "$pending" && [ "$(cat "$pending")" = "$marker" ] || fail
rm -f "$pending" || fail
fsync "$run" || { (set -C; printf '%s\n' "$marker" > "$pending") 2>/dev/null || :;fail; }
exit 0
