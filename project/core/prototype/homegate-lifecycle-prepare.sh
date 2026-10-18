#!/bin/sh
# Fixed cold-start preparation. Not installed; no production business switch.
set -u
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
runtime_prepare_enabled=false
var_root=/var
tmp_root=/tmp
run_alias=/var/run
linux_run=/run
fail() {
    printf '{"api_version":1,"prototype":true,"ok":false,"phase":"lifecycle-prepare","error":"%s"}\n' "$1"
    exit "${2:-7}"
}
present() { [ -e "$1" ] || [ -L "$1" ]; }
owned_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    case "$(stat -c '%u:%a' "$1" 2>/dev/null)" in "$owner:700"|"$owner:755") ;; *) return 1;; esac
}
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "$owner:700" ]; }
private_lock() {
    [ -f "$lock" ] && [ ! -L "$lock" ] &&
        [ "$(stat -c '%u:%a:%h:%s' "$lock" 2>/dev/null)" = "$owner:600:1:0" ]
}
check_tmp_parent() {
    [ -d "$tmp_root" ] && [ ! -L "$tmp_root" ] || fail 'Unsafe temporary parent'
    case "$(stat -c '%u:%a' "$tmp_root")" in "$owner:1777"|"$owner:700"|"$owner:755") ;; *) fail 'Unsafe temporary parent';; esac
}
check_binding() {
    private_dir "$runtime" && private_lock || fail 'Unsafe runtime writer lock'
    [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/6 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] || fail 'Runtime lock identity changed'
}
[ "$#" -eq 1 ] || fail 'Expected one lifecycle preparation command' 2
case "$1" in prepare) bootstrap_action=bootstrap;; resume) bootstrap_action=resume;; *) fail 'Unsupported lifecycle preparation command' 2;; esac
[ "$runtime_prepare_enabled" = true ] || fail 'Lifecycle preparation is not ready' 2
owner=$(id -u) || fail 'Unable to identify lifecycle owner'
[ "$owner" = 0 ] || fail 'Lifecycle preparation requires root'
# Accept the system /var -> /tmp layout and /var/run -> /run layout, but
# operate on the checked physical runtime parent. Never mkdir a parent chain.
[ -d "$var_root" ] && [ "$(stat -c %u "$var_root" 2>/dev/null)" = "$owner" ] || fail 'Unsafe variable-data parent'
physical_var=$(CDPATH= cd -P "$var_root" && pwd -P) || fail 'Unable to resolve variable-data parent'
case "$physical_var" in
    "$var_root") owned_dir "$var_root" || fail 'Unsafe variable-data parent';;
    "$tmp_root") check_tmp_parent;;
    *) fail 'Unsupported variable-data layout';;
esac
[ -d "$run_alias" ] && [ "$(stat -c %u "$run_alias" 2>/dev/null)" = "$owner" ] || fail 'Unsafe runtime alias'
runtime_base=$(CDPATH= cd -P "$run_alias" && pwd -P) || fail 'Unable to resolve runtime parent'
case "$runtime_base" in
    "$linux_run"|"$var_root/run") ;;
    "$tmp_root/run") check_tmp_parent;;
    *) fail 'Unsupported runtime layout';;
esac
owned_dir "$runtime_base" || fail 'Unsafe runtime parent'
runtime="$runtime_base/homegate"
if ! present "$runtime"; then
    # A competing initializer may win. Validate its result without replacing it.
    mkdir "$runtime" 2>/dev/null || :
fi
private_dir "$runtime" || fail 'Runtime directory must already be private'
lock="$runtime/frontend.lock"
if ! present "$lock"; then
    (set -C; : > "$lock") 2>/dev/null || :
fi
private_lock || fail 'Runtime lock must already be private'
# This lifecycle entry acquires its own open description; it is not an internal
# borrowed-lock command. A live inherited writer must remain busy.
exec 6>&- 7>&- 8>&- 9>&-
# Reserve the same admission lock before acquiring the business lock. Keep it
# through bootstrap, including while a scheduler would otherwise be waiting.
schedule_lock="$runtime/ddns-schedule.lock"
if ! present "$schedule_lock"; then
    (set -C; : > "$schedule_lock") 2>/dev/null || :
    fsync "$schedule_lock" "$runtime" 2>/dev/null || fail 'Schedule lock durability is uncertain'
fi
schedule_file() {
    [ -f "$schedule_lock" ] && [ ! -L "$schedule_lock" ] &&
        [ "$(stat -c '%u:%a:%h:%s' "$schedule_lock")" = "$owner:600:1:0" ]
}
schedule_binding() {
    schedule_file &&
        [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/9 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$schedule_lock")" ]
}
schedule_file || fail 'Unsafe schedule lock'
exec 9>>"$schedule_lock" || fail 'Unable to open schedule lock'
schedule_binding || fail 'Unsafe schedule lock'
flock -n 9 || fail 'Schedule admission is active' 4
schedule_binding || fail 'Schedule lock identity changed'
! present "$runtime/ddns-schedule" || fail 'Schedule control requires explicit stop and reap' 4
for pending in "$runtime/".dns-check-* "$runtime/".ddns-plan-*; do
    ! present "$pending" || fail 'DDNS work requires explicit recovery' 4
done
exec 6>>"$lock" || fail 'Unable to open runtime writer lock'
check_binding
flock -n 6 || fail 'Lifecycle writer is busy' 4
check_binding
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail 'Unable to locate lifecycle dependencies'
if present "$runtime/ddns-ui-jobs";then
    ash "$dir/homegate-ddns-job.sh" check-quiescent >/dev/null 2>/dev/null || fail 'Retained DDNS job requires attention' 4
fi
ash "$dir/homegate-store-bootstrap-prototype.sh" "$bootstrap_action" >/dev/null 2>/dev/null
result=$?
case "$result" in
    0) ;;
    2|4|6|7) fail 'Persistent preparation requires attention' "$result";;
    *) fail 'Persistent preparation failed';;
esac
check_binding
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"lifecycle-prepare","runtime_ready":true,"baseline_ready":true,"readers_switched":false,"production_ready":false}\n'
