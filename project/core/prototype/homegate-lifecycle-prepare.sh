#!/bin/sh
# Fixed cold-start preparation. Not installed; no production business switch.
set -u
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
runtime_prepare_enabled=false
lifecycle_startup_enabled=false
lifecycle_intent_check_enabled=false
lifecycle_intent_record_enabled=false
phase=lifecycle-prepare
startup=false
source_only=false
intent_check=false
record_action=none
desired=
startup_source=/etc/config/homegate
startup_parent=/etc/config
startup_etc=/etc
var_root=/var
tmp_root=/tmp
run_alias=/var/run
linux_run=/run
fail() {
    printf '{"api_version":1,"prototype":true,"ok":false,"phase":"%s","error":"%s"}\n' "$phase" "$1"
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
startup_source_stamp() {
    for parent_path in "$startup_etc" "$startup_parent"; do
        owned_dir "$parent_path" || return 1
    done
    [ -f "$startup_source" ] && [ ! -L "$startup_source" ] &&
        [ "$(stat -c '%u:%a:%h' "$startup_source")" = "$owner:600:1" ] || return 1
    size=$(stat -c %s "$startup_source") || return 1
    [ "$size" -ge 1 ] && [ "$size" -le 262144 ] || return 1
    stamp=$(stat -c '%d:%i:%u:%a:%h:%s' "$startup_source") || return 1
    sum=$(sha256sum "$startup_source") || return 1;sum=${sum%% *}
    [ "$stamp" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$startup_source")" ] || return 1
    printf '%s:%s' "$stamp" "$sum"
}
startup_fences() {
    for pending in "$runtime/".health-read-* "$runtime/".recovery-read-* "$runtime/.ddns-recovery-next" "$runtime/.ddns-recovery-pending"; do
        ! present "$pending" || return 1
    done
}
startup_store_stamp() {
    for metadata in "$store/identity" "$store/gen-$revision/manifest"; do
        [ -f "$metadata" ] && [ ! -L "$metadata" ] &&
            [ "$(stat -c '%u:%a:%h' "$metadata")" = "$owner:600:1" ] || return 1
        size=$(stat -c %s "$metadata") || return 1
        [ "$size" -ge 1 ] && [ "$size" -le 262144 ] || return 1
        stamp=$(stat -c '%d:%i:%u:%a:%h:%s' "$metadata") || return 1
        sum=$(sha256sum "$metadata") || return 1;sum=${sum%% *}
        [ "$stamp" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$metadata")" ] || return 1
        printf '%s:%s\n' "$stamp" "$sum"
    done
}
[ "$#" -ge 1 ] || fail 'Expected a lifecycle preparation command' 2
case "$1" in
    intent-check|record-save|record-resume|record-check|record-apply|record-cancel) [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 'Explicit intent confirmation required' 2
        case "$2" in enabled|disabled) desired=$2;; *) fail 'Invalid requested state' 2;; esac;;
    *) [ "$#" -eq 1 ] || fail 'Expected one lifecycle preparation command' 2;;
esac
case "$1" in prepare) bootstrap_action=bootstrap;; resume) bootstrap_action=resume;;
    startup) bootstrap_action=bootstrap;startup=true;phase=lifecycle-startup;;
    intent) startup=true;source_only=true;phase=lifecycle-source-intent;;
    intent-check) bootstrap_action=bootstrap;startup=true;intent_check=true;phase=lifecycle-intent-check;;
    record-save|record-resume|record-check|record-apply|record-cancel) startup=true;intent_check=true;record_action=${1#record-};phase=lifecycle-intent-record;;
    *) fail 'Unsupported lifecycle preparation command' 2;; esac
[ "$runtime_prepare_enabled" = true ] || fail 'Lifecycle preparation is not ready' 2
[ "$startup" = false ] || [ "$lifecycle_startup_enabled" = true ] || fail 'Startup preparation is not ready' 2
[ "$intent_check" = false ] || [ "$lifecycle_intent_check_enabled" = true ] || fail 'Intent application preflight is not ready' 2
[ "$record_action" = none ] || [ "$lifecycle_intent_record_enabled" = true ] || fail 'Intent record is not ready' 2
owner=$(id -u) || fail 'Unable to identify lifecycle owner'
[ "$owner" = 0 ] || fail 'Lifecycle preparation requires root'
if [ "$startup" = true ]; then
    exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
    dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail 'Unable to locate startup dependencies'
    source_stamp=$(startup_source_stamp) || fail 'Unsafe startup configuration'
    configuration=$(lua "$dir/homegate-startup.lua" source < "$startup_source") || fail 'Startup configuration is invalid' 1
    case "$configuration" in ordinary-enabled|ordinary-disabled|projection-disabled) ;; *) fail 'Startup configuration unavailable';; esac
    [ "$(startup_source_stamp)" = "$source_stamp" ] || fail 'Startup configuration changed'
    if [ "$source_only" = true ]; then
        report=$(lua "$dir/homegate-startup.lua" intent-report "$configuration") || fail 'Enable intent report unavailable'
        [ "$(startup_source_stamp)" = "$source_stamp" ] || fail 'Startup configuration changed'
        printf '%s\n' "$report"
        exit 0
    fi
fi
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
! present "$runtime/proxy" || fail 'Proxy control requires explicit stop and reap' 4
! present "$runtime/ddns-schedule" || fail 'Schedule control requires explicit stop and reap' 4
for pending in "$runtime/".dns-check-* "$runtime/".ddns-plan-*; do
    ! present "$pending" || fail 'DDNS work requires explicit recovery' 4
done
exec 6>>"$lock" || fail 'Unable to open runtime writer lock'
check_binding
flock -n 6 || fail 'Lifecycle writer is busy' 4
check_binding
if [ "$startup" = true ]; then
    startup_fences || fail 'Runtime observations require explicit recovery' 4
    [ "$(startup_source_stamp)" = "$source_stamp" ] || fail 'Startup configuration changed'
fi
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail 'Unable to locate lifecycle dependencies'
if present "$runtime/ddns-ui-jobs";then
    ash "$dir/homegate-ddns-job.sh" check-quiescent >/dev/null 2>/dev/null || fail 'Retained DDNS job requires attention' 4
fi
store=/etc/homegate/transactions
if [ "$record_action" = none ]; then
    ash "$dir/homegate-store-bootstrap-prototype.sh" "$bootstrap_action" >/dev/null 2>/dev/null
    result=$?
    case "$result" in
        0) ;;
        2|4|6|7) fail 'Persistent preparation requires attention' "$result";;
        *) fail 'Persistent preparation failed';;
    esac
else
    private_dir "$store" || fail 'Intent record requires an existing prepared store'
fi
check_binding
if [ "$startup" = true ]; then
    # Bootstrap is metadata preparation only. A pristine or migration-copy
    # baseline must not impersonate an adopted ordinary configuration.
    store=/etc/homegate/transactions
    supervisor=$store/.supervisor.lock
    supervisor_file() {
        [ -f "$supervisor" ] && [ ! -L "$supervisor" ] &&
            [ "$(stat -c '%u:%a:%h:%s' "$supervisor")" = "$owner:600:1:0" ]
    }
    supervisor_binding() {
        supervisor_file &&
            [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/7)" = "$(stat -c '%d:%i:%u:%a:%h' "$supervisor")" ]
    }
    supervisor_file || fail 'Unsafe startup supervisor lock'
    exec 7>>"$supervisor" || fail 'Startup supervisor lock unavailable'
    supervisor_binding || fail 'Unsafe startup supervisor lock'
    flock -n 7 || fail 'Startup supervisor is busy' 4
    supervisor_binding || fail 'Startup supervisor identity changed'
    revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || fail 'Startup revision unavailable'
    store_stamp=$(startup_store_stamp) || fail 'Unsafe startup store binding'
    snapshot() { ash "$dir/homegate-config-prototype.sh" --persistent runtime-startup-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null; }
    validate_bound() { snapshot | lua "$dir/homegate-startup.lua" bound "$revision" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; }
    startup_recheck() {
        check_binding
        schedule_binding && supervisor_binding && startup_fences || fail 'Intent admission changed' 4
        ! present "$runtime/ddns-schedule" || fail 'Schedule control changed' 4
        for pending in "$runtime/".dns-check-* "$runtime/".ddns-plan-*; do
            ! present "$pending" || fail 'DDNS work changed' 4
        done
        [ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current")" = "$revision" ] &&
            [ "$(startup_store_stamp)" = "$store_stamp" ] &&
            [ "$(startup_source_stamp)" = "$source_stamp" ] && [ "$(validate_bound)" = "$configuration" ] &&
            [ "$(startup_store_stamp)" = "$store_stamp" ] &&
            [ "$(startup_source_stamp)" = "$source_stamp" ] || fail 'Intent application binding changed'
    }
    bound=$(validate_bound) || fail 'Startup requires a valid published ordinary source'
    [ "$bound" = "$configuration" ] && [ "$(validate_bound)" = "$bound" ] || fail 'Startup configuration changed'
    check_binding
    supervisor_binding && startup_fences || fail 'Startup admission changed' 4
    [ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current")" = "$revision" ] &&
        [ "$(startup_store_stamp)" = "$store_stamp" ] &&
        [ "$(startup_source_stamp)" = "$source_stamp" ] || fail 'Startup source changed'
    if [ "$record_action" != none ]; then
        record="$store/startup-intent";record_stage="$store/.startup-intent-next"
        # Candidate bytes enter only the hash pipe. A separate FD carries the
        # producer result: portable ash must not accept the hash of a failure.
        . "$dir/startup-record.sh"
        startup_record_expected
        record_validate() {
            private_dir "$record_path" || return 1
            for entry in "$record_path/"* "$record_path/".[!.]* "$record_path/"..?*; do
                present "$entry" || continue
                [ "$entry" = "$record_path/context" ] || return 1
            done
            [ -f "$record_path/context" ] && [ ! -L "$record_path/context" ] &&
                [ "$(stat -c '%u:%a:%h' "$record_path/context")" = "$owner:600:1" ] &&
                [ "$(stat -c %s "$record_path/context")" -eq "$((${#record_body}+1))" ] || return 1
            sum=$(sha256sum "$record_path/context") || return 1
            [ "${sum%% *}" = "$expected_sum" ] || return 1
        }
        record_stamp() { stat -c '%d:%i:%u:%a:%h:%s' "$record_path" "$record_path/context"; }
        startup_recheck
        if [ "$record_action" = save ]; then
            ! present "$record" && ! present "$record_stage" || fail 'Intent record already requires attention' 4
            mkdir "$record_stage" || fail 'Unable to allocate intent stage'
            record_path=$record_stage
            (set -C; printf '%s\n' "$record_body" > "$record_path/context") || fail 'Unable to write intent record'
        else
            if present "$record"; then
                ! present "$record_stage" || fail 'Conflicting intent records'
                record_path=$record
            else
                if ! present "$record_stage" && [ "$record_action" = apply ];then
                    ! present "$store/.startup-active-next" || fail 'Active intent stage requires attention' 6
                    startup_record_file "$store/startup-active" && startup_recheck || fail 'No matching applied intent'
                    fsync "$store/startup-active" "$store" 2>/dev/null || fail 'Active intent durability uncertain' 6
                    lua "$dir/homegate-startup.lua" record-report "$revision" "$desired" prepared apply || fail 'Intent result unavailable'
                    exit 0
                fi
                present "$record_stage" || fail 'No retained intent record'
                record_path=$record_stage
            fi
        fi
        active_record="$store/startup-active";active_stage="$store/.startup-active-next"
        if [ "$record_action" = apply ] || [ "$record_action" = cancel ];then
            for existing_active in "$active_record" "$active_stage";do
                ! present "$existing_active" || startup_record_framed "$existing_active" || fail 'Unsafe active intent'
            done
            if ! record_validate;then
                private_dir "$record_path" && [ -z "$(ls -A "$record_path")" ] || fail 'Retained intent record does not match current candidate'
                # An empty checked directory carries no candidate or DNS data.
                # Cancel may finish only this cleanup; apply needs exact active bytes.
                if [ "$record_action" = apply ];then startup_record_file "$active_record" || fail 'Incomplete intent cleanup requires attention';fi
            fi
            startup_recheck
            if [ "$record_action" = cancel ];then
                ! present "$active_stage" || fail 'Active intent stage requires apply resume' 6
                if startup_record_file "$active_record";then fail 'Intent already applied; resume apply' 6;fi
            else
                # Revoke before publishing either switch state. The preparation
                # fence stays until both revocation and active durability hold.
                ash "$dir/homegate-ddns-authority.sh" cancel --confirm >/dev/null 2>/dev/null || fail 'Unable to cancel old grant confirmation' 4
                if present "$store/ddns-authority";then
                    ash "$dir/homegate-ddns-authority.sh" revoke --confirm >/dev/null 2>/dev/null || fail 'Unable to revoke previous DDNS authority' 4
                fi
                startup_recheck
                if present "$active_stage";then startup_record_file "$active_stage" || fail 'Conflicting active intent stage'
                else (set -C; printf '%s\n' "$record_body" > "$active_stage") || fail 'Unable to stage active intent';fi
                fsync "$active_stage" "$store" 2>/dev/null || fail 'Active intent durability uncertain' 6
                mv -f "$active_stage" "$active_record" || fail 'Unable to publish active intent'
                fsync "$active_record" "$store" 2>/dev/null || fail 'Active intent durability uncertain' 6
                startup_record_file "$active_record" || fail 'Active intent changed'
            fi
            # All entries were checked by record_validate (or its exact empty
            # cleanup case). Never remove DNS/application recovery evidence.
            if present "$record_path/context";then rm -f "$record_path/context" || fail 'Unable to finish intent cleanup' 6;fi
            rmdir "$record_path" && fsync "$store" 2>/dev/null || fail 'Intent cleanup durability uncertain' 6
            lua "$dir/homegate-startup.lua" record-report "$revision" "$desired" prepared "$record_action" || fail 'Intent result unavailable'
            exit 0
        fi
        record_validate || fail 'Retained intent record does not match current candidate'
        retained_stamp=$(record_stamp) || fail 'Intent record identity unavailable'
        if [ "$record_action" != check ]; then
            fsync "$record_path/context" "$record_path" "$store" 2>/dev/null || fail 'Intent record durability uncertain' 6
            startup_recheck
            record_validate && [ "$(record_stamp)" = "$retained_stamp" ] || fail 'Intent record changed'
            if [ "$record_path" = "$record_stage" ]; then
                ! present "$record" || fail 'Intent destination appeared'
                mv "$record_stage" "$record" || fail 'Unable to publish intent record'
                record_path=$record
                record_validate && [ "$(record_stamp)" = "$retained_stamp" ] || fail 'Published intent record identity changed'
            fi
            fsync "$record_path/context" "$record_path" "$store" 2>/dev/null || fail 'Published intent durability uncertain' 6
        fi
        startup_recheck
        record_validate && [ "$(record_stamp)" = "$retained_stamp" ] || fail 'Intent record changed'
        state=prepared;[ "$record_path" != "$record_stage" ] || state=staged
        report=$(lua "$dir/homegate-startup.lua" record-report "$revision" "$desired" "$state" "$record_action") || fail 'Intent record report unavailable'
        startup_recheck
        record_validate && [ "$(record_stamp)" = "$retained_stamp" ] || fail 'Intent record changed'
        printf '%s\n' "$report"
    elif [ "$intent_check" = true ]; then
        report=$(snapshot | lua "$dir/homegate-startup.lua" request-report "$revision" "$configuration" "$desired" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-) || fail 'Intent application report unavailable'
        startup_recheck
        printf '%s\n' "$report"
    else
        lua "$dir/homegate-startup.lua" report "$revision" "$configuration" || fail 'Startup report unavailable'
    fi
    exit 0
fi
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"lifecycle-prepare","runtime_ready":true,"baseline_ready":true,"readers_switched":false,"production_ready":false}\n'
