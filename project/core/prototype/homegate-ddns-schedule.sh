#!/bin/sh
# Foreground, finite admissions; cooperative stop never signals stored PIDs.
set -u
umask 077
export LC_ALL=C
ddns_schedule_enabled=false
ddns_schedule_continuous_enabled=false
ddns_schedule_events_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-schedule","effect":"none","write_ready":false,"error":"DDNS schedule is unavailable"}\n';exit "${1:-7}"; }
action=${1:-}
mode=run
[ "$action" != serve ] || mode=serve
case "$action" in serve) [ "$ddns_schedule_enabled" = true ] && [ "$ddns_schedule_continuous_enabled" = true ] && [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
    run) [ "$ddns_schedule_enabled" = true ] && [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
    status|quiescent) [ "$#" -eq 1 ] || fail 2;; stop|reap) [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
    event) [ "$ddns_schedule_events_enabled" = true ] && [ "$#" -eq 4 ] || fail 2
        event_action=$2;event_interface=$3;event_device=$4
        case "$event_action" in ifup|ifupdate|ifdown) ;; *) fail 2;; esac
        case "$event_interface:$event_device" in *[!a-zA-Z0-9_.:-]*) fail 2;; esac
        [ "${#event_interface}" -le 64 ] && [ "${#event_device}" -le 32 ] || fail 2;;
    *) fail 2;; esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
exec 2>/dev/null
owner=$(id -u) || fail;[ "$owner" = 0 ] || fail
run=/var/run/homegate;store=/etc/homegate/transactions
work=$run/ddns-schedule;lease=$work/lease;report=$work/report
runlock=$run/ddns-schedule.lock;control=$run/ddns-schedule.control.lock
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ]; }
event_reply() { printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-network-event","matched":%s,"active":%s,"effect":"none","write_ready":false}\n' "$1" "$2"; }
if [ "$action" = event ] && ! exists "$work";then event_reply false false;exit 0;fi
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ]; }
private_dir "$run" && private_dir "$store" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
now() { moment=$(lua "$dir/worker-process.lua" now 2>/dev/null) || return 1; }
framed() { digest=$(printf '%s\n' "$payload" | sha256sum) || return 1;printf '%s\n' "$payload" "${digest%% *}"; }
checked() {
    private_file "$1" && [ "$(stat -c %s "$1")" -le 4096 ] || return 1
    exec 3<"$1" || return 1;IFS= read -r payload <&3 && IFS= read -r digest <&3 || return 1
    if IFS= read -r extra <&3; then return 1;fi;exec 3<&-
    expected=$(framed) || return 1
    [ "$(stat -c %s "$1")" -eq "$((${#expected}+1))" ] && [ "$(cat "$1")" = "$expected" ]
}
publish() {
    ! exists "$destination.next" || return 1
    (set -C; : > "$destination.next") 2>/dev/null && framed > "$destination.next" && private_file "$destination.next" &&
        fsync "$destination.next" "$work" 2>/dev/null && mv -f "$destination.next" "$destination" && fsync "$destination" "$work" 2>/dev/null
}
locks() {
    for lock in "$runlock" "$control"; do
        if ! exists "$lock"; then (set -C; : > "$lock") 2>/dev/null || return 1;fsync "$lock" "$run" 2>/dev/null || return 1;fi
        private_file "$lock" && [ "$(stat -c %s "$lock")" -eq 0 ] || return 1
    done
}
bound_lock() {
    private_file "$2" && [ "$(stat -c %s "$2")" -eq 0 ] &&
        [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$1 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$2")" ]
}
open_control() { exec 4>>"$control" || return 1;flock -n 4 && bound_lock 4 "$control"; }
business_lock() {
    exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock" || return 1
    flock -n 6 && flock -n 7 && bound_lock 6 "$run/frontend.lock" && bound_lock 7 "$store/.supervisor.lock"
}
business_unlock() { exec 6>&- 7>&-; }
binding() {
    ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || return 1
    revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null) || return 1
    names=$(ash "$dir/homegate-ddns-authority.sh" check 2>/dev/null | lua "$dir/homegate-ddns-batch.lua" names "$revision" 2>/dev/null) || return 1
    hash "$store/identity" || return 1;identity=$sum;hash "$store/gen-$revision/manifest" || return 1;generation=$sum
    hash "$store/ddns-authority" || return 1;grant=$sum;boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    binding_seen=$identity:$generation:$grant:$revision:$boot
}
read_lease() {
    private_dir "$work" && checked "$lease" || return 1
    exec 3<"$lease" || return 1;info=$(lua "$dir/homegate-ddns-schedule.lua" inspect 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- 2>/dev/null) || return 1
    old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs;[ "$#" -eq 11 ] || return 1
    pid=$1;birth=$2;lease_boot=$3;token=$4;lease_revision=$5;deadline=$6;lease_identity=$7;lease_generation=$8;lease_grant=$9;shift 9;started=$1;lease_mode=$2
}
alive() {
    live=false
    [ "$(cat /proc/sys/kernel/random/boot_id)" = "$lease_boot" ] || return 0
    info=$(lua "$dir/worker-process.lua" info "$pid" none 2>/dev/null) || return 1
    [ -n "$info" ] || return 0
    old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs;[ "$#" -eq 6 ] || return 1
    [ "$5" = "$birth" ] || return 0;case "$1" in Z|X) return 0;; esac
    lua "$dir/homegate-ddns-schedule.lua" owner "$pid" "$lease_mode" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>/dev/null || return 1
    [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/$pid/fd/9 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$runlock")" ] || return 1
    live=true
}
check_members() {
    private_dir "$work" || return 1
    for p in "$work/"* "$work/".[!.]* "$work/"..?*; do
        exists "$p" || continue;private_file "$p" || return 1
        case "${p##*/}" in lease|lease.next|report|report.next) maximum=4096;; batch) maximum=65536;; stop|stop.next|wake|wake.next) maximum=33;; *) return 1;; esac
        [ "$(stat -c %s "$p")" -le "$maximum" ] || return 1
    done
}
stop_content() {
    check_members || return 1
    stopping=false
    for p in "$work/stop" "$work/stop.next"; do
        if exists "$p"; then private_file "$p" && [ "$(stat -c %s "$p")" -eq 33 ] && [ "$(cat "$p")" = "$token" ] || return 1;stopping=true;fi
    done
}
stop_read() {
    control_busy=false
    opened=false
    if [ "$(stat -Lc '%d:%i' /proc/self/fd/4 2>/dev/null)" != "$(stat -c '%d:%i' "$control")" ]; then exec 4>>"$control" || return 1;opened=true;fi
    if ! flock -n 4; then
        # A stop writer owns this lock. Admit nothing while its intent is being
        # published; never mistake its briefly empty stage for durable damage.
        [ "$opened" = false ] || exec 4>&-
        if [ "$ddns_schedule_events_enabled" = true ];then control_busy=true;stopping=false
        else stopping=true;fi
        return 0
    fi
    stop_rc=0;stop_content || stop_rc=$?
    [ "$opened" = false ] || exec 4>&-
    return "$stop_rc"
}
public_status() {
    checked "$report" || return 1;exec 3<"$report" || return 1
    lua "$dir/homegate-ddns-schedule.lua" status "$live" "$stopping" 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- 2>/dev/null
}
token_file() { private_file "$1" && [ "$(stat -c %s "$1")" -eq 33 ] && [ "$(cat "$1")" = "$token" ]; }
wake_take() {
    woke=false
    if ! exists "$work/wake" && ! exists "$work/wake.next";then return 0;fi
    if ! open_control;then exec 4>&-;control_busy=true;return 0;fi
    if exists "$work/wake.next";then token_file "$work/wake.next" || return 1;fi
    if exists "$work/wake";then token_file "$work/wake" && rm -f "$work/wake" && fsync "$work" || return 1;woke=true;fi
    exec 4>&-
}
token_publish() {
    target=$1
    if exists "$target";then token_file "$target" || return 1;return 0;fi
    if exists "$target.next";then token_file "$target.next" || return 1
    else (set -C; : > "$target.next") && printf '%s\n' "$token" > "$target.next" || return 1;fi
    fsync "$target.next" "$work" && mv -f "$target.next" "$target" && fsync "$target" "$work"
}
validate_control() {
    check_members || return 1
    for p in "$work/"* "$work/".[!.]* "$work/"..?*; do
        exists "$p" || continue
        case "${p##*/}" in
            lease) checked "$p" || return 1;;
            lease.next) checked "$p" && [ "$(cat "$p")" = "$(cat "$lease")" ] || return 1;;
            report|report.next) checked "$p" || return 1;exec 3<"$p" || return 1;lua "$dir/homegate-ddns-schedule.lua" check-report 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>/dev/null || return 1;;
            stop|stop.next) stop_read || return 1;;
            wake|wake.next) token_file "$p" || return 1;;
            batch) ;;
            *) return 1;;
        esac
    done
}
if [ "$action" = quiescent ]; then
    # A point-in-time observation. No lock creation, cleanup, permission grant
    # or claim about the old production daemon follows from this response.
    if exists "$runlock"; then
        private_file "$runlock" || fail;exec 9>>"$runlock" || fail;flock -n 9 && bound_lock 9 "$runlock" || fail 4
    elif exists "$work"; then fail;fi
    if exists "$control"; then private_file "$control" && open_control || fail 4;fi
    if exists "$work"; then
        private_file "$runlock" && private_file "$control" || fail
        if ! exists "$lease" && exists "$lease.next"; then lease=$lease.next;fi
        read_lease && alive && stop_read && validate_control || fail
        [ "$live" = false ] || fail 4
    fi
    business_lock && ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || fail 4
    for p in "$run/".dns-check-* "$run/".ddns-plan-*; do ! exists "$p" || fail 4;done
    if exists "$run/ddns-ui-jobs";then ash "$dir/homegate-ddns-job.sh" check-quiescent >/dev/null 2>/dev/null || fail 4;fi
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-quiescent","quiescent":true,"point_in_time":true,"effect":"none","write_ready":false,"production_ready":false}\n'
    exit 0
fi
if [ "$action" = event ];then
    private_file "$runlock" && private_file "$control" && open_control || fail 4
    read_lease && alive && stop_read || fail
    [ "$live" = true ] && [ "$stopping" = false ] || { event_reply false false;exit 0; }
    now && { [ "$lease_mode" = serve ] || [ "$moment" -lt "$deadline" ]; } || fail 4
    # Signals cannot authorize work. Inspect the immutable configuration bound
    # by this lease without contending with an admitted provider's business
    # locks, so ifdown can request cooperative stop during a running batch.
    private_file "$store/identity" && private_dir "$store/gen-$lease_revision" && private_file "$store/gen-$lease_revision/manifest" && private_file "$store/gen-$lease_revision/public.conf" || fail
    hash "$store/identity" && [ "$sum" = "$lease_identity" ] || fail
    hash "$store/gen-$lease_revision/manifest" && [ "$sum" = "$lease_generation" ] || fail
    [ "$(stat -c %s "$store/gen-$lease_revision/public.conf")" -le 262144 ] || fail
    # The immutable manifest SHA is lease-bound and was validated at admission.
    # Hash the one known public file used by this signal; never interpret paths
    # supplied by a manifest or require optional BusyBox checksum-check support.
    IFS= read -r public_binding < "$store/gen-$lease_revision/manifest" || fail
    public_actual=$(cd "$store/gen-$lease_revision" && sha256sum public.conf) || fail
    [ "$public_binding" = "$public_actual" ] || fail
    matched=$(lua "$dir/homegate-ddns-schedule.lua" event "$event_interface" "$event_device" '*' < "$store/gen-$lease_revision/public.conf") || fail
    [ "$matched" = true ] || { event_reply false true;exit 0; }
    if [ "$event_action" = ifdown ];then token_publish "$work/stop" || fail
    else token_publish "$work/wake" || fail;fi
    event_reply true true;exit 0
fi
if [ "$action" = status ] && ! exists "$work"; then
    lua "$dir/homegate-ddns-schedule.lua" report true idle '' 0 none 2>/dev/null || fail;exit 0
fi
if [ "$action" = run ] || [ "$action" = serve ]; then
    if exists "$run/acme-schedule";then ash "$dir/homegate-acme-schedule.sh" quiescent >/dev/null 2>/dev/null || fail 4;fi
    locks || fail;exec 9>>"$runlock" || fail;flock -n 9 && bound_lock 9 "$runlock" || fail 4;open_control || fail 4
    ! exists "$work" || fail 4
    business_lock || fail 4
    if exists "$run/acme-schedule";then ash "$dir/homegate-acme-schedule.sh" quiescent >/dev/null 2>/dev/null || fail 4;fi
    binding && now || fail 4
    bound=$binding_seen;started=$moment;deadline=$((moment+900));ticks=0;last_effect=none;interrupted=false
    trap 'interrupted=true' TERM INT
    info=$(lua "$dir/worker-process.lua" info "$$" none 2>/dev/null) || fail
    old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs;[ "$#" -eq 6 ] || fail;birth=$5
    token=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 2>/dev/null) || fail
    mkdir "$work" && fsync "$run" 2>/dev/null || fail
    payload=$(lua "$dir/homegate-ddns-schedule.lua" lease "$identity" "$generation" "$grant" "$revision" "$boot" "$$" "$birth" "$token" "$started" "$mode" 2>/dev/null) || fail
    destination=$lease;publish || fail
    (set -C; : > "$work/batch") 2>/dev/null && private_file "$work/batch" || fail
    exec 4>&-;business_unlock
else
    private_file "$runlock" && private_file "$control" || fail
    if [ "$action" = reap ]; then exec 9>>"$runlock" || fail;flock -n 9 && bound_lock 9 "$runlock" || fail 4;fi
    if [ "$action" != status ]; then open_control || fail 4;fi
    if [ "$action" = reap ] && ! exists "$lease" && exists "$lease.next"; then lease=$lease.next;fi
    read_lease && alive && stop_read || fail
    if [ "$action" = stop ]; then
        if [ "$live" = true ]; then
            if ! exists "$work/stop"; then
                if ! exists "$work/stop.next"; then (set -C; : > "$work/stop.next") 2>/dev/null && printf '%s\n' "$token" > "$work/stop.next" || fail;fi
                stop_read && fsync "$work/stop.next" "$work" 2>/dev/null && mv -f "$work/stop.next" "$work/stop" && fsync "$work/stop" "$work" 2>/dev/null || fail
            fi
            stopping=true
        fi
        public_status || fail;exit 0
    elif [ "$action" = status ]; then public_status || fail;exit 0;fi
    [ "$live" = false ] || fail 4
    business_lock && ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || fail 4
    for p in "$run/".dns-check-* "$run/".ddns-plan-*; do ! exists "$p" || fail 4;done
    validate_control || fail
    for name in lease lease.next report report.next stop stop.next wake wake.next batch; do rm -f "$work/$name" || fail;done
    rmdir "$work" && fsync "$run" 2>/dev/null || fail
    lua "$dir/homegate-ddns-schedule.lua" report true idle '' 0 none 2>/dev/null || fail;exit 0
fi
emit() {
    payload=$(lua "$dir/homegate-ddns-schedule.lua" report "$1" "$2" "$3" "$ticks" "$last_effect" "$mode" 2>/dev/null) || return 1
    destination=$report;publish
}
finish() { business_unlock;emit "$1" finished "$2" || fail;printf '%s\n' "$payload";exit "$3"; }
emit true running '' || fail
last_now=$started
while :; do
    now && [ "$moment" -ge "$last_now" ] || finish false clock_invalid 7;last_now=$moment
    stop_read || finish false failed 7
    if [ "$stopping" = true ] || [ "$interrupted" = true ]; then finish true stopped 0;fi
    [ "$mode" = serve ] || [ "$moment" -lt "$deadline" ] || finish true budget 0
    if [ "$mode" = serve ];then [ "$ticks" -lt 2147483647 ] || finish true ticks 0
    else [ "$ticks" -lt 8 ] || finish true ticks 0;fi
    if [ "$control_busy" = true ];then sleep 0.05 || finish false failed 7;continue;fi
    business_lock || finish false blocked 4
    binding && [ "$binding_seen" = "$bound" ] || finish false changed 4
    states=
    for rule in $names; do
        info=$(ash "$dir/homegate-ddns-state.sh" status "$rule" 9>&- 2>/dev/null | lua "$dir/homegate-ddns-schedule.lua" state "$revision" "$rule" 9>&- 2>/dev/null) || finish false failed 7
        status=${info%%:*};delay=${info#*:}
        states=${states:+$states }$rule:$status:$delay
    done
    decision=$(lua "$dir/homegate-ddns-schedule.lua" decision $states 9>&- 2>/dev/null) || finish false failed 7
    wait_for=${decision#*:};decision=${decision%%:*}
    case "$decision" in ready|wait) ;; idle) finish true idle 0;; blocked) finish false blocked 4;; *) finish false failed 7;; esac
    if [ "$decision" = wait ]; then
        emit true waiting '' || fail;business_unlock
        now || finish false clock_invalid 7;[ "$mode" != serve ] || [ "$wait_for" -le 60 ] || wait_for=60;wake=$((moment+wait_for));[ "$mode" = serve ] || [ "$wake" -le "$deadline" ] || wake=$deadline
        while :; do
            stop_read || finish false failed 7
            if [ "$stopping" = true ] || [ "$interrupted" = true ]; then finish true stopped 0;fi
            now && [ "$moment" -ge "$last_now" ] || finish false clock_invalid 7;last_now=$moment
            [ "$moment" -lt "$wake" ] || break
            if [ "$control_busy" = false ];then
                wake_take || finish false failed 7
                [ "$woke" = false ] || break
            fi
            sleep 1 || { [ "$interrupted" = true ] || finish false failed 7; }
        done
        continue
    fi
    # Stop is cooperative. Once admitted, retain both locks until the existing
    # bounded batch and its supervised provider family have finished.
    now && [ "$moment" -ge "$last_now" ] || finish false clock_invalid 7;last_now=$moment
    [ "$mode" = serve ] || [ "$moment" -lt "$deadline" ] || finish true budget 0
    stop_read || finish false failed 7
    if [ "$stopping" = true ] || [ "$interrupted" = true ]; then finish true stopped 0;fi
    if [ "$control_busy" = true ];then business_unlock;sleep 0.05 || finish false failed 7;continue;fi
    ticks=$((ticks+1));emit true running '' || fail
    ash "$dir/homegate-ddns-batch.sh" sync --confirm 4>&- 9>&- > "$work/batch" 2>/dev/null & child=$!
    child_info=$(lua "$dir/worker-process.lua" info "$child" none 2>/dev/null) || fail
    child_birth=
    if [ -n "$child_info" ]; then old_ifs=$IFS;IFS=:;set -- $child_info;IFS=$old_ifs;[ "$#" -eq 6 ] || fail;child_birth=$5;fi
    rc=0
    while :; do
        rc=0
        wait "$child" || rc=$?
        info=$(lua "$dir/worker-process.lua" info "$child" none 2>/dev/null) || fail
        [ -n "$info" ] && [ -n "$child_birth" ] || break
        old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
        [ "$5" = "$child_birth" ] || break;case "$1" in Z|X) break;; esac
        sleep 0.05 || :
    done
    private_file "$work/batch" && [ "$(stat -c %s "$work/batch")" -le 65536 ] || fail
    selection=;for item in $names; do selection=${selection:+$selection,}$item;done
    effect=$(lua "$dir/homegate-ddns-schedule.lua" batch "$revision" "$rc" "$selection" < "$work/batch" 9>&- 2>/dev/null) || { last_effect=unknown;finish false failed 7; }
    case "$effect" in unknown) last_effect=unknown;finish false reconciliation_required 4;; confirmed) last_effect=confirmed;finish false blocked 4;; none) ;; *) last_effect=unknown;finish false failed 7;; esac
    case "$rc" in 0|1|4) ;; *) finish false failed 7;; esac
    business_unlock
done
