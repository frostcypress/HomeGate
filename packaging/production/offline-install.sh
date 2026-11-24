#!/bin/sh
set -eu
umask 077
export LC_ALL=C
unset IPKG_INSTROOT OFFLINE_ROOT IPKG_NO_SCRIPT

version=@VERSION@
minimum_release=@MINIMUM_RELEASE@
target_release=@RELEASE@
series=${version%-r*}
architecture=@ARCHITECTURE@
nginx_version=@NGINX_VERSION@
wol_version=@WOL_VERSION@
core=homegate-core
web=luci-app-homegate
language=luci-i18n-homegate-zh-cn
store=/etc/homegate/transactions
checkpoint=
upgrade_from=
upgrade_stage=precheck

fail() {
    printf 'homegate_offline_failed=%s\n' "$1" >&2
    exit 7
}

@DNS_MIGRATION_CHECK@

case "$#:$*" in
    1:--fresh) mode=fresh;;
    1:--migrate) mode=migrate;;
    *) fail choose_fresh_or_migrate;;
esac
[ "$(id -u)" = 0 ] || fail root_required
cd -P "$(dirname "$0")"
bundle=$PWD
sha256sum -c SHA256SUMS || fail bundle_checksum

write_upgrade_log() {
    for attempt in 1 2 3; do
        if ash "$bundle/upgrade-log.sh" package-upgrade "$1" "$upgrade_from" "$version" "$2" >/dev/null 2>&1; then
            return 0
        fi
        [ "$attempt" -eq 3 ] || sleep 1
    done
    printf 'homegate_upgrade_log_warning=%s\n' "$1" >&2
    return 1
}

record_upgrade_verified() {
    [ -n "$upgrade_from" ] || return 0
    receipt="$checkpoint/upgrade-log-verified"
    if [ -e "$receipt" ] || [ -L "$receipt" ]; then
        if [ -f "$receipt" ] && [ ! -L "$receipt" ] &&
           [ "$(stat -c '%u:%a:%h:%s' "$receipt")" = 0:600:1:0 ]; then
            return 0
        fi
        printf 'homegate_upgrade_log_warning=verified_receipt\n' >&2
        return 0
    fi
    if write_upgrade_log verified none; then
        # The logger deduplicates a retry between the log write and this receipt.
        if ! (set -C; : > "$receipt") || ! fsync "$receipt" "$checkpoint"; then
            printf 'homegate_upgrade_log_warning=verified_receipt\n' >&2
        fi
    fi
}

work=$(mktemp -d /tmp/homegate-offline.XXXXXX)
cleanup() {
    status=$?
    if [ "$status" -ne 0 ] && [ -n "$upgrade_from" ] && [ -n "$upgrade_stage" ]; then
        write_upgrade_log failed "$upgrade_stage" || :
    fi
    rm -f "$work/architectures" "$work/opkg.conf" "$work/installed" "$work/plan" || :
    rmdir "$work/empty-conf" "$work/empty-lists" "$work" 2>/dev/null || :
    exit "$status"
}
trap cleanup EXIT
mkdir "$work/empty-conf" "$work/empty-lists"
opkg print-architecture > "$work/architectures" || fail architecture_query
awk -v arch="$architecture" '$1=="arch" && $2==arch && $3~/^[0-9]+$/ {ok=1} END {exit !ok}' \
    "$work/architectures" || fail target_architecture
{
    printf 'dest root /\nlists_dir ext %s\n' "$work/empty-lists"
    cat "$work/architectures"
} > "$work/opkg.conf"
export OPKG_CONF_DIR="$work/empty-conf"
pkg() { opkg -f "$work/opkg.conf" -l "$work/empty-lists" -t "$work" "$@"; }
read_packages() { pkg list-installed > "$work/installed" || fail package_query; }
installed() { awk -v package="$1" '$1==package && $2=="-" {print $3}' "$work/installed"; }

supported_source() {
    local source_release
    case "$1" in
        1.3.0-r240|1.3.0-r265) return 0;;
        "$series"-r*) source_release=${1##*-r};;
        *) return 1;;
    esac
    case "$source_release" in ''|0*|*[!0-9]*) return 1;; esac
    [ "${#source_release}" -le 9 ] && [ "$source_release" -ge "$minimum_release" ] &&
        [ "$source_release" -lt "$target_release" ]
}

find_checkpoint() {
    local path source_release
    for path in /etc/.homegate-r*-before-r"$target_release"; do
        [ -e "$path" ] || [ -L "$path" ] || continue
        source_release=${path##*/.homegate-r}
        source_release=${source_release%-before-r"$target_release"}
        supported_source "$series-r$source_release" || continue
        [ -z "$checkpoint" ] || fail ambiguous_checkpoint
        checkpoint=$path
    done
    [ -n "$checkpoint" ] || fail checkpoint_missing
}
observe_procd() {
    sample=$(lua /usr/libexec/homegate/project/core/prototype/homegate-service-observer.lua 3>&1 >/dev/null) ||
        return 1
    printf '%s\n' "$sample" | awk 'NR==1 {h=$0} NR==2 {b=$0} NR==3 {r=$0}
             END {if (NR!=4 || h!="HGSERVICE1" || b!~/^[01]$/ || r!~/^[01]$/) exit 1; print b ":" r}'
}
boot_enabled() {
    if /etc/init.d/homegate enabled >/dev/null 2>&1; then
        printf '1\n'
    else
        [ "$?" -eq 1 ] || return 1
        printf '0\n'
    fi
}
observe_native() {
    boot=$(boot_enabled) || return 1
    snapshot=$(ash /usr/libexec/homegate/native-service.sh overview-status) || return 1
    running=$(printf '%s\n' "$snapshot" | lua -e '
        local d=require("luci.jsonc").parse(io.read("*a"))
        if type(d)~="table" or d.ok~=true or type(d.service)~="table" or type(d.coordinator)~="table" then os.exit(1) end
        if d.service.running==true and type(d.runtime)=="table" and type(d.runtime.pid)=="number" and d.runtime.pid>=2 then
            print(1)
        elseif d.service.running==false and d.coordinator.state=="stopped" and d.runtime==nil then
            print(0)
        else
            os.exit(1)
        end
    ') || return 1
    if [ "$running" = 0 ]; then
        # An unlocked native owner alone cannot prove that procd has no instance.
        registration=$(ubus -t 2 -S call service list '{"name":"homegate"}') || return 1
        printf '%s\n' "$registration" | awk '
            {body=body $0 "\n"}
            END {exit !(body ~ /^[[:space:]]*[{][[:space:]]*[}][[:space:]]*$/ ||
                body ~ /^[[:space:]]*[{][[:space:]]*"homegate"[[:space:]]*:[[:space:]]*[{][[:space:]]*[}][[:space:]]*[}][[:space:]]*$/ ||
                body ~ /^[[:space:]]*[{][[:space:]]*"homegate"[[:space:]]*:[[:space:]]*[{][[:space:]]*"autostart"[[:space:]]*:[[:space:]]*false[[:space:]]*[}][[:space:]]*[}][[:space:]]*$/)}
        ' || return 1
    fi
    confirmed=$(ash /usr/libexec/homegate/native-service.sh overview-status) || return 1
    [ "$confirmed" = "$snapshot" ] && [ "$(boot_enabled)" = "$boot" ] || return 1
    printf '%s:%s\n' "$boot" "$running"
}
observe() {
    if observe_procd; then return 0; fi
    result=$(observe_native) || return 1
    printf 'runtime_state_source=native\n' >&2
    printf '%s\n' "$result"
}
observe_with_retry() {
    attempt=1
    while [ "$attempt" -le 3 ]; do
        if result=$(observe); then printf '%s\n' "$result"; return 0; fi
        [ "$attempt" -eq 3 ] || sleep 1
        attempt=$((attempt+1))
    done
    printf '%s\n' 'runtime_state_check=procd_and_native_unconfirmed' >&2
    return 1
}

wait_for_service_stop() {
    /usr/bin/homegate service-stop --confirm >/dev/null || fail service_stop_request
    remaining=60
    until /usr/bin/homegate service-quiescent >/dev/null; do
        [ "$remaining" -gt 0 ] || fail service_stop_timeout
        sleep 1
        remaining=$((remaining - 1))
    done
}

config_state() {
    status=$(/usr/bin/homegate config-status) || {
        printf '%s\n' 'configuration_check=status_unavailable' >&2
        return 1
    }
    printf '%s\n' "$status" | lua -e '
        local d=require("luci.jsonc").parse(io.read("*a"))
        if type(d)~="table" or d.ok~=true then
            io.stderr:write("configuration_check=invalid_status\n")
            os.exit(1)
        end
        for _,name in ipairs({"preview_present","application_pending","workers_pending","persistent_fence_pending"}) do
            if d[name]~=false then
                io.stderr:write("configuration_check=",name,"=",d[name]==true and "true" or "unknown","\n")
                os.exit(1)
            end
        end
        if type(d.revision)~="number" or d.revision<1 or d.revision%1~=0 then
            io.stderr:write("configuration_check=invalid_revision\n")
            os.exit(1)
        end
        print(d.revision)
    '
}
checked_checkpoint() {
    [ -d "$checkpoint" ] && [ ! -L "$checkpoint" ] &&
        [ "$(stat -c '%u:%a' "$checkpoint")" = 0:700 ] || return 1
    for file in state.tar SHA256SUMS live.sha256 observed; do
        [ -f "$checkpoint/$file" ] && [ ! -L "$checkpoint/$file" ] &&
            [ "$(stat -c '%u:%a:%h' "$checkpoint/$file")" = 0:600:1 ] || return 1
    done
    (cd "$checkpoint" && sha256sum -c SHA256SUMS >/dev/null) &&
        sha256sum -c "$checkpoint/live.sha256" >/dev/null
}
check_expected_packages() {
    read_packages
    for name in "$core" "$web" "$language"; do
        [ "$(installed "$name")" = "$version" ] || fail "package_version:$name"
    done
    (cd / && sha256sum -c "$bundle/installed-SHA256SUMS" >/dev/null) || fail installed_payload
    report=$(/usr/libexec/homegate/components/nginx -v 2>&1) || fail nginx_execution
    [ "$report" = "nginx version: nginx/$nginx_version (homegate-ip-san-v1)" ] || fail nginx_version
    printf '%s\n' "$report"
    report=$(/usr/libexec/homegate/components/wol-send --version) || fail wol_execution
    [ "$report" = "homegate-wol $wol_version" ] || fail wol_version
    printf '%s\n' "$report"
}
retire_legacy() {
    set --
    for name in homegate-nginx homegate-wol; do
        old=$(installed "$name")
        case "$name:$old" in
            *:) ;;
            homegate-nginx:1.30.6-r3|homegate-nginx:1.30.7-r1|homegate-wol:1-r1) set -- "$@" "$name";;
            *) fail "unknown_legacy_version:$name";;
        esac
    done
    [ "$#" -gt 0 ] || return 0
    if ! pkg --noaction remove "$@" > "$work/plan" 2>&1; then
        cat "$work/plan"; fail legacy_removal_preflight
    fi
    awk -v names="$*" '
        BEGIN {n=split(names,items," "); for(i=1;i<=n;i++) wanted[items[i]]=1}
         /^Removing package / {if (!($3 in wanted) || $4!="from" || $5!="root...") bad=1; seen[$3]=1}
        /^(Installing|Upgrading|Downgrading|Collected errors:)/ {bad=1}
        END {for (item in wanted) if (!(item in seen)) bad=1; exit bad}
    ' "$work/plan" || { cat "$work/plan"; fail unexpected_legacy_removal; }
    pkg remove "$@" || fail legacy_removal
    check_expected_packages
    for name do [ -z "$(installed "$name")" ] || fail "legacy_package_present:$name"; done
}

finish_migration() {
    check_expected_packages
    checked_checkpoint || fail retained_configuration
    if [ -z "$upgrade_from" ]; then
        # The checkpoint identifies the previous release when resuming after installation.
        from_release=${checkpoint##*/.homegate-r}
        upgrade_from="$series-r${from_release%%-before-r*}"
    fi
    revision=$(config_state) || fail configuration_recovery_required
    retire_legacy
    checked_checkpoint || fail retained_configuration
    prior=$(cat "$checkpoint/observed")
    case "$prior" in
        [01]:[01]) ;;
        *) fail unknown_previous_state;;
    esac
    actual=$(observe_with_retry) || fail unknown_runtime_state
    [ "${actual%%:*}" = "${prior%%:*}" ] || fail boot_state_changed
    if [ "${prior#*:}:${actual#*:}" = 1:0 ]; then
        /etc/init.d/homegate start || fail previous_service_restart
        n=0
        while [ "$n" -lt 30 ]; do
            if current=$(observe) && [ "$current" = "$prior" ]; then break; fi
            n=$((n+1)); sleep 1
        done
        [ "$n" -lt 30 ] || fail previous_service_restart_unverified
        actual=$current
    fi
    [ "$actual" = "$prior" ] || fail runtime_state_changed
    record_upgrade_verified
    upgrade_stage=
    printf 'configuration_revision=%s\n' "$revision"
    printf 'homegate_offline_mode=%s\nhomegate_offline_verified=true\n' "$mode"
}

read_packages
[ -z "$(installed homegate)" ] && [ -z "$(installed homegate-engineering-core)" ] || fail unsupported_other_homegate
current=$(installed "$core")
if [ "$mode" = fresh ]; then
    for name in "$core" "$web" "$language" homegate-nginx homegate-wol; do
        [ -z "$(installed "$name")" ] || fail "already_installed:$name"
    done
    for path in /etc/homegate /etc/config/homegate /usr/libexec/homegate /etc/.homegate-transition \
        /usr/libexec/homegate-nginx /usr/libexec/homegate-wol; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || fail "existing_homegate_state:$path"
    done
else
    if [ "$current" != "$version" ]; then
        supported_source "$current" || fail unsupported_migration_version
        if check_dns_migration /etc/config/homegate && check_dns_migration "${store%/*}/package-config"; then
            :
        else
            case "$?" in
                2) fail unsupported_dns_provider;;
                *) fail dns_provider_configuration_unverified;;
            esac
        fi
        upgrade_from=$current
        write_upgrade_log begin none || :
    fi
    for name in "$web" "$language"; do
        [ "$(installed "$name")" = "$current" ] || fail mixed_homegate_versions
    done
    nginx=$(installed homegate-nginx)
    wol=$(installed homegate-wol)
    case "$nginx:$wol" in
        :|:1-r1|1.30.6-r3:|1.30.7-r1:|1.30.6-r3:1-r1|1.30.7-r1:1-r1) ;;
        *) fail unknown_legacy_component_versions;;
    esac
    if [ "$current" = "$version" ]; then
        upgrade_stage=verify
        find_checkpoint
        finish_migration
        exit 0
    fi
    if [ "$current" = '1.3.0-r240' ] || [ "$current" = '1.3.0-r265' ]; then
        [ -n "$nginx" ] && [ -n "$wol" ] || fail incomplete_legacy_components
        for path in /usr/libexec/homegate/components /usr/share/licenses/homegate-core/nginx \
            /usr/share/licenses/homegate-core/wol; do
            [ ! -e "$path" ] && [ ! -L "$path" ] || fail "component_path_occupied:$path"
        done
    else
        [ -z "$nginx$wol" ] || fail unexpected_legacy_components
    fi
    checkpoint=/etc/.homegate-r${current##*-r}-before-r$target_release
fi

set -- "$bundle/${core}_${version}_${architecture}.ipk" \
       "$bundle/${web}_${version}_all.ipk" "$bundle/${language}_${version}_all.ipk"
if ! pkg --noaction install "$@" > "$work/plan" 2>&1; then
    cat "$work/plan"; fail install_preflight
fi
awk -v mode="$mode" -v from="$current" -v to="$version" '
    BEGIN {want["homegate-core"]=1; want["luci-app-homegate"]=1; want["luci-i18n-homegate-zh-cn"]=1}
    /^Installing / {if (mode!="fresh" || !($2 in want) || $3!=("(" to ")") || $4!="to" || $5!="root...") bad=1; seen[$2]=1}
    /^Upgrading / {if (mode!="migrate" || !($2 in want) || $3!="on" || $4!="root" || $5!="from" || $6!=from || $7!="to" || $8!=(to "...")) bad=1; seen[$2]=1}
    /^Removing package / {if (mode!="migrate" || ($3!="homegate-nginx" && $3!="homegate-wol") || $4!="from" || $5!="root...") bad=1}
    /^(Downgrading|Collected errors:)/ {bad=1}
    END {for (item in want) if (!(item in seen)) bad=1; exit bad}
' "$work/plan" || { cat "$work/plan"; fail unexpected_install_plan; }
cat "$work/plan"

if [ "$mode" = migrate ]; then
    upgrade_stage=checkpoint
    if [ -e "$checkpoint" ] || [ -L "$checkpoint" ]; then
        checked_checkpoint || fail checkpoint
    else
        upgrade_stage=stop
        before=$(observe_with_retry) || fail unknown_runtime_state
        # Keep the running baseline, then let the coordinator finish before init unregisters it.
        if [ "${before#*:}" = 1 ]; then wait_for_service_stop; fi
        /etc/init.d/homegate stop || fail service_stop
        /usr/bin/homegate service-quiescent >/dev/null || fail service_not_quiescent
        # An active worker can prevent this read. Check the persisted state
        # after the service and its children have stopped.
        upgrade_stage=checkpoint
        revision=$(config_state) || fail configuration_recovery_required
        mkdir "$checkpoint" || fail checkpoint_directory
        tar -C / -cpf "$checkpoint/state.tar" etc/config/homegate etc/homegate || fail checkpoint_backup
        sha256sum /etc/config/homegate "$store/current" "$store/gen-$revision/manifest" > "$checkpoint/live.sha256"
        printf '%s\n' "$before" > "$checkpoint/observed"
        (cd "$checkpoint" && sha256sum state.tar live.sha256 observed > SHA256SUMS)
        fsync "$checkpoint/state.tar" "$checkpoint/live.sha256" "$checkpoint/observed" \
            "$checkpoint/SHA256SUMS" "$checkpoint" /etc || fail checkpoint_sync
        checked_checkpoint || fail checkpoint
    fi
    upgrade_stage=stop
    /usr/bin/homegate service-quiescent >/dev/null || fail service_not_quiescent
    printf 'checkpoint_verified=true\n'
fi

upgrade_stage=install
pkg install "$@" || fail package_install
if [ "$mode" = migrate ]; then
    upgrade_stage=verify
    finish_migration
else
    check_expected_packages
    [ "$(observe_with_retry)" = 0:0 ] || fail unexpected_fresh_service_state
fi
[ "$mode" = fresh ] || exit 0
printf 'homegate_offline_mode=%s\nhomegate_offline_verified=true\n' "$mode"
