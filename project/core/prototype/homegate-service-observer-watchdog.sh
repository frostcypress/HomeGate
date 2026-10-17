#!/bin/sh
# Fixed observer/action/read-only DNS sessions; deadlines survive caller loss.
set -u
umask 077
export LC_ALL=C
service_actions_enabled=false
ddns_plan_enabled=false
dns_read_enabled=false
aliyun_read_enabled=false
dnspod_read_enabled=false
huaweicloud_read_enabled=false
huaweicloud_records_enabled=false
huaweicloud_reconcile_enabled=false
huaweicloud_receipt_enabled=false
dnspod_records_enabled=false
dnspod_reconcile_enabled=false
dnspod_receipt_enabled=false
aliyun_records_enabled=false
aliyun_reconcile_enabled=false
aliyun_receipt_enabled=false
dns_records_enabled=false
dns_reconcile_enabled=false
dns_receipt_enabled=false
action=observe
budget=5
dns_provider=cloudflare
if [ "${1:-}" = --cloudflare-check ] || [ "${1:-}" = --aliyun-check ] || [ "${1:-}" = --dnspod-check ] || [ "${1:-}" = --huaweicloud-check ]; then
    if [ "$1" = --aliyun-check ]; then
        [ "$aliyun_read_enabled" = true ] || exit 2;dns_provider=aliyun
    elif [ "$1" = --huaweicloud-check ]; then
        [ "$huaweicloud_read_enabled" = true ] || exit 2;dns_provider=huaweicloud
    elif [ "$1" = --dnspod-check ]; then
        [ "$dnspod_read_enabled" = true ] || exit 2;dns_provider=dnspod
    fi
    shift
    [ "$dns_read_enabled" = true ] && { [ "$#" -eq 4 ] || [ "$#" -eq 5 ]; } || exit 2
    action=cloudflare-check; budget=30
    dns_account=$2; dns_revision=$3; dns_job=$4
    dns_mode=${5:-check}; case "$dns_mode" in check|zones) ;; records) [ "$dns_records_enabled" = true ] || exit 2;; reconcile) [ "$dns_records_enabled" = true ] && [ "$dns_reconcile_enabled" = true ] || exit 2;; *) exit 2;; esac
    [ "$dns_provider" != huaweicloud ] || { [ "$dns_mode" = check ] || [ "$dns_mode" = zones ] || { { [ "$dns_mode" = records ] || { [ "$dns_mode" = reconcile ] && [ "$huaweicloud_reconcile_enabled" = true ]; }; } && [ "$huaweicloud_records_enabled" = true ] && [ "$dns_receipt_enabled" = false ]; }; } || exit 2
    [ "$dns_provider" != dnspod ] || { [ "$dns_mode" = check ] || [ "$dns_mode" = zones ] || { { [ "$dns_mode" = records ] || { [ "$dns_mode" = reconcile ] && [ "$dnspod_reconcile_enabled" = true ]; }; } && [ "$dnspod_records_enabled" = true ] && [ "$dns_receipt_enabled" = false ]; }; } || exit 2
    [ "$dns_provider" != aliyun ] || { [ "$dns_mode" = check ] || [ "$dns_mode" = zones ] || { { [ "$dns_mode" = records ] || { [ "$dns_mode" = reconcile ] && [ "$aliyun_reconcile_enabled" = true ]; }; } && [ "$aliyun_records_enabled" = true ] && [ "$dns_receipt_enabled" = false ]; }; } || exit 2
    case "$dns_account" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
    [ "${#dns_account}" -le 64 ] || exit 2
    case "$dns_revision:$dns_job" in *[!0-9:]*) exit 2;; esac
    [ "$dns_revision" -ge 1 ] && [ "$dns_revision" -le 32 ] && [ "${#dns_job}" -le 9 ] && [ "$dns_job" -ge 2 ] || exit 2
    set -- --action "$1" cloudflare-check
fi
if [ "${1:-}" = --ddns-plan ]; then
    [ "$ddns_plan_enabled" = true ] || exit 2;shift
    [ "$#" -eq 4 ] || exit 2
    action=ddns-plan;budget=5;ddns_revision=$2;ddns_job=$3;ddns_rule=$4
    case "$ddns_revision:$ddns_job" in *[!0-9:]*) exit 2;; esac
    [ "$ddns_revision" -ge 1 ] && [ "$ddns_revision" -le 32 ] && [ "${#ddns_job}" -le 9 ] && [ "$ddns_job" -ge 2 ] || exit 2
    case "$ddns_rule" in *[!a-zA-Z0-9_-]*) exit 2;; esac
    [ "${#ddns_rule}" -le 64 ] || exit 2
    set -- --action "$1" ddns-plan
fi
if [ "${1:-}" = --action ]; then
    shift
    [ "$#" -eq 2 ] || exit 2
    [ "$2" != cloudflare-check ] || [ "$action" = cloudflare-check ] || exit 2
    [ "$2" != ddns-plan ] || [ "$action" = ddns-plan ] || exit 2
    [ "$action" = cloudflare-check ] || [ "$action" = ddns-plan ] || [ "$service_actions_enabled" = true ] || exit 2
    action=$2
    case "$action" in precheck|start|stop|cloudflare-check|ddns-plan) ;; *) exit 2;; esac
    set -- "$1"
    PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
    unset IPKG_INSTROOT INIT_TRACE PROCD_DEBUG TRACE_SYSCALLS LUA_INIT LUA_PATH LUA_CPATH
    unset HOMEGATE_PACKAGE_UPGRADE_STATE HOMEGATE_RUNTIME_STATE HOMEGATE_LOG_PATH HOMEGATE_DDNS_STATUS HOMEGATE_RECOVERY_STATUS
    unset HOMEGATE_PROXY_STATUS HOMEGATE_DAEMON_LOCK HOMEGATE_HOME_DIR HOMEGATE_SYS_CLASS_NET HOMEGATE_FIREWALL_STATUS HOMEGATE_FIREWALL_COMPAT_STATUS
    unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR CURL_HOME XDG_CONFIG_HOME HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
    # Both descriptions must be the trusted coordinator's existing locks.
    # The watchdog retains them until its own family has become quiet.
    for pair in '6:/var/run/homegate/frontend.lock' '7:/etc/homegate/transactions/.supervisor.lock'; do
        fd=${pair%%:*}; lock=${pair#*:}
        [ -f "$lock" ] && [ ! -L "$lock" ] && [ "$(stat -c '%u:%a:%h' "$lock")" = 0:600:1 ] &&
            [ "$(stat -Lc '%d:%i:%u:%a:%h' "/proc/self/fd/$fd")" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] &&
            flock -n "$fd" || exit 1
    done
fi
[ "$#" -eq 1 ] && [ "${#1}" -eq 32 ] || exit 1
case "$1" in *[!0-9a-f]*) exit 1;; esac
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
process="$dir/worker-process.lua"
info=$(lua "$process" info "$$" "$1" 2>/dev/null) || exit 1
old_ifs=$IFS; IFS=:; set -- $info; IFS=$old_ifs
[ "$#" -eq 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] && [ "$6" = 1 ] || exit 1
sleep 0.001 >/dev/null 2>&1 || exit 1
kill -0 "$$" >/dev/null 2>&1 || exit 1
# Missing executables/modules are unknown, never "disabled" or "stopped".
[ "$(id -u)" = 0 ] || exit 1
if [ "$action" != cloudflare-check ] && [ "$action" != ddns-plan ]; then
    [ -f /etc/init.d/homegate ] && [ ! -L /etc/init.d/homegate ] && [ -x /etc/init.d/homegate ] &&
        [ -x /etc/rc.common ] && [ -x /sbin/ubus ] || exit 1
fi
stop_requested=false
trap 'stop_requested=true' TERM INT
now=$(lua "$process" now 2>/dev/null) || exit 1
deadline=$((now + budget))
stop_family() {
    # Signal only this still-running session leader's own process group.
    kill -TERM "-$$" 2>/dev/null || :
    sleep 1
    kill -KILL "-$$" 2>/dev/null
    exit 1
}
{ [ "$action" != cloudflare-check ] && [ "$action" != ddns-plan ]; } || exec 5<&0
case "$action" in
    observe) lua "$dir/homegate-service-observer.lua" 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    precheck) /sbin/uci -q show homegate 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    start) /etc/init.d/homegate start 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    stop) /etc/init.d/homegate stop 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    ddns-plan) ash "$dir/homegate-ddns-plan-worker.sh" "$ddns_revision" "$ddns_job" "$ddns_rule" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    cloudflare-check)
        if [ "$dns_provider" = huaweicloud ]; then
            if [ "$huaweicloud_receipt_enabled" = true ]; then
            ash "$dir/homegate-huaweicloud-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 8>&- 9>&- >/dev/null 2>&1 &
            else
            ash "$dir/homegate-huaweicloud-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
            fi
        elif [ "$dns_provider" = dnspod ]; then
            if [ "$dnspod_receipt_enabled" = true ]; then
            ash "$dir/homegate-dnspod-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 8>&- 9>&- >/dev/null 2>&1 &
            else
            ash "$dir/homegate-dnspod-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
            fi
        elif [ "$dns_provider" = aliyun ]; then
            if [ "$aliyun_receipt_enabled" = true ]; then
            ash "$dir/homegate-aliyun-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 8>&- 9>&- >/dev/null 2>&1 &
            else
            ash "$dir/homegate-aliyun-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
            fi
        elif [ "$dns_receipt_enabled" = true ]; then
            ash "$dir/homegate-cloudflare-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 8>&- 9>&- >/dev/null 2>&1 &
        else
            ash "$dir/homegate-cloudflare-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
        fi;;
esac
worker=$!
{ [ "$action" != cloudflare-check ] && [ "$action" != ddns-plan ]; } || exec 5<&-
while :; do
    info=$(lua "$process" info "$worker" none 2>/dev/null) || stop_family
    case "$info" in ''|Z:*|X:*) break;; esac
    [ "$stop_requested" = false ] || stop_family
    now=$(lua "$process" now 2>/dev/null) || stop_family
    [ "$now" -lt "$deadline" ] || stop_family
    sleep 0.05 2>/dev/null || stop_family
done
[ "$stop_requested" = false ] || stop_family
result=0; wait "$worker" || result=$?
members=$(lua "$process" group "$$" "$$" 2>/dev/null) || stop_family
[ "$members" = 0 ] || stop_family
sleep 0.05 2>/dev/null || stop_family
members=$(lua "$process" group "$$" "$$" 2>/dev/null) || stop_family
[ "$members" = 0 ] || stop_family
exit "$result"
