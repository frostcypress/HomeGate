#!/bin/sh
# Fixed observer/action/read-only DNS sessions; deadlines survive caller loss.
set -u
umask 077
export LC_ALL=C
service_actions_enabled=false
certificate_validation_enabled=false
ddns_plan_enabled=false
network_resolve_enabled=false
health_status_enabled=false
recovery_status_enabled=false
ddns_recovery_read_enabled=false
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
if [ "${1:-}" = --certificate-validate ];then
    [ "$certificate_validation_enabled" = true ] && [ "$#" -eq 3 ] || exit 2
    action=certificate-validate;budget=10;certificate_id=$3
    case "$certificate_id" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
    [ "${#certificate_id}" -le 64 ] || exit 2
    set -- --action "$2" certificate-validate
fi
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
if [ "${1:-}" = --network-resolve ]; then
    [ "$network_resolve_enabled" = true ] || exit 2;shift
    [ "$#" -eq 4 ] || exit 2
    action=network-resolve;budget=5;network_revision=$2;network_job=$3;network_bridge=$4
    case "$network_revision:$network_job" in *[!0-9:]*) exit 2;; esac
    [ "$network_revision" -ge 1 ] && [ "$network_revision" -le 32 ] && [ "${#network_job}" -le 9 ] && [ "$network_job" -ge 2 ] || exit 2
    case "$network_bridge" in ''|.|..|*[!a-zA-Z0-9_.:-]*) exit 2;; esac
    [ "${#network_bridge}" -le 32 ] || exit 2
    set -- --action "$1" network-resolve
fi
if [ "${1:-}" = --health-status ]; then
    [ "$health_status_enabled" = true ] || exit 2;shift
    [ "$#" -eq 3 ] || exit 2
    action=health-status;budget=5;health_revision=$2;health_job=$3
    case "$health_revision:$health_job" in *[!0-9:]*) exit 2;; esac
    [ "$health_revision" -ge 1 ] && [ "$health_revision" -le 32 ] && [ "${#health_job}" -le 9 ] && [ "$health_job" -ge 2 ] || exit 2
    set -- --action "$1" health-status
fi
if [ "${1:-}" = --recovery-status ]; then
    [ "$recovery_status_enabled" = true ] || exit 2;shift
    { [ "$#" -eq 4 ] || { [ "$#" -eq 5 ] && [ "$ddns_recovery_read_enabled" = true ]; }; } || exit 2
    action=recovery-status;budget=5;recovery_revision=$2;recovery_job=$3;recovery_token=$4
    recovery_ddns_proof=${5:-}
    [ "${#recovery_ddns_proof}" -le 110 ] || exit 2
    case "$recovery_ddns_proof" in *[!a-z0-9:-]*) exit 2;; esac
    case "$recovery_revision:$recovery_job" in *[!0-9:]*) exit 2;; esac
    [ "$recovery_revision" -ge 1 ] && [ "$recovery_revision" -le 32 ] && [ "${#recovery_job}" -le 9 ] && [ "$recovery_job" -ge 2 ] || exit 2
    [ "${#recovery_token}" -le 160 ] || exit 2
    case "$recovery_token" in ''|*[!a-z0-9:]*) exit 2;; esac
    set -- --action "$1" recovery-status
fi
if [ "${1:-}" = --action ]; then
    shift
    [ "$#" -eq 2 ] || exit 2
    [ "$2" != cloudflare-check ] || [ "$action" = cloudflare-check ] || exit 2
    [ "$2" != ddns-plan ] || [ "$action" = ddns-plan ] || exit 2
    [ "$2" != network-resolve ] || [ "$action" = network-resolve ] || exit 2
    [ "$2" != health-status ] || [ "$action" = health-status ] || exit 2
    [ "$2" != certificate-validate ] || [ "$action" = certificate-validate ] || exit 2
    [ "$2" != recovery-status ] || [ "$action" = recovery-status ] || exit 2
    [ "$action" = cloudflare-check ] || [ "$action" = ddns-plan ] || [ "$action" = network-resolve ] || [ "$action" = health-status ] || [ "$action" = recovery-status ] || [ "$action" = certificate-validate ] || [ "$service_actions_enabled" = true ] || exit 2
    action=$2
    case "$action" in precheck|start|stop|cloudflare-check|ddns-plan|network-resolve|health-status|recovery-status|certificate-validate) ;; *) exit 2;; esac
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
if [ "$action" != cloudflare-check ] && [ "$action" != ddns-plan ] && [ "$action" != network-resolve ] && [ "$action" != health-status ] && [ "$action" != recovery-status ] && [ "$action" != certificate-validate ]; then
    [ -f /etc/init.d/homegate ] && [ ! -L /etc/init.d/homegate ] && [ -x /etc/init.d/homegate ] &&
        [ -x /etc/rc.common ] && [ -x /sbin/ubus ] || exit 1
fi
stop_requested=false
trap 'stop_requested=true' TERM INT
now=$(lua "$process" now 2>/dev/null) || exit 1
deadline=$((now + budget))
stop_family() {
    # Signal only this still-running session leader's own process group.
    kill -TERM -- "-$$" 2>/dev/null || :
    sleep 1
    kill -KILL -- "-$$" 2>/dev/null
    exit 1
}
{ [ "$action" != cloudflare-check ] && [ "$action" != ddns-plan ] && [ "$action" != network-resolve ] && [ "$action" != health-status ] && [ "$action" != recovery-status ]; } || exec 5<&0
case "$action" in
    certificate-validate) ash "$dir/homegate-certificate-worker.sh" "$certificate_id" 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    observe) lua "$dir/homegate-service-observer.lua" 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    precheck) /sbin/uci -q show homegate 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    start) /etc/init.d/homegate start 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    stop) /etc/init.d/homegate stop 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    ddns-plan) ash "$dir/homegate-ddns-plan-worker.sh" "$ddns_revision" "$ddns_job" "$ddns_rule" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    network-resolve) ash "$dir/homegate-network-worker.sh" "$network_revision" "$network_job" "$network_bridge" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    health-status) ash "$dir/homegate-health-worker.sh" "$health_revision" "$health_job" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    recovery-status)
        if [ -n "$recovery_ddns_proof" ]; then
            ash "$dir/homegate-recovery-worker.sh" "$recovery_revision" "$recovery_job" "$recovery_token" "$recovery_ddns_proof" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
        else
            ash "$dir/homegate-recovery-worker.sh" "$recovery_revision" "$recovery_job" "$recovery_token" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
        fi;;
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
{ [ "$action" != cloudflare-check ] && [ "$action" != ddns-plan ] && [ "$action" != network-resolve ] && [ "$action" != health-status ] && [ "$action" != recovery-status ]; } || exec 5<&-
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
