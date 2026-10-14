#!/bin/sh
# Fixed observer/action/read-only DNS sessions; deadlines survive caller loss.
set -u
umask 077
export LC_ALL=C
service_actions_enabled=false
dns_read_enabled=false
dns_records_enabled=false
dns_reconcile_enabled=false
dns_receipt_enabled=false
action=observe
budget=5
if [ "${1:-}" = --cloudflare-check ]; then
    shift
    [ "$dns_read_enabled" = true ] && { [ "$#" -eq 4 ] || [ "$#" -eq 5 ]; } || exit 2
    action=cloudflare-check; budget=30
    dns_account=$2; dns_revision=$3; dns_job=$4
    dns_mode=${5:-check}; case "$dns_mode" in check|zones) ;; records) [ "$dns_records_enabled" = true ] || exit 2;; reconcile) [ "$dns_records_enabled" = true ] && [ "$dns_reconcile_enabled" = true ] || exit 2;; *) exit 2;; esac
    case "$dns_account" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
    [ "${#dns_account}" -le 64 ] || exit 2
    case "$dns_revision:$dns_job" in *[!0-9:]*) exit 2;; esac
    [ "$dns_revision" -ge 1 ] && [ "$dns_revision" -le 32 ] && [ "${#dns_job}" -le 9 ] && [ "$dns_job" -ge 2 ] || exit 2
    set -- --action "$1" cloudflare-check
fi
if [ "${1:-}" = --action ]; then
    shift
    [ "$#" -eq 2 ] || exit 2
    [ "$2" != cloudflare-check ] || [ "$action" = cloudflare-check ] || exit 2
    [ "$action" = cloudflare-check ] || [ "$service_actions_enabled" = true ] || exit 2
    action=$2
    case "$action" in precheck|start|stop|cloudflare-check) ;; *) exit 2;; esac
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
if [ "$action" != cloudflare-check ]; then
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
[ "$action" != cloudflare-check ] || exec 5<&0
case "$action" in
    observe) lua "$dir/homegate-service-observer.lua" 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    precheck) /sbin/uci -q show homegate 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    start) /etc/init.d/homegate start 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    stop) /etc/init.d/homegate stop 3>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &;;
    cloudflare-check)
        if [ "$dns_receipt_enabled" = true ]; then
            ash "$dir/homegate-cloudflare-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 8>&- 9>&- >/dev/null 2>&1 &
        else
            ash "$dir/homegate-cloudflare-worker.sh" "$dns_account" "$dns_revision" "$dns_job" "$dns_mode" 0<&5 5<&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
        fi;;
esac
worker=$!
[ "$action" != cloudflare-check ] || exec 5<&-
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
