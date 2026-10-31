#!/bin/sh
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 2>/dev/null
fail() { printf '{"api_version":1,"engineering":true,"ok":false,"effect":"none","write_ready":false,"error":"Configuration request refused"}\n';exit "${1:-7}"; }
[ "$(id -u)" = 0 ] && [ "$#" -eq 1 ] || fail 2
case "$1" in /tmp/homegate-engineering-web-*/request) ;; *) fail 2;; esac
request=$1;work=${request%/request};nonce=${work#/tmp/homegate-engineering-web-}
[ "${#nonce}" -eq 32 ] || fail 2;case "$nonce" in *[!0-9a-f]*) fail 2;; esac
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
[ -d /tmp ] && [ ! -L /tmp ] && private_dir "$work" && private_file "$request" && [ "$(stat -c %s "$request")" -le 1572864 ] || fail
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
exec 3<"$request" || fail
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$request")" ] || fail
base=/usr/libexec/homegate-engineering;entry=$base/ddns-control.sh
parsed=$(lua "$base/config-web.lua" request) || fail 2
action=${parsed%%:*};payload=${parsed#*:};rc=0
cleanup() { [ ! -f "$work/current" ] || rm -f "$work/current"; }
trap cleanup EXIT
case "$action" in
 backup_export) raw=$(ash "$entry" config-export) || fail;printf '%s\n' "$raw" | lua "$base/config-web.lua" backup-export || fail;exit 0;;
 backup_preview) candidate=$(lua "$base/config-web.lua" payload) || fail 2;raw=$(printf '%s\n' "$candidate" | ash "$entry" config-preview) || rc=$?;;
 rollback_preview) raw=$(ash "$entry" config-rollback-preview "$payload") || rc=$?;;
 wol_status) raw=$(ash "$entry" wol-status) || rc=$?;;
 wol_send) raw=$(ash "$entry" wol "$payload" --confirm) || rc=$?;;
 wol_direct) iface=${payload%%,*};mac=${payload#*,};raw=$(ash "$entry" wol "$iface" "$mac" --confirm) || rc=$?;;
 access_status|access_recent) raw=$(ash "$entry" "access-${action#access_}") || rc=$?;;
 access_update|access_refresh|access_clear|access_clear_denied|access_stop|access_reap)
  command="access-${action#access_}";[ "$action" != access_clear_denied ] || command=access-clear-denied
  raw=$(ash "$entry" "$command" --confirm) || rc=$?;;
 proxy_start) selection=${payload%%:*};policy=${payload#*:};raw=$(ash "$entry" proxy-start "$selection" "$policy" --confirm) || rc=$?;;
 firewall_status) raw=$(ash "$entry" firewall-status) || rc=$?;;
 firewall_apply|firewall_cleanup) raw=$(ash "$entry" "firewall-${action#firewall_}" --confirm) || rc=$?;;
 proxy_status) raw=$(ash "$entry" proxy-status) || rc=$?;;
 proxy_stop|proxy_reap) raw=$(ash "$entry" "proxy-${action#proxy_}" --confirm) || rc=$?;;
 web_target_put) raw=$(lua "$base/config-web.lua" payload | ash "$entry" web-target-put "$payload" --confirm) || rc=$?;;
 read)
  raw=$(ash "$entry" config-export) || fail
  printf '%s\n' "$raw" | lua "$base/config-web.lua" read || fail;exit $?;;
 acme_schedule_start) raw=$(ash "$entry" acme-schedule-start "$payload" --confirm) || rc=$?;;
 acme_schedule_status) raw=$(ash "$entry" acme-schedule-status) || rc=$?;;
 acme_schedule_stop|acme_schedule_reap) raw=$(ash "$entry" "acme-schedule-${action#acme_schedule_}" --confirm) || rc=$?;;
 acme_issue|acme_renew)
  id=${payload%%:*};job=${payload#*:}
  raw=$(ash "$entry" "acme-${action#acme_}" "$id" "$job" --confirm) || rc=$?;;
 acme_status) raw=$(ash "$entry" acme-job "$payload") || rc=$?;;
 acme_stop|acme_cleanup) raw=$(ash "$entry" "acme-${action#acme_}" "$payload" --confirm) || rc=$?;;
 cert_status) raw=$(ash "$entry" cert-status "$payload") || rc=$?;;
 cert_resume|cert_cancel) raw=$(ash "$entry" "cert-${action#cert_}" "$payload" --confirm) || rc=$?;;
 cert_import)
  candidate=$(lua "$base/config-web.lua" payload) || fail 2
  raw=$(printf '%s' "$candidate" | ash "$entry" cert-import "$payload" --confirm) || rc=$?;;
 provider_status) raw=$(ash "$entry" dns-provider-status "$payload") || rc=$?;;
 zones) raw=$(ash "$entry" dns-zones "$payload") || rc=$?;;
 delete_rule) raw=$(ash "$entry" ddns-delete "$payload" --confirm) || rc=$?;;
 recover) raw=$(ash "$entry" config-recover --confirm) || rc=$?;;
 production_copy_preview) raw=$(ash "$entry" production-copy-preview) || rc=$?;;
 production_copy_commit) raw=$(ash "$entry" production-copy-commit "$payload") || rc=$?;;
 prepare) raw=$(ash "$entry" prepare) || rc=$?;;
 lifecycle_status) raw=$(ash "$entry" lifecycle-status) || rc=$?;;
 lifecycle_enable|lifecycle_disable) raw=$(ash "$entry" "lifecycle-${action#lifecycle_}" --confirm) || rc=$?;;
 schedule_status) raw=$(ash "$entry" schedule-status) || rc=$?;;
 schedule_serve|schedule_start|schedule_stop|schedule_reap) raw=$(ash "$entry" "schedule-${action#schedule_}" --confirm) || rc=$?;;
 cancel) raw=$(ash "$entry" config-cancel) || rc=$?;;
 activate_preview) raw=$(ash "$entry" activate-preview) || rc=$?;;
 apply|finish)
  command=config-commit;[ "$action" != finish ] || command=config-finish
  raw=$(ash "$entry" "$command" "$payload") || rc=$?;;
 preview_wol_host|preview_wol_settings|preview_access|preview_web_rule|preview_account|preview_rule|preview_local_certificate|preview_acme_certificate)
  (set -C; : > "$work/current") || fail
  ash "$entry" config-export > "$work/current" || fail
  private_file "$work/current" && [ "$(stat -c %s "$work/current")" -le 262144 ] || fail
  exec 4<"$work/current" || fail
  # Check the generator independently; ash has no pipefail. The candidate is
  # public-only and bounded by the existing codec before preview publication.
  candidate=$(lua "$base/config-web.lua" payload) || fail 2
  exec 4<&-
  raw=$(printf '%s\n' "$candidate" | ash "$entry" config-preview) || rc=$?;;
 secret_put)
  provider=${payload%%:*};rest=${payload#*:};account=${rest%%:*};slot=${rest#*:}
  # Secret bytes remain on stdin. The decoder was validated before dispatch.
  raw=$(lua "$base/config-web.lua" payload | ash "$entry" secret-put "$provider" "$account" "$slot") || rc=$?;;
 *) fail 2;;
esac
printf '%s\n' "$raw" | lua "$base/config-web.lua" response "$rc" "$action" || fail
exit "$rc"
