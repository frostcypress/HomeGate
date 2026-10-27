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
[ -d /tmp ] && [ ! -L /tmp ] && private_dir "$work" && private_file "$request" && [ "$(stat -c %s "$request")" -le 32768 ] || fail
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
exec 3<"$request" || fail
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$request")" ] || fail
base=/usr/libexec/homegate-engineering;entry=$base/ddns-control.sh
parsed=$(lua "$base/config-web.lua" request) || fail 2
action=${parsed%%:*};payload=${parsed#*:};rc=0
cleanup() { [ ! -f "$work/current" ] || rm -f "$work/current"; }
trap cleanup EXIT
case "$action" in
 read)
  raw=$(ash "$entry" config-export) || fail
  printf '%s\n' "$raw" | lua "$base/config-web.lua" read || fail;exit $?;;
 provider_status) raw=$(ash "$entry" dns-provider-status "$payload") || rc=$?;;
 zones) raw=$(ash "$entry" dns-zones "$payload") || rc=$?;;
 delete_rule) raw=$(ash "$entry" ddns-delete "$payload" --confirm) || rc=$?;;
 prepare) raw=$(ash "$entry" prepare) || rc=$?;;
 schedule_status) raw=$(ash "$entry" schedule-status) || rc=$?;;
 schedule_start|schedule_stop|schedule_reap) raw=$(ash "$entry" "schedule-${action#schedule_}" --confirm) || rc=$?;;
 cancel) raw=$(ash "$entry" config-cancel) || rc=$?;;
 activate_preview) raw=$(ash "$entry" activate-preview) || rc=$?;;
 apply|finish)
  command=config-commit;[ "$action" != finish ] || command=config-finish
  raw=$(ash "$entry" "$command" "$payload") || rc=$?;;
 preview_account|preview_rule)
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
