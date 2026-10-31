#!/bin/sh
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 3>&- 4>&- 5>&- 6>&- 7>&- 9>&-
# Only the CN launch crosses the existing web admission fence. The controller
# checks this exact FD8 against frontend-web.lock before dropping it.
case "${1:-}" in access-region) ;;*) exec 8>&-;;esac
exec 2>/dev/null
base=/usr/libexec/homegate;dir=$base/project/core/prototype;run=/var/run/homegate
fail() { printf '{"api_version":1,"ok":false,"error":"Compatibility operation unavailable; inspect retained state"}\n';exit "${1:-7}"; }
[ "$(id -u)" = 0 ] || fail
action=${1:-};shift || fail 2
case "$action" in
 access-region)
  [ "$#" = 2 ] || fail 2;case "$1" in update|refresh) ;;*) fail 2;;esac
  operation=$1;selection=$(lua "$base/native-adapters.lua" access-select "$2");code=$?
  if [ "$code" != 0 ];then printf '%s\n' "$selection";exit 1;fi
  ash "$base/ddns-control.sh" "access-$operation" --confirm >/dev/null || { lua "$base/native-adapters.lua" access-error;exit 1; }
  exec 8>&-
  token=$(lua "$base/native-adapters.lua" access-token) || { lua "$base/native-adapters.lua" access-error;exit 1; }
  now=$(lua "$dir/worker-process.lua" now) || fail 1;deadline=$((now+45))
  while :;do
   status=$(ash "$base/ddns-control.sh" access-status) || { lua "$base/native-adapters.lua" access-error;exit 1; }
   row=$(printf '%s\n' "$status" | lua "$base/native-adapters.lua" access-row "$operation" "$token");code=$?
   case "$code" in 0|1) printf '%s\n' "$row";exit "$code";;3) ;;*) lua "$base/native-adapters.lua" access-error;exit 1;;esac
   now=$(lua "$dir/worker-process.lua" now) || fail 1
   if [ "$now" -ge "$deadline" ];then ash "$base/ddns-control.sh" access-stop --confirm >/dev/null;lua "$base/native-adapters.lua" access-error;exit 1;fi
   sleep .1 || fail 1
  done;;
 access-clear)
  lock=$run/proxy.lock
  [ -d "$run" ] && [ ! -L "$run" ] && [ "$(stat -c '%u:%a' "$run")" = 0:700 ] || fail
  if [ ! -e "$lock" ] && [ ! -L "$lock" ];then (set -C;: > "$lock") || fail;fi
  [ -f "$lock" ] && [ ! -L "$lock" ] && [ "$(stat -c '%u:%a:%h:%s' "$lock")" = 0:600:1:0 ] || fail
  exec 9>>"$lock";[ "$(stat -Lc '%d:%i' /proc/$$/fd/9)" = "$(stat -c '%d:%i' "$lock")" ] || fail
  if flock -n 9;then
   # Exclude a new proxy owner while clearing persisted observations. A stale
   # owner group must also be gone; a free lease alone does not prove that.
   if [ -e "$run/proxy" ] || [ -L "$run/proxy" ];then
    [ -d "$run/proxy" ] && [ ! -L "$run/proxy" ] && [ "$(stat -c '%u:%a' "$run/proxy")" = 0:700 ] || fail
   fi
   if [ -e "$run/proxy/owner" ] || [ -L "$run/proxy/owner" ];then
    [ -f "$run/proxy/owner" ] && [ ! -L "$run/proxy/owner" ] && [ "$(stat -c '%u:%a:%h' "$run/proxy/owner")" = 0:600:1 ] && [ "$(stat -c %s "$run/proxy/owner")" -le 128 ] || fail
    owner=$(cat "$run/proxy/owner");pid=${owner%%:*};birth=${owner#*:}
    case "$pid:$birth" in ''|*[!0-9:]*) fail;;esac
    [ "$pid" -gt 1 ] && [ "$birth" -gt 0 ] && [ "$(lua "$dir/worker-process.lua" group "$pid" 0)" = 0 ] || fail 4
   fi
   lua "$dir/homegate-access-audit.lua" clear-idle "$@" >/dev/null || fail 1
  else
   exec 9>&-
   lua "$dir/homegate-access-audit.lua" clear "$@" >/dev/null || fail 1
  fi
  now=$(lua "$dir/worker-process.lua" now) || fail;deadline=$((now+5))
  while [ -e "$run/proxy/audit-clear" ] || [ -L "$run/proxy/audit-clear" ] || [ -e "$run/proxy/audit-clear.next" ] || [ -L "$run/proxy/audit-clear.next" ];do
   now=$(lua "$dir/worker-process.lua" now) || fail;[ "$now" -lt "$deadline" ] || fail 1;sleep .1 || fail
  done
  reply=$(lua "$dir/homegate-access-audit.lua" read) || fail
  printf '%s\n' "$reply" | lua "$base/native-adapters.lua" access-result;exit $?;;
 dns-check-private)
  [ "$#" = 1 ] || fail 2
  provider=$(lua "$base/native-adapters.lua" private-provider "$1") || fail
  for path in "$run" /etc/homegate/transactions;do [ -d "$path" ] && [ ! -L "$path" ] && [ "$(stat -c '%u:%a' "$path")" = 0:700 ] || fail;done
  for path in "$run/frontend.lock" /etc/homegate/transactions/.supervisor.lock;do [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -c '%u:%a:%h:%s' "$path")" = 0:600:1:0 ] || fail;done
  exec 6>>"$run/frontend.lock" 7>>/etc/homegate/transactions/.supervisor.lock
  flock -n 6 && flock -n 7 || fail 4
  ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null || fail 4
  for old in "$run"/.dns-check-*;do [ ! -e "$old" ] && [ ! -L "$old" ] || fail 4;done
  ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
  job=$$;work=$run/.dns-check-$job;mkdir "$work" || fail
  for name in request result zones state sign-input sign-output;do (set -C;: > "$work/$name") || fail;done
  rc=0
  lua "$base/native-adapters.lua" private-frame "$1" "$provider" |
   setsid ash "$dir/homegate-service-observer-watchdog.sh" --"$provider"-check "$ticket" offline_probe 1 "$job" zones 3>"$work/result" >/dev/null || rc=$?
  case "$rc" in 0|1) ;;*) fail;;esac
  if [ "$provider" = cloudflare ];then lua "$dir/cloudflare-zones.lua" result offline_probe 1 "$rc" < "$work/result" > "$work/zones" || fail
  else lua "$dir/$provider-reader.lua" result offline_probe 1 "$rc" zones < "$work/result" > "$work/zones" || fail;fi
  reply=$(lua "$base/native-adapters.lua" private-result < "$work/zones");code=$?
  case "$code" in 0|1) ;;*) fail;;esac
  for name in request result zones state sign-input sign-output;do rm "$work/$name" || fail;done
  rmdir "$work" || fail;printf '%s\n' "$reply";exit "$code";;
 acme-ca-status)
  [ "$#" = 1 ] || [ "$#" = 2 ] || fail 2
  selection=$(lua "$base/native-public.lua" ca-selection "$1" "${2:-production}") || fail 1
  ca=${selection%%:*};environment=${selection#*:};[ "$ca" = letsencrypt ] || fail 1
  case "$environment" in production) host=acme-v02.api.letsencrypt.org;;staging) host=acme-staging-v02.api.letsencrypt.org;;*) fail 1;;esac
  # Public fixed-host GET only, without curlrc, proxy, redirect or body logging.
  (ulimit -f 128; /usr/bin/curl --disable --proto '=https' --proto-redir '=https' --proxy '' --noproxy '*' --connect-timeout 3 --max-time 10 --max-filesize 65536 --fail --silent --cacert /etc/ssl/certs/ca-certificates.crt "https://$host/directory";printf '\nHGCA:%s\n' "$?") |
   lua "$base/native-adapters.lua" ca-response "$environment";exit $?;;
 cert-renew)
  [ "$#" -le 1 ] || fail 2
  if [ "$#" = 1 ];then names=$1;else
   names=$(ash "$base/native-service.sh" plan-certificates) || fail
  fi
  rows=;overall=0
  for name in $names;do
   case "$name" in ''|*[!a-zA-Z0-9_-]*) fail 2;;esac;[ "${#name}" -le 64 ] || fail 2
   command=acme-issue
   if [ "$#" = 0 ];then
    material=$(ash "$base/ddns-control.sh" cert-status "$name") || fail
    printf '%s\n' "$material" | lua "$base/native-service.lua" ready due;code=$?
    [ "$code" != 3 ] || continue;[ "$code" = 0 ] || fail;command=acme-renew
   fi
   token=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
   ash "$base/ddns-control.sh" "$command" "$name" "$token" --confirm >/dev/null || fail
   start=$(lua "$dir/worker-process.lua" now) || fail;deadline=$((start+720))
   while :;do
    status=$(ash "$base/ddns-control.sh" acme-job "$token") || fail
    row=$(printf '%s\n' "$status" | lua "$base/native-adapters.lua" renew-row);code=$?
    case "$code" in 0|1) [ "$code" = 0 ] || overall=1;break;;3) ;;*) fail;;esac
    now=$(lua "$dir/worker-process.lua" now) || fail
    if [ "$now" -ge "$deadline" ];then ash "$base/ddns-control.sh" acme-stop "$token" --confirm >/dev/null;fail 1;fi
    sleep 1 || fail
   done
   rows=${rows:+"$rows
"}$row
  done
  if [ "$#" = 1 ];then printf '%s\n' "$row";exit "$overall";fi
  printf '%s\n' "$rows" | lua "$base/native-adapters.lua" renew-aggregate;exit $?;;
 *) fail 2;;
esac
