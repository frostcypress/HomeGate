#!/bin/sh
# Canonical candidate entry; native maintenance uses the same checked helpers.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
base=/usr/libexec/homegate;dir=$base/project/core/prototype
fail() { printf '{"api_version":1,"native":true,"ok":false,"phase":"native-cli","effect":"none","write_ready":false,"error":"Native command unavailable or invalid arguments"}\n';exit "${1:-2}"; }
[ "$(id -u)" = 0 ] && [ "$#" -ge 1 ] || fail 7
action=$1;shift
if [ -e /etc/homegate/package-state ] || [ -L /etc/homegate/package-state ] || [ -e /etc/.homegate-transition/hold ] || [ -L /etc/.homegate-transition/hold ];then
 case "$action" in version|selftest|status|check|config-status|config-export|service-status|service-stop|service-quiescent|service-reap|service-admission|package-recover|proxy-status|wol-status|ddns-status|recovery-status) ;;*) fail 4;;esac
fi
id() { [ -n "$1" ] && [ "${#1}" -le 64 ] || return 1;case "$1" in *[!a-zA-Z0-9_-]*) return 1;;esac; }
control() { exec ash "$base/ddns-control.sh" "$@"; }
case "$action" in
 version) [ "$#" = 0 ] || fail;exec lua "$base/native-cli.lua" version;;
 check-stdin) [ "$#" = 0 ] || fail;exec lua "$base/engineering.lua" "$action";;
 selftest) [ "$#" = 0 ] || fail;exec lua "$base/native-cli.lua" selftest;;
 daemon) [ "$#" = 0 ] || fail;exec ash "$base/native-service.sh" serve;;
 status|check) [ "$#" = 0 ] || fail;exec ash "$base/native-service.sh" "$action";;
 service-status|service-quiescent|service-admission) [ "$#" = 0 ] || fail;exec ash "$base/native-service.sh" "${action#service-}";;
 service-stop) [ "$#" = 1 ] && [ "$1" = --confirm ] || fail;exec ash "$base/native-service.sh" stop --confirm;;
 service-reap) [ "$#" = 1 ] && [ "$1" = --confirm ] || fail;exec ash "$base/native-service.sh" reap --confirm;;
 service-plan-set) [ "$#" = 5 ] && [ "$5" = --confirm ] || fail;exec ash "$base/native-service.sh" plan-set "$@";;
 package-recover) [ "$#" = 1 ] && [ "$1" = --confirm ] || fail;ash "$base/native-package.sh" restore-config || fail 7;printf '{"api_version":1,"native":true,"ok":true,"phase":"package-recovery","effect":"none","write_ready":false}\n';exit 0;;
 network-resolve|recovery-status|dns-provider-catalog|acme-ca-catalog) [ "$#" = 0 ] || fail;exec ash "$dir/homegate-cli.sh" "$action";;
 dns-provider-status|dns-zones) [ "$#" = 1 ] && id "$1" || fail;exec ash "$dir/homegate-cli.sh" "$action" "$@";;
 dns-check-private|acme-ca-status) exec ash "$base/native-adapters.sh" "$action" "$@";;
 cert-renew) [ "$#" -le 1 ] || fail;if [ "$#" = 1 ];then id "$1" || fail;fi;exec ash "$base/native-adapters.sh" "$action" "$@";;
 access-validate-file) [ "$#" = 1 ] || fail;exec lua "$base/native-adapters.lua" access-file "$1";;
 log-events) [ "$#" -le 1 ] || fail;exec lua "$base/native-adapters.lua" log-events "$@";;
 access-clear-entry) [ "$#" = 2 ] || fail;exec ash "$base/native-adapters.sh" access-clear entry "$1" "$2";;
 ddns-status|ddns-sync) [ "$#" -le 1 ] || fail;exec ash "$dir/homegate-cli.sh" "$action" "$@";;
 ddns-delete) [ "$#" = 1 ] && id "$1" || fail;control ddns-delete "$1" --confirm;;
 wol) case "$#" in 1|2) ;;*) fail;;esac;control wol "$@" --confirm;;
 wol-status|firewall-status|proxy-status|access-status|access-recent) [ "$#" = 0 ] || fail;control "$action";;
 firewall-apply|firewall-cleanup) [ "$#" = 0 ] || fail;control "$action" --confirm;;
 access-update|access-refresh) [ "$#" = 1 ] || fail;exec ash "$base/native-adapters.sh" access-region "${action#access-}" "$1";;
 access-clear-all) [ "$#" = 0 ] || fail;exec ash "$base/native-adapters.sh" access-clear all;;
 access-clear-denied) [ "$#" = 0 ] || fail;exec ash "$base/native-adapters.sh" access-clear denied;;
 cert-import) [ "$#" = 3 ] && id "$1" || fail
  # Check the generator independently; never run the importer on partial input.
  pair=$(lua "$base/native-cli.lua" import "$2" "$3") || fail 7
  printf '%s\n' "$pair" | ash "$base/ddns-control.sh" cert-import "$1" --confirm;exit $?;;
 cert-status)
  [ "$#" -le 1 ] || fail
  if [ "$#" = 1 ];then id "$1" || fail;control cert-status "$1";fi
  public=$(ash "$base/ddns-control.sh" config-export) || fail 7
  names=$(printf '%s\n' "$public" | lua "$base/native-cli.lua" ids certificate) || fail 7
  rows=
  for name in $names;do row=$(ash "$base/ddns-control.sh" cert-status "$name") || fail 7;rows=${rows:+"$rows
"}$row;done
  printf '%s' "$rows" | lua "$base/native-cli.lua" aggregate;exit $?;;
 certificate-status) [ "$#" = 1 ] && id "$1" || fail;control cert-status "$1";;
 prepare|prepare-resume|config-*|production-copy-*|import-*|activate-preview|secret-put|grant-*|schedule-*|lifecycle-*|proxy-*|web-target-put|acme-*|cert-resume|cert-cancel|access-stop|access-reap|access-quiescent)
  control "$action" "$@";;
 *) fail;;
esac
