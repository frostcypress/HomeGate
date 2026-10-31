#!/bin/sh
# Frozen public arities and operational exit status; maintenance stays typed.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
bad(){ printf '{"api_version":1,"ok":false,"error":"Invalid command arguments"}\n';exit 2; }
[ "$#" -ge 1 ] || bad
frozen=true
case "$1" in
 version|selftest|status|check|recovery-status|network-resolve|dns-provider-catalog|acme-ca-catalog|ddns-status|cert-status|proxy-status|access-status|access-recent|access-clear-all|access-clear-denied|firewall-status|firewall-apply|firewall-cleanup|wol-status|daemon) [ "$#" = 1 ] || bad;;
 dns-check-private|dns-provider-status|dns-zones|ddns-delete|access-update|access-refresh|access-validate-file|web-read|web-submit|web-job|web-job-status|web-job-ack) [ "$#" = 2 ] || bad;;
 cert-import) [ "$#" = 4 ] || bad;;
 access-clear-entry) [ "$#" = 3 ] || bad;;
 ddns-sync|cert-renew|log-events) [ "$#" = 1 ] || [ "$#" = 2 ] || bad;;
 acme-ca-status|wol) [ "$#" = 2 ] || [ "$#" = 3 ] || bad;;
 *) frozen=false;;
esac
if [ "$1" = log-events ] && [ "$#" = 2 ];then
 value=$(lua /usr/libexec/homegate/native-public.lua log-max "$2") || bad
 set -- log-events "$value"
fi
core=/usr/libexec/homegate/native-cli-core.sh
if [ "$1" = web-submit ];then
 lua /usr/libexec/homegate/native-web-store.lua validate-request "$2" >/dev/null || { printf '{"api_version":1,"ok":false,"error":"Invalid request file"}\n';exit 1; }
fi
if [ "$frozen" = false ] || [ "$1" = daemon ];then exec ash "$core" "$@";fi
selector=
case "$1" in dns-provider-status|dns-zones|cert-import|cert-renew|ddns-sync|ddns-delete) selector=${2:-};;esac
context=
case "$1" in ddns-sync|ddns-delete)
 context=$(lua /usr/libexec/homegate/native-public.lua ddns-context "$selector") || { printf '%s\n' "$context";exit 1; };;esac
{ [ -z "$context" ] || printf 'HGCTX:%s\n' "$context";ash "$core" "$@";printf '\nHGCLI:%s\n' "$?"; } |
 lua /usr/libexec/homegate/native-public.lua "$1" "$selector"
exit $?
