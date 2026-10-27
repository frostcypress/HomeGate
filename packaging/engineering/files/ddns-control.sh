#!/bin/sh
# Root-only manual engineering business entry. Fixed paths; no implicit grant.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
exec 2>/dev/null
fail() { printf '{"api_version":1,"engineering":true,"ok":false,"phase":"engineering-ddns","effect":"none","error":"Manual DDNS request refused"}\n';exit "${1:-2}"; }
[ "$(id -u)" = 0 ] || fail 7
base=/usr/libexec/homegate-engineering
dir=$base/project/core/prototype
engine=$dir/homegate-config-prototype.sh
action=${1:-};shift || fail
case "$action" in schedule-*) exec ash "$base/schedule-control.sh" "${action#schedule-}" "$@";; esac
id_valid() { case "$1" in ''|*[!a-zA-Z0-9_-]*) return 1;; esac;[ "${#1}" -le 64 ]; }
token_valid() { case "$1" in ''|*[!0-9a-f]*) return 1;; esac;[ "${#1}" -eq 32 ]; }
job_valid() { case "$1" in ''|0*|*[!0-9]*) return 1;; esac;[ "${#1}" -le 9 ] && [ "$1" -ge 2 ]; }
case "$action" in
    prepare|prepare-resume|config-status|config-export|import-preview|activate-preview|config-preview|config-cancel|grant-cancel) [ "$#" -eq 0 ] || fail;;
    import-commit|config-commit|config-finish|grant-commit) [ "$#" -eq 1 ] && token_valid "$1" || fail;;
    dns-provider-status|dns-zones|ddns-sync|ddns-status|grant-preview) [ "$#" -eq 1 ] && id_valid "$1" || fail;;
    grant-revoke) [ "$#" -eq 1 ] && [ "$1" = --confirm ] || fail;;
    ddns-delete|ddns-reset) [ "$#" -eq 2 ] && id_valid "$1" && [ "$2" = --confirm ] || fail;;
    ddns-reconcile|ddns-collect-receipt|ddns-collect-orphan|ddns-retire-archive)
        [ "$#" -eq 4 ] && id_valid "$2" && job_valid "$3" && [ "$4" = --confirm ] || fail
        case "$1" in cloudflare|aliyun|dnspod|huaweicloud) ;; *) fail;; esac;;
    ddns-collect-work) [ "$#" -eq 2 ] && job_valid "$1" && [ "$2" = --confirm ] || fail;;
    secret-put) [ "$#" -eq 3 ] && id_valid "$2" || fail
        case "$1" in cloudflare|aliyun|dnspod|huaweicloud) ;; *) fail;; esac
        case "$3" in key_id|secret|account_id|endpoint) ;; *) fail;; esac;;
    *) fail;;
esac
# Configuration and credential publication require the finite scheduler to be
# quiescent. Status/export and explicit revocation remain available.
case "$action" in ddns-delete|prepare|prepare-resume|import-preview|import-commit|activate-preview|config-preview|config-commit|config-finish|config-cancel|secret-put)
    if [ -e /var/run/homegate-engineering/ddns-schedule ] || [ -L /var/run/homegate-engineering/ddns-schedule ];then
        ash "$dir/homegate-ddns-schedule.sh" quiescent >/dev/null || fail 4
    fi;;
esac
# Fail before creating state when this target lacks a required runtime applet.
for tool in ash lua stat sha256sum flock fsync setsid head;do
    found=false
    for prefix in /usr/sbin /usr/bin /sbin /bin;do [ ! -x "$prefix/$tool" ] || found=true;done
    [ "$found" = true ] || fail 7
done
case "$action" in
    prepare) exec ash "$dir/homegate-lifecycle-prepare.sh" prepare;;
    prepare-resume) exec ash "$dir/homegate-lifecycle-prepare.sh" resume;;
    config-status) exec ash "$engine" --persistent status;;
    config-export) exec ash "$engine" --persistent export;;
    import-preview) exec ash "$engine" --persistent migration-source-preview;;
    import-commit) exec ash "$engine" --persistent migration-source-commit "$1";;
    config-preview) exec ash "$engine" --persistent preview;;
    config-cancel) exec ash "$engine" --persistent cancel;;
    activate-preview)
        # Capture a bounded public export, checking its producer separately.
        public=$(ash "$engine" --persistent export) || fail 7
        printf '%s\n' "$public" | ash "$engine" --persistent preview;exit $?;;
    config-commit)
        result=$(ash "$engine" --persistent commit-apply-projection "$1") || { rc=$?;printf '%s\n' "$result";exit "$rc"; }
        handle=$(printf '%s\n' "$result" | lua "$base/apply-handle.lua") || fail 7
        # A failed publication keeps the durable application journal. The
        # returned handle can only resume this already-bound transaction.
        ash "$engine" --persistent projection-publish "$handle" apply >/dev/null || { printf '%s\n' "$result";exit 7; }
        finished=$(ash "$engine" --persistent apply-finish-projection "$handle") || { printf '%s\n' "$result";exit 7; }
        printf '%s\n' "$finished";exit 0;;
    config-finish)
        ash "$engine" --persistent projection-publish "$1" apply >/dev/null || exit $?
        exec ash "$engine" --persistent apply-finish-projection "$1";;
    secret-put) exec ash "$engine" --persistent credential-put "$@";;
    grant-preview) exec ash "$dir/homegate-ddns-authority.sh" preview "$1";;
    grant-commit) exec ash "$dir/homegate-ddns-authority.sh" commit "$1";;
    grant-cancel) exec ash "$dir/homegate-ddns-authority.sh" cancel;;
    grant-revoke) exec ash "$dir/homegate-ddns-authority.sh" revoke --confirm;;
    dns-provider-status) exec ash "$dir/homegate-dns-status.sh" "$1";;
    dns-zones) exec ash "$dir/homegate-dns-status.sh" "$1" --zones;;
    ddns-delete) exec ash "$dir/homegate-ddns-read.sh" --runtime-delete "$1" --confirm;;
    ddns-status) exec ash "$dir/homegate-ddns-state.sh" status "$1";;
    ddns-sync) exec ash "$dir/homegate-ddns-state.sh" sync "$1" --confirm;;
    ddns-reset) exec ash "$dir/homegate-ddns-state.sh" reset "$1" --confirm;;
    ddns-collect-work) exec ash "$dir/homegate-ddns-work.sh" collect "$1" --confirm;;
    ddns-reconcile|ddns-collect-receipt|ddns-collect-orphan|ddns-retire-archive)
        exec ash "$dir/homegate-cloudflare-read.sh" "--runtime-${action#ddns-}-internal" "$@";;
esac
