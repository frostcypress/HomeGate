#!/bin/sh
# Fixed metadata and explicit single-rule job requests; no caller commands or paths.
set -u
umask 077
export LC_ALL=C
ddns_ui_enabled=false
effect=none
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-ui","effect":"%s","write_ready":false,"error":"DDNS UI request refused"}\n' "$effect";exit "${1:-7}"; }
[ "$ddns_ui_enabled" = true ] && [ "$#" -eq 1 ] || fail 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 2>/dev/null
owner=$(id -u) || fail;[ "$owner" = 0 ] || fail
case "$1" in /tmp/homegate-ddns-ui-*/request) ;; *) fail 2;; esac
request=$1;work=${request%/request};token=${work#/tmp/homegate-ddns-ui-}
[ "${#token}" -eq 32 ] || fail 2;case "$token" in *[!0-9a-f]*) fail 2;; esac
[ -d /tmp ] && [ ! -L /tmp ] && [ -d "$work" ] && [ ! -L "$work" ] && [ "$(stat -c '%u:%a' "$work")" = "$owner:700" ] || fail
[ -f "$request" ] && [ ! -L "$request" ] && [ "$(stat -c '%u:%a:%h' "$request")" = "$owner:600:1" ] && [ "$(stat -c %s "$request")" -le 4096 ] || fail
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
exec 3<"$request" || fail
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$request")" ] || fail
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
parsed=$(lua "$dir/homegate-ddns-ui.lua" request 2>/dev/null) || fail 2
exec 3<&-
action=${parsed%%:*};payload=${parsed#*:};rc=0
case "$action" in
 maintain_preview) raw=$(ash "$dir/homegate-ddns-job.sh" maintain-preview "$payload") || rc=$?;;
 maintain_commit) job=${payload%%:*};nonce=${payload#*:};raw=$(ash "$dir/homegate-ddns-job.sh" maintain-commit "$job" "$nonce" --confirm) || rc=$?;;
 jobs) raw=$(ash "$dir/homegate-ddns-job.sh" list) || rc=$?;;
 submit) effect=unknown;job=${payload%%:*};rule=${payload#*:};raw=$(ash "$dir/homegate-ddns-job.sh" submit "$job" "$rule" --confirm) || rc=$?;;
 status) raw=$(ash "$dir/homegate-cli.sh" ddns-status) || rc=$?;;
 preview) case "$payload" in *,*) mode=preview-rules;; *) mode=preview;; esac;raw=$(ash "$dir/homegate-ddns-authority.sh" "$mode" "$payload") || rc=$?;;
 commit) raw=$(ash "$dir/homegate-ddns-authority.sh" commit "$payload") || rc=$?;;
 revoke) raw=$(ash "$dir/homegate-ddns-authority.sh" revoke --confirm) || rc=$?;;
 *) fail 2;;
esac
case "$rc" in 0) ;; 2|4|5|7) fail "$rc";; *) fail;; esac
printf '%s\n' "$raw" | lua "$dir/homegate-ddns-ui.lua" response "$action" "$payload" 2>/dev/null || fail
