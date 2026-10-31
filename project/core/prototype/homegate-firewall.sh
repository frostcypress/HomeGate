#!/bin/sh
# Explicit engineering firewall admission; fixed private chains only.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
firewall_runtime_enabled=false
fail() { printf '{"api_version":1,"engineering":true,"ok":false,"phase":"firewall","known":false,"active":false,"effect":"unknown","write_ready":false,"error":"Firewall state unavailable; inspect retained admission"}\n';exit "${1:-7}"; }
[ "$firewall_runtime_enabled" = true ] && [ "$(id -u)" = 0 ] || fail 2
HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
HG_JOB=;. "$HG_DIR/homegate-acme-common.sh"
F=$HG_RUN/firewall;P=$HG_RUN/proxy;LOCK=$HG_RUN/firewall.lock;process=$HG_DIR/worker-process.lua
MARKER=/etc/homegate/firewall-owned
hg_dir /etc/homegate || fail
if hg_exists "$MARKER";then hg_file "$MARKER" 0 && [ "$(stat -c %s "$MARKER")" = 0 ] || fail;fi
action=${1:-};shift || fail 2
guard() {
 hg_dir "$P" && hg_file "$P/token" 33 && [ "$(cat "$P/token")" = "$1" ] && ! hg_exists "$P/stop" &&
 hg_bound 6 "$HG_RUN/frontend.lock" && hg_bound 7 "$HG_STORE/.supervisor.lock" &&
 [ "$(cat "$P/binding")" = "$(hg_binding)" ] && hg_file "$HG_STORE/startup-active" 16384 &&
 [ "$(cat "$P/intent")" = "$(sha256sum "$HG_STORE/startup-active")" ] &&
 ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null || return 1
 proxy_status=$(ash "$HG_DIR/homegate-proxy.sh" status) || return 1
 printf '%s\n' "$proxy_status" | lua "$HG_DIR/homegate-firewall.lua" live
}
if [ "$action" = guard-internal ];then
 [ "$#" = 1 ] && hg_bound 8 "$LOCK" && flock -n 8 && guard "$1" || fail 4;exit 0
fi
if [ "$action" = operate-internal ];then
 [ "$#" = 2 ] && hg_bound 8 "$LOCK" && flock -n 8 || fail 4
 mode=$1;token=$2;case "$mode" in apply|watch|status|cleanup) ;;*) fail 2;;esac
 info=$(lua "$process" info "$$" none) || fail
 old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
 [ "$#" = 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] || fail
 interrupted=false;trap 'interrupted=true' TERM INT
 stop_family() { kill -TERM -- "-$$" 2>/dev/null || :;sleep .2;kill -KILL -- "-$$" 2>/dev/null;exit 7; }
 (ulimit -f 64 || exit 7;exec lua "$HG_DIR/homegate-firewall.lua" "$mode" "$token") &
 child=$!;now=$(lua "$process" now) || stop_family;deadline=$((now+6))
 while kill -0 "$child" 2>/dev/null;do
  [ "$interrupted" = false ] || stop_family
  case "$mode" in apply|watch) ! hg_exists "$P/stop" || stop_family;;esac
  now=$(lua "$process" now) || stop_family;[ "$now" -lt "$deadline" ] || stop_family;sleep .1 || :
 done
 wait "$child";result=$?
 [ "$(lua "$process" group "$$" 0)" = 0 ] || stop_family
 exit "$result"
fi
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
case "$action" in
 status) [ "$#" = 0 ] || fail 2;;
 apply|cleanup|cleanup-if-owned) [ "$#" = 1 ] && [ "$1" = --confirm ] || fail 2;;
 watch) [ "$#" = 1 ] && hg_hex "$1" 32 || fail 2;requested=$1;;
 *) fail 2;;esac
case "$action" in watch)
 if ! hg_exists "$F";then exit 0;fi
 hg_dir "$F" || fail
 if ! hg_exists "$F/desired.json";then exit 0;fi
 hg_file "$F/desired.json" 32768 || fail
 lua "$HG_DIR/homegate-firewall.lua" watch-armed >/dev/null;rc=$?
 [ "$rc" != 3 ] || exit 0;[ "$rc" = 0 ] || fail
 ;;esac
if [ "$action" = cleanup-if-owned ] && ! hg_exists "$F" && ! hg_exists "$MARKER";then exit 0;fi
hg_dir "$HG_RUN" || fail
if ! hg_exists "$F";then mkdir "$F" || fail;fi
hg_dir "$F" || fail
for f in "$F/"* "$F/".[!.]* "$F/"..?*;do
 hg_exists "$f" || continue
 case "${f##*/}" in out|err|reply|desired.json|desired.next|report.json|report.next) hg_file "$f" 32768 || fail;;*) fail;;esac
done
if ! hg_exists "$LOCK";then (set -C; : > "$LOCK") || fail;fi
hg_file "$LOCK" 0 && [ "$(stat -c %s "$LOCK")" = 0 ] || fail
exec 8>>"$LOCK";hg_bound 8 "$LOCK" && flock -n 8 || fail 4
if [ "$action" = cleanup-if-owned ];then
 if ! hg_exists "$MARKER";then
  if ! hg_exists "$F/desired.json";then exit 0;fi
  lua "$HG_DIR/homegate-firewall.lua" armed >/dev/null;rc=$?
  [ "$rc" != 3 ] || exit 0;[ "$rc" = 0 ] || fail
 fi
 action=cleanup
fi
token=none
case "$action" in apply|watch)
 hg_file "$P/token" 33 || fail;token=$(cat "$P/token");hg_hex "$token" 32 || fail
 [ "$action" != watch ] || [ "$token" = "$requested" ] || fail 4
 hg_file "$HG_RUN/frontend.lock" 0 && hg_file "$HG_STORE/.supervisor.lock" 0 || fail
 exec 6>>"$HG_RUN/frontend.lock" 7>>"$HG_STORE/.supervisor.lock"
 flock -n 6 && flock -n 7 && guard "$token" || fail 4
 if ! hg_exists "$MARKER";then (set -C; : > "$MARKER") && fsync "$MARKER" /etc/homegate || fail;fi;;esac
setsid ash "$HG_DIR/homegate-firewall.sh" operate-internal "$action" "$token" </dev/null > "$F/reply" 2>/dev/null
rc=$?
hg_file "$F/reply" 32768 || fail
if [ "$action" = cleanup ] && [ "$rc" = 0 ];then
 lua "$HG_DIR/homegate-firewall.lua" clean-reply || fail
 if hg_exists "$MARKER";then hg_file "$MARKER" 0 && rm "$MARKER" && fsync /etc/homegate || fail;fi
fi
if ! lua "$HG_DIR/homegate-firewall.lua" reply;then
 lua "$HG_DIR/homegate-firewall.lua" uncertain || fail
 exit 7
fi
exit "$rc"
