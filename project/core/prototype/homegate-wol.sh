#!/bin/sh
# Explicit manual WOL, with separate config-independent direct mode.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
wol_runtime_enabled=false
fail() { printf '{"api_version":1,"engineering":true,"ok":false,"phase":"wol","effect":"unknown","write_ready":false,"device_wake_verified":false,"error":"Wake result unavailable; inspect retained operation before retry"}\n';exit "${1:-7}"; }
[ "$wol_runtime_enabled" = true ] && [ "$(id -u)" = 0 ] || fail 2
HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
HG_JOB=;. "$HG_DIR/homegate-acme-common.sh"
W=$HG_RUN/wol;LOCK=$HG_RUN/wol.lock;process=$HG_DIR/worker-process.lua
action=${1:-};shift || fail 2
if [ "$action" = send-internal ];then
 [ "$#" = 0 ] && hg_dir "$W" && hg_bound 8 "$LOCK" && flock -n 8 || fail 4
 info=$(lua "$process" info "$$" none) || fail
 old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
 [ "$#" = 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] || fail
 fields=$(lua "$HG_DIR/homegate-wol.lua" fields) || fail
 set -- $fields;[ "$#" = 2 ] || fail
 iface=$1;count=1
 printf '%s\n' "$iface" > "$W/allowed" || fail
 [ -d "/sys/class/net/$iface" ] || fail 2
 if [ -e "/sys/class/net/$iface/brif" ] || [ -L "/sys/class/net/$iface/brif" ];then
  [ -d "/sys/class/net/$iface/brif" ] && [ -r "/sys/class/net/$iface/brif" ] || fail
  for f in "/sys/class/net/$iface/brif/"* "/sys/class/net/$iface/brif/".[!.]* "/sys/class/net/$iface/brif/"..?*;do
   hg_exists "$f" || continue;name=${f##*/};case "$name" in ''|.|..|*[!a-zA-Z0-9_.:-]*) fail 2;;esac
   [ "${#name}" -le 32 ] || fail 2;count=$((count+1));[ "$count" -le 1025 ] || fail 2;printf '%s\n' "$name" >> "$W/allowed" || fail;set -- "$@" "$name"
  done
 fi
 interrupted=false;trap 'interrupted=true' TERM INT
 stop_family() { kill -TERM -- "-$$" 2>/dev/null || :;sleep .2;kill -KILL -- "-$$" 2>/dev/null;exit 7; }
 (version=$(/usr/libexec/homegate-wol/send --version) && [ "$version" = 'homegate-wol 1' ] && exec /usr/libexec/homegate-wol/send "$@") > "$W/result" 2>/dev/null &
 child=$!;now=$(lua "$process" now) || stop_family;deadline=$((now+6))
 while kill -0 "$child" 2>/dev/null;do
  [ "$interrupted" = false ] || stop_family;now=$(lua "$process" now) || stop_family;[ "$now" -lt "$deadline" ] || stop_family;sleep .1 || :
 done
 wait "$child";result=$?;[ "$(lua "$process" group "$$" 0)" = 0 ] || stop_family
 hg_file "$W/result" 131072 && lua "$HG_DIR/homegate-wol.lua" result "$result" "$count" || fail
 exit "$result"
fi
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
case "$action" in status) [ "$#" = 0 ] || fail 2;;host) [ "$#" = 2 ] && [ "$2" = --confirm ] || fail 2;;direct) [ "$#" = 3 ] && [ "$3" = --confirm ] || fail 2;;*) fail 2;;esac
# Direct send never reads or validates unrelated configuration.
if ! hg_exists "$HG_RUN";then mkdir "$HG_RUN" || fail;fi
hg_dir "$HG_RUN" || fail
if ! hg_exists "$LOCK";then (set -C; : > "$LOCK") || fail;fi
hg_file "$LOCK" 0 && [ "$(stat -c %s "$LOCK")" = 0 ] || fail
exec 8>>"$LOCK";hg_bound 8 "$LOCK" && flock -n 8 || fail 4
config_guard() {
 hg_dir "$HG_STORE" && hg_file "$HG_RUN/frontend.lock" 0 && hg_file "$HG_STORE/.supervisor.lock" 0 || fail
 exec 6>>"$HG_RUN/frontend.lock" 7>>"$HG_STORE/.supervisor.lock"
 hg_bound 6 "$HG_RUN/frontend.lock" && hg_bound 7 "$HG_STORE/.supervisor.lock" && flock -n 6 && flock -n 7 || fail 4
 ash "$HG_DIR/homegate-config-prototype.sh" --persistent writer-check >/dev/null
}
if [ "$action" != direct ];then config_guard || fail;fi
snapshot() { ash "$HG_DIR/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null; }
if [ "$action" = status ];then value=$(snapshot | lua "$HG_DIR/homegate-wol.lua" status) || fail;printf '%s\n' "$value";exit 0;fi
if [ "$action" = direct ] && [ -z "$1" ];then
 default=$( (config_guard && snapshot | lua "$HG_DIR/homegate-wol.lua" interface) 2>/dev/null) || default=br-lan
 set -- "$default" "$2" "$3"
fi
if ! hg_exists "$W";then mkdir "$W" || fail;fi
hg_dir "$W" || fail
for f in "$W/"* "$W/".[!.]* "$W/"..?*;do hg_exists "$f" || continue;case "${f##*/}" in plan.json|result|public|allowed) hg_file "$f" 131072 || fail;;*) fail;;esac;done
if [ "$action" = host ];then snapshot | lua "$HG_DIR/homegate-wol.lua" host "$1" || fail 2;else lua "$HG_DIR/homegate-wol.lua" direct "$1" "$2" || fail 2;fi
[ -f /usr/libexec/homegate-wol/send ] && [ ! -L /usr/libexec/homegate-wol/send ] && [ -x /usr/libexec/homegate-wol/send ] && [ "$(stat -c %u /usr/libexec/homegate-wol/send)" = 0 ] || fail
setsid ash "$HG_DIR/homegate-wol.sh" send-internal </dev/null > "$W/public" 2>/dev/null
rc=$?;hg_file "$W/public" 131072 || fail
[ -s "$W/public" ] || fail
cat "$W/public";exit "$rc"
