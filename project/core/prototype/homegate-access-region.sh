#!/bin/sh
# Explicit CN cache fetch. No access grant, configuration write or live reload.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset LUA_INIT LUA_PATH LUA_CPATH HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR CURL_HOME
access_region_enabled=false
fail() { printf '{"api_version":1,"engineering":true,"ok":false,"phase":"access-region","effect":"none","write_ready":false,"error":"CN cache operation unavailable"}\n';exit "${1:-7}"; }
action=${1:-};case "$action" in
 update|refresh) [ "$access_region_enabled" = true ] && [ "$#" = 2 ] && [ "$2" = --confirm ] || fail 2;;
 worker) [ "$access_region_enabled" = true ] && [ "$#" = 2 ] || fail 2;token=$2;;
 status|quiescent) [ "$#" = 1 ] || fail 2;;
 stop|reap) [ "$#" = 2 ] && [ "$2" = --confirm ] || fail 2;;*) fail 2;;esac
[ "$(id -u)" = 0 ] || fail 2
exec 2>/dev/null
HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
HG_JOB=;. "$HG_DIR/homegate-acme-common.sh"
D=$HG_RUN/access-update;BASE=/etc/homegate/access;LOCK=$HG_RUN/access-region.lock;CONTROL=$HG_RUN/access-region.control
process=$HG_DIR/worker-process.lua
seal() { (cd "$D" && sha256sum token boot mode); }
check() {
 hg_dir "$D" || return 1
 for n in token boot mode seal report;do hg_file "$D/$n" 4096 || return 1;done
 hg_hex "$(cat "$D/token")" 32 && [ "$(cat "$D/boot")" = "$(cat /proc/sys/kernel/random/boot_id)" ] && [ "$(cat "$D/seal")" = "$(seal)" ] && [ "$(stat -c %s "$D/seal")" = "$(seal | wc -c)" ]
}
live() { running=false;hg_file "$LOCK" 0 && [ "$(stat -c %s "$LOCK")" = 0 ] || return 1;exec 4>>"$LOCK";if ! flock -n 4;then running=true;fi; }
quiet() {
 [ "$running" = false ] || return 1
 if hg_exists "$D/owner";then
  hg_file "$D/owner" 128 || return 1;o=$(cat "$D/owner");pid=${o%%:*};birth=${o#*:};case "$pid:$birth" in ''|*[!0-9:]*) return 1;;esac
  [ "$pid" -gt 1 ] && [ "$birth" -gt 0 ] && [ "$(lua "$process" group "$pid" 0)" = 0 ] || return 1
 fi
}
control() { hg_file "$CONTROL" 0 && [ "$(stat -c %s "$CONTROL")" = 0 ] || return 1;exec 5>>"$CONTROL";hg_bound 5 "$CONTROL" && flock -n 5; }
reap() {
 check && live && quiet || return 1
 for f in "$D/"* "$D/".[!.]* "$D/"..?*;do hg_exists "$f" || continue
  case "${f##*/}" in token|boot|mode|seal|report|report.next|owner|stop|download|candidate|http|transport) hg_file "$f" 25165825 || return 1;;*) return 1;;esac
 done
 for n in token boot mode seal report report.next owner stop download candidate http transport;do rm -f "$D/$n" || return 1;done;rmdir "$D"
}
if [ "$action" != worker ];then exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;fi
hg_dir /etc/homegate && hg_dir "$HG_RUN" || fail
if hg_exists "$BASE";then hg_dir "$BASE" || fail;fi
if hg_exists "$BASE/CN.cidr";then hg_file "$BASE/CN.cidr" 25165824 || fail;fi
if [ "$action" = status ];then
 if hg_exists "$D";then check && live || fail;else running=false;fi
 lua "$HG_DIR/homegate-access.lua" status "$running";exit $?
fi
if [ "$action" = stop ] || [ "$action" = reap ] || [ "$action" = quiescent ];then
 if ! hg_exists "$D";then lua "$HG_DIR/homegate-access.lua" status false;exit $?;fi
 check && live || fail
 if [ "$action" = stop ];then
  control || fail 4
  if ! hg_exists "$D/stop";then (set -C; : > "$D/stop") || fail;fi
  hg_file "$D/stop" 0 && [ "$(stat -c %s "$D/stop")" = 0 ] || fail
 elif [ "$action" = reap ];then control && reap || fail 4
 else quiet || fail 4;fi
 lua "$HG_DIR/homegate-access.lua" status "$running";exit $?
fi
if [ "$action" != worker ];then
 for f in "$LOCK" "$CONTROL";do if ! hg_exists "$f";then (set -C; : > "$f") || fail;fi;hg_file "$f" 0 && [ "$(stat -c %s "$f")" = 0 ] || fail;done
 control || fail 4
 if hg_exists "$D";then reap || fail 4;fi
 exec 4>&- 9>>"$LOCK";hg_bound 9 "$LOCK" && flock -n 9 || fail 4
 if ! hg_exists "$BASE";then mkdir "$BASE" && fsync "$BASE" /etc/homegate || fail;fi
 hg_dir "$BASE" && mkdir "$D" || fail
 token=$(lua "$HG_DIR/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
 printf '%s\n' "$token" > "$D/token" && cat /proc/sys/kernel/random/boot_id > "$D/boot" && printf '%s\n' "$action" > "$D/mode" && seal > "$D/seal" && lua "$HG_DIR/homegate-access.lua" report starting || fail
 if [ "$action" = update ] && lua "$HG_DIR/homegate-access.lua" cache-fresh;then lua "$HG_DIR/homegate-access.lua" report cached || fail;exec 9>&-;lua "$HG_DIR/homegate-access.lua" status false;exit $?;fi
 setsid ash "$HG_DIR/homegate-access-region.sh" worker "$token" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- </dev/null >/dev/null 2>&1 &
 exec 9>&-;lua "$HG_DIR/homegate-access.lua" status true;exit $?
fi
check && hg_bound 9 "$LOCK" && flock -n 9 && [ "$token" = "$(cat "$D/token")" ] || fail
info=$(lua "$process" info "$$" "$token") || fail
old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
[ "$#" = 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] && [ "$6" = 1 ] || fail
printf '%s:%s\n' "$$" "$5" > "$D/owner" || fail
interrupted=false;trap 'interrupted=true' TERM INT
finish() { lua "$HG_DIR/homegate-access.lua" report "$1" || :;kill -TERM -- "-$$" 2>/dev/null || :;sleep .2;kill -KILL -- "-$$" 2>/dev/null;exit 7; }
lua "$HG_DIR/homegate-access.lua" report downloading || fail
(
 exec 9>&-
 for source in https://ftp.apnic.net/stats/apnic/delegated-apnic-latest https://ftp.ripe.net/pub/stats/apnic/delegated-apnic-latest;do
  for n in download candidate http transport;do if hg_exists "$D/$n";then hg_file "$D/$n" 25165825 || exit 1;fi;done
  ( /usr/bin/curl --disable --proto '=https' --proto-redir '=https' --location --fail --silent --show-error --connect-timeout 5 --max-time 20 --url "$source" --output /proc/self/fd/3 --write-out '%{http_code}' 3>&1 > "$D/http";printf '%s\n' "$?" > "$D/transport" ) | head -c 25165825 > "$D/download"
  hg_file "$D/transport" 4 && [ "$(cat "$D/transport")" = 0 ] && hg_file "$D/http" 3 && [ "$(cat "$D/http")" = 200 ] && hg_file "$D/download" 25165824 || continue
  lua "$HG_DIR/homegate-access.lua" parse && hg_file "$D/candidate" 25165824 || continue
  if hg_exists "$BASE/.CN.next";then hg_file "$BASE/.CN.next" 25165824 && rm "$BASE/.CN.next" || exit 1;fi
  cp "$D/candidate" "$BASE/.CN.next" && fsync "$BASE/.CN.next" "$BASE" && mv -f "$BASE/.CN.next" "$BASE/CN.cidr" && fsync "$BASE/CN.cidr" "$BASE" || exit 1
  exit 0
 done
 exit 1
) 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- </dev/null >/dev/null 2>&1 &
child=$!;now=$(lua "$process" now) || finish failed;deadline=$((now+60))
while kill -0 "$child" 2>/dev/null;do
 [ "$interrupted" = false ] && ! hg_exists "$D/stop" || finish stopped
 now=$(lua "$process" now) || finish failed;[ "$now" -lt "$deadline" ] || finish failed;sleep .1 || :
done
result=failed;if wait "$child";then result=published;fi
[ "$(lua "$process" group "$$" 0)" = 0 ] || finish failed
lua "$HG_DIR/homegate-access.lua" report "$result" || fail
