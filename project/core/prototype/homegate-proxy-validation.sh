#!/bin/sh
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset LUA_INIT LUA_PATH LUA_CPATH HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy SSL_CERT_FILE SSL_CERT_DIR
[ "$#" = 2 ] && [ "$(id -u)" = 0 ] || exit 2
action=$1;token=$2;case "$action" in check|candidate-probe|accepted-probe) ;;*) exit 2;;esac
HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
HG_JOB=;. "$HG_DIR/homegate-acme-common.sh"
P=$HG_RUN/proxy;process=$HG_DIR/worker-process.lua
hg_hex "$token" 32 && hg_dir "$P" && hg_dir "$P/probe" && hg_file "$P/token" 33 && [ "$(cat "$P/token")" = "$token" ] && hg_bound 6 "$HG_RUN/frontend.lock" && hg_bound 7 "$HG_STORE/.supervisor.lock" && flock -n 6 && flock -n 7 || exit 1
exec 3>&- 4>&- 5>&- 8>&- 9>&-
info=$(lua "$process" info "$$" "$token") || exit 1
old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
[ "$#" = 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] && [ "$6" = 1 ] || exit 1
interrupted=false;trap 'interrupted=true' TERM INT
stop_family() { kill -TERM -- "-$$" 2>/dev/null || :;sleep .2;kill -KILL -- "-$$" 2>/dev/null;exit 1; }
(
 exec 6>&- 7>&-
 if [ "$action" = check ];then
  hg_file "$P/candidate.conf" 131072 || exit 1
  exec /usr/libexec/homegate-nginx/nginx -t -p "$P/" -c "$P/candidate.conf" -g 'daemon off;'
 fi
 which=${action%-probe};probes=$(lua "$HG_DIR/homegate-proxy.lua" probes "$which") || exit 1
 port=$(lua "$HG_DIR/homegate-proxy.lua" port) || exit 1
 printf '%s\n' "$probes" | while IFS=: read -r host expected;do
  [ -n "$host" ] || continue
  for n in peer.pem peer.der error;do if hg_exists "$P/probe/$n";then hg_file "$P/probe/$n" 131072 || exit 1;fi;done
  printf 'GET / HTTP/1.0\r\nHost: [::1]\r\n\r\n' | /usr/bin/openssl s_client -connect "127.0.0.1:$port" -servername "$host" -showcerts -ign_eof > "$P/probe/peer.pem" 2> "$P/probe/error" || exit 1
  hg_file "$P/probe/peer.pem" 131072 || exit 1
  /usr/bin/openssl x509 -in "$P/probe/peer.pem" -outform DER -out "$P/probe/peer.der" 2>/dev/null || exit 1
  sum=$(sha256sum "$P/probe/peer.der");[ "${sum%% *}" = "$expected" ] || exit 1
 done
) </dev/null >/dev/null 2>&1 &
child=$!;now=$(lua "$process" now) || stop_family;deadline=$((now+10))
while kill -0 "$child" 2>/dev/null;do
 [ "$interrupted" = false ] && ! hg_exists "$P/stop" || stop_family
 now=$(lua "$process" now) || stop_family;[ "$now" -lt "$deadline" ] || stop_family;sleep .1 || :
done
wait "$child";result=$?
[ "$(lua "$process" group "$$" 0)" = 0 ] || stop_family
exit "$result"
