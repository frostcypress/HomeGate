#!/bin/sh
# Explicit isolated nginx owner. Only a live owner signals its own session.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy SSL_CERT_FILE SSL_CERT_DIR
proxy_runtime_enabled=false
fail() { printf '{"api_version":1,"engineering":true,"ok":false,"phase":"proxy","effect":"none","write_ready":false,"error":"Proxy unavailable; inspect retained session"}\n';exit "${1:-7}"; }
action=${1:-}
case "$action" in
 start) [ "$proxy_runtime_enabled" = true ] && [ "$#" -eq 4 ] && [ "$4" = --confirm ] || fail 2;selection=$2;policy=$3;;
 serve) [ "$proxy_runtime_enabled" = true ] && [ "$#" -eq 2 ] || fail 2;token=$2;;
 status|quiescent) [ "$#" -eq 1 ] || fail 2;;
 stop|reap) [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
 *) fail 2;;esac
[ "$(id -u)" = 0 ] || fail 2
exec 2>/dev/null
HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
HG_JOB=;. "$HG_DIR/homegate-acme-common.sh"
AUDIT=/var/run/homegate-audit
P=$HG_RUN/proxy;LOCK=$HG_RUN/proxy.lock;CONTROL=$HG_RUN/proxy.control;BODY=/var/run/homegate-proxy-body
process=$HG_DIR/worker-process.lua
idle() { printf '{"api_version":1,"engineering":true,"ok":true,"phase":"proxy","state":"idle","running":false,"effect":"none","write_ready":false}\n'; }
seal() { (cd "$P" && sha256sum plan.json binding intent token boot snapshots cn.conf audit-token); }
control() { hg_file "$CONTROL" 0 && [ "$(stat -c %s "$CONTROL")" -eq 0 ] || return 1;exec 5>>"$CONTROL";hg_bound 5 "$CONTROL" && flock -n 5; }
business() { hg_file "$HG_RUN/frontend.lock" 0 && hg_file "$HG_STORE/.supervisor.lock" 0 || return 1;exec 6>>"$HG_RUN/frontend.lock" 7>>"$HG_STORE/.supervisor.lock";hg_bound 6 "$HG_RUN/frontend.lock" && hg_bound 7 "$HG_STORE/.supervisor.lock" && flock -n 6 && flock -n 7; }
unlock() { exec 6>&- 7>&-; }
intent() {
 if hg_exists "$HG_STORE/startup-active";then hg_file "$HG_STORE/startup-active" 16384 && sha256sum "$HG_STORE/startup-active";else printf 'absent\n';fi
}
certificates() { lua "$HG_DIR/homegate-proxy.lua" certificates; }
snapshots() { (cd "$P" && for c in $(certificates);do sha256sum "$c/fullchain.pem" "$c/privkey.pem" "$c/result.json" "$c/pointer" || exit 1;done); }
clear_next() {
 if ! hg_exists "$P/next";then return 0;fi
 hg_dir "$P/next" || return 1
 for f in "$P/next/"* "$P/next/".[!.]* "$P/next/"..?*;do
  hg_exists "$f" || continue;found=false
  for c in $(certificates);do [ "${f##*/}" != "$c" ] || found=true;done
  [ "$found" = true ] && hg_dir "$f" || return 1
  for cf in "$f/"* "$f/".[!.]* "$f/"..?*;do
   hg_exists "$cf" || continue;case "${cf##*/}" in pointer|result.json|fingerprint|leaf.der) hg_file "$cf" 65536 || return 1;;*) return 1;;esac
  done
 done
 for f in "$P/next/"*;do [ -d "$f" ] || continue;for n in pointer result.json fingerprint leaf.der;do rm -f "$f/$n" || return 1;done;rmdir "$f" || return 1;done
 rmdir "$P/next"
}
pointers() { for c in $(certificates);do hg_file "/etc/homegate/certs/$c/current" 38 && [ "$(stat -c %s "/etc/homegate/certs/$c/current")" = 38 ] && sha256sum "/etc/homegate/certs/$c/current" || return 1;done; }
capture_next() {
 clear_next && mkdir "$P/next" || return 1
 for c in $(certificates);do
  ash "$HG_DIR/homegate-certificate.sh" admission-status-internal "$c" --confirm | lua "$HG_DIR/homegate-proxy.lua" certificate-ok "$c" || return 1
  base=/etc/homegate/certs/$c;hg_dir /etc/homegate/certs && hg_dir "$base" && hg_file "$base/current" 38 && [ "$(stat -c %s "$base/current")" = 38 ] || return 1
  pair=$(cat "$base/current");case "$pair" in pair-*) ;;*) return 1;;esac
  hg_hex "${pair#pair-}" 32 && hg_dir "$base/$pair" || return 1
  for n in fullchain.pem privkey.pem scope.json result.json manifest;do hg_file "$base/$pair/$n" 65536 || return 1;done
  [ "$(cat "$base/$pair/manifest")" = "$(cd "$base/$pair" && sha256sum fullchain.pem privkey.pem scope.json result.json)" ] || return 1
  mkdir "$P/next/$c" && cp "$base/current" "$P/next/$c/pointer" && cp "$base/$pair/result.json" "$P/next/$c/result.json" || return 1
  /usr/bin/openssl x509 -in "$base/$pair/fullchain.pem" -outform DER -out "$P/next/$c/leaf.der" 2>/dev/null || return 1
  sum=$(sha256sum "$P/next/$c/leaf.der");printf '%s\n' "${sum%% *}" > "$P/next/$c/fingerprint" || return 1
 done
 lua "$HG_DIR/homegate-proxy.lua" capture "$1" && lua "$HG_DIR/homegate-proxy.lua" render && clear_next
}
check() {
 hg_dir "$HG_RUN" && hg_dir "$P" || return 1
 for n in plan.json binding intent token boot active.conf snapshots seal report accepted.json audit-token audit-health;do hg_file "$P/$n" 131072 || return 1;done
 hg_file "$P/cn.conf" 33554432 || return 1
 t=$(cat "$P/token");hg_hex "$t" 32 && [ "$(stat -c %s "$P/token")" -eq 33 ] || return 1
 [ "$(cat "$P/boot")" = "$(cat /proc/sys/kernel/random/boot_id)" ] && [ "$(cat "$P/seal")" = "$(seal)" ] && [ "$(stat -c %s "$P/seal")" -eq "$(seal | wc -c)" ] || return 1
 for c in $(certificates);do hg_dir "$P/$c" || return 1;for n in fullchain.pem privkey.pem result.json pointer;do hg_file "$P/$c/$n" 65536 || return 1;done;done
 [ "$(cat "$P/snapshots")" = "$(snapshots)" ] && [ "$(stat -c %s "$P/snapshots")" -eq "$(snapshots | wc -c)" ] && lua "$HG_DIR/homegate-proxy.lua" material-check
}
live() {
 running=false
 hg_file "$LOCK" 0 && [ "$(stat -c %s "$LOCK")" -eq 0 ] || return 1
 exec 4>>"$LOCK";if ! flock -n 4;then running=true;fi
}
owner() {
 hg_file "$P/owner" 128 || return 1
 o=$(cat "$P/owner");pid=${o%%:*};birth=${o#*:};case "$pid:$birth" in ''|*[!0-9:]*) return 1;;esac
 [ "$pid" -gt 1 ] && [ "$birth" -gt 0 ] || return 1
}
quiet() {
 [ "$running" = false ] || return 1
 if hg_exists "$P/owner";then owner && [ "$(lua "$process" group "$pid" 0)" = 0 ];else return 0;fi
}
if [ "$action" != serve ];then exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;fi
if [ "$action" = status ] || [ "$action" = stop ] || [ "$action" = quiescent ] || [ "$action" = reap ];then
 if ! hg_exists "$P";then idle;exit 0;fi
 check && live || fail
 if [ "$action" = status ];then
  if [ "$running" = true ] && hg_exists "$P/owner";then owner || fail;actual=$(lua "$process" info "$pid" "$(cat "$P/token")") || fail
   case "$actual" in *":$pid:$pid:$birth:1") ;;*) fail;;esac
  fi
  lua "$HG_DIR/homegate-proxy.lua" status "$running" || fail;exit 0
 fi
 if [ "$action" = stop ];then
  control || fail 4
  if ! hg_exists "$P/stop";then (set -C; : > "$P/stop") && fsync "$P/stop" "$P" || fail;fi
  hg_file "$P/stop" 0 && [ "$(stat -c %s "$P/stop")" -eq 0 ] || fail
  lua "$HG_DIR/homegate-proxy.lua" status "$running" || fail;exit 0
 fi
 quiet || fail 4
 if [ "$action" = quiescent ];then idle;exit 0;fi
 control || fail 4
 clear_next || fail
 # Validate every removable entry first; preserve unexpected files for recovery.
 for f in "$P/"* "$P/".[!.]* "$P/"..?*;do
  hg_exists "$f" || continue;name=${f##*/}
  case "$name" in plan.json|binding|intent|token|boot|active.conf|snapshots|seal|report|report.next|owner|nginx.pid|stop|version|audit-token|audit-health|audit-clear|audit-clear.next|accepted.json|candidate.json|candidate.conf|rollback.conf|rejected) hg_file "$f" 131072 || fail;;
   cn.conf) hg_file "$f" 33554432 || fail;;
   probe) hg_dir "$f" || fail
    for cf in "$f/"* "$f/".[!.]* "$f/"..?*;do hg_exists "$cf" || continue;case "${cf##*/}" in peer.pem|peer.der|error) hg_file "$cf" 131072 || fail;;*) fail;;esac;done;;
   *) found=false;for c in $(certificates);do [ "$name" != "$c" ] || found=true;done
    [ "$found" = true ] && hg_dir "$f" || fail
    for cf in "$f/"* "$f/".[!.]* "$f/"..?*;do hg_exists "$cf" || continue;case "${cf##*/}" in fullchain.pem|privkey.pem|result.json|pointer) hg_file "$cf" 65536 || fail;;*) fail;;esac;done;;esac
 done
 # nginx owns these five fixed scratch directories. Do not recursively purge.
 temp=$BODY/$(cat "$P/token")
 [ -d "$BODY" ] && [ ! -L "$BODY" ] && [ "$(stat -c '%u:%a' "$BODY")" = 0:755 ] && [ -d "$temp" ] && [ ! -L "$temp" ] && [ "$(stat -c '%u:%a' "$temp")" = 0:755 ] || fail
 count=0
 for f in "$temp/"* "$temp/".[!.]* "$temp/"..?*;do
  hg_exists "$f" || continue;case "${f##*/}" in client_body|proxy|fastcgi|uwsgi|scgi) ;;*) fail;;esac
  [ -d "$f" ] && [ ! -L "$f" ] || fail
  for cf in "$f/"* "$f/".[!.]* "$f/"..?*;do hg_exists "$cf" || continue
   name=${cf##*/};case "$name" in ''|*[!0-9]*) fail;;esac
   [ -f "$cf" ] && [ ! -L "$cf" ] && [ "$(stat -c %h "$cf")" = 1 ] || fail
   count=$((count+1));[ "$count" -le 4096 ] || fail
  done
 done
 for f in "$temp/"*;do [ -d "$f" ] || continue;for cf in "$f/"*;do hg_exists "$cf" || continue;rm "$cf" || fail;done;rmdir "$f" || fail;done
 rmdir "$temp" || fail
 if hg_exists "$AUDIT";then
  [ -d "$AUDIT" ] && [ ! -L "$AUDIT" ] && [ "$(stat -c '%u:%a' "$AUDIT")" = 0:755 ] || fail
  for f in "$AUDIT/"* "$AUDIT/".[!.]* "$AUDIT/"..?*;do hg_exists "$f" || continue;[ "$f" = "$AUDIT/socket" ] && [ -S "$f" ] && [ ! -L "$f" ] && [ "$(stat -c '%u:%a:%h' "$f")" = 0:622:1 ] || fail;done
  rm -f "$AUDIT/socket" && rmdir "$AUDIT" || fail
 fi
 for n in peer.pem peer.der error;do rm -f "$P/probe/$n" || fail;done;rmdir "$P/probe" || fail
 for c in $(certificates);do for n in fullchain.pem privkey.pem result.json pointer;do rm "$P/$c/$n" || fail;done;rmdir "$P/$c" || fail;done
 for n in plan.json binding intent token boot active.conf snapshots seal report report.next owner nginx.pid stop version cn.conf audit-token audit-health audit-clear audit-clear.next accepted.json candidate.json candidate.conf rollback.conf rejected;do rm -f "$P/$n" || fail;done
 rmdir "$P" && fsync "$HG_RUN" || fail;idle;exit 0
fi
if [ "$action" = start ];then
 case "$selection" in ''|*[!a-zA-Z0-9_,_-]*) fail 2;;esac
 case "$policy" in open|allow) ;;*) fail 2;;esac
 hg_dir "$HG_RUN" && hg_dir "$HG_STORE" && ! hg_exists "$P" || fail 4
 if hg_exists /etc/homegate/access;then hg_dir /etc/homegate/access || fail;fi
 if hg_exists /etc/homegate/access/CN.cidr;then hg_file /etc/homegate/access/CN.cidr 25165824 || fail;fi
 business && ash "$HG_DIR/homegate-config-prototype.sh" --persistent writer-check >/dev/null && ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null || fail 4
 [ -f /usr/libexec/homegate-nginx/nginx ] && [ ! -L /usr/libexec/homegate-nginx/nginx ] && [ -x /usr/libexec/homegate-nginx/nginx ] && [ "$(stat -c %u /usr/libexec/homegate-nginx/nginx)" = 0 ] || fail 7
 for f in "$LOCK" "$CONTROL";do if ! hg_exists "$f";then (set -C; : > "$f") && fsync "$f" "$HG_RUN" || fail;fi;hg_file "$f" 0 && [ "$(stat -c %s "$f")" = 0 ] || fail;done
 exec 9>>"$LOCK";hg_bound 9 "$LOCK" && flock -n 9 && control || fail 4
 plan=$(ash "$HG_DIR/homegate-config-prototype.sh" --persistent runtime-startup-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null | lua "$HG_DIR/homegate-proxy.lua" plan "$selection" "$policy" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-) || fail
 selected_certificates=$(printf '%s\n' "$plan" | lua "$HG_DIR/homegate-proxy.lua" selection-certificates) || fail
 for c in $selected_certificates;do ash "$HG_DIR/homegate-certificate.sh" admission-status-internal "$c" --confirm | lua "$HG_DIR/homegate-proxy.lua" certificate-ok "$c" || fail;done
 ! hg_exists "$AUDIT" || fail 4
 ! hg_exists "$P" && mkdir "$P" && printf '%s\n' "$plan" > "$P/plan.json" || fail 4
 token=$(lua "$HG_DIR/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
 printf '%s\n' "$token" > "$P/token" && hg_binding > "$P/binding" && intent > "$P/intent" && cat /proc/sys/kernel/random/boot_id > "$P/boot" || fail
 for c in $(certificates);do
  ash "$HG_DIR/homegate-certificate.sh" admission-status-internal "$c" --confirm | lua "$HG_DIR/homegate-proxy.lua" certificate-ok "$c" || fail
  base=/etc/homegate/certs/$c;hg_dir /etc/homegate/certs && hg_dir "$base" && hg_file "$base/current" 38 && [ "$(stat -c %s "$base/current")" = 38 ] || fail
  pair=$(cat "$base/current");case "$pair" in pair-*) ;;*) fail;;esac;hg_hex "${pair#pair-}" 32 && hg_dir "$base/$pair" || fail
  for n in fullchain.pem privkey.pem scope.json result.json manifest;do hg_file "$base/$pair/$n" 65536 || fail;done
  [ "$(cat "$base/$pair/manifest")" = "$(cd "$base/$pair" && sha256sum fullchain.pem privkey.pem scope.json result.json)" ] || fail
  mkdir "$P/$c" || fail
  for n in fullchain.pem privkey.pem result.json;do cp "$base/$pair/$n" "$P/$c/$n" || fail;done
  cp "$base/current" "$P/$c/pointer" || fail
 done
 audit_token=$(lua "$HG_DIR/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
 printf '%s\n' "$audit_token" > "$P/audit-token" && printf 'false\n' > "$P/audit-health" && lua "$HG_DIR/homegate-access.lua" snapshot && mkdir "$AUDIT" && chmod 755 "$AUDIT" || fail
 snapshots > "$P/snapshots" && mkdir "$P/probe" && capture_next 1 && mv "$P/candidate.conf" "$P/active.conf" && mv "$P/candidate.json" "$P/accepted.json" && seal > "$P/seal" && lua "$HG_DIR/homegate-proxy.lua" report starting || fail
 if ! hg_exists "$BODY";then mkdir "$BODY" && chmod 755 "$BODY" || fail;fi
 [ -d "$BODY" ] && [ ! -L "$BODY" ] && [ "$(stat -c '%u:%a' "$BODY")" = 0:755 ] && mkdir "$BODY/$token" && chmod 755 "$BODY/$token" || fail
 for f in "$P/"*;do if [ -d "$f" ];then for cf in "$f/"*;do hg_exists "$cf" || continue;fsync "$cf" || fail;done;fi;fsync "$f" || fail;done
 fsync "$P" "$HG_RUN" || fail
 setsid ash "$HG_DIR/homegate-proxy.sh" serve "$token" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- </dev/null >/dev/null 2>&1 &
 exec 9>&- 5>&-;unlock
 lua "$HG_DIR/homegate-proxy.lua" status true || fail;exit 0
fi
check && hg_bound 9 "$LOCK" && flock -n 9 && [ "$token" = "$(cat "$P/token")" ] || fail
info=$(lua "$process" info "$$" "$token") || fail
old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
[ "$#" = 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] && [ "$6" = 1 ] || fail
printf '%s:%s\n' "$$" "$5" > "$P/owner" || fail
interrupted=false;trap 'interrupted=true' TERM INT
finish() {
 unlock
 lua "$HG_DIR/homegate-proxy.lua" report "$1" || :
 # This process is still the validated session/group leader. Never signal a
 # recorded PID or any global nginx service. The hard tail covers all workers.
 kill -TERM -- "-$$" 2>/dev/null || :
 sleep 1
 kill -KILL -- "-$$" 2>/dev/null
 exit 7
}
# Both version identification and nginx's complete syntax/DNS/cert check share
# one ten-second process-family deadline. No unbounded admission subprocess.
( /usr/libexec/homegate-nginx/nginx -v > "$P/version" 2>&1 && lua "$HG_DIR/homegate-proxy.lua" version && exec /usr/libexec/homegate-nginx/nginx -t -p "$P/" -c "$P/active.conf" -g 'daemon off;' ) 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- >/dev/null 2>&1 &
child=$!;now=$(lua "$process" now) || finish failed;deadline=$((now+10))
while kill -0 "$child" 2>/dev/null;do
 [ "$interrupted" = false ] && ! hg_exists "$P/stop" || finish stopped
 now=$(lua "$process" now) || finish failed;[ "$now" -lt "$deadline" ] || finish failed;sleep .1 || :
done
wait "$child" || finish failed
[ "$interrupted" = false ] && ! hg_exists "$P/stop" || finish stopped
[ "$(cat "$P/binding")" = "$(hg_binding)" ] && ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null || finish failed
lua "$HG_DIR/homegate-access-audit.lua" serve "$token" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- </dev/null >/dev/null 2>&1 &
audit_child=$!;attempt=0
while [ "$(cat "$P/audit-health")" != true ];do
 kill -0 "$audit_child" 2>/dev/null || finish failed
 attempt=$((attempt+1));[ "$attempt" -lt 20 ] || finish failed;sleep .1 || :
done
audit_info=$(lua "$process" info "$audit_child" none) || finish failed
old_ifs=$IFS;IFS=:;set -- $audit_info;IFS=$old_ifs
[ "$#" = 6 ] && [ "$2" = "$$" ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] || finish failed
audit_birth=$5
/usr/libexec/homegate-nginx/nginx -p "$P/" -c "$P/active.conf" -g 'daemon off;' 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- </dev/null >/dev/null 2>&1 &
child=$!;sleep .1
kill -0 "$child" 2>/dev/null || finish failed
lua "$HG_DIR/homegate-proxy.lua" report running || finish failed
child_info=$(lua "$process" info "$child" none) || finish failed
old_ifs=$IFS;IFS=:;set -- $child_info;IFS=$old_ifs
[ "$#" = 6 ] && [ "$2" = "$$" ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] || finish failed
child_birth=$5
child_live() {
 actual=$(lua "$process" info "$child" none) || return 1
 case "$actual" in Z:*|X:*|'') return 1;;esac
 [ "${actual#*:}" = "$$:$$:$$:$child_birth:0" ]
}
validate() { setsid ash "$HG_DIR/homegate-proxy-validation.sh" "$1" "$token" 3>&- 4>&- 5>&- 8>&- 9>&- >/dev/null 2>&1; }
reject() {
 if hg_exists "$P/rejected";then hg_file "$P/rejected" 32768 || finish failed;fi
 printf '%s\n' "$signature" > "$P/rejected" || finish failed
 clear_next || finish failed
 lua "$HG_DIR/homegate-proxy.lua" report running rejected || finish failed
 now=$(lua "$process" now) || finish failed;retry_at=$((now+60))
 unlock
}
retry_at=0
while :;do
 [ "$interrupted" = false ] && ! hg_exists "$P/stop" || finish stopped
 child_live || finish failed
 audit_actual=$(lua "$process" info "$audit_child" none) || audit_actual=
 if [ "${audit_actual#*:}" != "$$:$$:$$:$audit_birth:0" ] || [ "${audit_actual%%:*}" = Z ] || [ "${audit_actual%%:*}" = X ];then
  [ "$(cat "$P/audit-health")" = false ] || printf 'false\n' > "$P/audit-health"
 fi
 [ "$(cat "$P/binding")" = "$(hg_binding)" ] && [ "$(cat "$P/intent")" = "$(intent)" ] && ! hg_exists "$HG_STORE/startup-intent" && ! hg_exists "$HG_STORE/.startup-intent-next" && ! hg_exists "$HG_STORE/.startup-active-next" || finish restart_required
 lua "$HG_DIR/homegate-proxy.lua" validity || finish restart_required
 if ! lua "$HG_DIR/homegate-proxy.lua" changed;then
  signature=$(pointers) || finish restart_required
  if hg_exists "$P/rejected";then hg_file "$P/rejected" 32768 || finish failed;[ "$(cat "$P/rejected")" != "$signature" ] || { now=$(lua "$process" now) || finish failed;if [ "$now" -lt "$retry_at" ];then sleep 1 || :;continue;fi; };fi
  if ! business;then unlock;sleep 1 || :;continue;fi
  [ "$(cat "$P/binding")" = "$(hg_binding)" ] && [ "$(cat "$P/intent")" = "$(intent)" ] && ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null || finish restart_required
  signature=$(pointers) || finish restart_required
  generation=$(lua "$HG_DIR/homegate-proxy.lua" generation) || finish failed
  lua "$HG_DIR/homegate-proxy.lua" report running reloading || finish failed
  if ! capture_next "$((generation+1))" || ! validate check;then
   [ "$interrupted" = false ] && ! hg_exists "$P/stop" || finish stopped
   reject;continue
  fi
  child_live && cp "$P/active.conf" "$P/rollback.conf" && mv "$P/candidate.conf" "$P/active.conf" && kill -HUP "$child" || finish failed
  verified=false
  # A HUP is only a request. Verify new SNI leaf fingerprints through actual
  # TLS; nginx may need one event-loop turn before the new workers accept.
  attempt=0
  while [ "$attempt" -lt 3 ];do
   [ "$interrupted" = false ] && ! hg_exists "$P/stop" || finish stopped
   child_live || finish failed
   if validate candidate-probe;then verified=true;break;fi
   attempt=$((attempt+1));sleep .2 || :
  done
  if [ "$verified" = true ];then
   mv "$P/candidate.json" "$P/accepted.json" && rm -f "$P/rollback.conf" "$P/rejected" || finish failed
   lua "$HG_DIR/homegate-proxy.lua" report running verified || finish failed
   unlock
  else
   [ "$interrupted" = false ] && ! hg_exists "$P/stop" || finish stopped
   child_live && mv "$P/rollback.conf" "$P/active.conf" && kill -HUP "$child" || finish failed
   restored=false;attempt=0
   while [ "$attempt" -lt 3 ];do
    [ "$interrupted" = false ] && ! hg_exists "$P/stop" || finish stopped
    child_live || finish failed
    if validate accepted-probe;then restored=true;break;fi
    attempt=$((attempt+1));sleep .2 || :
   done
   [ "$restored" = true ] || finish failed
   reject
  fi
 fi
 sleep 1 || :
done
