#!/bin/sh
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
exec 2>/dev/null
base=/usr/libexec/homegate;codec=$base/native-web-store.lua;root=/tmp/homegate-frontend-jobs;run=/var/run/homegate
clock=$base/project/core/prototype/worker-process.lua
pause(){ lua "$clock" pause "$1" || sleep "$2"; }
fail(){ printf '{"api_version":1,"ok":false,"error":"Web request refused; inspect retained task"}\n';exit "${1:-1}"; }
dir(){ [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
file(){ [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
empty(){ file "$1" && [ "$(stat -c %s "$1")" = 0 ]; }
valid_id(){ [ "${#1}" = 32 ] && case "$1" in *[!0-9a-f]*) false;;*) true;;esac; }
held(){ [ -e /etc/homegate/package-state ] || [ -L /etc/homegate/package-state ] || [ -e /etc/.homegate-transition/hold ] || [ -L /etc/.homegate-transition/hold ]; }
[ "$(id -u)" = 0 ] && [ "$#" = 2 ] || fail 2
action=$1;value=$2
case "$action" in
 purge)
  [ "$value" = - ] || fail
  if [ ! -e "$root" ] && [ ! -L "$root" ];then printf '{"ok":true}\n';exit 0;fi
  dir "$root" && empty "$root/.allocation.lock" || fail
  exec 7>>"$root/.allocation.lock";flock -n 7 || fail
  if [ -e "$run/frontend-web.lock" ] || [ -L "$run/frontend-web.lock" ];then empty "$run/frontend-web.lock" || fail;exec 8>>"$run/frontend-web.lock";flock -n 8 || fail;fi
  for p in "$root"/*;do [ -e "$p" ] || continue;dir "$p" || fail
   if [ -e "$p/owner.lock" ];then empty "$p/owner.lock" || fail;exec 9>>"$p/owner.lock";flock -n 9 || fail;exec 9>&-;fi
  done
  exec lua "$codec" purge -;;
 read) lua "$base/native-web-session.lua" read-owner "$value" & child=$!;wait "$child";exit $?;;
 read-owner)
  info=$(lua "$clock" info "$$" none) || fail;oldifs=$IFS;IFS=:;set -- $info;IFS=$oldifs;[ "$#" = 6 ] && [ "$3:$4" = "$$:$$" ] || fail
  now=$(lua "$clock" now) || fail;deadline=$((now+18))
  trap '' TERM INT
  (trap - TERM INT;exec lua "$base/native-web.lua" read "$value") & child=$!
  stop_read(){
   kill -TERM -- "-$$" 2>/dev/null || :
   pause 300 .3 || sleep 1 || :
   kill -KILL -- "-$$" 2>/dev/null;exit 1
  }
  while kill -0 "$child" 2>/dev/null;do
   now=$(lua "$clock" now) || now=$deadline
   [ "$now" -lt "$deadline" ] || stop_read
   pause 100 .1 || sleep 1 || stop_read
  done
  wait "$child";exit $?;;
 submit)
  lua "$codec" validate-request "$value" >/dev/null || fail 1
  held && fail 4
  if [ ! -e "$root" ] && [ ! -L "$root" ];then mkdir "$root" || fail;fi
  dir "$root" || fail
  if [ ! -e "$root/.allocation.lock" ] && [ ! -L "$root/.allocation.lock" ];then (set -C;: > "$root/.allocation.lock") || :;fi
  empty "$root/.allocation.lock" || fail
  exec 7>>"$root/.allocation.lock";flock -n 7 || fail
  held && fail 4
  token=$(lua "$codec" submit "$value") || fail
  valid_id "$token" || fail
  fsync "$root/$token/request" "$root/$token" "$root" || fail
  lua "$base/native-web-session.lua" owner "$token" 7>&- </dev/null >/dev/null &
  printf '{"ok":true,"pending":true,"job":"%s"}\n' "$token";exit 0;;
 job)
  valid_id "$value" && dir "$root" && dir "$root/$value" || fail
  if [ ! -e "$root/$value/owner.lock" ] && [ ! -L "$root/$value/owner.lock" ] && [ ! -e "$root/$value/result" ];then
   file "$root/$value/request" || fail;lua "$base/native-web-session.lua" owner "$value" </dev/null >/dev/null &
  fi
  exec ash "$base/native-web.sh" status "$value";;
 status|ack)
  valid_id "$value" && dir "$root" && dir "$root/$value" || fail
  live=false
  if [ -e "$root/$value/owner.lock" ] || [ -L "$root/$value/owner.lock" ];then
   empty "$root/$value/owner.lock" || fail;exec 9>>"$root/$value/owner.lock";flock -n 9 || live=true;exec 9>&-
  fi
  [ "$action" != ack ] || [ "$live" = false ] || fail
  exec lua "$codec" "$action" "$value" "$live";;
 owner)
  valid_id "$value" && dir "$root" && dir "$root/$value" || fail
  work=$root/$value;file "$work/request" || fail
  [ ! -e "$work/owner.lock" ] && [ ! -L "$work/owner.lock" ] || fail
  (set -C;: > "$work/owner.lock") || fail
  started=false;not_started_reason=preflight
  before_work_exit(){
   if [ "$started" = false ] && [ ! -e "$work/result" ];then
    lua "$codec" not-started "$not_started_reason" > "$work/result.next" && fsync "$work/result.next" && mv "$work/result.next" "$work/result" || return
    for name in request deadline;do if [ -e "$work/$name" ];then file "$work/$name" && rm "$work/$name" || return;fi;done
    fsync "$work"
   fi
  }
  trap before_work_exit EXIT
  empty "$work/owner.lock" || fail;exec 9>>"$work/owner.lock"
  # A status probe can briefly own this just-created file before its unique
  # creator acquires FD9. Retry only this pre-work claim, never an operation.
  tries=0
  while ! flock -n 9;do
   tries=$((tries+1));[ "$tries" -lt 40 ] || fail 4
   pause 10 .01 || fail 4
  done
  [ "$(stat -Lc '%d:%i' /proc/self/fd/9)" = "$(stat -c '%d:%i' "$work/owner.lock")" ] || fail
  [ ! -e "$work/result" ] && [ ! -e "$work/result.next" ] || fail
  now=$(lua "$clock" now) || fail;deadline=$((now+180))
  (set -C;printf '%s\n' "$deadline" > "$work/deadline") || fail
  info=$(lua "$clock" info "$$" none) || fail
  oldifs=$IFS;IFS=:;set -- $info;IFS=$oldifs;[ "$#" = 6 ] && [ "$3:$4" = "$$:$$" ] || fail
  not_started_reason=runtime-directory
  if [ ! -e "$run" ] && [ ! -L "$run" ];then mkdir "$run" || dir "$run" || fail;fi
  dir "$run" || fail
  not_started_reason=runtime-lock
  if [ ! -e "$run/frontend-web.lock" ] && [ ! -L "$run/frontend-web.lock" ];then (set -C;: > "$run/frontend-web.lock") || :;fi
  empty "$run/frontend-web.lock" || fail;exec 8>>"$run/frontend-web.lock"
  not_started(){ lua "$codec" not-started "$not_started_reason" > "$work/result.next" && fsync "$work/result.next" && mv "$work/result.next" "$work/result" && rm "$work/request" "$work/deadline" && fsync "$work" || fail;exit 0; }
  not_started_reason=busy
 while ! flock -n 8;do now=$(lua "$clock" now) || fail;[ "$now" -lt "$deadline" ] || not_started;pause 100 .1 || sleep 1;done
  not_started_reason=package-state
  held && not_started
  stopped=false;trap 'stopped=true' TERM INT
  started=true;trap - EXIT
  (ulimit -f 4096;exec lua "$base/native-web.lua" write "$work/request" 9>&-) > "$work/result.next" &
  child=$!
  while kill -0 "$child" 2>/dev/null;do
   now=$(lua "$clock" now) || stopped=true
   if [ "$stopped" = true ] || [ "$now" -ge "$deadline" ];then
    trap '' TERM INT;kill -TERM -- "-$$" 2>/dev/null || :;sleep .3 || sleep 1
    lua "$codec" error > "$work/interrupted";fsync "$work/interrupted";mv "$work/interrupted" "$work/result";fsync "$work"
    kill -KILL -- "-$$" 2>/dev/null;exit 1
   fi
  pause 100 .1 || sleep 1
  done
  wait "$child";code=$?
  if [ "$code" != 0 ] || [ ! -s "$work/result.next" ];then lua "$codec" error > "$work/result.next" || fail;fi
  publish_result(){ file "$work/result.next" && fsync "$work/result.next" && mv "$work/result.next" "$work/result" && fsync "$work/result" "$work"; }
  desired=$(lua "$codec" start-options "$value") || fail
  if [ -n "$desired" ];then
   (set -C; : > "$work/starting") || fail
   # Publication/intent are sealed. Release only the extra admission fence;
   # existing source/plan/revision guards still bind every service action.
   exec 8>&-
   running=false;status=;failure_stage=runtime-admission
   start_exit=;receipt=
   runtime_interrupted(){
    # Only the Web owner's verified session is signalled. The coordinator
    # dispatched by procd is independent, so its outcome remains uncertain.
    trap '' TERM INT;kill -TERM -- "-$$" 2>/dev/null || :;sleep 1
   lua "$codec" runtime-result "$value" false "$failure_stage" "$start_exit" "$receipt" </dev/null && publish_result
   if file "$work/starting";then rm "$work/starting";fsync "$work";fi
    kill -KILL -- "-$$" 2>/dev/null;exit 1
   }
   runtime_call(){
    until_time=$1;shift
    now=$(lua "$clock" now) || return 1
    [ "$stopped" = false ] && [ "$now" -lt "$until_time" ] || return 1
    "$@" 9>&- & child=$!
    while kill -0 "$child" 2>/dev/null;do
     now=$(lua "$clock" now) || runtime_interrupted
     [ "$stopped" = false ] && [ "$now" -lt "$until_time" ] || runtime_interrupted
     pause 100 .1 || sleep 1
    done
    wait "$child";runtime_exit=$?
    now=$(lua "$clock" now) || return 1
    [ "$stopped" = false ] && [ "$now" -lt "$until_time" ]
   }
   ready=false
   now=$(lua "$clock" now) || fail
   admission_deadline=$((now+30))
   while ! held;do
    runtime_call "$admission_deadline" /usr/bin/homegate service-admission >/dev/null || break
    if [ "$runtime_exit" = 0 ];then ready=true;break;fi
    sleep 1 || break
   done
   if [ "$ready" = true ] && ! held;then
    failure_stage=runtime-start
    now=$(lua "$clock" now) || fail
    if runtime_call "$((now+30))" /etc/init.d/homegate start >/dev/null;then
     start_exit=$runtime_exit
     # Init may fail after dispatch. It is called once and either return
     # code gets the full window for the source-bound coordinator receipt.
     now=$(lua "$clock" now) || fail
     receipt_deadline=$((now+60))
     (set -C;: > "$work/runtime-receipt") || fail
     while runtime_call "$receipt_deadline" ash "$base/native-service.sh" receipt "$desired" > "$work/runtime-receipt";do
      receipt=$runtime_exit
      if [ "$receipt" = 0 ];then
       status=$(cat "$work/runtime-receipt") || fail
       if printf '%s\n' "$status" | lua "$base/native-service.lua" web-ready "$desired" 9>&-;then running=true;break;fi
      fi
      [ "$receipt" != 1 ] || break
      sleep 1 || break
     done
    fi
   fi
   if [ "$running" = true ];then
    failure_stage=boot-enable
    now=$(lua "$clock" now) || fail
    boot_deadline=$((now+10))
    { runtime_call "$boot_deadline" /etc/init.d/homegate enable >/dev/null && [ "$runtime_exit" = 0 ] &&
      runtime_call "$boot_deadline" /etc/init.d/homegate enabled >/dev/null && [ "$runtime_exit" = 0 ]; } || running=false
   fi
   printf '%s\n' "$status" | lua "$codec" runtime-result "$value" "$running" "$failure_stage" "$start_exit" "$receipt" || fail
  fi
  publish_result || fail
  file "$work/deadline" && rm "$work/deadline" || fail
  file "$work/request" && rm "$work/request" || fail
  for name in call-input call-output runtime-receipt starting applying-start applying-stop;do if [ -e "$work/$name" ];then file "$work/$name" && rm "$work/$name" || fail;fi;done
  exit 0;;
 *) fail 2;;
esac
