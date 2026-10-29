#!/bin/sh
# One explicitly started renewal session. No cron, boot grant or stored-PID kill.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
acme_schedule_enabled=false
fail() { printf '{"api_version":1,"engineering":true,"ok":false,"phase":"acme-schedule","effect":"none","write_ready":false,"error":"Renewal session unavailable; inspect retained tasks"}\n';exit "${1:-7}"; }
action=${1:-}
case "$action" in
 start) [ "$acme_schedule_enabled" = true ] && [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2;certificate=$2;;
 serve) [ "$acme_schedule_enabled" = true ] && [ "$#" -eq 3 ] || fail 2;certificate=$2;token=$3;;
 status|quiescent) [ "$#" -eq 1 ] || fail 2;;
 stop|reap) [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
 *) fail 2;;esac
[ "$(id -u)" = 0 ] || fail 2
exec 2>/dev/null
HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
HG_JOB=
. "$HG_DIR/homegate-acme-common.sh"
AS_DIR=$HG_RUN/acme-schedule;AS_LOCK=$HG_RUN/acme-schedule.lock;AS_CONTROL=$HG_RUN/acme-schedule.control
idle() { printf '{"api_version":1,"engineering":true,"ok":true,"phase":"acme-schedule","state":"idle","running":false,"checks":0,"next_check":0,"job":"","effect":"none","write_ready":false}\n'; }
check_session() {
 hg_dir "$AS_DIR" || return 1
 for member in "$AS_DIR/"* "$AS_DIR/".[!.]* "$AS_DIR/"..?*;do
  hg_exists "$member" || continue;hg_file "$member" 16384 || return 1
  case "${member##*/}" in scope.json|binding|token|boot|seal|report|report.next) ;; current-job.next) [ "$(stat -c %s "$member")" -le 33 ] || return 1;; current-job) [ "$(stat -c %s "$member")" -eq 33 ] && hg_hex "$(cat "$member")" 32 || return 1;; stop) [ "$(stat -c %s "$member")" -eq 0 ] || return 1;; *) return 1;;esac
 done
 for member in scope.json binding token boot seal report;do hg_file "$AS_DIR/$member" 16384 || return 1;done
 [ "$(cat "$AS_DIR/seal")" = "$(hg_schedule_seal)" ] && [ "$(stat -c %s "$AS_DIR/seal")" -eq "$(hg_schedule_seal | wc -c)" ]
}
live() {
 running=false
 hg_file "$AS_LOCK" 0 && [ "$(stat -c %s "$AS_LOCK")" -eq 0 ] || return 1
 exec 4>>"$AS_LOCK" || return 1
 if ! flock -n 4;then running=true;fi
}
control() { hg_file "$AS_CONTROL" 0 && [ "$(stat -c %s "$AS_CONTROL")" -eq 0 ] || return 1;exec 5>>"$AS_CONTROL";hg_bound 5 "$AS_CONTROL" && flock -n 5; }
business() { hg_file "$HG_RUN/frontend.lock" 0 && hg_file "$HG_STORE/.supervisor.lock" 0 || return 1;exec 6>>"$HG_RUN/frontend.lock" 7>>"$HG_STORE/.supervisor.lock";hg_bound 6 "$HG_RUN/frontend.lock" && hg_bound 7 "$HG_STORE/.supervisor.lock" && flock -n 6 && flock -n 7; }
unlock() { exec 6>&- 7>&-; }
emit() {
 ! hg_exists "$AS_DIR/report.next" || return 1
 lua "$HG_DIR/homegate-acme.lua" session-report "$1" "$checks" "$next_check" "${current:--}" > "$AS_DIR/report.next" && fsync "$AS_DIR/report.next" "$AS_DIR" &&
 mv -f "$AS_DIR/report.next" "$AS_DIR/report" && fsync "$AS_DIR/report" "$AS_DIR"
}
stopping() {
 if hg_exists "$AS_DIR/stop";then hg_file "$AS_DIR/stop" 0 && [ "$(stat -c %s "$AS_DIR/stop")" -eq 0 ] || fail;return 0;fi
 return 1
}
stop_child() {
 if hg_exists "$AS_DIR/current-job";then
  hg_file "$AS_DIR/current-job" 33 && [ "$(stat -c %s "$AS_DIR/current-job")" -eq 33 ] || return 1
  child_job=$(cat "$AS_DIR/current-job");hg_hex "$child_job" 32 || return 1
  if hg_exists "$HG_ROOT/$child_job";then ash "$HG_DIR/homegate-acme-job.sh" stop "$child_job" --confirm 9>&- >/dev/null || return 1;fi
 fi
}
if [ "$action" != serve ];then exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;fi
if [ "$action" = status ] || [ "$action" = quiescent ] || [ "$action" = stop ] || [ "$action" = reap ];then
 if ! hg_exists "$AS_DIR";then [ "$action" != quiescent ] || hg_jobs_clear || fail 4;idle;exit 0;fi
 check_session && live || fail
 if [ "$action" = status ];then lua "$HG_DIR/homegate-acme.lua" session-status "$running" || fail;exit 0;fi
 if [ "$action" = stop ];then
  control || fail 4
  if ! hg_exists "$AS_DIR/stop";then (set -C; : > "$AS_DIR/stop") && fsync "$AS_DIR/stop" "$AS_DIR" || fail;fi
  stop_child || fail
  lua "$HG_DIR/homegate-acme.lua" session-status "$running" || fail;exit 0
 fi
 [ "$running" = false ] && hg_jobs_clear || fail 4
 if [ "$action" = quiescent ];then idle;exit 0;fi
 control || fail 4
 # Fixed, individually validated members only. Never recursively erase jobs,
 # keys, provider receipts or an unknown temporary file.
 for member in scope.json binding token boot seal report report.next current-job current-job.next stop;do rm -f "$AS_DIR/$member" || fail;done
 rmdir "$AS_DIR" && fsync "$HG_RUN" || fail;idle;exit 0
fi
if [ "$action" = start ];then
 case "$certificate" in ''|*[!a-zA-Z0-9_-]*) fail 2;;esac;[ "${#certificate}" -le 64 ] || fail 2
 hg_dir "$HG_RUN" && hg_dir "$HG_STORE" && ! hg_exists "$AS_DIR" || fail 4
 if hg_exists "$HG_RUN/ddns-schedule";then ash "$HG_DIR/homegate-ddns-schedule.sh" quiescent >/dev/null || fail 4;fi
 business && hg_jobs_clear || fail 4
 ash "$HG_DIR/homegate-config-prototype.sh" --persistent writer-check >/dev/null && ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null || fail 4
 scope=$(hg_scope "$certificate") || fail
 for member in "$AS_LOCK" "$AS_CONTROL";do
  if ! hg_exists "$member";then (set -C; : > "$member") && fsync "$member" "$HG_RUN" || fail;fi
  hg_file "$member" 0 && [ "$(stat -c %s "$member")" -eq 0 ] || fail
 done
 exec 9>>"$AS_LOCK";hg_bound 9 "$AS_LOCK" && flock -n 9 && control || fail 4
 ! hg_exists "$AS_DIR" && mkdir "$AS_DIR" || fail 4
 token=$(lua "$HG_DIR/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
 printf '%s\n' "$scope" > "$AS_DIR/scope.json" && hg_binding > "$AS_DIR/binding" && printf '%s\n' "$token" > "$AS_DIR/token" && cat /proc/sys/kernel/random/boot_id > "$AS_DIR/boot" && hg_schedule_seal > "$AS_DIR/seal" || fail
 for member in scope.json binding token boot seal;do fsync "$AS_DIR/$member" || fail;done
 checks=0;next_check=0;current=;emit starting && fsync "$AS_DIR" "$HG_RUN" || fail
 # Only the session owner retains FD9; HTTP never waits for a certificate.
 setsid ash "$HG_DIR/homegate-acme-schedule.sh" serve "$certificate" "$token" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- </dev/null >/dev/null 2>&1 &
 exec 9>&- 5>&-;unlock
 lua "$HG_DIR/homegate-acme.lua" session-status true || fail;exit 0
fi
check_session && hg_schedule_check "$token" "$certificate" || fail
info=$(lua "$HG_DIR/worker-process.lua" info "$$" "$token") || fail
old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
[ "$#" -eq 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] && [ "$6" = 1 ] || fail
checks=0;next_check=0;current=;last_now=0;interrupted=false
trap 'interrupted=true' TERM INT
finish() { unlock;next_check=0;emit "$1" || fail;exit "$2"; }
while :;do
 if stopping || [ "$interrupted" = true ];then stop_child || fail;finish stopped 0;fi
 now=$(lua "$HG_DIR/worker-process.lua" now) || finish failed 7
 [ "$now" -ge "$last_now" ] && [ "$checks" -lt 2147483647 ] || finish failed 7;last_now=$now
 if [ "$now" -lt "$next_check" ];then sleep 1 || :;continue;fi
 business || finish failed 4
 hg_schedule_check "$token" "$certificate" && hg_jobs_clear && ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null || finish failed 4
 checks=$((checks+1));emit checking || fail
 status=$(ash "$HG_DIR/homegate-certificate.sh" scheduler-status-internal "$certificate" "$token" --confirm) || finish failed 7
 due=$(printf '%s\n' "$status" | lua "$HG_DIR/homegate-acme.lua" session-due) || finish failed 7
 if [ "$due" = issue ];then
  current=$(lua "$HG_DIR/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
  printf '%s\n' "$current" > "$AS_DIR/current-job.next" && fsync "$AS_DIR/current-job.next" "$AS_DIR" && mv -f "$AS_DIR/current-job.next" "$AS_DIR/current-job" && fsync "$AS_DIR/current-job" "$AS_DIR" || fail
  emit working || fail;unlock
  ash "$HG_DIR/homegate-acme-job.sh" scheduled-renew "$certificate" "$current" "$token" --confirm >/dev/null || finish failed 4
  while :;do
   if stopping || [ "$interrupted" = true ];then stop_child || fail;fi
   raw=$(ash "$HG_DIR/homegate-acme-job.sh" status "$current" 9>&-) || finish failed 7
   # Terminal validation accepts only this certificate's complete success or
   # no-op. Interruption/unknown ends this session without a new order.
   if printf '%s\n' "$raw" | lua "$HG_DIR/homegate-acme.lua" session-pending >/dev/null;then sleep 0.25 || :;continue;fi
   if stopping || [ "$interrupted" = true ];then finish stopped 0;fi
   printf '%s\n' "$raw" | lua "$HG_DIR/homegate-acme.lua" session-result || finish failed 4
   break
  done
 else unlock;fi
 now=$(lua "$HG_DIR/worker-process.lua" now) || finish failed 7
 next_check=$((now+3600));emit waiting || fail
done
