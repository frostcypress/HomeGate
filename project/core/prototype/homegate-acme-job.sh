#!/bin/sh
# Explicit bounded ACME jobs. No boot/cron scheduling and no retries after unknown DNS.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
acme_jobs_enabled=false
fail() { printf '{"api_version":1,"engineering":true,"ok":false,"phase":"acme-job","effect":"none","write_ready":false,"error":"ACME request unavailable; inspect retained job and DNS receipts"}\n';exit "${1:-7}"; }
[ "$acme_jobs_enabled" = true ] && [ "$(id -u)" = 0 ] || fail 2
scheduled=false
action=${1:-}
if [ "$action" = scheduled-renew ];then
 [ "$#" -eq 5 ] && [ "$5" = --confirm ] || fail 2
 schedule_token=$4;scheduled=true;set -- renew "$2" "$3" --confirm;action=renew
fi
case "$action" in
 issue|renew) [ "$#" -eq 4 ] && [ "$4" = --confirm ] || fail 2;certificate=$2;HG_JOB=$3;case "$certificate" in ''|*[!a-zA-Z0-9_-]*) fail 2;;esac;[ "${#certificate}" -le 64 ] || fail 2;;
 status|work|work-cleanup) [ "$#" -eq 2 ] || fail 2;HG_JOB=$2;;
 stop|cleanup) [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2;HG_JOB=$2;;
 *) fail 2;;esac
HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
. "$HG_DIR/homegate-acme-common.sh"
hg_hex "$HG_JOB" 32 || fail 2
publish_result() {
 lua "$HG_DIR/homegate-acme.lua" report "$HG_JOB" "$1" "$2" > "$HG_PATH/result.next" &&
 fsync "$HG_PATH/result.next" "$HG_PATH" && mv -f "$HG_PATH/result.next" "$HG_PATH/result" && fsync "$HG_PATH/result" "$HG_PATH"
}
cleanup_known() {
 hg_source_guard || return 1
 for entry in "$HG_PATH/challenges/"*;do
  hg_exists "$entry" || continue;key=${entry##*/};key=${key%.json};hg_hex "$key" 64 && hg_file "$entry" 4096 || return 1
  # The codec refuses unknown/prepared ownership. No guessed cleanup is possible.
  if lua "$HG_DIR/homegate-acme.lua" challenge-load "$HG_JOB" "$key" > "$HG_PATH/cleanup.input";then
   ash "$HG_DIR/homegate-acme-dns.sh" remove < "$HG_PATH/cleanup.input" || return 1
  fi
 done
 hg_challenges
}
if [ "$action" = work ] || [ "$action" = work-cleanup ];then
 hg_job_check || fail
 HOMEGATE_ACME_JOB=$HG_JOB;export HOMEGATE_ACME_JOB
 if [ "$action" = work ];then hg_guard || { publish_result failed true;exit 1; };else hg_source_guard || { publish_result failed true;exit 1; };fi
 if [ "$action" = work-cleanup ];then
  cleanup=false;cleanup_known && cleanup=true
  if [ "$cleanup" = true ];then publish_result cleaned false;else publish_result failed true;fi
  exit 0
 fi
 # This process is a fresh session leader, and retains job/business locks until
 # its entire acme.sh process family has become quiescent.
 info=$(lua "$HG_DIR/worker-process.lua" info "$$" "$HG_JOB") || fail
 old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs
 [ "$#" -eq 6 ] && [ "$3" = "$$" ] && [ "$4" = "$$" ] && [ "$6" = 1 ] || fail
 created=$(cat "$HG_PATH/created");case "$created" in ''|*[!0-9]*) fail;;esac
 now=$(lua "$HG_DIR/worker-process.lua" now);[ "$now" -ge "$created" ] && [ "$now" -le "$((created+900))" ] || fail
 deadline=$((created+900));stopping=false;trap 'stopping=true' TERM INT
 certificate=$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" id) || fail
 mode=$(cat "$HG_PATH/mode");case "$mode" in issue) ;;renew)
  due=$(ash "$HG_DIR/homegate-certificate.sh" acme-status-internal "$certificate" "$HG_JOB" --confirm | lua "$HG_DIR/homegate-acme.lua" renew-due "$HG_JOB") || fail
  if [ "$due" = skip ];then publish_result skipped false;exit 0;fi;;*) fail;;esac
 ash "$HG_DIR/homegate-acme-client.sh" "$HG_JOB" > "$HG_PATH/client.output" 2>&1 & child=$!
 while :;do
  info=$(lua "$HG_DIR/worker-process.lua" info "$child" none) || stopping=true
  case "$info" in ''|Z:*|X:*) break;;esac
  now=$(lua "$HG_DIR/worker-process.lua" now) || stopping=true
  if hg_exists "$HG_PATH/stop" || [ "$stopping" = true ] || [ "$now" -ge "$deadline" ];then
   # Unknown work is kept. Do not publish a certificate or retry the order.
   kill -TERM -- "-$$" 2>/dev/null || :;sleep 1;kill -KILL -- "-$$" 2>/dev/null;exit 1
  fi
  sleep 0.05 || stopping=true
 done
 rc=0;wait "$child" || rc=$?
 members=$(lua "$HG_DIR/worker-process.lua" group "$$" "$$") || fail
 [ "$members" = 0 ] || fail
 if [ "$rc" -eq 0 ] && hg_guard && hg_challenges;then
  if lua "$HG_DIR/homegate-acme.lua" install "$HG_JOB" | ash "$HG_DIR/homegate-certificate.sh" acme-import-internal "$certificate" "$HG_JOB" --confirm > "$HG_PATH/install.result" 2>/dev/null;then
   publish_result issued false;exit 0
  fi
 fi
 cleanup=true;hg_challenges && cleanup=false
 publish_result failed "$cleanup";exit 1
fi
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&-
[ "$scheduled" = true ] || exec 9>&-
if [ "$action" = status ] || [ "$action" = stop ];then
 hg_dir "$HG_PATH" && hg_file "$HG_PATH/lock" 0 && hg_file "$HG_PATH/seal" 1024 || fail 5
 [ "$(cat "$HG_PATH/seal")" = "$(hg_seal)" ] || fail
 if [ "$action" = stop ];then
  if ! hg_exists "$HG_PATH/stop";then (set -C; : > "$HG_PATH/stop") && fsync "$HG_PATH/stop" "$HG_PATH" || fail;else hg_file "$HG_PATH/stop" 0 || fail;fi
 fi
 exec 9>>"$HG_PATH/lock" || fail
 if flock -n 9;then
  if hg_exists "$HG_PATH/result";then hg_file "$HG_PATH/result" 16384 && lua "$HG_DIR/homegate-acme.lua" read-report "$HG_JOB" || fail
  else lua "$HG_DIR/homegate-acme.lua" report "$HG_JOB" interrupted true;fi
 else lua "$HG_DIR/homegate-acme.lua" report "$HG_JOB" pending false;fi
 exit 0
fi
# Serialize admission before creating any persistent account/job state.
if [ "$scheduled" != true ] && { [ "$action" = issue ] || [ "$action" = renew ]; };then
 ash "$HG_DIR/homegate-acme-schedule.sh" quiescent >/dev/null 2>/dev/null || fail 4
fi
hg_dir "$HG_RUN" && hg_dir "$HG_STORE" || fail
if hg_exists "$HG_RUN/ddns-schedule";then ash "$HG_DIR/homegate-ddns-schedule.sh" quiescent >/dev/null 2>/dev/null || fail 4;fi
for fd in 6 7;do
 lock=$HG_RUN/frontend.lock;[ "$fd" != 7 ] || lock=$HG_STORE/.supervisor.lock
 hg_file "$lock" 0 || fail
 case "$fd" in 6) exec 6>>"$lock";;7) exec 7>>"$lock";;esac
 hg_bound "$fd" "$lock" && flock -n "$fd" || fail 4
done
# Recheck under the admission locks: a session may have started after the
# earlier point-in-time quiescence observation.
if [ "$scheduled" != true ] && { [ "$action" = issue ] || [ "$action" = renew ]; };then
 ash "$HG_DIR/homegate-acme-schedule.sh" quiescent >/dev/null 2>/dev/null || fail 4
fi
ash "$HG_DIR/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || fail 4
if [ "$action" != cleanup ];then ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null 2>/dev/null || fail 4;fi
if [ "$scheduled" = true ];then hg_schedule_check "$schedule_token" "$certificate" || fail 4;exec 9>&-;fi
if hg_exists "$HG_RUN/ddns-ui-jobs";then ash "$HG_DIR/homegate-ddns-job.sh" check-quiescent >/dev/null 2>/dev/null || fail 4;fi
for parent in /etc/homegate/acme "$HG_ROOT";do
 if ! hg_exists "$parent";then mkdir "$parent" && fsync "$parent" "${parent%/*}" || fail;fi
 hg_dir "$parent" || fail
done
if [ "$action" = cleanup ];then
 hg_dir "$HG_PATH" && hg_file "$HG_PATH/lock" 0 || fail
 exec 8>>"$HG_PATH/lock";hg_bound 8 "$HG_PATH/lock" && flock -n 8 || fail 4
 hg_job_check && [ "$(hg_binding)" = "$(cat "$HG_PATH/binding")" ] || fail
 if hg_exists "$HG_PATH/result" && ! hg_exists "$HG_PATH/result-before-cleanup";then cp "$HG_PATH/result" "$HG_PATH/result-before-cleanup" && fsync "$HG_PATH/result-before-cleanup" || fail;fi
 setsid ash "$HG_DIR/homegate-acme-job.sh" work-cleanup "$HG_JOB" 9>&- </dev/null >/dev/null 2>&1 &
 exec 8>&- 6>&- 7>&-
 lua "$HG_DIR/homegate-acme.lua" report "$HG_JOB" accepted false;exit 0
fi
if hg_exists "$HG_PATH";then
 hg_dir "$HG_PATH" && hg_file "$HG_PATH/lock" 0 && hg_file "$HG_PATH/scope.json" 16384 && hg_file "$HG_PATH/mode" 16 || fail
 [ "$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" id)" = "$certificate" ] && [ "$(cat "$HG_PATH/mode")" = "$action" ] || fail 4
 exec 6>&- 7>&-
 exec ash "$HG_DIR/homegate-acme-job.sh" status "$HG_JOB"
fi
hg_jobs_clear || fail 4
ready=$(ash "$HG_DIR/homegate-certificate.sh" admission-status-internal "$certificate" --confirm) || fail 4
printf '%s\n' "$ready" | lua "$HG_DIR/homegate-acme.lua" certificate-ready "$certificate" || fail 4
scope=$(hg_scope "$certificate") || fail
count=0;for member in "$HG_ROOT/"*;do hg_exists "$member" || continue;hg_dir "$member" || fail;count=$((count+1));done;[ "$count" -lt 16 ] || fail 4
mkdir "$HG_PATH" "$HG_PATH/challenges" "$HG_PATH/receipts" "$HG_PATH/issued" || fail
printf '%s\n' "$scope" > "$HG_PATH/scope.json" && hg_binding > "$HG_PATH/binding" && printf '%s\n' "$action" > "$HG_PATH/mode" && hg_seal > "$HG_PATH/seal" || fail
lua "$HG_DIR/worker-process.lua" now > "$HG_PATH/created" || fail
(set -C; : > "$HG_PATH/lock") || fail
exec 8>>"$HG_PATH/lock";hg_bound 8 "$HG_PATH/lock" && flock -n 8 || fail
for member in scope.json binding mode seal created lock;do fsync "$HG_PATH/$member" || fail;done
fsync "$HG_PATH" "$HG_ROOT" || fail
setsid ash "$HG_DIR/homegate-acme-job.sh" work "$HG_JOB" 9>&- </dev/null >/dev/null 2>&1 &
exec 8>&- 6>&- 7>&-
lua "$HG_DIR/homegate-acme.lua" report "$HG_JOB" accepted false
