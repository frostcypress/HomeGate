#!/bin/sh
# One foreground owner. Reuse component session contracts, never signal a saved PID.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
exec 2>/dev/null
base=/usr/libexec/homegate;dir=$base/project/core/prototype
run=/var/run/homegate;store=/etc/homegate/transactions;lock=$run/native-service.lock
codec=$base/native-service.lua;action=${1:-};stage=arguments
# Keep the actual foreground owner PID while exposing the legacy daemon status.
trap 'code=$?; if [ "$action" = serve ] && [ "$code" != 0 ];then exit 1;fi' EXIT
fail() { printf '{"api_version":1,"native":true,"ok":false,"phase":"native-service","effect":"none","write_ready":false,"failure_step":"%s","error":"Service unavailable; retained operations require attention"}\n' "$stage";exit "${1:-7}"; }
[ "$(id -u)" = 0 ] || fail 7
case "$action:$#" in serve:1|status:1|check:1|quiescent:1|admission:1|plan-certificates:1) ;;receipt:2) ;;stop:2|reap:2) [ "$2" = --confirm ] || fail 2;;plan-set:6) [ "$6" = --confirm ] || fail 2;;*) fail 2;;esac
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ] && [ "$(stat -c %s "$1")" -le "${2:-16384}" ]; }
bound() { private_file "$2" 0 && [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$1)" = "$(stat -c '%d:%i:%u:%a:%h' "$2")" ]; }
component() { ash "$dir/$1" "$2" ${3:+"$3"} 8>&- 9>&-; }
entry() { ash "$base/ddns-control.sh" "$@" 8>&- 9>&-; }
stamp() {
 private_dir "$store" && private_dir "$run" || return 1
 for file in /etc/config/homegate "$store/current" "$store/identity" "$store/startup-active";do private_file "$file" 262144 && stat -c '%d:%i:%u:%a:%h:%s' "$file" && sha256sum "$file" || return 1;done
}
plan_stamp() { if exists /etc/homegate/native-service-plan;then private_file /etc/homegate/native-service-plan && sha256sum /etc/homegate/native-service-plan;else printf 'absent\n';fi; }
intent_guard() {
 for file in "$run/frontend.lock" "$store/.supervisor.lock";do private_file "$file" 0 || return 1;done
 exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock"
 if ! { bound 6 "$run/frontend.lock" && bound 7 "$store/.supervisor.lock" && flock -n 6 && flock -n 7; };then exec 6>&- 7>&-;return 3;fi
 ash "$dir/homegate-startup-active.sh" check 9>&- >/dev/null;result=$?
 exec 6>&- 7>&-;return "$result"
}
if [ "$action" = plan-certificates ];then
 private_file "$run/frontend.lock" 0 && private_file "$store/.supervisor.lock" 0 || fail
 exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock"
 bound 6 "$run/frontend.lock" && bound 7 "$store/.supervisor.lock" && flock -n 6 && flock -n 7 || fail 4
 ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null || fail 4
 if ! exists /etc/homegate/native-service-plan;then exit 0;fi
 binding=$(stamp) || fail
 plan=$(lua "$codec" plan "$binding") || fail
 printf '%s\n' "$plan" | lua "$codec" field certificates;exit $?
fi
live=false
if exists "$lock";then
 private_dir "$run" && private_file "$lock" 0 || fail
 exec 8>>"$lock";bound 8 "$lock" || fail
 if ! flock -n 8;then live=true;fi
 exec 8>&-
fi
quiet() {
 for item in homegate-access-region.sh homegate-proxy.sh homegate-acme-schedule.sh homegate-ddns-schedule.sh;do component "$item" quiescent >/dev/null || return 1;done
 # The certificate helper's quiescent contract checks persistent ACME jobs too.
 ash "$dir/homegate-firewall.sh" cleanup-if-owned --confirm 9>&- >/dev/null || return 1
}
if [ "$action" = receipt ];then
 # The coordinator already admitted the immutable source under FD6/7. Its
 # running receipt follows real component checks. Verify that exact binding
 # and process again without competing with the admitted provider batch.
 [ "$live" = true ] && ! exists "$run/native-service.stop" || exit 3
 before=$(stamp && plan_stamp) || fail
 digest=$(printf '%s\n' "$before" | sha256sum) || fail
 receipt=$(lua "$codec" web-running "$2" "${digest%% *}");code=$?
 [ "$code" = 0 ] || exit "$code"
 [ "$(stamp && plan_stamp)" = "$before" ] || fail
 printf '%s\n' "$receipt";exit 0
fi
if [ "$action" = status ] || [ "$action" = check ];then
 config=$(ash "$dir/homegate-cli.sh" status 9>&-);config_code=$?
 # Legacy health may report an inactive raw switch while the validated native
 # intent overlay is active. Recompute native health from both actual records.
 case "$config_code" in 0|1) ;;*) fail;;esac
 intent=$(ash "$dir/homegate-startup-active.sh" status 9>&-) || fail
 printf '%s\n' "$config" | lua "$codec" status "$intent" "$live" "$action";exit $?
fi
if [ "$action" = quiescent ];then [ "$live" = false ] && quiet || fail 4;printf '{"api_version":1,"native":true,"ok":true,"phase":"native-service","quiescent":true,"effect":"none","write_ready":false}\n';exit 0;fi
if [ "$action" = reap ];then
 [ "$live" = false ] && quiet || fail 4
 for pair in homegate-access-region.sh:access-update homegate-proxy.sh:proxy homegate-acme-schedule.sh:acme-schedule homegate-ddns-schedule.sh:ddns-schedule;do
  if exists "$run/${pair#*:}";then component "${pair%%:*}" reap --confirm >/dev/null || fail 4;fi
 done
 for file in "$run/native-service.json" "$run/native-service.json.next" "$run/native-service.stop";do ! exists "$file" || private_file "$file" || fail;done
 rm -f "$run/native-service.json" "$run/native-service.json.next" "$run/native-service.stop" && fsync "$run" || fail
 printf '{"api_version":1,"native":true,"ok":true,"phase":"native-service","quiescent":true,"effect":"none","write_ready":false}\n';exit 0
fi
if [ "$action" = stop ];then
 private_dir "$run" || fail
 if [ "$live" = true ];then
  if ! exists "$run/native-service.stop";then (set -C; : > "$run/native-service.stop") && fsync "$run/native-service.stop" "$run" || fail;fi
  private_file "$run/native-service.stop" 0 || fail
 fi
 for pair in homegate-access-region.sh:access-update homegate-proxy.sh:proxy homegate-acme-schedule.sh:acme-schedule homegate-ddns-schedule.sh:ddns-schedule;do
  if exists "$run/${pair#*:}";then component "${pair%%:*}" stop --confirm >/dev/null || fail 4;fi
 done
 printf '{"api_version":1,"native":true,"ok":true,"phase":"native-service","stop_requested":true,"effect":"none","write_ready":false}\n'
 exit 0
fi
if [ "$action:$live" = admission:true ];then lua "$codec" alive;exit $?;fi
# Startup never grants DDNS authority, migrates a source, clears unknown jobs or
# replays retained network writes. Existing admission records must remain valid.
stage=namespace;private_dir "$run" && private_dir "$store" || fail 4
if exists /etc/homegate/package-state;then
 [ "$action" = admission ] && private_file /etc/homegate/package-state 64 &&
 [ "$(head -n 2 /etc/homegate/package-state)" = "$(printf 'HGPKG1\nready')" ] || fail 4
fi
stage=intent;intent=$(ash "$dir/homegate-startup-active.sh" status) || fail 4
printf '%s\n' "$intent" | lua "$codec" ready intent || fail 4
stage=writer;ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null || fail 4
if [ "$action" = admission ];then quiet || fail 4;exit 0;fi
if [ "$action" = plan-set ];then
 [ "$live" = false ] && quiet || fail 4
 source_binding=$(stamp) || fail
 for file in /etc/homegate/native-service-plan /etc/homegate/.native-service-plan.next;do ! exists "$file" || private_file "$file" || fail;done
 lua "$codec" plan-set "$source_binding" "$2" "$3" "$4" "$5" > /etc/homegate/.native-service-plan.next || fail 2
 [ "$(stamp)" = "$source_binding" ] && fsync /etc/homegate/.native-service-plan.next &&
 mv -f /etc/homegate/.native-service-plan.next /etc/homegate/native-service-plan && fsync /etc/homegate/native-service-plan /etc/homegate || fail
 printf '{"api_version":1,"native":true,"ok":true,"phase":"native-service-plan","effect":"none","write_ready":false,"plan_saved":true,"authority_granted":false}\n';exit 0
fi
stage=owner;if ! exists "$lock";then (set -C; : > "$lock") && fsync "$lock" "$run" || fail;fi
private_file "$lock" 0 || fail
exec 9>>"$lock";bound 9 "$lock" && flock -n 9 || fail 4
# A previous owner must be fully quiet before fixed ephemeral records are reused.
quiet || fail 4
for pair in homegate-access-region.sh:access-update homegate-proxy.sh:proxy homegate-acme-schedule.sh:acme-schedule homegate-ddns-schedule.sh:ddns-schedule;do
 item=${pair%%:*};member=${pair#*:}
 if exists "$run/$member";then component "$item" reap --confirm >/dev/null || fail 4;fi
done
if exists "$run/native-service.stop";then private_file "$run/native-service.stop" 0 && rm "$run/native-service.stop" || fail;fi
for file in "$run/native-service.json" "$run/native-service.json.next";do ! exists "$file" || private_file "$file" || fail;done
stage=source;source_binding=$(stamp) || fail
binding=$(stamp && plan_stamp) || fail
binding_digest=$(printf '%s\n' "$binding" | sha256sum) || fail;binding_digest=${binding_digest%% *}
stage=plan;plan=$(lua "$codec" plan "$source_binding" 9>&-) || fail
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 9>&-) || fail
ddns=$(printf '%s\n' "$plan" | lua "$codec" field ddns 9>&-) || fail
certificates=$(printf '%s\n' "$plan" | lua "$codec" field certificates 9>&-) || fail
web=$(printf '%s\n' "$plan" | lua "$codec" field web 9>&-) || fail
policy=$(printf '%s\n' "$plan" | lua "$codec" field policy 9>&-) || fail
auto_firewall=$(printf '%s\n' "$plan" | lua "$codec" field auto_firewall 9>&-) || fail
info=$(lua "$dir/worker-process.lua" info "$$" none 9>&-) || fail
oldifs=$IFS;IFS=:;set -- $info;IFS=$oldifs;[ "$#" = 6 ] || fail;birth=$5
stage=admission;intent_guard && [ "$(stamp && plan_stamp)" = "$binding" ] || fail 4
emit() {
 case "$1" in failed|restart_required) final_state=$1;final_reason=$2;;esac
 for file in "$run/native-service.json" "$run/native-service.json.next";do ! exists "$file" || private_file "$file" || return 1;done
 lua "$codec" emit "$1" "$$" "$birth" "$revision" "$2" "$binding_digest" 9>&- > "$run/native-service.json.next" &&
 fsync "$run/native-service.json.next" && mv -f "$run/native-service.json.next" "$run/native-service.json" && fsync "$run/native-service.json" "$run"
}
stopping=false;reload=false;job=;ddns_started=false;proxy_started=false;final_state=stopped;final_reason=known
trap 'stopping=true' TERM INT
trap 'reload=true' HUP
trap ':' USR1
shutdown() {
 trap - EXIT;emit stopping requested >/dev/null || :
 [ -z "$job" ] || entry acme-stop "$job" --confirm >/dev/null || :
 for item in homegate-access-region.sh homegate-proxy.sh homegate-acme-schedule.sh homegate-ddns-schedule.sh;do component "$item" stop --confirm >/dev/null || :;done
 tries=0
 while [ "$tries" -lt 15 ];do
  if quiet;then emit "$final_state" "$final_reason" >/dev/null;return $?;fi
  tries=$((tries+1));sleep 1 9>&- || return 1
 done
 emit failed stop_unknown >/dev/null;return 1
}
trap 'code=$?; shutdown || code=4; [ "$code" = 0 ] || code=1;exit "$code"' EXIT
emit starting admission || fail
start_ddns() {
 [ -n "$ddns" ] || return 0
 authorized=$(ash "$dir/homegate-ddns-authority.sh" check 9>&- | lua "$dir/homegate-ddns-batch.lua" names "$revision" 9>&-) || return 1
 expected_authorized=$(printf '%s\n' "$ddns" | tr ' ' '\n') || return 1
 [ "$authorized" = "$expected_authorized" ] || return 1
 entry schedule-serve --confirm >/dev/null || return 1;ddns_started=true
}
pause_ddns() {
 [ "$ddns_started" = true ] || return 0
 entry schedule-stop --confirm >/dev/null || return 1
 tries=0
 while [ "$tries" -lt 8 ];do
  if entry schedule-quiescent >/dev/null;then entry schedule-reap --confirm >/dev/null || return 1;ddns_started=false;return 0;fi
  tries=$((tries+1));sleep 1 9>&- || return 1
 done;return 1
}
if [ -z "$certificates" ];then start_ddns || { emit failed authorization_required;exit 4; };fi
last_check=0;scan_due=true
while :;do
 if [ "$stopping" = true ] || exists "$run/native-service.stop";then
  ! exists "$run/native-service.stop" || private_file "$run/native-service.stop" 0 || fail
  exit 0
 fi
 current=$(stamp && plan_stamp) || { emit failed source_unavailable;exit 4; }
 if [ "$reload" = true ] || [ "$current" != "$binding" ];then emit restart_required source_changed;exit 4;fi
 # Each component admits its own work under the existing business locks.
 # The coordinator watches the already-validated immutable binding instead
 # of competing with an active DNS/ACME transaction for those same locks.
 if [ -n "$job" ];then
  state=$(entry acme-job "$job") || { emit failed certificate_unknown;exit 7; }
  printf '%s\n' "$state" | lua "$codec" ready job 9>&-;code=$?
  if [ "$code" = 0 ];then job=;scan_due=true
  elif [ "$code" != 3 ];then emit failed certificate_failed;exit 7;fi
 fi
 now=$(lua "$dir/worker-process.lua" now 9>&-) || fail
 if [ -z "$job" ] && { [ "$scan_due" = true ] || [ "$((now-last_check))" -ge 60 ]; };then
  last_check=$now;scan_due=false
  if [ -n "$certificates" ];then pause_ddns || { emit failed ddns_pause_unknown;exit 4; };fi
  for certificate in $certificates;do
   material=$(ash "$dir/homegate-certificate.sh" status "$certificate" 9>&-) || { emit failed certificate_unavailable;exit 7; }
   printf '%s\n' "$material" | lua "$codec" ready due 9>&-;code=$?
   if [ "$code" = 3 ];then continue;fi
   [ "$code" = 0 ] || { emit failed certificate_unknown;exit 7; }
   pause_ddns || { emit failed ddns_pause_unknown;exit 4; }
   job=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 9>&-) || fail
   entry acme-renew "$certificate" "$job" --confirm >/dev/null || { emit failed certificate_start_failed;exit 7; }
   break
  done
 fi
 if [ -z "$job" ] && [ "$ddns_started" = false ];then start_ddns || { emit failed ddns_resume_failed;exit 4; };fi
 if [ -z "$job" ] && [ -n "$web" ] && [ "$proxy_started" = false ];then
  entry proxy-start "$web" "$policy" --confirm >/dev/null || { emit failed proxy_start_failed;exit 7; };proxy_started=true
  clock=$(lua "$dir/worker-process.lua" now 9>&-) || fail;ready_until=$((clock+8))
  while :;do
   state=$(entry proxy-status) || { emit failed proxy_unavailable;exit 7; }
   printf '%s\n' "$state" | lua "$codec" ready running 9>&-;code=$?
   [ "$code" != 0 ] || break
   clock=$(lua "$dir/worker-process.lua" now 9>&-) || fail
   [ "$code" = 3 ] && [ "$clock" -lt "$ready_until" ] || { emit failed proxy_start_failed;exit 7; }
   sleep 0.1 9>&- || fail
  done
  if [ "$auto_firewall" = true ];then entry firewall-apply --confirm >/dev/null || { emit failed firewall_apply_failed;exit 7; };fi
 fi
 if [ "$ddns_started" = true ];then state=$(entry schedule-status) && printf '%s\n' "$state" | lua "$codec" ready running 9>&- || { emit failed ddns_stopped;exit 7; };fi
 if [ "$proxy_started" = true ];then state=$(entry proxy-status) && printf '%s\n' "$state" | lua "$codec" ready running 9>&- || { emit failed proxy_stopped;exit 7; };fi
 if [ -n "$job" ];then emit renewing certificate;else emit running ready;fi || fail
 sleep 1 9>&- || fail
done
