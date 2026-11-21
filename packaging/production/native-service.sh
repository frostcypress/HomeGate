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
case "$action:$#" in serve:1|status:1|check:1|overview-status:1|owner-state:1|quiescent:1|admission:1|plan-certificates:1) ;;receipt:2|receipt:3) ;;stop:2|reap:2) [ "$2" = --confirm ] || fail 2;;plan-set:6) [ "$6" = --confirm ] || fail 2;;*) fail 2;;esac
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
service_locks() {
 for file in "$run/frontend.lock" "$store/.supervisor.lock";do private_file "$file" 0 || return 1;done
 exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock"
 if ! { bound 6 "$run/frontend.lock" && bound 7 "$store/.supervisor.lock"; };then exec 6>&- 7>&-;return 1;fi
 flock -n 6 && flock -n 7;result=$?
 if [ "$result" != 0 ];then
  exec 6>&- 7>&-
  [ "$result" = 1 ] && return 3
  return 1
 fi
 if ! { bound 6 "$run/frontend.lock" && bound 7 "$store/.supervisor.lock"; };then exec 6>&- 7>&-;return 1;fi
}
intent_guard() {
 service_locks || return $?
 ash "$dir/homegate-startup-active.sh" check-current 9>&- >/dev/null;result=$?
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
 ! exists "$run/native-service.stop" || exit 3
 [ "$live" = true ] || [ "$#" = 3 ] || exit 3
 before=$(stamp && plan_stamp) || fail
 digest=$(printf '%s\n' "$before" | sha256sum) || fail
 if [ "$#" = 3 ];then
  receipt=$(lua "$codec" web-running "$2" "${digest%% *}" "$3" "$live");code=$?
 else
  receipt=$(lua "$codec" web-running "$2" "${digest%% *}");code=$?
 fi
 case "$code:$live:$#" in 0:true:*|1:false:3) ;;0:false:*) exit 3;;*) exit "$code";;esac
 [ "$(stamp && plan_stamp)" = "$before" ] || fail
 ! exists "$run/native-service.stop" || exit 3
 printf '%s\n' "$receipt";exit "$code"
fi
if [ "$action" = overview-status ];then
 exec lua "$codec" overview-status "$live"
fi
if [ "$action" = status ] || [ "$action" = check ];then
 stage=status-configuration
 config=$(ash "$dir/homegate-health-read.sh" configuration-report 9>&-) || fail
 # The native receipt and process identity supply the runtime observation.
 stage=status-intent
 intent=$(ash "$dir/homegate-startup-active.sh" status 9>&-) || fail
 stage=status-observation
 report=$(printf '%s\n' "$config" | lua "$codec" status "$intent" "$live" "$action");result=$?
 [ -n "$report" ] || fail
 printf '%s\n' "$report";exit "$result"
fi
if [ "$action" = owner-state ];then
 printf '%s\n' "$live"
 exit 0
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
 else
  # A live coordinator owns component shutdown after the stop marker.
  # Only an absent coordinator needs the orphaned components stopped here.
  for pair in homegate-access-region.sh:access-update homegate-proxy.sh:proxy homegate-acme-schedule.sh:acme-schedule homegate-ddns-schedule.sh:ddns-schedule;do
   if exists "$run/${pair#*:}";then component "${pair%%:*}" stop --confirm >/dev/null || fail 4;fi
  done
 fi
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
stage=intent;ash "$dir/homegate-startup-active.sh" admit >/dev/null || fail 4
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
# Leave the independent region task's terminal receipt visible until the next
# refresh, including when Apply restarts HomeGate after downloading data.
for pair in homegate-proxy.sh:proxy homegate-acme-schedule.sh:acme-schedule homegate-ddns-schedule.sh:ddns-schedule;do
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
web_configured=$(printf '%s\n' "$plan" | lua "$codec" field web_configured 9>&-) || fail
management_configured=$(printf '%s\n' "$plan" | lua "$codec" field management_configured 9>&-) || fail
if [ "$management_configured" = true ] && [ -z "$web" ];then web=-;fi
policy=$(printf '%s\n' "$plan" | lua "$codec" field policy 9>&-) || fail
auto_firewall=$(printf '%s\n' "$plan" | lua "$codec" field auto_firewall 9>&-) || fail
info=$(lua "$dir/worker-process.lua" info "$$" none 9>&-) || fail
oldifs=$IFS;IFS=:;set -- $info;IFS=$oldifs;[ "$#" = 6 ] || fail;birth=$5
stage=admission;intent_guard && [ "$(stamp && plan_stamp)" = "$binding" ] || fail 4
receipt=$run/native-service.json;next_receipt=$receipt.next
published_status=;published_report=;previous_log_state=
emit() {
 complete=${3:-false}
 retry_id=
 if [ "$2" = certificate_retry ];then retry_id=$retry_certificate;fi
 report_key="$1:$2:$complete:$retry_id"
 case "$1" in failed|restart_required) final_state=$1;final_reason=$2;;esac
 # Keep the published receipt when its state, bytes and private metadata agree.
 if [ "$published_status" = "$report_key" ] && ! exists "$next_receipt" &&
    [ -f "$receipt" ] && [ ! -L "$receipt" ] &&
    [ "$(stat -c '%u:%a:%h:%s' "$receipt")" = "0:600:1:$((${#published_report}+1))" ] &&
    IFS= read -r existing_report < "$receipt" && [ "$existing_report" = "$published_report" ];then
  return 0
 fi
 for file in "$receipt" "$next_receipt";do ! exists "$file" || private_file "$file" || return 1;done
 lua "$codec" emit "$1" "$$" "$birth" "$revision" "$2" "$binding_digest" "$complete" "$retry_id" 9>&- > "$next_receipt" &&
 IFS= read -r report < "$next_receipt" && fsync "$next_receipt" &&
 mv -f "$next_receipt" "$receipt" && fsync "$receipt" "$run" || return 1
 published_status=$report_key;published_report=$report
 if [ "$1:$2" != "$previous_log_state" ];then
  ash "$base/native-log.sh" service "$1" "$2" 9>&- >/dev/null || :
  previous_log_state=$1:$2
 fi
}
stopping=false;reload=false;job=;job_certificate=;retry_certificate=;ddns_started=false;proxy_started=false;certificate_blocked=false;certificate_rate_limited=false;final_state=stopped;final_reason=known
trap 'stopping=true' TERM INT
trap 'reload=true' HUP
trap ':' USR1
shutdown() {
 trap - EXIT;emit stopping requested >/dev/null || :
 [ -z "$job" ] || entry acme-stop "$job" --confirm >/dev/null || :
 pending_stops='homegate-access-region.sh homegate-proxy.sh homegate-acme-schedule.sh homegate-ddns-schedule.sh'
 tries=0
 while [ "$tries" -lt 15 ];do
  remaining=
  for item in $pending_stops;do
   component "$item" stop --confirm >/dev/null || remaining="$remaining $item"
  done
  pending_stops=$remaining
  if quiet;then emit "$final_state" "$final_reason" true >/dev/null;return $?;fi
  tries=$((tries+1));sleep 1 9>&- || return 1
 done
 if [ "$final_state" = stopped ];then emit failed stop_unknown >/dev/null
 else emit "$final_state" "$final_reason" >/dev/null;fi
 return 1
}
trap 'code=$?; shutdown || code=4; [ "$code" = 0 ] || code=1;exit "$code"' EXIT
emit starting admission || fail
start_ddns() {
 [ -n "$ddns" ] || return 0
 expected_authorized=$(printf '%s\n' "$ddns" | tr ' ' '\n') || return 1
 now=$(lua "$dir/worker-process.lua" now 9>&-) || return 1
 start_until=$((now+25))
 while :;do
  # No retry may remove an admitted or interrupted lease. Each attempt
  # rechecks the same authority and the worker owns a separate launch lock.
  [ "$stopping" = false ] && ! exists "$run/native-service.stop" && ! exists "$run/ddns-schedule" || return 1
  [ "$(stamp && plan_stamp)" = "$binding" ] || return 1
  authorized=$(
   service_locks || exit $?
   ash "$dir/homegate-ddns-authority.sh" check 9>&-
  )
  auth_result=$?
  if [ "$auth_result" = 0 ];then
   authorized=$(printf '%s\n' "$authorized" | lua "$dir/homegate-ddns-batch.lua" names "$revision" 9>&-) || return 1
   [ "$authorized" = "$expected_authorized" ] || return 1
   if entry schedule-serve --confirm >/dev/null;then ddns_started=true;return 0;fi
  elif [ "$auth_result" != 3 ];then return 1
  fi
  now=$(lua "$dir/worker-process.lua" now 9>&-) || return 1
  [ "$now" -lt "$start_until" ] && sleep 1 9>&- || return 1
 done
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
component_running() {
 state=$(entry "$1") && printf '%s\n' "$state" | lua "$codec" ready running 9>&-
}
watch_component() {
 # A receipt may be replaced while a status reader opens and validates it.
 # Require a repeat failure before stopping healthy sibling components.
 for delay in 200 400;do
  if component_running "$1";then return 0;fi
  lua "$dir/worker-process.lua" pause "$delay" 9>&- || sleep 1 9>&- || return 1
 done
 component_running "$1"
}
start_proxy() {
 proxy_poll_delay=0.1
 if ! sleep 0.001 9>&- >/dev/null 2>&1;then proxy_poll_delay=1;fi
 entry proxy-start "$web" "$policy" --confirm >/dev/null || return 1
 clock=$(lua "$dir/worker-process.lua" now 9>&-) || return 1
 ready_until=$((clock+20))
 while :;do
  [ "$stopping" = false ] && ! exists "$run/native-service.stop" || return 1
  if state=$(entry proxy-status);then
   printf '%s\n' "$state" | lua "$codec" ready running 9>&-;code=$?
   [ "$code" != 0 ] || { proxy_started=true;return 0; }
   [ "$code" = 3 ] || return 1
  fi
  clock=$(lua "$dir/worker-process.lua" now 9>&-) || return 1
  [ "$clock" -lt "$ready_until" ] && sleep "$proxy_poll_delay" 9>&- || return 1
 done
}
reset_failed_proxy() {
 # Retry only after the first attempt's process family and firewall are
 # confirmed gone. Leave partial or unverified sessions for diagnosis.
 tries=0
 while [ "$tries" -lt 5 ];do
  [ "$stopping" = false ] && ! exists "$run/native-service.stop" || return 1
  if component homegate-proxy.sh quiescent >/dev/null;then
   if exists "$run/proxy";then component homegate-proxy.sh reap --confirm >/dev/null || return 1;fi
   [ "$(stamp && plan_stamp)" = "$binding" ];return $?
  fi
  tries=$((tries+1));sleep 1 9>&- || return 1
 done
 return 1
}
idle_firewall_token=
next_firewall_check=0
if [ "$auto_firewall:$web_configured" = true:true ] && [ -z "$web" ];then
 idle_firewall_token=$(lua "$dir/cloudflare-codec.lua" nonce 9>&- < /proc/sys/kernel/random/uuid) || fail
 ash "$dir/homegate-firewall.sh" protect-idle "$idle_firewall_token" >/dev/null ||
   { emit failed firewall_apply_failed;exit 7; }
 now=$(lua "$dir/worker-process.lua" now 9>&-) || fail
 next_firewall_check=$((now+10))
fi
if [ -z "$certificates" ] && [ -z "$web" ];then start_ddns || { emit failed authorization_required;exit 4; };fi
next_check=0
while :;do
 if [ "$stopping" = true ] || exists "$run/native-service.stop";then
  ! exists "$run/native-service.stop" || private_file "$run/native-service.stop" 0 || fail
  exit 0
 fi
 current=$(stamp && plan_stamp) || { emit failed source_unavailable;exit 4; }
 if [ "$reload" = true ] || [ "$current" != "$binding" ];then emit restart_required source_changed;exit 4;fi
 if [ -n "$idle_firewall_token" ];then
  now=$(lua "$dir/worker-process.lua" now 9>&-) || fail
  if [ "$now" -ge "$next_firewall_check" ];then
   # Refresh on WAN address changes and after a firewall reload. The worker's
   # nonblocking locks leave any admitted DDNS or ACME operation in control.
   if ash "$dir/homegate-firewall.sh" protect-idle "$idle_firewall_token" >/dev/null;then
    next_firewall_check=$((now+10))
   fi
  fi
 fi
 # Bring up routes that already have usable certificates before making a
 # potentially long ACME request. Pending names fail closed in Nginx.
 if [ -n "$web" ] && [ "$proxy_started" = false ];then
  if ! start_proxy;then
   [ "$stopping" = false ] && ! exists "$run/native-service.stop" || exit 0
   reset_failed_proxy && start_proxy || { emit failed proxy_start_failed;exit 7; }
  fi
  if [ "$auto_firewall" = true ];then entry firewall-apply --confirm >/dev/null || { emit failed firewall_apply_failed;exit 7; };fi
 fi
 # Each component admits its own work under the existing business locks.
 # The coordinator watches the already-validated immutable binding instead
 # of competing with an active DNS/ACME transaction for those same locks.
 if [ -n "$job" ] && [ "$certificate_blocked" = false ];then
  if state=$(entry acme-job "$job");then
   printf '%s\n' "$state" | lua "$codec" ready job 9>&-;code=$?
  else code=7;fi
  if [ "$code" = 0 ];then job=;next_check=0;retry_certificate=
  elif [ "$code" != 3 ];then
   if [ "$code" = 9 ];then
    job=;next_check=0;certificate_rate_limited=true
   elif [ "$code" = 5 ];then
    [ "$proxy_started" = true ] || { emit failed certificate_failed;exit 7; }
    job=;now=$(lua "$dir/worker-process.lua" now 9>&-) || fail
    next_check=$((now+300));retry_certificate=$job_certificate
   else
    [ "$proxy_started" = true ] || { emit failed certificate_failed;exit 7; }
    # Keep the existing proxy available, but do not admit another DNS
    # mutation until the uncertain certificate job has been reconciled.
    certificate_blocked=true
   fi
  fi
 fi
 if [ -n "$certificates" ] && [ -z "$job" ] && [ "$certificate_blocked" = false ];then
  now=$(lua "$dir/worker-process.lua" now 9>&-) || fail
  if [ "$now" -ge "$next_check" ];then
   next_check=$((now+60))
   certificate_rate_limited=false
   for certificate in $certificates;do
    # Take a read under the same ordered locks as DDNS and the firewall.
    # A busy reader reschedules the scan without stopping the DDNS lease.
    material=$(
     service_locks || exit $?
     ash "$dir/homegate-certificate.sh" admission-status-internal "$certificate" --confirm 9>&-
    )
    code=$?
    if [ "$code" = 3 ];then next_check=$((now+5));break;fi
    if [ "$code" != 0 ];then
     [ "$proxy_started" = true ] || { emit failed certificate_unavailable;exit 7; }
     retry_certificate=$certificate;continue
    fi
    printf '%s\n' "$material" | lua "$codec" ready due 9>&-;code=$?
    if [ "$code" = 3 ];then
     [ "$retry_certificate" != "$certificate" ] || retry_certificate=
     continue
    fi
    if [ "$code" != 0 ];then
     [ "$proxy_started" = true ] || { emit failed certificate_unknown;exit 7; }
     certificate_blocked=true;break
    fi
    pause_ddns || { emit failed ddns_pause_unknown;exit 4; }
    job=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 9>&-) || fail
    job_certificate=$certificate
    [ "$retry_certificate" != "$certificate" ] || retry_certificate=
    entry acme-renew "$certificate" "$job" --confirm >/dev/null;code=$?
    if [ "$code" = 9 ];then
     job=;certificate_rate_limited=true;continue
    elif [ "$code" != 0 ];then
     [ "$proxy_started" = true ] || { emit failed certificate_start_failed;exit 7; }
     certificate_blocked=true
    fi
    break
   done
  fi
 fi
 # Proxy and firewall admission acquire the same locks as the first DDNS batch.
 if [ -z "$job" ] && [ "$certificate_blocked" = false ] && [ "$ddns_started" = false ];then start_ddns || { emit failed ddns_resume_failed;exit 4; };fi
 if [ "$ddns_started" = true ];then watch_component schedule-status || { emit failed ddns_stopped;exit 7; };fi
 if [ "$proxy_started" = true ];then watch_component proxy-status || { emit failed proxy_stopped;exit 7; };fi
 if [ "$certificate_blocked" = true ];then emit running certificate_unknown
 elif [ -n "$job" ];then
  if [ "$proxy_started" = true ];then emit running certificate;else emit renewing certificate;fi
 elif [ "$certificate_rate_limited" = true ];then emit running certificate_rate_limited
 elif [ -n "$retry_certificate" ];then emit running certificate_retry
 else emit running ready;fi || fail
 sleep 1 9>&- || fail
done
