#!/bin/sh
# One retained single-rule job per explicit UI submission; never retry or collect.
set -u
umask 077
export LC_ALL=C
ddns_ui_jobs_enabled=false
ddns_ui_maintenance_enabled=false
effect=none
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-job","effect":"%s","write_ready":false,"error":"DDNS job unavailable; inspect retained jobs"}\n' "$effect";exit "${1:-7}"; }
action=${1:-}
case "$action" in submit) [ "$#" -eq 4 ] && [ "$4" = --confirm ] || fail 2;job=$2;rule=$3;; work) [ "$#" -eq 2 ] || fail 2;job=$2;; maintain-preview) [ "$#" -eq 2 ] && [ "$ddns_ui_maintenance_enabled" = true ] || fail 2;job=$2;; maintain-commit) [ "$#" -eq 4 ] && [ "$4" = --confirm ] && [ "$ddns_ui_maintenance_enabled" = true ] || fail 2;job=$2;confirmation=$3;; list|check-quiescent) [ "$#" -eq 1 ] || fail 2;; *) fail 2;; esac
{ [ "$ddns_ui_jobs_enabled" = true ] || [ "$action" = check-quiescent ]; } || fail 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
exec 2>/dev/null
owner=$(id -u) || fail;[ "$owner" = 0 ] || fail
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ] && [ "$(stat -c %s "$1")" -le 65536 ]; }
hex() { [ "${#1}" -eq "$2" ] || return 1;case "$1" in *[!0-9a-f]*) return 1;; esac; }
id() { [ -n "$1" ] && [ "${#1}" -le 64 ] || return 1;case "$1" in *[!a-zA-Z0-9_-]*) return 1;; esac; }
case "$action" in submit|work|maintain-preview|maintain-commit) hex "$job" 32 || fail 2;; esac
[ "$action" != maintain-commit ] || hex "$confirmation" 32 || fail 2
[ "$action" != submit ] || id "$rule" || fail 2
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
run=/var/run/homegate;store=/etc/homegate/transactions
root=$run/ddns-ui-jobs;catalog=$run/ddns-ui-jobs.lock
private_dir "$run" && private_dir "$store" || fail
bound() { private_file "$2" && [ "$(stat -c %s "$2")" -eq 0 ] && [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$1)" = "$(stat -c '%d:%i:%u:%a:%h' "$2")" ]; }
hash() { h=$(sha256sum "$1") || return 1;h=${h%% *};hex "$h" 64; }
frame() { frame_text=$(printf '%s\n' "$1" "$2");digest=$(printf '%s\n' "$frame_text" | sha256sum) || return 1;printf '%s\n' "$frame_text" "${digest%% *}"; }
read_frame() {
 private_file "$1" && [ "$(stat -c %s "$1")" -le 4096 ] || return 1
 exec 4<"$1" || return 1
 IFS= read -r tag <&4 && IFS= read -r data <&4 && IFS= read -r digest <&4 || return 1
 if IFS= read -r extra <&4;then return 1;fi;exec 4<&-
 [ "$tag" = "$2" ] && hex "$digest" 64 || return 1
 expected=$(frame "$tag" "$data") || return 1
 [ "$(stat -c %s "$1")" -eq "$((${#expected}+1))" ] && [ "$(cat "$1")" = "$expected" ]
}
read_meta() {
 read_frame "$1/meta" HGDDNSUIJOB1 || return 1
 old_ifs=$IFS;IFS=:;set -- $data;IFS=$old_ifs
 [ "$#" -eq 10 ] || return 1
 jid=$1;jrule=$2;provider=$3;revision=$4;identity=$5;generation=$6;grant=$7;boot=$8;created=$9;deadline=${10}
 hex "$jid" 32 && id "$jrule" || return 1
 case "$provider" in cloudflare|aliyun|dnspod|huaweicloud) ;; *) return 1;; esac
 case "$revision:$created:$deadline" in *[!0-9:]*) return 1;; esac
 case "$revision" in ''|0*) return 1;; esac
 case "$created" in ''|0?*) return 1;; esac;case "$deadline" in ''|0?*) return 1;; esac
 [ "${#revision}" -le 2 ] && [ "$revision" -le 32 ] && [ "${#created}" -le 9 ] && [ "${#deadline}" -le 9 ] && [ "$deadline" -eq "$((created+300))" ] || return 1
 for v in "$identity" "$generation" "$grant";do hex "$v" 64 || return 1;done
 [ "${#boot}" -eq 36 ] || return 1;case "$boot" in *[!0-9a-f-]*) return 1;; esac
}
fallback() { printf '{"rule":"%s","provider":"%s","status":"%s","effect":"%s","error_kind":"temporary","retryable":false,"retry_in":0}' "$jrule" "$provider" "$1" "$2"; }
report() {
 # Caller holds catalog lock. No common business lock is acquired by observation.
 p=$1;private_dir "$p" && read_meta "$p" && [ "${p##*/}" = "$jid" ] || return 1
 members=0
 for member in "$p/"* "$p/".[!.]* "$p/"..?*;do
  exists "$member" || continue;members=$((members+1));[ "$members" -le 11 ] && private_file "$member" || return 1
  case "${member##*/}" in meta|lock|start|raw|result|result.next|proof|maintenance|maintenance.next|maintenance-used|maintained|maintained.next) ;; *) return 1;; esac
 done
 private_file "$p/lock" && [ "$(stat -c %s "$p/lock")" -eq 0 ] || return 1
 exec 5>>"$p/lock" || return 1;bound 5 "$p/lock" || return 1
 pending=false;state=interrupted;reason=interrupted;last=unknown;row=false
 if flock -n 5;then
  if exists "$p/result";then
   private_file "$p/start" && [ "$(stat -c %s "$p/start")" -eq 0 ] && read_frame "$p/result" HGDDNSUIRESULT1 || return 1
   reason=${data%%:*};row=${data#*:}
   case "$reason" in completed|changed|unavailable) ;; *) return 1;; esac
   checked=$(printf '%s\n' "$row" | lua "$dir/homegate-ddns-job.lua" validate "$jrule") || return 1
   [ "$checked" = "$row" ] || return 1
   last=$(printf '%s\n' "$row" | lua "$dir/homegate-ddns-job.lua" effect "$jrule") || return 1;state=finished
   ! exists "$p/result.next" || return 1
   if exists "$p/maintained";then
    saved_row=$row;saved_last=$last
    read_frame "$p/maintained" HGDDNSUIMAINTAINED1 || return 1
    hash "$p/meta" || return 1;hm=$h;hash "$p/result" || return 1
    case "$data" in "$hm:$h:archive") [ "$saved_last" = confirmed ] || return 1;reason=archived;; "$hm:$h:compact") [ "$saved_last" = none ] || return 1;reason=compacted;; *) return 1;; esac
    row=$saved_row;last=$saved_last
   fi
  fi
 else pending=true;state=pending;reason=accepted;fi
 exec 5>&-
 printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-job","job":"%s","rule":"%s","configuration_revision":%s,"pending":%s,"state":"%s","result":%s,"last_effect":"%s","reason":"%s","effect":"none","write_ready":false}' "$jid" "$jrule" "$revision" "$pending" "$state" "$row" "$last" "$reason"
}
business_locks() {
 private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || return 1
 exec 6>>"$run/frontend.lock" 7>>"$store/.supervisor.lock" || return 1
 bound 6 "$run/frontend.lock" && bound 7 "$store/.supervisor.lock" && flock -n 6 && flock -n 7
}
snapshot() {
 current_revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || return 1
 hash "$store/identity" || return 1;current_identity=$h
 hash "$store/gen-$current_revision/manifest" || return 1;current_generation=$h
 hash "$store/ddns-authority" || return 1;current_grant=$h
 current_boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
 current_now=$(lua "$dir/worker-process.lua" now) || return 1
}
origin() {
 tree=$1
 private_dir "$tree" && private_file "$tree/current" && [ "$(stat -c %s "$tree/current")" -eq 2 ] || return 1
 active=$(cat "$tree/current");case "$active" in 1|2) ;; *) return 1;; esac
 manifest=$tree/slot-$active/manifest;terminal=$tree/terminal
 private_dir "$tree/slot-$active" && private_file "$manifest" && private_file "$terminal" && [ "$(stat -c %s "$manifest")" -le 512 ] && [ "$(stat -c %s "$terminal")" -le 4096 ] || return 1
 origin_info=$(lua "$dir/homegate-ddns-job.lua" origin "$jrule" "$revision" "$provider" "$identity" "$generation" "$boot" 3<"$manifest" 4<"$terminal" < "$p/raw") || return 1
 hash "$manifest" || return 1;h_manifest=$h;hash "$terminal" || return 1
 origin_data=$origin_info:$h_manifest:$h
}
if [ "$action" = work ];then
 # Only the fixed detached child receives these three open lock descriptions.
 p=$root/$job
 private_dir "$root" && private_dir "$p" && bound 8 "$p/lock" && bound 6 "$run/frontend.lock" && bound 7 "$store/.supervisor.lock" && flock -n 8 && flock -n 6 && flock -n 7 || fail
 read_meta "$p" && [ "$jid" = "$job" ] || fail
 (set -C; : > "$p/start") || fail
 reason=changed;row=$(fallback blocked none)
 if snapshot && [ "$revision:$identity:$generation:$grant:$boot" = "$current_revision:$current_identity:$current_generation:$current_grant:$current_boot" ] && [ "$current_now" -ge "$created" ] && [ "$current_now" -le "$deadline" ];then
  (set -C; : > "$p/raw") || fail
  rc=0;ash "$dir/homegate-ddns-state.sh" sync "$jrule" --confirm > "$p/raw" 8>&- 9>&- || rc=$?
  reason=completed;row=$(lua "$dir/homegate-ddns-job.lua" row "$jrule" "$revision" "$rc" < "$p/raw") || { reason=unavailable;row=$(fallback failed unknown); }
  case "$row" in *'"effect":"confirmed"'*)
   if origin "$store/dns-operation";then
    (set -C;frame HGDDNSUIORIGIN1 "$origin_data" > "$p/proof") && fsync "$p/proof" "$p" || fail
   else reason=unavailable;row=$(fallback failed unknown);fi;;
  esac
 fi
 (set -C;frame HGDDNSUIRESULT1 "$reason:$row" > "$p/result.next") && fsync "$p/result.next" "$p" && mv "$p/result.next" "$p/result" && fsync "$p/result" "$p" || fail
 exit 0
fi
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
if ! exists "$root";then
 case "$action" in maintain-preview|maintain-commit) fail 4;; esac
 if [ "$action" != submit ];then printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-jobs","jobs":[],"effect":"none","write_ready":false}\n';exit 0;fi
 mkdir "$root" || fail
fi
private_dir "$root" || fail
if ! exists "$catalog";then [ "$action" = submit ] && (set -C; : > "$catalog") || fail;fi
private_file "$catalog" && [ "$(stat -c %s "$catalog")" -eq 0 ] || fail
exec 9>>"$catalog" || fail;bound 9 "$catalog" && flock -n 9 || fail 4
bound 9 "$catalog" || fail
count=0;joined=;sep=;existing=;unresolved=false
for p in "$root/"* "$root/".[!.]* "$root/"..?*;do
 exists "$p" || continue;count=$((count+1));[ "$count" -le 8 ] || fail
 one=$(report "$p") || fail
 case "$one" in *'"state":"finished"'*) case "$one" in *'"last_effect":"unknown"'*) unresolved=true;; esac;; *) unresolved=true;; esac
 joined=$joined$sep$one;sep=,
 if [ "$action" = submit ] && [ "${p##*/}" = "$job" ];then read_meta "$p" && [ "$jrule" = "$rule" ] || fail 4;existing=$one;fi
done
case "$action" in maintain-preview|maintain-commit)
 p=$root/$job;summary=$(report "$p") || fail
 case "$summary" in *'"state":"finished"'*) ;; *) fail 4;; esac
 case "$summary" in *'"reason":"archived"'*|*'"reason":"compacted"'*|*'"last_effect":"unknown"'*) fail 4;; esac
 business_locks || fail 4
 exec 8>>"$p/lock" || fail;bound 8 "$p/lock" && flock -n 8 && bound 8 "$p/lock" || fail 4
 read_meta "$p" && snapshot && [ "$revision:$identity:$generation:$grant:$boot" = "$current_revision:$current_identity:$current_generation:$current_grant:$current_boot" ] || fail 4
 source_ready=$(ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null |
  lua "$dir/homegate-ddns-sync.lua" source "$revision" 3>&- 4>&- 5>&- 8>&- 9>&-) || fail
 [ "$source_ready" = HGDDNSSOURCE1 ] || fail
 hash "$p/meta" || fail;hm=$h;hash "$p/result" || fail;hr=$h
 raw_hash=none;if exists "$p/raw";then private_file "$p/raw" && hash "$p/raw" || fail;raw_hash=$h;fi
 operation=compact;proof_hash=none
 case "$summary" in *'"last_effect":"confirmed"'*)
  operation=archive;[ "$raw_hash" != none ] && read_frame "$p/proof" HGDDNSUIORIGIN1 || fail
  wanted_origin=$data;hash "$p/proof" || fail;proof_hash=$h
  tree=$store/dns-operation;exists "$tree" || tree=$store/dns-settled
  origin "$tree" && [ "$origin_data" = "$wanted_origin" ] || fail
  account=${origin_info%%:*};original_job=${origin_info#*:};;
 esac
 binding=$job:$hm:$hr:$raw_hash:$proof_hash:$operation:$current_boot
 if [ "$action" = maintain-preview ];then
  nonce=$(cat /proc/sys/kernel/random/uuid) || fail;old_ifs=$IFS;IFS=-;set -- $nonce;IFS=$old_ifs;[ "$#" -eq 5 ] || fail;nonce=$1$2$3$4$5;hex "$nonce" 32 || fail
  for f in "$p/maintenance" "$p/maintenance.next";do ! exists "$f" || private_file "$f" || fail;done
  ! exists "$p/maintenance.next" || fail
  (set -C;frame HGDDNSUIMAINTENANCE1 "$binding:$nonce:$current_now:$((current_now+300))" > "$p/maintenance.next") && fsync "$p/maintenance.next" "$p" && mv -f "$p/maintenance.next" "$p/maintenance" && fsync "$p/maintenance" "$p" || fail
  printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-maintenance","job":"%s","rule":"%s","operation":"%s","confirmation":"%s","expires_in":300,"effect":"none","write_ready":false}\n' "$job" "$jrule" "$operation" "$nonce";exit 0
 fi
 read_frame "$p/maintenance" HGDDNSUIMAINTENANCE1 || fail 5
 prefix=$binding:$confirmation:;case "$data" in "$prefix"*) times=${data#"$prefix"};; *) fail 5;; esac
 start=${times%%:*};finish=${times#*:};case "$start:$finish" in *[!0-9:]*) fail 5;; esac
 case "$start" in ''|0?*) fail 5;; esac;case "$finish" in ''|0?*) fail 5;; esac
 [ "${#start}" -le 9 ] && [ "${#finish}" -le 9 ] && [ "$finish" -eq "$((start+300))" ] && [ "$current_now" -ge "$start" ] && [ "$current_now" -le "$finish" ] || fail 5
 ! exists "$p/maintenance-used" || private_file "$p/maintenance-used" || fail
 mv -f "$p/maintenance" "$p/maintenance-used" && fsync "$p/maintenance-used" "$p" || fail
 if [ "$operation" = archive ];then
  ash "$dir/homegate-cloudflare-read.sh" --runtime-collect-receipt-internal "$provider" "$account" "$original_job" --confirm 8>&- 9>&- >/dev/null || fail
  origin "$store/dns-settled" && [ "$origin_data" = "$wanted_origin" ] || fail
 else
  ! exists "$p/raw" || { private_file "$p/raw" && rm -f "$p/raw" && fsync "$p"; } || fail
 fi
 if exists "$p/maintained.next";then read_frame "$p/maintained.next" HGDDNSUIMAINTAINED1 && [ "$data" = "$hm:$hr:$operation" ] || fail
 else (set -C;frame HGDDNSUIMAINTAINED1 "$hm:$hr:$operation" > "$p/maintained.next") || fail;fi
 fsync "$p/maintained.next" "$p" && mv "$p/maintained.next" "$p/maintained" && fsync "$p/maintained" "$p" || fail
 printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-maintenance","job":"%s","rule":"%s","operation":"%s","completed":true,"effect":"none","write_ready":false}\n' "$job" "$jrule" "$operation";exit 0;;
esac
if [ "$action" != submit ];then
 [ "$action" != check-quiescent ] || [ "$unresolved" = false ] || fail 4
 printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-jobs","jobs":[%s],"effect":"none","write_ready":false}\n' "$joined";exit 0
fi
if [ -n "$existing" ];then printf '%s\n' "$existing";exit 0;fi
[ "$unresolved" = false ] && [ "$count" -lt 8 ] || fail 4
business_locks || fail 4
snapshot || fail
provider=$(ash "$dir/homegate-ddns-state.sh" status "$rule" | lua "$dir/homegate-ddns-job.lua" status "$rule") || fail 4
case "$provider" in cloudflare|aliyun|dnspod|huaweicloud) ;; *) fail;; esac
p=$root/$job;mkdir "$p" || fail
(set -C; : > "$p/lock";frame HGDDNSUIJOB1 "$job:$rule:$provider:$current_revision:$current_identity:$current_generation:$current_grant:$current_boot:$current_now:$((current_now+300))" > "$p/meta") || fail
exec 8>>"$p/lock" || fail;bound 8 "$p/lock" && flock -n 8 && fsync "$p/meta" "$p/lock" "$p" "$root" || fail
effect=unknown
setsid ash "$dir/homegate-ddns-job.sh" work "$job" 9>&- </dev/null >/dev/null 2>&1 &
# Do not wait; no child pipe remains connected to the HTTP/RPC response.
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-job","job":"%s","rule":"%s","configuration_revision":%s,"pending":true,"state":"pending","result":false,"last_effect":"unknown","reason":"accepted","effect":"none","write_ready":false}\n' "$job" "$rule" "$current_revision"
