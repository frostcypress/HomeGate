#!/bin/sh
# Explicit engineering certificate import/status. Never reloads a live service.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
certificate_material_enabled=false
native_certificate_maintenance_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"certificate-material","effect":"none","write_ready":false,"error":"Certificate material unavailable; inspect retained candidate"}\n';exit "${1:-7}"; }
[ "$certificate_material_enabled" = true ] || fail 2
[ "$#" -ge 2 ] || fail 2
action=$1;id=$2
acme_internal=false;schedule_internal=false;preflight_internal=false;scope_mode=scope
adopting=false
if [ "$action" = adopt ];then
 [ "$native_certificate_maintenance_enabled" = true ] && [ "$#" = 3 ] && [ "$3" = --confirm ] || fail 2
 adopting=true;action=import;scope_mode=scope-any
fi
if [ "$action" = admission-status-internal ];then
 [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2
 HG_JOB=;acme_internal=true;preflight_internal=true;action=status;set -- status "$id"
fi
if [ "$action" = scheduler-status-internal ];then
 [ "$#" -eq 4 ] && [ "$4" = --confirm ] || fail 2
 schedule_token=$3;HG_JOB=;acme_internal=true;schedule_internal=true;action=status;set -- status "$id"
fi
case "$action" in acme-import-internal|acme-status-internal)
 [ "$#" -eq 4 ] && [ "$4" = --confirm ] || fail 2
 HG_JOB=$3;case "$HG_JOB" in *[!0-9a-f]*|'') fail 2;;esac;[ "${#HG_JOB}" -eq 32 ] || fail 2
 acme_internal=true;scope_mode=scope-acme
 if [ "$action" = acme-status-internal ];then action=status;set -- status "$id";else action=import;set -- import "$id" --confirm;fi;;esac
case "$action" in status|resume|cancel) scope_mode=scope-any;;esac
case "$id" in ''|*[!a-zA-Z0-9_-]*) fail 2;; esac;[ "${#id}" -le 64 ] || fail 2
case "$action" in status) [ "$#" -eq 2 ] || fail 2;; import|resume|cancel) [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2;; *) fail 2;; esac
exec 2>/dev/null
if [ "$acme_internal" = true ];then
 exec 3>&- 4>&- 5>&-
 [ "$schedule_internal" = true ] || exec 9>&-
 HG_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
 . "$HG_DIR/homegate-acme-common.sh"
 if [ "$preflight_internal" = true ];then :
 elif [ "$schedule_internal" = true ];then
  hg_schedule_check "$schedule_token" "$id" && ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null || fail
 else hg_guard || fail
  [ "$(lua "$HG_DIR/homegate-acme.lua" field "$HG_JOB" id)" = "$id" ] || fail
 fi
else exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;fi
[ "$(id -u)" = 0 ] || fail
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
store=/etc/homegate/transactions;run=/var/run/homegate;root=/etc/homegate/certs;base=$root/$id;pending=$base/.pending
private_dir /etc/homegate && private_dir "$store" && private_dir "$run" || fail
for fd in 6 7;do
 lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
 private_file "$lock" && [ "$(stat -c %s "$lock")" -eq 0 ] || fail
 if [ "$acme_internal" = false ];then case "$fd" in 6) exec 6>>"$lock";;7) exec 7>>"$lock";;esac;fi
 [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd)" = "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ] && flock -n "$fd" || fail 4
done
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
engine=$dir/homegate-config-prototype.sh
ash "$engine" --persistent writer-check >/dev/null 2>/dev/null || fail 4
scope() { ash "$engine" --persistent runtime-startup-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null | lua "$dir/homegate-certificate.lua" "$scope_mode" "$id" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; }
expected_scope=$(scope) || fail
if [ "$action" = resume ];then
 HG_DIR=$dir;HG_JOB=
 . "$dir/homegate-acme-common.sh"
 hg_jobs_clear || fail 4
fi
binding() {
 for f in /etc/config/homegate "$store/identity" "$store/current";do
  private_file "$f" || return 1;stat -c '%d:%i:%u:%a:%h:%s' "$f" && sha256sum "$f" || return 1
 done
 rev=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || return 1
 private_file "$store/gen-$rev/manifest" && sha256sum "$store/gen-$rev/manifest"
}
expected_binding=$(binding) || fail
legacy_binding() { for p in "$base/fullchain.pem" "$base/privkey.pem";do [ -f "$p" ] && [ ! -L "$p" ] && stat -c '%d:%i:%u:%a:%h:%s' "$p" && sha256sum "$p" || return 1;done; }
if [ "$adopting" = true ];then
 private_dir "$root" && private_dir "$base" || fail
 legacy_expected=$(legacy_binding) || fail
 if exists "$base/legacy-adopted";then private_file "$base/legacy-adopted" && [ "$(cat "$base/legacy-adopted")" = "$legacy_expected" ] || fail;fi
fi
recheck() { [ "$adopting" = false ] || [ "$(legacy_binding)" = "$legacy_expected" ] || return 1;[ "$(binding)" = "$expected_binding" ] && [ "$(scope)" = "$expected_scope" ] && ash "$engine" --persistent writer-check >/dev/null 2>/dev/null; }
pair_manifest() { (cd "$1" && sha256sum fullchain.pem privkey.pem scope.json result.json); }
pair_valid() {
 private_dir "$1" || return 1
 for name in fullchain.pem privkey.pem scope.json result.json manifest;do private_file "$1/$name" && [ "$(stat -c %s "$1/$name")" -le 65536 ] || return 1;done
 [ "$(cat "$1/manifest")" = "$(pair_manifest "$1")" ] && [ "$(stat -c %s "$1/manifest")" -eq "$(($(pair_manifest "$1" | wc -c)))" ]
}
current_pair() {
 private_file "$base/current" && [ "$(stat -c %s "$base/current")" -eq 38 ] || return 1
 current=$(cat "$base/current");case "$current" in pair-*) ;;*) return 1;;esac
 suffix=${current#pair-};[ "${#suffix}" -eq 32 ] || return 1;case "$suffix" in *[!0-9a-f]*) return 1;;esac
 pair_valid "$base/$current"
}
stage_seal() { (cd "$pending" && sha256sum fullchain.pem privkey.pem scope.json binding); }
stage_files() {
 private_dir "$pending" || return 1
 for item in "$pending/"* "$pending/".[!.]* "$pending/"..?*;do
  exists "$item" || continue
  case "${item##*/}" in fullchain.pem|privkey.pem|scope.json|binding|seal|leaf.pem|keypub.der|certpub.pem|certpub.der|chain.p7b|dates|san|result.json) ;;*) return 1;;esac
  private_file "$item" && [ "$(stat -c %s "$item")" -le 65536 ] || return 1
 done
}
stage_integrity() {
 stage_files || return 1
 for name in fullchain.pem privkey.pem scope.json binding seal;do private_file "$pending/$name" || return 1;done
 [ "$(cat "$pending/seal")" = "$(stage_seal)" ] && [ "$(stat -c %s "$pending/seal")" -eq "$(stage_seal | wc -c)" ]
}
stage_valid() {
 stage_integrity && [ "$(cat "$pending/scope.json")" = "$expected_scope" ] && [ "$(cat "$pending/binding")" = "$expected_binding" ]
}
clean_stage() {
 stage_files || fail
 for name in fullchain.pem privkey.pem scope.json binding seal leaf.pem keypub.der certpub.pem certpub.der chain.p7b dates san result.json;do
  ! exists "$pending/$name" || rm -f "$pending/$name" || fail 6
 done
 rmdir "$pending" && fsync "$base" 2>/dev/null || fail 6
}
if [ "$action" = status ];then
 present=false;has_pending=false
 if exists "$root";then private_dir "$root" || fail
  if exists "$base";then private_dir "$base" || fail
   ! exists "$pending" || { private_dir "$pending" || fail;has_pending=true; }
   if exists "$base/current";then current_pair || fail;present=true;fi
  fi
 fi
 # Public scope is delivered through a private pipe; no request-selected paths.
 if [ "$present" = true ];then exec 4<"$base/$current/result.json" 5<"$base/$current/scope.json";fi
 printf '%s\n' "$expected_scope" | lua "$dir/homegate-certificate.lua" status "$id" "$present" "$has_pending" 3<&0
 exit $?
fi
if ! exists "$root";then mkdir "$root" && fsync "$root" /etc/homegate 2>/dev/null || fail 6;fi
private_dir "$root" || fail
if ! exists "$base";then mkdir "$base" && fsync "$base" "$root" 2>/dev/null || fail 6;fi
private_dir "$base" || fail
if exists "$base/current";then current_pair || fail;else current=;fi
if [ "$action" = cancel ];then
 exists "$pending" || fail 5
 stage_files || fail
 if exists "$base/.current.next";then
  stage_integrity || fail
  sum=$(sha256sum "$pending/seal");candidate=pair-$(printf '%.32s' "${sum%% *}")
  private_file "$base/.current.next" && [ "$(cat "$base/.current.next")" = "$candidate" ] && [ "$(stat -c %s "$base/.current.next")" -eq 38 ] || fail
  rm -f "$base/.current.next" && fsync "$base" 2>/dev/null || fail 6
 fi
 clean_stage
 printf '{"api_version":1,"engineering":true,"ok":true,"phase":"certificate-material","cancelled":true,"effect":"none","write_ready":false}\n';exit 0
fi
if [ "$action" = import ];then
 ! exists "$pending" && ! exists "$base/.current.next" || fail 4
 count=0;for item in "$base/"pair-*;do exists "$item" || continue;private_dir "$item" || fail;count=$((count+1));done;[ "$count" -lt 16 ] || fail 4
 mkdir "$pending" || fail
 printf '%s\n' "$expected_scope" > "$pending/scope.json" && printf '%s\n' "$expected_binding" > "$pending/binding" || fail
 if [ "$adopting" = true ];then
  pair=$(lua /usr/libexec/homegate/native-cli.lua legacy-import "$id") || fail 1
  printf '%s\n' "$pair" | lua "$dir/homegate-certificate.lua" receive "$id" || fail 1
  unset pair
 else lua "$dir/homegate-certificate.lua" receive "$id" || fail 1;fi
 stage_seal > "$pending/seal" || fail
else
 exists "$pending" || fail 5
 # Resume can finish a cleanup interrupted after the last private input unlink.
 if private_dir "$pending" && [ -z "$(ls -A "$pending")" ] && [ -n "$current" ];then
  recheck && [ "$(cat "$base/$current/scope.json")" = "$expected_scope" ] || fail
  fsync "$base/$current/fullchain.pem" "$base/$current/privkey.pem" "$base/$current/scope.json" "$base/$current/result.json" "$base/$current/manifest" "$base/$current" "$base/current" "$base" 2>/dev/null || fail 6
  clean_stage
  printf '{"api_version":1,"engineering":true,"ok":true,"phase":"certificate-material","imported":true,"resumed":true,"effect":"private-certificate-publication","write_ready":false}\n';exit 0
 fi
fi
stage_valid && recheck || fail
fsync "$pending/fullchain.pem" "$pending/privkey.pem" "$pending/scope.json" "$pending/binding" "$pending/seal" "$pending" "$base" 2>/dev/null || fail 6
# The existing watchdog bounds the complete OpenSSL process family to ten seconds.
(set -C; : > "$pending/result.json") 2>/dev/null || { private_file "$pending/result.json" || fail; : > "$pending/result.json"; }
token=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid) || fail
setsid ash "$dir/homegate-service-observer-watchdog.sh" --certificate-validate "$token" "$id" 3>"$pending/result.json" >/dev/null 2>/dev/null || fail 1
stage_valid && recheck && private_file "$pending/result.json" && [ -s "$pending/result.json" ] || fail
sum=$(sha256sum "$pending/seal");candidate=pair-$(printf '%.32s' "${sum%% *}")
if ! exists "$base/$candidate";then mkdir "$base/$candidate" || fail;fi
private_dir "$base/$candidate" || fail
for name in fullchain.pem privkey.pem scope.json result.json;do
 if exists "$base/$candidate/$name";then
  private_file "$base/$candidate/$name" || fail
  a=$(sha256sum "$pending/$name");b=$(sha256sum "$base/$candidate/$name")
  if [ "${a%% *}" != "${b%% *}" ];then
   [ "$current" != "$candidate" ] || fail
   cp "$pending/$name" "$base/$candidate/$name" || fail
  fi
 else (set -C; : > "$base/$candidate/$name") && cp "$pending/$name" "$base/$candidate/$name" || fail;fi
done
if exists "$base/$candidate/manifest";then
 private_file "$base/$candidate/manifest" || fail
 if [ "$(cat "$base/$candidate/manifest")" != "$(pair_manifest "$base/$candidate")" ];then
  [ "$current" != "$candidate" ] || fail
  pair_manifest "$base/$candidate" > "$base/$candidate/manifest" || fail
 fi
else (set -C; pair_manifest "$base/$candidate" > "$base/$candidate/manifest") || fail;fi
pair_valid "$base/$candidate" && recheck || fail
fsync "$base/$candidate/fullchain.pem" "$base/$candidate/privkey.pem" "$base/$candidate/scope.json" "$base/$candidate/result.json" "$base/$candidate/manifest" "$base/$candidate" "$base" 2>/dev/null || fail 6
if exists "$base/.current.next";then private_file "$base/.current.next" && [ "$(cat "$base/.current.next")" = "$candidate" ] && [ "$(stat -c %s "$base/.current.next")" -eq 38 ] || fail
else (set -C; printf '%s\n' "$candidate" > "$base/.current.next") || fail;fi
fsync "$base/.current.next" "$base" 2>/dev/null && recheck || fail 6
mv -f "$base/.current.next" "$base/current" || fail
fsync "$base/current" "$base" 2>/dev/null || fail 6
current_pair && [ "$current" = "$candidate" ] || fail
clean_stage
if [ "$adopting" = true ];then
 recheck || fail
 if ! exists "$base/legacy-adopted";then (set -C;printf '%s\n' "$legacy_expected" > "$base/legacy-adopted") || fail;fi
 fsync "$base/legacy-adopted" "$base" || fail 6
fi
printf '{"api_version":1,"engineering":true,"ok":true,"phase":"certificate-material","imported":true,"effect":"private-certificate-publication","write_ready":false}\n'
