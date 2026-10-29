#!/bin/sh
# Read the applied private main-switch overlay under the business locks.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
startup_active_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"lifecycle-active","effect":"none","write_ready":false,"error":"Applied intent unavailable; inspect retained state"}\n';exit "${2:-7}"; }
[ "$startup_active_enabled" = true ] && [ "$#" -eq 1 ] || fail gate 2
action=$1;case "$action" in check|status) ;; *) fail command 2;; esac
exec 2>/dev/null
exec 3>&- 4>&- 5>&- 8>&- 9>&-
owner=$(id -u);[ "$owner" = 0 ] || fail owner
store=/etc/homegate/transactions;run=/var/run/homegate;active=$store/startup-active
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail path
present() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
private_dir "$store" && private_dir "$run" || fail namespace
for fd in 6 7;do
 lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
 private_file "$lock" && [ "$(stat -c %s "$lock")" -eq 0 ] || fail lock
 if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd)" != "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ];then
  case "$fd" in 6) exec 6>>"$lock";; 7) exec 7>>"$lock";; esac
 fi
 flock -n "$fd" || fail busy 4
done
for pending in "$store/startup-intent" "$store/.startup-intent-next" "$store/.startup-active-next";do ! present "$pending" || fail pending 4;done
if ! present "$active";then
 [ "$action" != status ] || printf '{"api_version":1,"prototype":true,"ok":true,"phase":"lifecycle-active","known":false,"active_overlay":false,"effect":"none","write_ready":false}\n'
 exit 0
fi
. "$dir/startup-record.sh"
startup_record_framed "$active" || fail record
exec 8<"$active";IFS= read -r line <&8;IFS= read -r line <&8;IFS= read -r line <&8;IFS= read -r desired <&8;exec 8<&-
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current") || fail revision
stamp() {
 private_file "$1" && [ "$(stat -c %s "$1")" -le 262144 ] || return 1
 local stamp_before sum_after
 stamp_before=$(stat -c '%d:%i:%u:%a:%h:%s' "$1") || return 1
 sum_after=$(sha256sum "$1") || return 1
 [ "$stamp_before" = "$(stat -c '%d:%i:%u:%a:%h:%s' "$1")" ] || return 1
 printf '%s:%s\n' "$stamp_before" "${sum_after%% *}"
}
source_stamp=$(stamp /etc/config/homegate) || fail source
store_stamp=$(stamp "$store/identity" && stamp "$store/gen-$revision/manifest") || fail generation
configuration=$(lua "$dir/homegate-startup.lua" source < /etc/config/homegate) || fail source
snapshot() { ash "$dir/homegate-config-prototype.sh" --persistent runtime-startup-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null; }
startup_record_expected
startup_record_file "$active" && [ "$(stamp /etc/config/homegate)" = "$source_stamp" ] &&
 [ "$(stamp "$store/identity" && stamp "$store/gen-$revision/manifest")" = "$store_stamp" ] &&
 [ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current")" = "$revision" ] || fail binding
fsync "$active" "$store" 2>/dev/null || fail durability
if [ "$action" = check ];then [ "$desired" = enabled ] || fail disabled 4;exit 0;fi
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"lifecycle-active","known":true,"active_overlay":true,"main_enabled":%s,"source_bound":true,"configuration_revision":%s,"effect":"none","write_ready":false}\n' "$([ "$desired" = enabled ] && printf true || printf false)" "$revision"
