#!/bin/sh
# Standalone reviewed kit driver; never invoked by package hooks or the daemon.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_PACKAGE_UPGRADE_STATE HOMEGATE_PACKAGE_OPKG_CMDLINE
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
root=/etc/.homegate-transition;kit=/tmp/homegate-native-kit;codec=$kit/native-transition.lua
fail() { printf '{"api_version":1,"ok":false,"phase":"legacy-package-transition","recovery_retained":true,"error":"Transition incomplete; retained configuration and hooks require recovery"}\n';exit "${1:-7}"; }
dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ] && [ "$(stat -c %s "$1")" -le 65536 ]; }
[ "$(id -u)" = 0 ] && [ "$#" = 2 ] && [ "$2" = --confirm ] || fail 2
action=$1;case "$action" in prepare|install|recover) ;;*) fail 2;;esac
dir "$kit" && file "$codec" && file "$kit/receipt.json" || fail
checks=$(lua "$codec" kit) || fail;printf '%s\n' "$checks" | sha256sum -c - >/dev/null 2>&1 || fail
[ -d /etc/homegate ] && [ ! -L /etc/homegate ] && [ "$(stat -c %u /etc/homegate)" = 0 ] || fail
if [ ! -e "$root" ] && [ ! -L "$root" ];then [ "$action" = prepare ] && mkdir "$root" || fail;fi
dir "$root" || fail
if [ ! -e "$root/lock" ] && [ ! -L "$root/lock" ];then (set -C;: > "$root/lock") || fail;fi
file "$root/lock" && [ "$(stat -c %s "$root/lock")" = 0 ] || fail
exec 8>>"$root/lock";flock -n 8 || fail 4
record=$root/state
save() {
 [ ! -e "$record.next" ] && [ ! -L "$record.next" ] || fail
 printf '%s\n' HGTRANS1 "$phase" "$boot" "$running" > "$record.next" && fsync "$record.next" && mv "$record.next" "$record" && fsync "$record" "$root" || fail
}
load() {
 file "$record" || fail
 { IFS= read -r magic && IFS= read -r phase && IFS= read -r boot && IFS= read -r running && ! IFS= read -r extra; } < "$record" || fail
 case "$magic:$phase:$boot:$running" in HGTRANS1:preparing:[01]:[01]|HGTRANS1:prepared:[01]:[01]|HGTRANS1:removing:[01]:[01]|HGTRANS1:installing:[01]:[01]|HGTRANS1:awaiting-adoption:[01]:[01]|HGTRANS1:recovered:[01]:[01]) ;;*) fail;;esac
 expected=$(printf '%s\n' "$magic" "$phase" "$boot" "$running");[ "$(cat "$record")" = "$expected" ] && [ "$(stat -c %s "$record")" = "$((${#expected}+1))" ] || fail
}
if [ "$action" = prepare ];then
 [ ! -e "$record" ] && [ ! -L "$record" ] || fail 4
 [ ! -e /tmp/.homegate-purge-request ] && [ ! -L /tmp/.homegate-purge-request ] || fail 4
 # A queued old web job can launch after stop; resolve/ack it before migration.
 for p in /tmp/homegate-frontend-jobs/* /tmp/homegate-frontend-jobs/.[!.]*;do [ ! -e "$p" ] && [ ! -L "$p" ] || fail 4;done
 boot=0;/etc/init.d/homegate enabled >/dev/null 2>&1;code=$?;case "$code" in 0) boot=1;;1) ;;*) fail;;esac
 status=$(/usr/bin/homegate status);code=$?;case "$code" in 0|1) ;;*) fail;;esac
 running=$(printf '%s\n' "$status" | lua "$codec" status) || fail
 phase=preparing;save
 lua "$codec" hooks-save || fail
 (set -C;: > "$root/hold") && fsync "$root/hold" "$root" || fail
 # Retain inode identity before disabling the old service. No stored PID kill.
 lua "$codec" old-identity || fail
 /etc/init.d/homegate stop >/dev/null 2>&1 || fail 4
 lua "$codec" old-move || fail
 n=0;while ! lua "$codec" old-quiet;do [ "$n" -lt 30 ] || fail 4;n=$((n+1));sleep 1;done
 # The legacy Go writer and native configuration writer share this lease.
 [ -d /var/run/homegate ] && [ ! -L /var/run/homegate ] || fail
 if [ ! -e /var/run/homegate/frontend.lock ] && [ ! -L /var/run/homegate/frontend.lock ];then (set -C;: > /var/run/homegate/frontend.lock) || fail;fi
 file /var/run/homegate/frontend.lock && [ "$(stat -c %s /var/run/homegate/frontend.lock)" = 0 ] || fail
 exec 6>>/var/run/homegate/frontend.lock;flock -n 6 || fail 4
 lua "$codec" old-quiet && lua "$codec" source-stash && lua "$codec" hooks-mask || fail
 fsync "$root" /etc/config /usr/lib/opkg/info || fail
 phase=prepared;save
 printf '{"api_version":1,"ok":true,"phase":"legacy-package-transition","prepared":true,"old_boot":%s,"old_running":%s,"service_stopped":true,"activation_pending":true}\n' "$boot" "$running";exit 0
fi
load
if [ "$action" = recover ];then
 file /var/run/homegate/frontend.lock || fail
 exec 6>>/var/run/homegate/frontend.lock;flock -n 6 || fail 4
 lua "$codec" old-quiet && lua "$codec" source-restore && lua "$codec" hooks-restore && lua "$codec" old-restore || fail
 fsync "$root" /etc/config /usr/lib/opkg/info || fail
 phase=recovered;save
 if [ -e "$root/hold" ];then file "$root/hold" && rm "$root/hold" && fsync "$root" || fail;fi
 printf '{"api_version":1,"ok":true,"phase":"legacy-package-transition","source_restored":true,"activation_pending":true,"package_rollback_performed":false}\n';exit 0
fi
[ "$phase" = prepared ] || fail 4
file /var/run/homegate/frontend.lock || fail
exec 6>>/var/run/homegate/frontend.lock;flock -n 6 || fail 4
lua "$codec" old-quiet && lua "$codec" hooks-check || fail 4
[ ! -e /etc/config/homegate ] && [ ! -L /etc/config/homegate ] || fail 4
installed=$(lua "$codec" installed) || fail;[ -n "$installed" ] || fail
set --;for name in $installed;do case "$name" in homegate|luci-app-homegate|luci-i18n-homegate-zh-cn) set -- "$@" "$name";;*) fail;;esac;done
phase=removing;save
# Only these explicitly snapshotted product packages; no dependent force-remove.
opkg remove "$@" >/dev/null 2>&1 || fail 4
remaining=$(lua "$codec" installed) || fail;[ -z "$remaining" ] || fail 4
phase=installing;save
exec 6>&-
opkg install "$kit/homegate-core.ipk" "$kit/luci-app-homegate.ipk" "$kit/luci-i18n-homegate-zh-cn.ipk" >/dev/null 2>&1 || fail 4
lua "$codec" native-installed || fail 4
lua "$codec" source-restore || fail
fsync /etc/config "$root" /etc/homegate || fail
exec 6>&-
if [ "$boot" = 1 ];then /etc/init.d/homegate enable >/dev/null || fail;else /etc/init.d/homegate disable >/dev/null || fail;fi
phase=awaiting-adoption;save
file "$root/hold" && rm "$root/hold" && fsync "$root" || fail
printf '{"api_version":1,"ok":true,"phase":"legacy-package-transition","packages_replaced":true,"source_restored":true,"activation_pending":true,"old_boot":%s,"old_running":%s,"runtime_authority_granted":false}\n' "$boot" "$running"
