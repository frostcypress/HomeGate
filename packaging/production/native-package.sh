#!/bin/sh
# Fixed native package lifecycle. Only live package operations touch state.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
[ "$(id -u)" = 0 ] || exit 7
root=/etc/homegate;record=$root/package-state
dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ] && [ "$(stat -c %s "$1")" -le 64 ]; }
read_record() {
 file "$record" || return 1
 { IFS= read -r magic && IFS= read -r mode && IFS= read -r boot && IFS= read -r running && ! IFS= read -r extra; } < "$record" || return 1
 [ "$magic" = HGPKG1 ] || return 1
 case "$mode:$boot:$running" in fresh:0:0|upgrade:[01]:[01]|reinstall:[01]:[01]|remove:[01]:[01]|stopping:[01]:[01]|ready:[01]:[01]) ;;*) return 1;;esac
 expected=$(printf '%s\n' "$magic" "$mode" "$boot" "$running")
 [ "$(cat "$record")" = "$expected" ] && [ "$(stat -c %s "$record")" = "$((${#expected}+1))" ]
}
write_record() {
 for p in "$record" "$record.next";do [ ! -e "$p" ] && [ ! -L "$p" ] || file "$p" || return 1;done
 printf '%s\n' HGPKG1 "$mode" "$boot" "$running" > "$record.next" && fsync "$record.next" && mv -f "$record.next" "$record" && fsync "$record" "$root"
}
source_locks() {
 [ ! -e /var/run/homegate ] && [ ! -L /var/run/homegate ] || dir /var/run/homegate || return 1
 if [ -e /var/run/homegate/frontend.lock ] || [ -L /var/run/homegate/frontend.lock ];then
  p=/var/run/homegate/frontend.lock
  file "$p" && [ "$(stat -c %s "$p")" = 0 ] || return 1
  exec 6>>"$p";flock -n 6 || return 1
 fi
 if [ -e "$root/transactions" ] || [ -L "$root/transactions" ];then
  dir "$root/transactions" || return 1
  p=$root/transactions/.supervisor.lock
  file "$p" && [ "$(stat -c %s "$p")" = 0 ] || return 1
  exec 7>>"$p";flock -n 7 || return 1
 fi
}
stash_config() {
 if [ "$desired_mode" = remove ];then
  file "$record" || return 1
  exec 9>>"$record"
  [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/9)" = "$(stat -c '%d:%i:%u:%a:%h' "$record")" ] && flock -n 9 || return 1
  /etc/init.d/homegate disable >/dev/null;result=$?
  exec 9>&-
  return "$result"
 fi
 source_locks && lua /usr/libexec/homegate/native-package.lua move-config || return 1
 [ ! -e /etc/homegate/package-config ] || fsync /etc/homegate/package-config /etc/homegate /etc/config || return 1
 exec 6>&- 7>&-
}
action=${1:-};shift || exit 2
case "$action" in
 preinst)
  # Old Go package postrm performs FULL PURGE. Never let opkg remove it as a
  # side effect of an unprepared package-name transition.
  [ ! -e /usr/lib/opkg/info/homegate.control ] && [ ! -L /usr/lib/opkg/info/homegate.control ] || { printf '%s\n' 'Legacy HomeGate package transition requires the coordinated migration installer.' >&2;exit 4; }
  if [ ! -e "$root" ] && [ ! -L "$root" ];then mkdir "$root" || exit 7;fi
  dir "$root" || exit 7
  if [ -e "$record" ] || [ -L "$record" ];then read_record && [ "$mode" != stopping ] || exit 7
  else mode=fresh;boot=0;running=0;write_record || exit 7;fi;;
 prerm)
  for p in /etc/.homegate-transition/hold /etc/.homegate-transition/source.config;do
   [ ! -e "$p" ] && [ ! -L "$p" ] || exit 4
  done
  dir "$root" || exit 7
  resumed=false
  if [ -e "$record" ] || [ -L "$record" ];then
   read_record || exit 7
   if [ "$mode" = stopping ];then resumed=true;fi
  fi
  if [ "$resumed" = false ];then
   boot=0;running=0
   /etc/init.d/homegate enabled >/dev/null 2>&1;code=$?;case "$code" in 0) boot=1;;1) ;;*) exit 7;;esac
   if [ -d /var/run/homegate ];then
    state=$(/usr/bin/homegate status) || exit 7
    observed=$(printf '%s\n' "$state" | lua /usr/libexec/homegate/native-package.lua) || exit 7
    running=$observed
   fi
  fi
  mode=remove
  if [ "${PKG_UPGRADE:-0}" = 1 ] || [ "${1:-}" = upgrade ];then mode=upgrade
  else
   ancestor=$PPID;depth=0
   while [ "$ancestor" -gt 1 ] && [ "$depth" -lt 8 ];do
    command=$(tr '\000' ' ' < "/proc/$ancestor/cmdline") || exit 7
    case " $command " in *' --force-reinstall '*) mode=reinstall;break;;esac
    proc=$(cat "/proc/$ancestor/stat") || exit 7;tail=${proc##*) }
    oldifs=$IFS;IFS=' ';set -- $tail;IFS=$oldifs;ancestor=$2
    case "$ancestor" in ''|*[!0-9]*) exit 7;;esac;depth=$((depth+1))
   done
  fi
  # Save intent before any SDK default stop. Unknown children preserve both
  # executable files and data by making prerm fail.
  desired_mode=$mode;mode=stopping;write_record || exit 7
  if [ -e /tmp/homegate-frontend-jobs ] || [ -L /tmp/homegate-frontend-jobs ];then
   /usr/libexec/homegate/native-web.sh purge - >/dev/null || { printf '%s\n' 'HomeGate Web task is active or unresolved; inspect retained receipt before removal.' >&2;exit 4; }
  fi
  if [ -d /var/run/homegate ];then
   /usr/bin/homegate service-stop --confirm >/dev/null || exit 4
   count=0
   while [ "$count" -lt 20 ];do
    if /usr/bin/homegate service-quiescent >/dev/null;then
     /usr/bin/homegate service-reap --confirm >/dev/null || exit 4
     stash_config || exit 7;mode=$desired_mode;write_record || exit 7;exit 0
    fi
    count=$((count+1));sleep 1 || exit 4
   done;exit 4
  fi
  stash_config || exit 7;mode=$desired_mode;write_record || exit 7;;
 postinst)
  dir "$root" && read_record || exit 7
  case "$mode" in fresh|upgrade|reinstall) ;;*) exit 7;;esac
  source_locks && lua /usr/libexec/homegate/native-package.lua restore-config || exit 7
  fsync /etc/config /etc/homegate || exit 7
  exec 6>&- 7>&-
  mode=ready;write_record || exit 7;;
 restore-config)
  dir "$root" && read_record || exit 7
  source_locks && lua /usr/libexec/homegate/native-package.lua restore-config || exit 7
  fsync /etc/config /etc/homegate || exit 7;;
 *) exit 2;;
esac
