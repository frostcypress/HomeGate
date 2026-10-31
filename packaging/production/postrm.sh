#!/bin/sh
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
[ "$(id -u)" = 0 ] || exit 7
[ "${PKG_UPGRADE:-0}" != 1 ] && [ "${1:-}" != upgrade ] || exit 0
root=/etc/homegate;record=$root/package-state
[ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c '%u:%a' "$root")" = 0:700 ] || exit 7
[ -f "$record" ] && [ ! -L "$record" ] && [ "$(stat -c '%u:%a:%h' "$record")" = 0:600:1 ] && [ "$(stat -c %s "$record")" -le 64 ] || exit 7
{ IFS= read -r magic && IFS= read -r mode && IFS= read -r boot && IFS= read -r running && ! IFS= read -r extra; } < "$record" || exit 7
[ "$magic" = HGPKG1 ] || exit 7
case "$mode:$boot:$running" in upgrade:[01]:[01]|reinstall:[01]:[01]) exit 0;;remove:[01]:[01]) ;;*) exit 7;;esac
expected=$(printf '%s\n' "$magic" "$mode" "$boot" "$running")
[ "$(cat "$record")" = "$expected" ] && [ "$(stat -c %s "$record")" = "$((${#expected}+1))" ] || exit 7
# prerm already established native and component quiescence before opkg could
# remove executable files. Literal plugin roots only; never follow a root link.
for path in /etc/homegate /var/run/homegate /etc/.homegate-transition;do
 [ ! -L "$path" ] || exit 7
 [ ! -e "$path" ] || [ -d "$path" ] || exit 7
done
if [ -e /etc/.homegate-transition ];then
 [ "$(stat -c '%u:%a' /etc/.homegate-transition)" = 0:700 ] || exit 7
 for path in /etc/.homegate-transition/hold /etc/.homegate-transition/source.config /usr/lib/opkg/info/homegate.control;do
  [ ! -e "$path" ] && [ ! -L "$path" ] || exit 7
 done
fi
for path in /etc/config/homegate /etc/config/homegate-opkg /var/log/homegate.log;do
 [ ! -L "$path" ] || exit 7
 [ ! -e "$path" ] || [ -f "$path" ] || exit 7
done
rm -rf /etc/homegate /var/run/homegate /etc/.homegate-transition || exit 7
rm -f /etc/config/homegate /etc/config/homegate-opkg /var/log/homegate.log || exit 7
