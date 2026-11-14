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
set -- /etc/homegate /var/run/homegate /var/run/homegate-audit /var/run/homegate-proxy-body /etc/.homegate-transition
for path do
 [ ! -L "$path" ] || exit 7
 [ ! -e "$path" ] || { [ -d "$path" ] && [ "$(stat -c %u "$path")" = 0 ]; } || exit 7
done
if [ -e /etc/.homegate-transition ];then
 [ "$(stat -c '%u:%a' /etc/.homegate-transition)" = 0:700 ] || exit 7
 for path in /etc/.homegate-transition/hold /etc/.homegate-transition/source.config /usr/lib/opkg/info/homegate.control;do
  [ ! -e "$path" ] && [ ! -L "$path" ] || exit 7
 done
fi
# Older delivery scripts wrote full, private checkpoints outside the data root.
# Match their release-to-release naming convention and private directory mode.
for path in /etc/.homegate-r*-before-r*;do
 name=${path##*/};from=${name#.homegate-r};to=${from#*-before-r};from=${from%%-before-r*}
 case "$from" in ''|*[!0-9]*) continue;;esac
 case "$to" in ''|*[!0-9]*) continue;;esac
 [ ! -L "$path" ] && [ -d "$path" ] && [ "$(stat -c '%u:%a' "$path")" = 0:700 ] || continue
 set -- "$@" "$path"
done
# An interrupted LuCI request can leave its UUID-named private request directory.
for path in /tmp/homegate-web-* /tmp/homegate-luci-*;do
 id=${path##*-}
 [ "${#id}" = 32 ] || continue
 case "$id" in *[!0-9a-f]*) continue;;esac
 [ ! -L "$path" ] && [ -d "$path" ] && [ "$(stat -c '%u:%a' "$path")" = 0:700 ] || continue
 set -- "$@" "$path"
done
[ ! -L /tmp/.uci ] && { [ ! -e /tmp/.uci ] || [ -d /tmp/.uci ]; } || exit 7
for path in /etc/config/homegate /etc/config/homegate-opkg /etc/config/homegate.opkg /tmp/.uci/homegate /var/log/homegate.log;do
 [ ! -L "$path" ] || exit 7
 [ ! -e "$path" ] || [ -f "$path" ] || exit 7
done
for path in /etc/config/.homegate-projection.*;do
 pid=${path##*.}
 case "$pid" in ''|*[!0-9]*) continue;;esac
 [ ! -L "$path" ] && [ -f "$path" ] && [ "$(stat -c '%u:%a:%h' "$path")" = 0:600:1 ] || continue
 rm -f "$path" || exit 7
done
rm -f /etc/config/homegate /etc/config/homegate-opkg /etc/config/homegate.opkg /tmp/.uci/homegate /var/log/homegate.log || exit 7
rm -rf "$@" || exit 7
