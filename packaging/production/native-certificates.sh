#!/bin/sh
# Fixed-path legacy adoption and recoverable, unreferenced native cleanup.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
exec 2>/dev/null
[ "$(id -u)" = 0 ] && [ "$#" = 3 ] && [ "$3" = --confirm ] || exit 2
action=$1;id=$2;case "$id" in ''|*[!a-zA-Z0-9_-]*) exit 2;;esac;[ "${#id}" -le 64 ] || exit 2
base=/usr/libexec/homegate;dir=$base/project/core/prototype
ash "$base/native-service.sh" quiescent >/dev/null || exit 4
case "$action" in adopt) exec ash "$dir/homegate-certificate.sh" adopt "$id" --confirm;;purge) ;;*) exit 2;;esac
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
for pair in '6:/var/run/homegate/frontend.lock' '7:/etc/homegate/transactions/.supervisor.lock';do
 fd=${pair%%:*};p=${pair#*:};[ -f "$p" ] && [ ! -L "$p" ] && [ "$(stat -c '%u:%a:%h:%s' "$p")" = 0:600:1:0 ] || exit 7
 case "$fd" in 6) exec 6>>"$p";;7) exec 7>>"$p";;esac
 [ "$(stat -Lc '%d:%i' /proc/self/fd/$fd)" = "$(stat -c '%d:%i' "$p")" ] && flock -n "$fd" || exit 4
done
ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null || exit 4
ash "$dir/homegate-config-prototype.sh" --persistent runtime-startup-snapshot-read 3>&1 >/dev/null |
 lua "$dir/homegate-certificate.lua" unreferenced "$id" >/dev/null || exit 4
lua "$base/native-certificates.lua" purge "$id";code=$?
if [ "$code" != 0 ];then printf '{"api_version":1,"ok":false,"phase":"certificate-cleanup","error":"Certificate ownership or retained cleanup requires attention"}\n';fi
exit "$code"
