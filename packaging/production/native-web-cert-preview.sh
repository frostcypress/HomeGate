#!/bin/sh
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
exec 2>/dev/null
[ "$(id -u)" = 0 ] && [ "$#" = 1 ] && [ "${#1}" = 32 ] || exit 2
job=$1;case "$job" in *[!0-9a-f]*) exit 2;;esac
work=/tmp/homegate-frontend-jobs/$job
dir(){ [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
dir /tmp/homegate-frontend-jobs && dir "$work" || exit 7
root=$work/certificate-check;pending=$root/.pending
mkdir "$root" && mkdir "$pending" || exit 7
cleanup(){
 for name in fullchain.pem privkey.pem leaf.pem keypub.der certpub.pem certpub.der chain.p7b dates san phase rejection;do
  path=$pending/$name
  if [ -e "$path" ] || [ -L "$path" ];then
   [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -c '%u:%a:%h' "$path")" = 0:600:1 ] || return 7
   rm "$path" || return 7
  fi
 done
 rmdir "$pending" "$root"
}
trap cleanup EXIT
base=/usr/libexec/homegate/project/core/prototype
for pair in '6:/var/run/homegate/frontend.lock' '7:/etc/homegate/transactions/.supervisor.lock';do
 fd=${pair%%:*};path=${pair#*:}
 [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -c '%u:%a:%h:%s' "$path")" = 0:600:1:0 ] || exit 7
 case "$fd" in 6) exec 6>>"$path";;7) exec 7>>"$path";;esac
 flock -n "$fd" || exit 4
done
lua "$base/native-web-certificate.lua" receive check "$job" || exit 1
setsid ash "$base/native-web-certificate-watchdog.sh" --certificate-validate "$job" "$job" 3>&1 >/dev/null
code=$?
if [ "$code" != 0 ];then
 stage=0;if [ -f "$pending/phase" ] && [ ! -L "$pending/phase" ];then stage=$(cat "$pending/phase");fi
 case "$stage" in ''|*[!0-9]*) stage=0;;esac
 line=0;if [ -f "$pending/rejection" ] && [ ! -L "$pending/rejection" ];then line=$(cat "$pending/rejection");fi
 case "$line" in ''|*[!0-9]*) line=0;;esac
 printf '{"ok":false,"error":"Certificate validation refused at bounded stage %s/%s"}\n' "$stage" "$line"
fi
exit "$code"
