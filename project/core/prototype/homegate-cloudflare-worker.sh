#!/bin/sh
# Runs only in the fixed DNS watchdog session with a private snapshot pipe.
set -u
umask 077
export LC_ALL=C
dns_read_enabled=false
[ "$dns_read_enabled" = true ] && { [ "$#" -eq 3 ] || [ "$#" -eq 4 ]; } || exit 2
account=$1; revision=$2; job=$3
mode=${4:-check};case "$mode" in check|zones) ;; *) exit 2;; esac
case "$account" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
[ "${#account}" -le 64 ] || exit 2
case "$revision:$job" in *[!0-9:]*) exit 2;; esac
[ "$revision" -ge 1 ] && [ "$revision" -le 32 ] && [ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || exit 2
[ -p /proc/self/fd/0 ] || exit 1
work=/var/run/homegate/.dns-check-$job
[ -d "$work" ] && [ ! -L "$work" ] && [ "$(stat -c '%u:%a' "$work")" = 0:700 ] || exit 1
for slot in request result zones state; do
    [ -f "$work/$slot" ] && [ ! -L "$work/$slot" ] && [ "$(stat -c '%u:%a:%h' "$work/$slot")" = 0:600:1 ] || exit 1
done
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/3)" = "$(stat -c '%d:%i:%u:%a:%h' "$work/result")" ] || exit 1
[ -f /usr/bin/curl ] && [ ! -L /usr/bin/curl ] && [ -x /usr/bin/curl ] || exit 1
case "$(stat -c '%u:%a:%h' /usr/bin/curl)" in 0:700:1|0:755:1) ;; *) exit 1;; esac
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
exec 4>>"$work/request" || exit 1
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/4)" = "$(stat -c '%d:%i:%u:%a:%h' "$work/request")" ] || exit 1
if [ "$mode" = zones ]; then
    ready=$(lua "$dir/cloudflare-codec.lua" request "$account" "$revision" zones 2>/dev/null)
else
    ready=$(lua "$dir/cloudflare-codec.lua" request "$account" "$revision" 2>/dev/null)
fi
code=$?; exec 4>&-
if [ "$code" -ne 0 ]; then printf '%s\n' "$ready" >&3; exit 1; fi
[ "$ready" = HGDNSREADY1 ] || exit 1
# Curl does not receive credentials in argv or environment. Disable curlrc,
# proxies, redirects and alternate protocols. CA is a fixed system trust file.
# The bounded Lua reader also closes chunked/unknown-size responses at 64 KiB;
# do not rely on old curl --max-filesize to bound these cases.
fetch() {
    rc=0
    /usr/bin/curl --disable --config "$work/request" --proto '=https' --proto-redir '=https' --proxy '' --noproxy '*' \
        --connect-timeout 3 --max-time 10 --cacert /etc/ssl/certs/ca-certificates.crt --silent \
        --write-out '\nHGHTTP:%{http_code}\n' "$@" 3>&- 4>&- 5>&- || rc=$?
    printf '\nHGTRANSPORT:%s\n' "$rc"
}
if [ "$mode" = check ]; then
    fetch | lua "$dir/cloudflare-codec.lua" response "$account" "$revision" 4>&- 5>&- 2>/dev/null
    exit $?
fi
# Fixed URL and numeric page only; no response-supplied URL, account or cursor.
exec 4>>"$work/zones" 5>>"$work/state" || exit 1
page=1
while [ "$page" -le 1000 ]; do
    ready=$(fetch --url "https://api.cloudflare.com/client/v4/zones?page=$page&per_page=50" |
        lua "$dir/cloudflare-zones.lua" page "$account" "$revision" "$page" 2>/dev/null)
    code=$?
    [ "$code" -eq 0 ] || exit 1
    case "$ready" in
        HGDNSDONE1) lua "$dir/cloudflare-zones.lua" finish "$account" "$revision" 2>/dev/null; exit $?;;
        HGDNSNEXT1) page=$((page + 1));;
        *) exit 1;;
    esac
done
exit 1
