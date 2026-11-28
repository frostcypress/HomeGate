#!/bin/sh
# Best-effort LAN cache maintenance for the QWRT pdnsd/dnsmasq chain.
# Called under the existing DDNS locks after a verified provider readback.
set -uf
umask 077
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
[ "$#" -eq 1 ] && [ "$(id -u)" = 0 ] || exit 1
rule=$1
case "$rule" in ''|*[!a-zA-Z0-9_-]*) exit 1;; esac
[ "${#rule}" -le 64 ] || exit 1
IFS=' ' read -r outcome host device address ttl extra || exit 1
[ -z "$extra" ] || exit 1
case "$outcome" in changed|unchanged) ;; *) exit 1;; esac
case "$host" in ''|-*|*[!a-z0-9.-]*) exit 1;; esac
case "$device" in ''|-*|*[!a-zA-Z0-9_.:-]*) exit 1;; esac
case "$address" in [23]*:*) ;; *) exit 1;; esac
case "$ttl" in ''|0*|*[!0-9]*) exit 1;; esac
[ "${#ttl}" -le 5 ] && [ "$ttl" -le 86400 ] || exit 1

dir=${0%/*}
run=/var/run/homegate
ledger=$run/ddns-local-cache
[ -d "$run" ] && [ ! -L "$run" ] && [ "$(stat -c '%u:%a' "$run")" = 0:700 ] || exit 1
if [ -e "$ledger" ] || [ -L "$ledger" ]; then
    [ -f "$ledger" ] && [ ! -L "$ledger" ] && [ "$(stat -c '%u:%a:%h' "$ledger")" = 0:600:1 ] &&
        [ "$(stat -c %s "$ledger")" -le 32768 ] || exit 1
    input=$ledger
else
    input=/dev/null
fi
now=$(lua "$dir/worker-process.lua" now) || exit 1
key=$(printf '%s\n' "$host" "$device" "$address" | sha256sum) || exit 1
key=${key%% *}
deadline=$(awk -v r="$rule" -v k="$key" '$1==r && $2==k && $3 ~ /^[0-9]+$/ {print $3; exit}' "$input") || exit 1
if [ "$outcome" = unchanged ] && [ -n "$deadline" ] && [ "$deadline" -le "$now" ]; then exit 0;fi

listener_pid() {
    netstat -lntp 2>/dev/null | awk -v listener="$1" -v owner="$2" '
        $4 == listener && $7 ~ /^[0-9]+\/[a-z]+$/ {
            split($7, p, "/"); if (p[2] == owner) { print p[1]; exit }
        }'
}
[ -S /var/dnscache/pdnsd.status ] && command -v pdnsd-ctl >/dev/null || exit 0
pdnsd=$(listener_pid 127.0.0.1:5333 dnscache)
[ -n "$pdnsd" ] && cmp -s "/proc/$pdnsd/exe" /usr/sbin/pdnsd || exit 0
normalized() { lua "$dir/homegate-ddns-sync.lua" cache-address; }
current=$(ip -6 -o addr show dev "$device" scope global |
    awk '$3=="inet6" && $0 !~ / (deprecated|tentative|dadfailed)( |$)/ {sub(/\/.*/, "", $4); print $4}' |
    normalized) || exit 0
[ "$current" = "$address" ] || exit 0

publish() {
    temp=$(mktemp "$run/.ddns-local-cache.XXXXXX") || return 1
    if awk -v rule="$rule" -v key="$key" -v now="$now" -v expires="$1" '
        $1 != rule {
            rows[++count]=$0
            if (!discard && $3 <= now) discard=count
        }
        END {
            if (count > 192 || (count == 192 && !discard)) exit 1
            for (i=1; i<=count; i++) if (count < 192 || i != discard) print rows[i]
            print rule, key, expires
        }' "$input" > "$temp" && mv -f "$temp" "$ledger"; then return 0; fi
    rm -f "$temp"
    return 1
}
if [ "$outcome" = changed ] || [ -z "$deadline" ]; then
    # A recursive resolver can still have the preceding TTL cached. Allow
    # subsequent verified checks to retry. A confirmed first observation also
    # covers upgrades from a firmware without a successful local refresh.
    expire=$((now + ttl + 900))
    publish "$expire" || exit 1
    input=$ledger
fi
answer() {
    lookup_status=0
    reply=$(lua "$dir/homegate-ddns-cache-command.lua" lookup "$host" "$1" 2>/dev/null) || lookup_status=$?
    # BusyBox can return 1 for a missing A record alongside a valid AAAA.
    case "$lookup_status" in 0|1) ;; *) return 1;; esac
    printf '%s\n' "$reply" |
        awk '/^Name:/ { reply=1 } reply && (/^Address [0-9]+:/ || /^Address:/) && index($NF,":") { print $NF }' |
        normalized
}
upstream='127.0.0.1#5333'
upstream_address=$(answer "$upstream") || exit 0
if [ "$upstream_address" != "$address" ]; then
    lua "$dir/homegate-ddns-cache-command.lua" evict "$host" >/dev/null || exit 0
    [ "$(answer "$upstream")" = "$address" ] || exit 0
fi
local_address=$(answer 127.0.0.1) || exit 0
if [ "$local_address" != "$address" ]; then
    dnsmasq=$(listener_pid 127.0.0.1:53 dnsmasq)
    [ -n "$dnsmasq" ] && cmp -s "/proc/$dnsmasq/exe" /usr/sbin/dnsmasq || exit 0
    kill -HUP "$dnsmasq" || exit 0
    # The signal is asynchronous. A subsequent successful DDNS check can
    # confirm the local answer without signaling again after it is current.
    exit 0
fi
publish 0
