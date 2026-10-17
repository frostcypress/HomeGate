#!/bin/sh
# Managed single-rule pacing and bounded historical status. Never bypass DNS fences.
set -u
umask 077
export LC_ALL=C
ddns_state_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-state","effect":"none","write_ready":false,"error":"DDNS state is unavailable"}\n';exit "${1:-7}"; }
[ "$ddns_state_enabled" = true ] || fail 2
action=${1:-};rule=${2:-}
case "$action" in status) [ "$#" -eq 2 ] || fail 2;; sync|reset) [ "$#" -eq 3 ] && [ "$3" = --confirm ] || fail 2;; *) fail 2;; esac
case "$rule" in ''|*[!a-zA-Z0-9_-]*) fail 2;; esac
[ "${#rule}" -le 64 ] || fail 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
[ "$(id -u)" = 0 ] || fail
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ]; }
run=/var/run/homegate;store=/etc/homegate/transactions
cache=$run/ddns-state;file=$cache/$rule;next=$cache/.$rule.next;result=$cache/.$rule.result
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
private_dir "$run" && private_dir "$store" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
for fd in 6 7; do
    lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
    if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ]; then
        case "$fd" in 6) exec 6>>"$lock" || fail;; 7) exec 7>>"$lock" || fail;; esac
    fi
    flock -n "$fd" || fail 4
done
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null) || fail
scope_mode=scope;[ "$action" != reset ] || scope_mode=reset-scope
scope=$(ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 4>&- 8>&- 9>&- >/dev/null 2>/dev/null |
    lua "$dir/homegate-ddns-state.lua" "$scope_mode" "$revision" "$rule" 3>&- 4>&- 8>&- 9>&- 2>/dev/null) || fail
old_ifs=$IFS;IFS=:;set -- $scope;IFS=$old_ifs
[ "$#" -eq 3 ] || fail;provider=$1;account=$2;interval=$3
hash "$store/identity" || fail;identity=$sum;hash "$store/gen-$revision/manifest" || fail;generation=$sum
boot=$(cat /proc/sys/kernel/random/boot_id) || fail
now=$(lua "$dir/worker-process.lua" now 2>/dev/null) || fail
blocked=false;authorized=false;incomplete=false
ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || blocked=true
for p in "$run/".dns-check-* "$run/".ddns-plan-*; do ! exists "$p" || blocked=true;done
if [ "$blocked" = false ]; then ash "$dir/homegate-ddns-authority.sh" check-rule "$rule" >/dev/null 2>/dev/null && authorized=true;fi
# status is read-only: do not create the cache directory just to query it.
count=0
if exists "$cache"; then
    private_dir "$cache" || fail
    for p in "$cache/"* "$cache/".[!.]* "$cache/"..?*; do
        exists "$p" || continue
        private_file "$p" && [ "$(stat -c %s "$p")" -le 65536 ] || fail
        name=${p##*/};case "$name" in .*.next|.*.result) id=${name#.};id=${id%.*};; .*) fail;; *) id=$name;; esac
        case "$id" in ''|*[!a-zA-Z0-9_-]*) fail;; esac;[ "${#id}" -le 64 ] || fail
        count=$((count+1));[ "$count" -le 192 ] || fail
    done
fi
for p in "$next" "$result"; do ! exists "$p" || incomplete=true;done
if exists "$file"; then private_file "$file" && [ "$(stat -c %s "$file")" -le 4096 ] || fail;exec 8<"$file" || fail;else exec 8</dev/null;fi
codec() { lua "$dir/homegate-ddns-state.lua" "$1" "$revision" "$rule" "$provider" "$account" "$identity" "$generation" "$boot" "$now" "$interval" "$blocked" "$authorized" "$incomplete" ${2:+"$2"} 2>/dev/null; }
if [ "$action" = status ]; then codec status || fail;exit 0;fi
if [ "$action" = reset ]; then
    [ "$blocked" = false ] || fail 4
    # Explicit cache reset can only forget scheduling history. Durable barriers stay.
    if exists "$cache"; then
        for p in "$file" "$next" "$result"; do if exists "$p"; then private_file "$p" && [ "$(stat -c %s "$p")" -le 65536 ] && rm -f "$p" || fail;fi;done
        fsync "$cache" 2>/dev/null || fail
    fi
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-state","state_reset":true,"effect":"none","write_ready":false}\n';exit 0
fi
decision=$(codec decision) || fail
case "$decision" in ready|stale) ;; *) codec status || fail;exit 4;; esac
if ! exists "$cache"; then mkdir "$cache" && fsync "$run" 2>/dev/null || fail;fi
reserve=2;exists "$file" || reserve=3
private_dir "$cache" && [ "$((count+reserve))" -le 192 ] || fail
publish() { private_file "$next" && [ "$(stat -c %s "$next")" -le 4096 ] && fsync "$next" "$cache" 2>/dev/null && mv -f "$next" "$file" && fsync "$file" "$cache" 2>/dev/null; }
(set -C; : > "$next") 2>/dev/null || fail
codec begin > "$next" && publish || fail
exec 8<&-
(set -C; : > "$result") 2>/dev/null || fail
rc=0
ash "$dir/homegate-ddns-read.sh" --runtime-sync "$rule" --confirm > "$result" 8>&- 9>&- 2>/dev/null || rc=$?
private_file "$result" && [ "$(stat -c %s "$result")" -le 65536 ] || fail
case "$rc" in 0|1) ;; *) fail;; esac
now=$(lua "$dir/worker-process.lua" now 2>/dev/null) || fail
exec 8<"$file" || fail
(set -C; : > "$next") 2>/dev/null || fail
codec finish "$rc" < "$result" > "$next" && publish || fail
exec 5<"$result" || fail
rm -f "$result" && fsync "$cache" 2>/dev/null || fail
cat <&5;exit "$rc"
