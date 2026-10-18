#!/bin/sh
# Explicit bounded batch. Reuses one sample, ordinary workers and global fences.
set -u
umask 077
export LC_ALL=C
ddns_batch_enabled=false
ddns_batch_closeout_enabled=false
rows=;effect=none;sampled=false;closeouts=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-batch","effect":"%s","sampled":%s,"write_ready":false,"rules":[%s],"error":"DDNS batch is unavailable"}\n' "$effect" "$sampled" "$rows";exit "${1:-7}"; }
[ "$ddns_batch_enabled" = true ] && [ "$#" -eq 2 ] && [ "$1" = sync ] || fail 2
case "$2" in --confirm) ;; --confirm-closeouts) [ "$ddns_batch_closeout_enabled" = true ] || fail 2;closeouts=true;; *) fail 2;; esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
owner=$(id -u) || fail;[ "$owner" = 0 ] || fail
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ]; }
store=/etc/homegate/transactions;run=/var/run/homegate
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
private_dir "$store" && private_dir "$run" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
for fd in 6 7; do
    lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
    if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ]; then
        case "$fd" in 6) exec 6>>"$lock" || fail;; 7) exec 7>>"$lock" || fail;; esac
    fi
    flock -n "$fd" || fail 4
done
if [ "$closeouts" = true ]; then
    for p in "$store/dns-batch-results" "$store/.dns-batch-results-next" "$store/dns-settled" "$store/dns-collection" "$store/.dns-collection-next"; do ! exists "$p" || fail 4;done
fi
ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || fail 4
for p in "$run/".dns-check-* "$run/".ddns-plan-*; do ! exists "$p" || fail 4;done
revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null) || fail
names=$(ash "$dir/homegate-ddns-authority.sh" check 2>/dev/null | lua "$dir/homegate-ddns-batch.lua" names "$revision" 2>/dev/null) || fail
due=false;pre_rows=
for rule in $names; do
    status=$(ash "$dir/homegate-ddns-state.sh" status "$rule" 2>/dev/null) || fail
    row=$(printf '%s\n' "$status" | lua "$dir/homegate-ddns-batch.lua" row "$revision" "$rule" 0 2>/dev/null) || fail
    case "$row" in *'"status":"ready"'*|*'"status":"stale"'*) due=true;; esac
    pre_rows=${pre_rows:+$pre_rows,}$row
done
report() { ok=false;[ "$1" != 0 ] || ok=true;printf '{"api_version":1,"prototype":true,"ok":%s,"phase":"ddns-batch","configuration_revision":%s,"effect":"%s","sampled":%s,"write_ready":false,"rules":[%s]}\n' "$ok" "$revision" "$effect" "$sampled" "$rows";exit "$1"; }
if [ "$due" = false ]; then rows=$pre_rows;report 4;fi
job=$$;work=$run/.ddns-plan-$job
ticket=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 2>/dev/null) || fail
mkdir "$work" || fail
for name in result public plan intent envelope call; do (set -C; : > "$work/$name") 2>/dev/null && private_file "$work/$name" || fail;done
rc=0
ash "$dir/homegate-ddns-authority.sh" snapshot 3>&1 4>"$work/intent" 8>&- 9>&- >/dev/null 2>/dev/null |
    setsid ash "$dir/homegate-service-observer-watchdog.sh" --ddns-plan "$ticket" "$revision" "$job" '' 3>"$work/result" 8>&- 9>&- >/dev/null 2>/dev/null || rc=$?
case "$rc" in 0|1) ;; *) fail;; esac
lua "$dir/homegate-ddns-plan.lua" result "$revision" '' "$rc" < "$work/result" >/dev/null 2>/dev/null || fail
hash "$store/identity" || fail;identity=$sum;hash "$store/gen-$revision/manifest" || fail;generation=$sum
hash "$store/ddns-authority" || fail;grant=$sum;boot=$(cat /proc/sys/kernel/random/boot_id) || fail
info=$(lua "$dir/worker-process.lua" info "$job" none 2>/dev/null) || fail
old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs;[ "$#" -eq 6 ] || fail;parent=$job:$5
ash "$dir/homegate-ddns-authority.sh" snapshot 3>&1 4>"$work/intent" 8>&- 9>&- >/dev/null 2>/dev/null |
    lua "$dir/homegate-ddns-batch.lua" seal "$revision" "$identity" "$generation" "$grant" "$boot" "$parent" 4<"$work/intent" 8<"$work/plan" > "$work/envelope" 2>/dev/null || fail
exec 5<"$work/envelope" 8>"$work/call" || fail
# The sampling-only stage is removed before any provider attempt. Unknown
# members are preserved; no unbound work is automatically swept after a crash.
for p in "$work/"* "$work/".[!.]* "$work/"..?*; do
    exists "$p" || continue
    case "${p##*/}" in result|public|plan|intent|envelope|call) private_file "$p" || fail;; *) fail;; esac
done
for name in result public plan intent envelope call; do rm -f "$work/$name" || fail;done
rmdir "$work" || fail
sampled=true;result=0
for rule in $names; do
    rc=0;previous_effect=$effect;effect=unknown
    ash "$dir/homegate-ddns-state.sh" batch-sync-internal "$rule" "$job" --confirm > /proc/self/fd/8 8>&- 9>&- 2>/dev/null || rc=$?
    row=$(lua "$dir/homegate-ddns-batch.lua" row "$revision" "$rule" "$rc" < /proc/self/fd/8 8>&- 9>&- 2>/dev/null) || fail
    effect=$previous_effect
    case "$row" in *'"effect":"unknown"'*) effect=unknown;; *'"effect":"confirmed"'*) [ "$effect" = unknown ] || effect=confirmed;; esac
    prefix=${rows:+$rows,};rows=$prefix$row
    if [ "$closeouts" = true ]; then
        case "$row" in *'"effect":"confirmed"'*)
            ash "$dir/homegate-ddns-batch-results.sh" capture-close "$rule" "$job" 8</proc/self/fd/8 9>&- >/dev/null 2>/dev/null || fail
            row=$(lua "$dir/homegate-ddns-batch.lua" row-closed "$revision" "$rule" "$rc" < /proc/self/fd/8 8>&- 9>&- 2>/dev/null) || fail
            rows=$prefix$row;;
        esac
    fi
    case "$rc" in 0) ;; 1) result=1;; 4) [ "$result" != 0 ] || result=4;; *) fail;; esac
done
exec 5<&- 8>&-
report "$result"
