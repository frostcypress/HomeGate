#!/bin/sh
# Internal checkpoint only. Not installed, no caller paths, no collection API.
set -u
umask 077
export LC_ALL=C
dns_receipt_enabled=false
[ "$dns_receipt_enabled" = true ] && [ "$#" -eq 4 ] && [ "$1" = checkpoint ] || exit 2
account=$2;revision=$3;job=$4
case "$account" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
[ "${#account}" -le 64 ] || exit 2
case "$revision:$job" in *[!0-9:]*) exit 2;; esac
[ "${#revision}" -le 2 ] && [ "$revision" -ge 1 ] && [ "$revision" -le 32 ] || exit 2
case "$job" in ''|0*) exit 2;; esac
[ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || exit 2
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
owner=$(id -u) || exit 1
[ "$owner" = 0 ] || exit 1
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1" 2>/dev/null)" = "$owner:600:1" ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ] || return 1; }
store=/etc/homegate/transactions
work=/var/run/homegate/.dns-check-$job
private_dir "$store" && private_dir "$work" || exit 1
private_file /var/run/homegate/frontend.lock && private_file "$store/.supervisor.lock" || exit 1
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/6 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' /var/run/homegate/frontend.lock)" ] || exit 1
[ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/7 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$store/.supervisor.lock")" ] || exit 1
flock -n 6 && flock -n 7 || exit 1
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
# Reuse the real namespace/generation/application checks, under loaned locks.
ash "$dir/homegate-config-prototype.sh" --persistent dns-recovery-check >/dev/null 2>/dev/null || exit 1
[ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null)" = "$revision" ] || exit 1
private_file "$work/context" && private_file "$work/attempt" || exit 1
[ "$(stat -c %s "$work/context")" -le 8388608 ] || exit 1
[ "$(stat -c %s "$work/attempt")" = 13 ] && [ "$(cat "$work/attempt")" = HGCFATTEMPT1 ] || exit 1
hash "$store/identity" || exit 1;identity_hash=$sum
hash "$store/gen-$revision/manifest" || exit 1;generation_hash=$sum
boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || exit 1
[ "${#boot}" -eq 36 ] || exit 1
case "$boot" in *[!0-9a-f-]*) exit 1;; esac
journal=$store/dns-operation
payload() { printf '%s\n' HGCFJOURNAL1 homegate "$identity_hash" "$boot" "$revision" "$account" "$job" "$generation_hash" "$context_hash"; }
meta() {
    body=$(payload) || return 1
    checksum=$(printf '%s\n' "$body" | sha256sum) || return 1
    printf '%s\n' "$body" "${checksum%% *}"
}
slot_check() {
    private_dir "$1" && private_file "$1/context" && private_file "$1/manifest" || return 1
    [ "$(stat -c %s "$1/context")" -le 8388608 ] && [ "$(stat -c %s "$1/manifest")" -le 512 ] || return 1
    for entry in "$1/"* "$1/".[!.]* "$1/"..?*; do
        [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
        case "$entry" in "$1/context"|"$1/manifest") ;; *) return 1;; esac
    done
    hash "$1/context" || return 1;context_hash=$sum
    expected=$(meta) || return 1
    [ "$(stat -c %s "$1/manifest")" -eq "$((${#expected} + 1))" ] && [ "$(cat "$1/manifest")" = "$expected" ]
}
created=false
if [ ! -e "$journal" ] && [ ! -L "$journal" ]; then
    mkdir "$journal" 2>/dev/null || exit 1
    created=true
    # Even an incomplete initialization is a durable barrier before HTTP.
    fsync "$store" 2>/dev/null || exit 1
fi
private_dir "$journal" || exit 1
for entry in "$journal/"* "$journal/".[!.]* "$journal/"..?*; do
    [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
    case "$entry" in "$journal/current"|"$journal/slot-1"|"$journal/slot-2") ;; *) exit 1;; esac
done
active=0
if [ "$created" = false ]; then
    private_file "$journal/current" && [ "$(stat -c %s "$journal/current")" = 2 ] || exit 1
    active=$(cat "$journal/current") || exit 1
    case "$active" in 1|2) ;; *) exit 1;; esac
    slot_check "$journal/slot-$active" || exit 1
fi
next=1;[ "$active" != 1 ] || next=2
inactive=$journal/slot-$next
if [ -e "$inactive" ] || [ -L "$inactive" ]; then
    slot_check "$inactive" || exit 1
    rm -f "$inactive/context" "$inactive/manifest" && rmdir "$inactive" || exit 1
    fsync "$journal" 2>/dev/null || exit 1
fi
stage=$journal/.prepare
mkdir "$stage" 2>/dev/null || exit 1
(set -C; : > "$stage/context" && : > "$stage/manifest" && : > "$journal/.next") 2>/dev/null || exit 1
private_dir "$stage" && private_file "$stage/context" && private_file "$stage/manifest" && private_file "$journal/.next" || exit 1
lua "$dir/cloudflare-records.lua" receipt "$account" "$revision" 5<"$work/context" 3>"$stage/context" 4>&- 8>&- 9>&- >/dev/null 2>/dev/null || exit 1
hash "$stage/context" || exit 1;context_hash=$sum
meta > "$stage/manifest" || exit 1
fsync "$stage/context" "$stage/manifest" "$stage" 2>/dev/null || exit 1
mv "$stage" "$inactive" 2>/dev/null || exit 1
fsync "$journal" 2>/dev/null || exit 1
printf '%s\n' "$next" > "$journal/.next" || exit 1
fsync "$journal/.next" 2>/dev/null || exit 1
mv -f "$journal/.next" "$journal/current" 2>/dev/null || exit 1
fsync "$journal" "$store" 2>/dev/null || exit 1
# No remote mutation may precede this successful return. Keep both slots and
# the barrier even on confirmed success, until a later authorized settlement.
exit 0
