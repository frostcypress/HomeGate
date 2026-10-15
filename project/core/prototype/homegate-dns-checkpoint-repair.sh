#!/bin/sh
# Resume only a complete checkpoint publication; never send or retry DNS.
set -u
umask 077
export LC_ALL=C
dns_checkpoint_repair_enabled=false
[ "$dns_checkpoint_repair_enabled" = true ] && [ "$#" -eq 4 ] && [ "$1" = repair-checkpoint ] || exit 2
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
exists() { [ -e "$1" ] || [ -L "$1" ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ] || return 1; }
store=/etc/homegate/transactions
private_dir "$store" && private_file "$store/identity" && private_file /var/run/homegate/frontend.lock && private_file "$store/.supervisor.lock" || exit 1
for fd in 6 7; do
    target=/var/run/homegate/frontend.lock;[ "$fd" != 7 ] || target=$store/.supervisor.lock
    [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$target")" ] || exit 1
    flock -n "$fd" || exit 1
done
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
ash "$dir/homegate-config-prototype.sh" --persistent dns-recovery-check >/dev/null 2>/dev/null || exit 1
[ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null)" = "$revision" ] || exit 1
journal=$store/dns-operation
private_dir "$journal" || exit 1
for entry in "$journal/"* "$journal/".[!.]* "$journal/"..?*; do
    ! exists "$entry" && continue
    case "$entry" in "$journal/current"|"$journal/slot-1"|"$journal/slot-2"|"$journal/.prepare"|"$journal/.next") ;; *) exit 1;; esac
done
active=0
if exists "$journal/current"; then
    private_file "$journal/current" && [ "$(stat -c %s "$journal/current")" = 2 ] || exit 1
    active=$(cat "$journal/current") || exit 1
    case "$active" in 1|2) ;; *) exit 1;; esac
fi
pointer=false;pointer_value=
if exists "$journal/.next"; then
    pointer=true;private_file "$journal/.next" || exit 1
    case "$(stat -c %s "$journal/.next")" in
        0) ;;
        2) pointer_value=$(cat "$journal/.next") || exit 1;case "$pointer_value" in 1|2) ;; *) exit 1;; esac;;
        *) exit 1;;
    esac
fi
next=1;[ "$active" != 1 ] || next=2
candidate=$journal/slot-$active;comparison=current;publish=false
if [ "$active" = 0 ] || [ "$pointer" = true ]; then
    [ "$pointer" = true ] || exit 1
    [ -z "$pointer_value" ] || [ "$pointer_value" = "$next" ] || exit 1
    candidate=$journal/slot-$next;comparison=advance;publish=true
    if exists "$journal/.prepare"; then
        [ -z "$pointer_value" ] && ! exists "$candidate" || exit 1
        candidate=$journal/.prepare
    fi
    if [ "$active" = 0 ]; then comparison=initial;! exists "$journal/slot-2" || exit 1;fi
else
    ! exists "$journal/.prepare" || exit 1
fi
private_dir "$candidate" && private_file "$candidate/manifest" || exit 1
[ "$(stat -c %s "$candidate/manifest")" -le 512 ] || exit 1
exec 8<"$candidate/manifest" || exit 1
IFS= read -r format <&8 && IFS= read -r slug <&8 && IFS= read -r stored_identity <&8 && IFS= read -r boot <&8 &&
    IFS= read -r stored_revision <&8 && IFS= read -r stored_account <&8 && IFS= read -r stored_job <&8 &&
    IFS= read -r generation_hash <&8 && IFS= read -r context_hash <&8 && IFS= read -r checksum <&8 || exit 1
if IFS= read -r extra <&8; then exit 1;fi
exec 8<&-
hash "$store/identity" || exit 1;identity_hash=$sum
[ "$format:$slug:$stored_identity:$stored_revision:$stored_account:$stored_job" = "HGCFJOURNAL1:homegate:$identity_hash:$revision:$account:$job" ] || exit 1
[ "${#boot}" -eq 36 ] || exit 1;case "$boot" in *[!0-9a-f-]*) exit 1;; esac
private_file "$store/gen-$revision/manifest" && hash "$store/gen-$revision/manifest" && [ "$sum" = "$generation_hash" ] || exit 1
slot_check() (
    private_dir "$1" && private_file "$1/context" && private_file "$1/manifest" || exit 1
    [ "$(stat -c %s "$1/context")" -le 8388608 ] && [ "$(stat -c %s "$1/manifest")" -le 512 ] || exit 1
    for item in "$1/"* "$1/".[!.]* "$1/"..?*; do
        ! exists "$item" && continue
        case "$item" in "$1/context"|"$1/manifest") ;; *) exit 1;; esac
    done
    hash "$1/context" || exit 1
    frame=$(printf '%s\n' HGCFJOURNAL1 homegate "$identity_hash" "$boot" "$revision" "$account" "$job" "$generation_hash" "$sum") || exit 1
    digest=$(printf '%s\n' "$frame" | sha256sum) || exit 1
    expected=$(printf '%s\n' "$frame" "${digest%% *}") || exit 1
    [ "$(stat -c %s "$1/manifest")" -eq "$((${#expected} + 1))" ] && [ "$(cat "$1/manifest")" = "$expected" ]
)
for slot in "$journal/slot-1" "$journal/slot-2" "$journal/.prepare"; do
    ! exists "$slot" && continue
    slot_check "$slot" || exit 1
done
slot_check "$candidate" || exit 1
previous=$candidate/context
[ "$active" = 0 ] || { slot_check "$journal/slot-$active" || exit 1;previous=$journal/slot-$active/context; }
ready=$(ash "$dir/homegate-config-prototype.sh" --persistent dns-recovery-snapshot-read 3>&1 8<&- 9<&- >/dev/null 2>/dev/null |
    lua "$dir/cloudflare-records.lua" receipt-checkpoint "$account" "$revision" "$comparison" 8<"$candidate/context" 9<"$previous" 3>&- 4>&- 5>&- 2>/dev/null) || exit 1
[ "$ready" = HGCFCVALID1 ] || exit 1
# Validate every byte and candidate relationship before the first mutation.
for slot in "$journal/slot-1" "$journal/slot-2" "$journal/.prepare"; do
    ! exists "$slot" && continue
    fsync "$slot/context" "$slot/manifest" "$slot" 2>/dev/null || exit 1
done
fsync "$journal" "$store" 2>/dev/null || exit 1
if [ "$publish" = true ]; then
    if [ "$candidate" = "$journal/.prepare" ]; then
        mv "$candidate" "$journal/slot-$next" || exit 1
        fsync "$journal" 2>/dev/null || exit 1
    fi
    if [ -z "$pointer_value" ]; then printf '%s\n' "$next" > "$journal/.next" || exit 1;fi
    fsync "$journal/.next" "$journal" 2>/dev/null || exit 1
    mv -f "$journal/.next" "$journal/current" || exit 1
fi
private_file "$journal/current" && [ "$(stat -c %s "$journal/current")" = 2 ] || exit 1
case "$(cat "$journal/current")" in 1|2) ;; *) exit 1;; esac
fsync "$journal/current" "$journal" "$store" 2>/dev/null || exit 1
exit 0
