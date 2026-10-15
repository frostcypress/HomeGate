#!/bin/sh
# Fixed internal recovery/collection. No remote mutations and no recursive purge.
set -u
umask 077
export LC_ALL=C
dns_settlement_enabled=false
dns_terminal_repair_enabled=false
action=${1:-}
case "$action" in
    archive-check) [ "$#" -eq 1 ] || exit 2;;
    settle|load|collect|retire-check|repair-terminal)
        [ "$dns_settlement_enabled" = true ] && [ "$#" -eq 4 ] || exit 2
        [ "$action" != repair-terminal ] || [ "$dns_terminal_repair_enabled" = true ] || exit 2
        account=$2;revision=$3;job=$4
        case "$account" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
        [ "${#account}" -le 64 ] || exit 2
        case "$revision:$job" in *[!0-9:]*) exit 2;; esac
        [ "${#revision}" -le 2 ] && [ "$revision" -ge 1 ] && [ "$revision" -le 32 ] || exit 2
        case "$job" in ''|0*|*[!0-9]*) exit 2;; esac
        [ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || exit 2;;
    *) exit 2;;
esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
owner=$(id -u) || exit 1
[ "$owner" = 0 ] || exit 1
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1" 2>/dev/null)" = "$owner:600:1" ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ] || return 1; }
store=/etc/homegate/transactions
private_dir "$store" && private_file "$store/identity" && private_file /var/run/homegate/frontend.lock && private_file "$store/.supervisor.lock" || exit 1
for fd in 6 7; do
    target=/var/run/homegate/frontend.lock;[ "$fd" != 7 ] || target=$store/.supervisor.lock
    [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$target")" ] || exit 1
    flock -n "$fd" || exit 1
done
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
# archive-check is called by the already locked engine; avoid recursive checks.
if [ "$action" != archive-check ]; then
    ash "$dir/homegate-config-prototype.sh" --persistent dns-recovery-check >/dev/null 2>/dev/null || exit 1
    [ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null)" = "$revision" ] || exit 1
fi
hash "$store/identity" || exit 1;identity_hash=$sum
journal=$store/dns-operation;archive=$store/dns-settled;ledger=$store/dns-collection
if [ "$action" = archive-check ] || [ "$action" = retire-check ]; then journal=$archive
elif [ "$action" = collect ] && [ ! -e "$journal" ] && [ ! -L "$journal" ]; then journal=$archive; fi
private_dir "$journal" || exit 1
for entry in "$journal/"* "$journal/".[!.]* "$journal/"..?*; do
    [ ! -e "$entry" ] && [ ! -L "$entry" ] && continue
    case "$entry" in
        "$journal/current"|"$journal/slot-1"|"$journal/slot-2"|"$journal/terminal"|"$journal/terminal-meta") ;;
        "$journal/.terminal"|"$journal/.terminal-meta") [ "$action" = repair-terminal ] || exit 1;;
        *) exit 1;;
    esac
done
private_file "$journal/current" && [ "$(stat -c %s "$journal/current")" = 2 ] || exit 1
active=$(cat "$journal/current") || exit 1
case "$active" in 1|2) ;; *) exit 1;; esac
slot=$journal/slot-$active
private_dir "$slot" && private_file "$slot/context" && private_file "$slot/manifest" || exit 1
[ "$(stat -c %s "$slot/context")" -le 8388608 ] && [ "$(stat -c %s "$slot/manifest")" -le 512 ] || exit 1
exec 8<"$slot/manifest" || exit 1
IFS= read -r format <&8 && IFS= read -r slug <&8 && IFS= read -r stored_identity <&8 && IFS= read -r original_boot <&8 &&
    IFS= read -r stored_revision <&8 && IFS= read -r stored_account <&8 && IFS= read -r stored_job <&8 &&
    IFS= read -r generation_hash <&8 && IFS= read -r context_hash <&8 && IFS= read -r checksum <&8 || exit 1
if IFS= read -r extra <&8; then exit 1; fi
exec 8<&-
[ "$format:$slug:$stored_identity" = "HGCFJOURNAL1:homegate:$identity_hash" ] || exit 1
case "$stored_account" in ''|*[!a-zA-Z0-9_-]*) exit 1;; esac
[ "${#stored_account}" -le 64 ] || exit 1
case "$stored_revision:$stored_job" in *[!0-9:]*) exit 1;; esac
[ "${#stored_revision}" -le 2 ] && [ "$stored_revision" -ge 1 ] && [ "$stored_revision" -le 32 ] || exit 1
case "$stored_job" in ''|0*|*[!0-9]*) exit 1;; esac
[ "${#stored_job}" -le 9 ] && [ "$stored_job" -ge 2 ] && [ "${#original_boot}" -eq 36 ] || exit 1
case "$original_boot" in *[!0-9a-f-]*) exit 1;; esac
if [ "$action" = archive-check ]; then account=$stored_account;revision=$stored_revision;job=$stored_job
elif [ "$action" = retire-check ]; then
    [ "$account:$job" = "$stored_account:$stored_job" ] || exit 1
    revision=$stored_revision
else [ "$account:$revision:$job" = "$stored_account:$stored_revision:$stored_job" ] || exit 1; fi
private_file "$store/gen-$revision/manifest" || exit 1
hash "$store/gen-$revision/manifest" && [ "$sum" = "$generation_hash" ] || exit 1
hash "$slot/context" && [ "$sum" = "$context_hash" ] || exit 1
frame=$(printf '%s\n' HGCFJOURNAL1 homegate "$identity_hash" "$original_boot" "$revision" "$account" "$job" "$generation_hash" "$context_hash") || exit 1
digest=$(printf '%s\n' "$frame" | sha256sum) || exit 1
expected=$(printf '%s\n' "$frame" "${digest%% *}") || exit 1
[ "$(stat -c %s "$slot/manifest")" -eq "$((${#expected} + 1))" ] && [ "$(cat "$slot/manifest")" = "$expected" ] || exit 1
hash "$slot/manifest" || exit 1;checkpoint_hash=$sum
slot_extra_check() (
    private_dir "$1" && private_file "$1/context" && private_file "$1/manifest" || exit 1
    [ "$(stat -c %s "$1/context")" -le 8388608 ] && [ "$(stat -c %s "$1/manifest")" -le 512 ] || exit 1
    for item in "$1/"* "$1/".[!.]* "$1/"..?*; do
        [ ! -e "$item" ] && [ ! -L "$item" ] && continue
        case "$item" in "$1/context"|"$1/manifest") ;; *) exit 1;; esac
    done
    hash "$1/context" || exit 1
    frame=$(printf '%s\n' HGCFJOURNAL1 homegate "$identity_hash" "$original_boot" "$revision" "$account" "$job" "$generation_hash" "$sum") || exit 1
    digest=$(printf '%s\n' "$frame" | sha256sum) || exit 1
    expected=$(printf '%s\n' "$frame" "${digest%% *}") || exit 1
    [ "$(stat -c %s "$1/manifest")" -eq "$((${#expected} + 1))" ] && [ "$(cat "$1/manifest")" = "$expected" ]
)
for other in "$journal/slot-1" "$journal/slot-2"; do
    [ ! -e "$other" ] && [ ! -L "$other" ] && continue
    slot_extra_check "$other" || exit 1
done
terminal_meta() {
    frame=$(printf '%s\n' HGCFTerminal1 homegate "$identity_hash" "$original_boot" "$revision" "$account" "$job" "$generation_hash" "$checkpoint_hash" "$terminal_hash") || return 1
    digest=$(printf '%s\n' "$frame" | sha256sum) || return 1
    printf '%s\n' "$frame" "${digest%% *}"
}
terminal_check() {
    terminal_file=${1:-$journal/terminal};meta_file=${2:-$journal/terminal-meta}
    private_file "$terminal_file" && private_file "$meta_file" || return 1
    [ "$(stat -c %s "$terminal_file")" -le 4096 ] && [ "$(stat -c %s "$meta_file")" -le 1024 ] || return 1
    hash "$terminal_file" || return 1;terminal_hash=$sum
    expected=$(terminal_meta) || return 1
    [ "$(stat -c %s "$meta_file")" -eq "$((${#expected} + 1))" ] && [ "$(cat "$meta_file")" = "$expected" ] || return 1
    ready=$(lua "$dir/cloudflare-records.lua" receipt-terminal "$account" "$revision" 8<"$slot/context" < "$terminal_file" 3>&- 4>&- 5>&- 9>&- 2>/dev/null) || return 1
    [ "$ready" = HGCFTVALID1 ] || return 1
    hash "$meta_file" || return 1;terminal_binding=$sum
}
ledger_body() {
    frame=$(printf '%s\n' HGCFCollection1 homegate "$identity_hash" "$terminal_binding" "$1") || return 1
    digest=$(printf '%s\n' "$frame" | sha256sum) || return 1
    printf '%s\n' "$frame" "${digest%% *}"
}
ledger_check() {
    private_file "$ledger" && [ "$(stat -c %s "$ledger")" -le 512 ] || return 1
    expected=$(ledger_body "$1") || return 1
    [ "$(stat -c %s "$ledger")" -eq "$((${#expected} + 1))" ] && [ "$(cat "$ledger")" = "$expected" ]
}
ledger_write() {
    next=$store/.dns-collection-next
    (set -C; : > "$next") 2>/dev/null || return 1
    private_file "$next" || return 1
    ledger_body "$1" > "$next" || return 1
    fsync "$next" 2>/dev/null && mv -f "$next" "$ledger" 2>/dev/null && fsync "$store" 2>/dev/null
}
case "$action" in
    repair-terminal)
        # Only continue an existing bound success pair. Never create evidence
        # from a current provider observation or the volatile work directory.
        terminal_candidate=$journal/terminal;meta_candidate=$journal/terminal-meta
        if [ -e "$journal/.terminal" ] || [ -L "$journal/.terminal" ]; then
            [ ! -e "$terminal_candidate" ] && [ ! -L "$terminal_candidate" ] || exit 1
            terminal_candidate=$journal/.terminal
        fi
        if [ -e "$journal/.terminal-meta" ] || [ -L "$journal/.terminal-meta" ]; then
            [ ! -e "$meta_candidate" ] && [ ! -L "$meta_candidate" ] || exit 1
            meta_candidate=$journal/.terminal-meta
        fi
        terminal_check "$terminal_candidate" "$meta_candidate" || exit 1
        fsync "$terminal_candidate" "$meta_candidate" "$journal" "$store" 2>/dev/null || exit 1
        if [ "$terminal_candidate" != "$journal/terminal" ]; then
            mv "$terminal_candidate" "$journal/terminal" || exit 1
        fi
        if [ "$meta_candidate" != "$journal/terminal-meta" ]; then
            mv "$meta_candidate" "$journal/terminal-meta" || exit 1
        fi
        terminal_check && fsync "$journal/terminal" "$journal/terminal-meta" "$journal" "$store" 2>/dev/null || exit 1;;
    retire-check)
        [ ! -e "$store/.dns-collection-next" ] && [ ! -L "$store/.dns-collection-next" ] || exit 1
        terminal_check && ledger_check settled || exit 1
        fsync "$ledger" "$journal" "$store" 2>/dev/null || exit 1;;
    load)
        # Original boot may differ. Only current private credentials will be used
        # by the later supervised GET; no mutation/collection follows an observation.
        [ -f /proc/self/fd/5 ] && [ "$(stat -Lc '%u:%a:%h' /proc/self/fd/5)" = "$owner:600:1" ] || exit 1
        cat "$slot/context" >&5 || exit 1;;
    settle)
        [ "$journal" != "$archive" ] || exit 1
        [ "$(cat /proc/sys/kernel/random/boot_id)" = "$original_boot" ] || exit 1
        work=/var/run/homegate/.dns-check-$job
        private_dir "$work" && private_file "$work/zones" || exit 1
        [ "$(stat -c %s "$work/zones")" -le 4096 ] || exit 1
        ready=$(lua "$dir/cloudflare-records.lua" receipt-terminal "$account" "$revision" 8<"$slot/context" < "$work/zones" 3>&- 4>&- 5>&- 9>&- 2>/dev/null) || exit 1
        [ "$ready" = HGCFTVALID1 ] || exit 1
        if [ -e "$journal/terminal" ] || [ -L "$journal/terminal" ] || [ -e "$journal/terminal-meta" ] || [ -L "$journal/terminal-meta" ]; then terminal_check || exit 1;exit 0;fi
        temp=$journal/.terminal;binding=$journal/.terminal-meta
        (set -C; : > "$temp" && : > "$binding") 2>/dev/null || exit 1
        private_file "$temp" && private_file "$binding" || exit 1
        cat "$work/zones" > "$temp" || exit 1
        hash "$temp" || exit 1;terminal_hash=$sum
        terminal_meta > "$binding" || exit 1
        fsync "$temp" "$binding" 2>/dev/null || exit 1
        mv "$temp" "$journal/terminal" && mv "$binding" "$journal/terminal-meta" || exit 1
        fsync "$journal" "$store" 2>/dev/null || exit 1;;
    archive-check)
        [ ! -e "$store/dns-operation" ] && [ ! -L "$store/dns-operation" ] || exit 1
        [ ! -e "$store/.dns-collection-next" ] && [ ! -L "$store/.dns-collection-next" ] || exit 1
        terminal_check && ledger_check settled || exit 1
        # Re-sync an uncertain settled rename before opening the next writer.
        fsync "$ledger" "$journal" "$store" 2>/dev/null || exit 1;;
    collect)
        [ ! -e "$store/.dns-collection-next" ] && [ ! -L "$store/.dns-collection-next" ] || exit 1
        terminal_check || exit 1
        if [ "$journal" != "$archive" ]; then
            [ ! -e "$archive" ] && [ ! -L "$archive" ] || exit 1
            fsync "$journal/terminal" "$journal/terminal-meta" "$journal" "$store" 2>/dev/null || exit 1
            if [ -e "$ledger" ] || [ -L "$ledger" ]; then ledger_check collecting || exit 1;fsync "$ledger" "$store" 2>/dev/null || exit 1
            else ledger_write collecting || exit 1;fi
            mv "$journal" "$archive" || exit 1
            journal=$archive
            fsync "$store" 2>/dev/null || exit 1
        else
            if ledger_check settled; then fsync "$ledger" "$archive" "$store" 2>/dev/null || exit 1;exit 0;fi
            ledger_check collecting || exit 1
        fi
        ledger_write settled || exit 1;;
esac
exit 0
