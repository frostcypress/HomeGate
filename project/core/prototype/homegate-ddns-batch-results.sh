#!/bin/sh
# Explicit current-batch receipt closeout and bounded durable original results.
set -u
umask 077
export LC_ALL=C
ddns_batch_closeout_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-batch-results","effect":"none","write_ready":false,"error":"Batch results are unavailable"}\n';exit "${1:-7}"; }
action=${1:-}
case "$action" in
    check-writer|check-recovery|status) [ "$#" -eq 1 ] || fail 2;;
    recover|forget) [ "$ddns_batch_closeout_enabled" = true ] && [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;;
    capture-close) [ "$ddns_batch_closeout_enabled" = true ] && [ "$#" -eq 3 ] || fail 2;rule=$2;parent=$3;;
    *) fail 2;;
esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
owner=$(id -u) || fail;[ "$owner" = 0 ] || fail
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ]; }
store=/etc/homegate/transactions;run=/var/run/homegate
file=$store/dns-batch-results;next=$store/.dns-batch-results-next
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
private_dir "$store" && private_dir "$run" && private_file "$store/identity" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
for fd in 6 7; do
    lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
    if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ]; then
        case "$fd" in 6) exec 6>>"$lock" || fail;; 7) exec 7>>"$lock" || fail;; esac
    fi
    flock -n "$fd" || fail 4
done
hash "$store/identity" || fail;identity=$sum
framed() { digest=$(printf '%s\n' "$payload" | sha256sum) || return 1;printf '%s\n' "$payload" "${digest%% *}"; }
checked() {
    private_file "$1" && [ "$(stat -c %s "$1")" -le 524288 ] || return 1
    exec 3<"$1" || return 1
    IFS= read -r payload <&3 && IFS= read -r digest <&3 || return 1
    if IFS= read -r extra <&3; then return 1;fi
    exec 3<&-
    expected=$(framed) || return 1
    [ "$(stat -c %s "$1")" -eq "$((${#expected}+1))" ] && [ "$(cat "$1")" = "$expected" ]
}
open_records() {
    previous=none
    if exists "$file"; then checked "$file" && hash "$file" || return 1;previous=$sum;fi
    if exists "$next"; then checked "$next" || return 1;fi
    if exists "$file"; then exec 3<"$file" || return 1;else exec 3</dev/null;fi
    if exists "$next"; then exec 4<"$next" || return 1;else exec 4</dev/null;fi
}
guard() { open_records && lua "$dir/homegate-ddns-batch-results.lua" guard "$previous" "$identity" "$1" 5>&- 8>&- 9>&- >/dev/null 2>/dev/null; }
if [ "$action" = check-writer ] || [ "$action" = check-recovery ]; then
    mode=writer;[ "$action" != check-recovery ] || mode=recovery
    guard "$mode" || fail 4
    if exists "$file"; then fsync "$file" "$store" 2>/dev/null || fail;fi
    if exists "$next"; then fsync "$next" "$store" 2>/dev/null || fail;fi
    exit 0
fi
publish() {
    desired=$(framed) || return 1
    if exists "$next"; then checked "$next" && [ "$(cat "$next")" = "$desired" ] || return 1
    else (set -C; : > "$next") 2>/dev/null && printf '%s\n' "$desired" > "$next" || return 1;fi
    guard recovery || return 1
    fsync "$next" "$store" 2>/dev/null && mv -f "$next" "$file" && fsync "$file" "$store" 2>/dev/null
}
if [ "$action" = status ]; then
    guard recovery || fail;exec 3<"$file" || fail
    lua "$dir/homegate-ddns-batch-results.lua" status 4>&- 5>&- 8>&- 9>&- 2>/dev/null || fail;exit 0
fi
if [ "$action" = forget ]; then
    guard writer && ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || fail 4
    rm -f "$file" && fsync "$store" 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-batch-results","forgotten":true,"effect":"none","write_ready":false}\n';exit 0
fi
fingerprint() {
    private_dir "$tree" && private_file "$tree/current" && [ "$(stat -c %s "$tree/current")" -eq 2 ] && private_file "$tree/terminal" && private_file "$tree/terminal-meta" || return 1
    [ "$(stat -c %s "$tree/terminal")" -le 4096 ] && [ "$(stat -c %s "$tree/terminal-meta")" -le 1024 ] || return 1
    hash "$tree/current" || return 1;h_current=$sum;h_c1=-;h_m1=-;h_c2=-;h_m2=-
    for n in 1 2; do
        if exists "$tree/slot-$n"; then
            private_dir "$tree/slot-$n" && private_file "$tree/slot-$n/context" && private_file "$tree/slot-$n/manifest" || return 1
            [ "$(stat -c %s "$tree/slot-$n/context")" -le 8388608 ] && [ "$(stat -c %s "$tree/slot-$n/manifest")" -le 512 ] || return 1
            hash "$tree/slot-$n/context" || return 1;hc=$sum;hash "$tree/slot-$n/manifest" || return 1
            if [ "$n" = 1 ]; then h_c1=$hc;h_m1=$sum;else h_c2=$hc;h_m2=$sum;fi
        fi
    done
    hash "$tree/terminal" || return 1;h_terminal=$sum;hash "$tree/terminal-meta" || return 1
    fingerprints=$h_current:$h_c1:$h_m1:$h_c2:$h_m2:$h_terminal:$sum
}
if [ "$action" = capture-close ]; then
    case "$parent" in ''|0*|*[!0-9]*) fail 2;; esac
    [ "${#parent}" -le 9 ] && [ "$parent" -ge 2 ] && [ -f /proc/self/fd/5 ] && [ "$(stat -Lc '%u:%a:%h' /proc/self/fd/5)" = "$owner:600:0" ] && [ "$(stat -Lc %s /proc/self/fd/5)" -le 524288 ] || fail
    [ "$(stat -Lc '%d:%i' /proc/self/fd/5)" = "$(stat -Lc '%d:%i' /proc/$parent/fd/5 2>/dev/null)" ] || fail
    batch=$(lua "$dir/homegate-ddns-batch.lua" parent closeout "$$" "$rule" "$parent" 2>/dev/null) || fail
    ! exists "$next" || fail 4
    tree=$store/dns-operation;fingerprint || fail;wanted=$fingerprints
    active=$(cat "$tree/current") || fail;case "$active" in 1|2) ;; *) fail;; esac
    revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null) || fail
    hash "$store/gen-$revision/manifest" || fail;generation=$sum;hash "$store/ddns-authority" || fail;grant=$sum;boot=$(cat /proc/sys/kernel/random/boot_id) || fail
    previous=none
    if exists "$file"; then guard writer || fail;hash "$file" || fail;previous=$sum;fi
    if exists "$file"; then exec 9<"$file" || fail;else exec 9</dev/null;fi
    payload=$(ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-batch-results.lua" capture "$rule" "$identity" "$generation" "$grant" "$boot" "$batch" "$previous" "$fingerprints" 3<"$tree/slot-$active/context" 4<"$tree/terminal" 2>/dev/null) || fail
    # No original evidence is deleted here. The existing collector validates
    # the complete terminal/checkpoint before its durable archive rename.
    info=$(printf '%s\n' "$payload" | lua "$dir/homegate-ddns-batch-results.lua" candidate-info 2>/dev/null) || fail
    old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs;[ "$#" -eq 5 ] || fail;provider=$1;account=$2;job=$3
    ash "$dir/homegate-cloudflare-read.sh" --runtime-collect-receipt-internal "$provider" "$account" "$job" --confirm 3>&- 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null || fail
    tree=$store/dns-settled;fingerprint && [ "$fingerprints" = "$wanted" ] || fail
    # fingerprint/guard use globals: retain the intended canonical candidate.
    candidate=$payload;payload=$candidate;publish || fail
else
    guard recovery || fail
    if exists "$next"; then
        open_records || fail;payload=$(lua "$dir/homegate-ddns-batch-results.lua" stage "$previous" "$identity" 5>&- 8>&- 9>&- 2>/dev/null) || fail
        publish || fail
    fi
fi
guard recovery || fail;exec 3<"$file" || fail
info=$(lua "$dir/homegate-ddns-batch-results.lua" info 4>&- 5>&- 8>&- 9>&- 2>/dev/null) || fail
old_ifs=$IFS;IFS=:;set -- $info;IFS=$old_ifs;[ "$#" -eq 5 ] || fail;provider=$1;account=$2;job=$3;revision=$4;state=$5
if [ "$state" != closed ]; then
    exec 3<"$file" || fail;wanted=$(lua "$dir/homegate-ddns-batch-results.lua" hashes 4>&- 5>&- 8>&- 9>&- 2>/dev/null) || fail
    if exists "$store/dns-operation"; then tree=$store/dns-operation;fingerprint && [ "$fingerprints" = "$wanted" ] || fail
        ash "$dir/homegate-cloudflare-read.sh" --runtime-collect-receipt-internal "$provider" "$account" "$job" --confirm 3>&- 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null || fail
    fi
    if exists "$store/dns-settled"; then tree=$store/dns-settled;fingerprint && [ "$fingerprints" = "$wanted" ] || fail;fi
    # Validate a partial/completed retirement against this row before resuming.
    for proof in "$store/dns-retirement" "$store/.dns-retirement-next"; do
        if exists "$proof"; then private_file "$proof" && [ "$(stat -c %s "$proof")" -le 2048 ] || fail
            exec 3<"$file" 4<"$proof" || fail;lua "$dir/homegate-ddns-batch-results.lua" retired none 5>&- 8>&- 9>&- >/dev/null 2>/dev/null || fail
        fi
    done
    ash "$dir/homegate-cloudflare-read.sh" --runtime-retire-archive-internal "$provider" "$account" "$job" --confirm 3>&- 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null || fail
    ash "$dir/homegate-dns-retention.sh" check 3>&- 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null || fail
    private_file "$store/dns-retired" && [ "$(stat -c %s "$store/dns-retired")" -le 2048 ] || fail
    hash "$file" || fail;previous=$sum;exec 3<"$file" 4<"$store/dns-retired" || fail
    payload=$(lua "$dir/homegate-ddns-batch-results.lua" closed "$previous" 5>&- 8>&- 9>&- 2>/dev/null) || fail
    publish || fail
fi
guard writer || fail
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-batch-results","closed":true,"effect":"none","write_ready":false}\n'
