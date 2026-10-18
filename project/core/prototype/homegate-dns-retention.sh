#!/bin/sh
# Confirmed, fixed-path archive retirement. Never remove an active DNS journal.
set -u
umask 077
export LC_ALL=C
ddns_closeout_enabled=false
dns_retention_enabled=false
aliyun_retention_enabled=false
dnspod_retention_enabled=false
huaweicloud_retention_enabled=false
provider=cloudflare
if [ "${1:-}" = --aliyun-internal ]; then
    [ "$aliyun_retention_enabled" = true ] || exit 2;provider=aliyun;shift
    [ "${1:-}" = retire ] || exit 2
elif [ "${1:-}" = --dnspod-internal ]; then
    [ "$dnspod_retention_enabled" = true ] || exit 2;provider=dnspod;shift
    [ "${1:-}" = retire ] || exit 2
elif [ "${1:-}" = --huaweicloud-internal ]; then
    [ "$huaweicloud_retention_enabled" = true ] || exit 2;provider=huaweicloud;shift
    [ "${1:-}" = retire ] || exit 2
fi
retire_format=HGCFRetire1
[ "$provider" != aliyun ] || retire_format=HGALIRetire1
[ "$provider" != dnspod ] || retire_format=HGDNPRetire1
[ "$provider" != huaweicloud ] || retire_format=HGHWRetire1
action=${1:-}
case "$action" in
    check) [ "$#" -eq 1 ] || exit 2;;
    retire)
        { [ "$provider" != cloudflare ] || [ "$dns_retention_enabled" = true ]; } && [ "$#" -eq 4 ] || exit 2
        account=$2;revision=$3;job=$4
        case "$account" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
        [ "${#account}" -le 64 ] || exit 2
        case "$revision" in ''|*[!0-9]*) exit 2;; esac
        [ "${#revision}" -le 2 ] && [ "$revision" -ge 1 ] && [ "$revision" -le 32 ] || exit 2
        case "$job" in ''|0*|*[!0-9]*) exit 2;; esac
        [ "${#job}" -le 9 ] && [ "$job" -ge 2 ] || exit 2;;
    *) exit 2;;
esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
owner=$(id -u) || exit 1
[ "$owner" = 0 ] || exit 1
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1" 2>/dev/null)" = "$owner:600:1" ]; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};[ "${#sum}" -eq 64 ]; }
hex() { [ "${#1}" -eq 64 ] || return 1;case "$1" in *[!0-9a-f]*) return 1;; esac; }
store=/etc/homegate/transactions
archive=$store/dns-settled;retiring=$store/dns-retiring;ledger=$store/dns-collection
plan=$store/dns-retirement;next=$store/.dns-retirement-next;completed=$store/dns-retired
private_dir "$store" && private_file "$store/identity" && private_file /var/run/homegate/frontend.lock && private_file "$store/.supervisor.lock" || exit 1
for fd in 6 7; do
    target=/var/run/homegate/frontend.lock;[ "$fd" != 7 ] || target=$store/.supervisor.lock
    [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" = "$(stat -c '%d:%i:%u:%a:%h' "$target")" ] || exit 1
    flock -n "$fd" || exit 1
done
hash "$store/identity" || exit 1;identity_hash=$sum
plan_body() {
    printf '%s\n' "$p_format" homegate "$identity_hash" "$p_account" "$p_job" "$ledger_hash" "$current_hash" "$c1" "$m1" "$c2" "$m2" "$terminal_hash" "$meta_hash"
}
plan_read() {
    private_file "$1" && [ "$(stat -c %s "$1")" -le 2048 ] || return 1
    exec 8<"$1" || return 1
    IFS= read -r format <&8 && IFS= read -r slug <&8 && IFS= read -r stored_identity <&8 &&
        IFS= read -r p_account <&8 && IFS= read -r p_job <&8 && IFS= read -r ledger_hash <&8 &&
        IFS= read -r current_hash <&8 && IFS= read -r c1 <&8 && IFS= read -r m1 <&8 &&
        IFS= read -r c2 <&8 && IFS= read -r m2 <&8 && IFS= read -r terminal_hash <&8 &&
        IFS= read -r meta_hash <&8 && IFS= read -r checksum <&8 || return 1
    if IFS= read -r extra <&8; then return 1;fi
    exec 8<&-
    case "$format" in HGCFRetire1|HGALIRetire1|HGDNPRetire1|HGHWRetire1) p_format=$format;; *) return 1;;esac
    [ "$slug:$stored_identity" = "homegate:$identity_hash" ] || return 1
    case "$p_account" in ''|*[!a-zA-Z0-9_-]*) return 1;; esac
    [ "${#p_account}" -le 64 ] || return 1
    case "$p_job" in ''|0*|*[!0-9]*) return 1;; esac
    [ "${#p_job}" -le 9 ] && [ "$p_job" -ge 2 ] || return 1
    for value in "$ledger_hash" "$current_hash" "$terminal_hash" "$meta_hash";do hex "$value" || return 1;done
    if [ "$c1:$m1" != -:- ]; then hex "$c1" && hex "$m1" || return 1;fi
    if [ "$c2:$m2" != -:- ]; then hex "$c2" && hex "$m2" || return 1;fi
    [ "$c1:$c2" != -:- ] || return 1
    frame=$(plan_body) || return 1
    digest=$(printf '%s\n' "$frame" | sha256sum) || return 1
    expected=$(printf '%s\n' "$frame" "${digest%% *}") || return 1
    [ "$(stat -c %s "$1")" -eq "$((${#expected} + 1))" ] && [ "$(cat "$1")" = "$expected" ]
}
# Presence fences every writer, regardless of the feature gate or apparent progress.
if [ "$action" = check ]; then
    ! exists "$plan" && ! exists "$next" && ! exists "$retiring" || exit 1
    plan_read "$completed" || exit 1
    fsync "$completed" "$store" 2>/dev/null || exit 1
    exit 0
fi
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
ash "$dir/homegate-config-prototype.sh" --persistent dns-recovery-check >/dev/null 2>/dev/null || exit 1
[ "$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null)" = "$revision" ] || exit 1
if exists "$store/gen-$revision/source.conf"; then
    [ "$ddns_closeout_enabled" = true ] || exit 2
    ready=$(ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-recovery-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-sync.lua" source "$revision" 3>&- 4>&- 5>&- 8>&- 9>&- 2>/dev/null) || exit 1
    [ "$ready" = HGDDNSSOURCE1 ] || exit 1
    for outer in /var/run/homegate/.ddns-plan-*; do ! exists "$outer" || exit 1;done
fi
! exists "$next" && ! exists "$store/.dns-collection-next" || exit 1
if exists "$completed"; then
    plan_read "$completed" || exit 1
    if ! exists "$plan" && ! exists "$retiring" && [ "$p_account:$p_job" = "$account:$job" ] && [ "$p_format" = "$retire_format" ]; then
        fsync "$completed" "$store" 2>/dev/null || exit 1;exit 0
    fi
fi
if ! exists "$plan"; then
    ! exists "$retiring" || exit 1
    # The existing validator proves the exact settled archive, terminal and ledger.
    if [ "$provider" = aliyun ]; then
        ash "$dir/homegate-dns-recovery.sh" --aliyun-internal retire-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
    elif [ "$provider" = dnspod ]; then
        ash "$dir/homegate-dns-recovery.sh" --dnspod-internal retire-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
    elif [ "$provider" = huaweicloud ]; then
        ash "$dir/homegate-dns-recovery.sh" --huaweicloud-internal retire-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
    else
    ash "$dir/homegate-dns-recovery.sh" retire-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
    fi
    p_format=$retire_format;p_account=$account;p_job=$job
    hash "$ledger" || exit 1;ledger_hash=$sum
    hash "$archive/current" || exit 1;current_hash=$sum
    hash "$archive/terminal" || exit 1;terminal_hash=$sum
    hash "$archive/terminal-meta" || exit 1;meta_hash=$sum
    c1=-;m1=-;c2=-;m2=-
    if exists "$archive/slot-1";then
        hash "$archive/slot-1/context" || exit 1;c1=$sum
        hash "$archive/slot-1/manifest" || exit 1;m1=$sum
    fi
    if exists "$archive/slot-2";then
        hash "$archive/slot-2/context" || exit 1;c2=$sum
        hash "$archive/slot-2/manifest" || exit 1;m2=$sum
    fi
    frame=$(plan_body) || exit 1
    digest=$(printf '%s\n' "$frame" | sha256sum) || exit 1
    (set -C; : > "$next") 2>/dev/null || exit 1
    private_file "$next" || exit 1
    printf '%s\n' "$frame" "${digest%% *}" > "$next" || exit 1
    fsync "$next" 2>/dev/null && mv "$next" "$plan" && fsync "$store" 2>/dev/null || exit 1
fi
plan_read "$plan" && [ "$p_account:$p_job" = "$account:$job" ] && [ "$p_format" = "$retire_format" ] || exit 1
fsync "$plan" "$store" 2>/dev/null || exit 1
if exists "$archive";then
    ! exists "$retiring" || exit 1
    if [ "$provider" = aliyun ]; then
        ash "$dir/homegate-dns-recovery.sh" --aliyun-internal retire-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
    elif [ "$provider" = dnspod ]; then
        ash "$dir/homegate-dns-recovery.sh" --dnspod-internal retire-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
    elif [ "$provider" = huaweicloud ]; then
        ash "$dir/homegate-dns-recovery.sh" --huaweicloud-internal retire-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
    else
    ash "$dir/homegate-dns-recovery.sh" retire-check "$account" "$revision" "$job" >/dev/null 2>/dev/null || exit 1
    fi
    # Verify the plan below before moving or removing any archive member.
    tree=$archive
else tree=$retiring;fi
verify_member() {
    if exists "$1";then
        [ "$2" != - ] && private_file "$1" && [ "$(stat -c %s "$1")" -le "$3" ] || return 1
        hash "$1" && [ "$sum" = "$2" ] || return 1
    fi
}
if exists "$tree";then
    private_dir "$tree" || exit 1
    for entry in "$tree/"* "$tree/".[!.]* "$tree/"..?*;do
        exists "$entry" || continue
        case "$entry" in "$tree/current"|"$tree/terminal"|"$tree/terminal-meta"|"$tree/slot-1"|"$tree/slot-2") ;; *) exit 1;; esac
    done
    verify_member "$tree/current" "$current_hash" 2 && verify_member "$tree/terminal" "$terminal_hash" 4096 && verify_member "$tree/terminal-meta" "$meta_hash" 1024 || exit 1
    for slot in 1 2;do
        if [ "$slot" = 1 ];then context_sum=$c1;manifest_sum=$m1;else context_sum=$c2;manifest_sum=$m2;fi
        if exists "$tree/slot-$slot";then
            [ "$context_sum" != - ] && private_dir "$tree/slot-$slot" || exit 1
            for entry in "$tree/slot-$slot/"* "$tree/slot-$slot/".[!.]* "$tree/slot-$slot/"..?*;do
                exists "$entry" || continue
                case "$entry" in "$tree/slot-$slot/context"|"$tree/slot-$slot/manifest") ;; *) exit 1;; esac
            done
            verify_member "$tree/slot-$slot/context" "$context_sum" 8388608 && verify_member "$tree/slot-$slot/manifest" "$manifest_sum" 512 || exit 1
        fi
    done
fi
verify_member "$ledger" "$ledger_hash" 512 || exit 1
if [ "$tree" = "$archive" ];then mv "$archive" "$retiring" || exit 1;fi
fsync "$store" 2>/dev/null || exit 1
if exists "$retiring";then
    for slot in 1 2;do
        if exists "$retiring/slot-$slot";then
            rm -f "$retiring/slot-$slot/context" "$retiring/slot-$slot/manifest" 2>/dev/null || exit 1
            fsync "$retiring/slot-$slot" 2>/dev/null && rmdir "$retiring/slot-$slot" && fsync "$retiring" 2>/dev/null || exit 1
        fi
    done
    rm -f "$retiring/current" "$retiring/terminal" "$retiring/terminal-meta" 2>/dev/null || exit 1
    fsync "$retiring" 2>/dev/null && rmdir "$retiring" && fsync "$store" 2>/dev/null || exit 1
fi
rm -f "$ledger" 2>/dev/null && fsync "$store" 2>/dev/null || exit 1
# Keep one bounded completion receipt. Never unlink the final writer fence.
fsync "$plan" 2>/dev/null && mv -f "$plan" "$completed" && fsync "$completed" "$store" 2>/dev/null || exit 1
exit 0
