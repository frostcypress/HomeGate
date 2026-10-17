#!/bin/sh
# Explicit DDNS authority for a published ordinary generation. Never starts services.
set -u
umask 077
export LC_ALL=C
ddns_authority_enabled=false
fail() { printf '{"api_version":1,"prototype":true,"ok":false,"phase":"ddns-authority","effect":"none","error":"DDNS authority is unavailable"}\n';exit "${1:-7}"; }
[ "$ddns_authority_enabled" = true ] || fail 2
action=${1:-}
case "$action" in preview) [ "$#" -eq 2 ] || fail 2;selected=$2;; commit) [ "$#" -eq 2 ] && [ "${#2}" -eq 32 ] || fail 2;case "$2" in *[!0-9a-f]*) fail 2;; esac;confirmation=$2;; revoke|cancel) [ "$#" -eq 2 ] && [ "$2" = --confirm ] || fail 2;; check-rule) [ "$#" -eq 2 ] || fail 2;selected=$2;action=check;; check|snapshot) [ "$#" -eq 1 ] || fail 2;; *) fail 2;; esac
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
owner=$(id -u) || fail
[ "$owner" = 0 ] || fail
exists() { [ -e "$1" ] || [ -L "$1" ]; }
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ]; }
hex() { [ "${#1}" -eq "$2" ] || return 1;case "$1" in *[!0-9a-f]*) return 1;; esac; }
hash() { sum=$(sha256sum "$1" 2>/dev/null) || return 1;sum=${sum%% *};hex "$sum" 64; }
id() { [ -n "$1" ] && [ "${#1}" -le 64 ] || return 1;case "$1" in *[!a-zA-Z0-9_-]*) return 1;; esac; }
store=/etc/homegate/transactions;run=/var/run/homegate
active=$store/ddns-authority;pending=$store/ddns-authority-pending;next=$store/.ddns-authority-next;preview_next=$store/.ddns-authority-preview
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || fail
private_dir "$store" && private_dir "$run" && private_file "$run/frontend.lock" && private_file "$store/.supervisor.lock" || fail
for fd in 6 7; do
    lock=$run/frontend.lock;[ "$fd" != 7 ] || lock=$store/.supervisor.lock
    if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$fd 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' "$lock")" ]; then
        case "$fd" in 6) exec 6>>"$lock" || fail;; 7) exec 7>>"$lock" || fail;; esac
    fi
    flock -n "$fd" || fail 4
done
ash "$dir/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null || fail 4
body() { printf '%s\n' HGDDNSAUTH1 "$state" "$identity" "$revision" "$generation" "$source_hash" "$rule" "$nonce" "$boot" "$created" "$previous"; }
framed() { frame=$(body) || return 1;digest=$(printf '%s\n' "$frame" | sha256sum) || return 1;printf '%s\n' "$frame" "${digest%% *}"; }
read_record() {
    private_file "$1" && [ "$(stat -c %s "$1")" -le 1024 ] || return 1
    exec 8<"$1" || return 1
    IFS= read -r format <&8 && IFS= read -r state <&8 && IFS= read -r identity <&8 && IFS= read -r revision <&8 &&
        IFS= read -r generation <&8 && IFS= read -r source_hash <&8 && IFS= read -r rule <&8 && IFS= read -r nonce <&8 &&
        IFS= read -r boot <&8 && IFS= read -r created <&8 && IFS= read -r previous <&8 && IFS= read -r checksum <&8 || return 1
    if IFS= read -r extra <&8; then return 1;fi
    exec 8<&-
    [ "$format" = HGDDNSAUTH1 ] && { [ "$state" = enabled ] || [ "$state" = disabled ]; } || return 1
    case "$revision:$created" in *[!0-9:]*) return 1;; esac
    case "$revision" in ''|0*) return 1;; esac
    case "$created" in ''|0?*) return 1;; esac
    [ "${#revision}" -le 2 ] && [ "$revision" -le 32 ] && [ "${#created}" -le 9 ] && id "$rule" && hex "$nonce" 32 || return 1
    for value in "$identity" "$generation" "$source_hash"; do hex "$value" 64 || return 1;done
    [ "$previous" = none ] || hex "$previous" 64 || return 1
    [ "${#boot}" -eq 36 ] || return 1;case "$boot" in *[!0-9a-f-]*) return 1;; esac
    expected=$(framed) || return 1
    [ "$(stat -c %s "$1")" -eq "$((${#expected}+1))" ] && [ "$(cat "$1")" = "$expected" ]
}
current() {
    current_revision=$(lua "$dir/cloudflare-codec.lua" context < "$store/current" 2>/dev/null) || return 1
    hash "$store/identity" || return 1;current_identity=$sum
    hash "$store/gen-$current_revision/manifest" || return 1;current_generation=$sum
    hash "$store/gen-$current_revision/public.conf" || return 1;current_source=$sum
}
same_current() { [ "$identity:$revision:$generation:$source_hash" = "$current_identity:$current_revision:$current_generation:$current_source" ]; }
scope() {
    provider=$(ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-snapshot-read 3>&1 4>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-authority.lua" scope "$revision" "$rule" 3>&- 4>&- 8>&- 9>&- 2>/dev/null) || return 1
    case "$provider" in cloudflare|aliyun|dnspod|huaweicloud) ;; *) return 1;; esac
}
active_hash() { previous_seen=none;if exists "$active"; then private_file "$active" && [ "$(stat -c %s "$active")" -le 1024 ] && hash "$active" || return 1;previous_seen=$sum;fi; }
discard_inert() { if exists "$1"; then private_file "$1" && [ "$(stat -c %s "$1")" -le 1024 ] && rm -f "$1" || return 1;fi; }
publish_active() {
    desired=$(framed) || return 1
    if exists "$next"; then
        private_file "$next" && [ "$(stat -c %s "$next")" -eq "$((${#desired}+1))" ] && [ "$(cat "$next")" = "$desired" ] || return 1
    else (set -C; : > "$next") 2>/dev/null && printf '%s\n' "$desired" > "$next" || return 1;fi
    fsync "$next" "$store" 2>/dev/null && mv -f "$next" "$active" && fsync "$active" "$store" 2>/dev/null
}
if [ "$action" = cancel ]; then
    discard_inert "$pending" && discard_inert "$preview_next" && fsync "$store" 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-authority","cancelled":true,"effect":"none"}\n';exit 0
fi
current || fail
if [ "$action" = preview ]; then
    id "$selected" && ! exists "$next" || fail 2
    # Verify an existing record before replacing a grant's confirmation context.
    if exists "$active"; then read_record "$active" || fail;fi
    active_hash || fail;previous=$previous_seen
    rule=$selected;revision=$current_revision;identity=$current_identity;generation=$current_generation;source_hash=$current_source;state=enabled
    scope || fail
    nonce=$(lua "$dir/cloudflare-codec.lua" nonce < /proc/sys/kernel/random/uuid 2>/dev/null) || fail
    boot=$(cat /proc/sys/kernel/random/boot_id) || fail;created=$(lua "$dir/worker-process.lua" now 2>/dev/null) || fail
    discard_inert "$preview_next" || fail
    if exists "$pending"; then private_file "$pending" && [ "$(stat -c %s "$pending")" -le 1024 ] || fail;fi
    (set -C; : > "$preview_next") 2>/dev/null && framed > "$preview_next" && read_record "$preview_next" && fsync "$preview_next" "$store" 2>/dev/null && mv -f "$preview_next" "$pending" && fsync "$store" 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-authority","confirmation":"%s","configuration_revision":%s,"rule":"%s","provider":"%s","expires_in":300,"authorized":false,"service_started":false}\n' "$nonce" "$revision" "$rule" "$provider";exit 0
fi
if [ "$action" = revoke ]; then
    read_record "$active" && [ "$identity" = "$current_identity" ] || fail 5
    state=disabled
    # Explicit revocation may discard this tool's bounded unfinished grant stage.
    discard_inert "$next" || fail
    publish_active && discard_inert "$pending" && discard_inert "$preview_next" && fsync "$store" 2>/dev/null || fail
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-authority","authorized":false,"revoked":true,"service_started":false}\n';exit 0
fi
if [ "$action" = commit ]; then
    read_record "$pending" && [ "$state:$nonce" = "enabled:$confirmation" ] && same_current || fail 5
    now=$(lua "$dir/worker-process.lua" now 2>/dev/null) || fail
    [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ] && [ "$now" -ge "$created" ] && [ "$now" -le "$((created+300))" ] || fail 5
    scope || fail
    desired=$(framed) || fail
    active_hash || fail
    if [ "$previous_seen" != "$previous" ]; then
        private_file "$active" && [ "$(stat -c %s "$active")" -eq "$((${#desired}+1))" ] && [ "$(cat "$active")" = "$desired" ] || fail 5
        ! exists "$next" && fsync "$active" "$store" 2>/dev/null || fail
    else publish_active || fail;fi
    discard_inert "$pending" && discard_inert "$preview_next" && fsync "$store" 2>/dev/null || fail
else
    ! exists "$next" && read_record "$active" && [ "$state" = enabled ] && same_current && scope || fail
    fsync "$active" "$store" 2>/dev/null || fail
fi
[ -z "${selected:-}" ] || [ "$selected" = "$rule" ] || fail
if [ "$action" = snapshot ]; then
    [ -p /proc/self/fd/3 ] && [ -f /proc/self/fd/4 ] && [ "$(stat -Lc '%u:%a:%h' /proc/self/fd/4)" = "$owner:600:1" ] || fail
    ash "$dir/homegate-config-prototype.sh" --persistent runtime-ddns-snapshot-read 3>&1 4>&- 8>&- 9>&- >/dev/null 2>/dev/null |
        lua "$dir/homegate-ddns-authority.lua" snapshot "$revision" "$rule" 8>&- 9>&- 2>/dev/null || fail
fi
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"ddns-authority","configuration_revision":%s,"rule":"%s","provider":"%s","authorized":true,"service_started":false}\n' "$revision" "$rule" "$provider"
