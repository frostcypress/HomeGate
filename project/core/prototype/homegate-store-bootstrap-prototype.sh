#!/bin/sh
# Fixed lifecycle-owned empty baseline experiment. NOT a production installer.
# Legacy UCI/secrets/services are untouched; complete migration remains gated.
set -u
umask 077
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH HOMEGATE_CONFIG_PROTO_STORE
bootstrap_enabled=false
parent=/etc/homegate
store=/etc/homegate/transactions
stage=/etc/homegate/.transactions-bootstrap
engine=/usr/libexec/homegate/config-transaction
codec=$(dirname "$0")/config-codec.lua
fail() {
    printf '{"api_version":1,"prototype":true,"ok":false,"phase":"store-bootstrap","error":"%s"}\n' "$1"
    exit "${2:-7}"
}
private_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "$owner:700" ]; }
private_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1" 2>/dev/null)" = "$owner:600:1" ]; }
present() { [ -e "$1" ] || [ -L "$1" ]; }
read_bounded() {
    private_file "$1" && [ "$(stat -c %s "$1")" -le "$2" ] || fail 'Unsafe bootstrap metadata'
    text=$(cat "$1") || fail 'Unable to read bootstrap metadata'
    [ "$(stat -c %s "$1")" -eq "$((${#text} + 1))" ] || fail 'Invalid bootstrap framing'
    # ash may discard NUL bytes. Compare exact raw bytes with the framed text,
    # so replacing the final LF by NUL cannot impersonate canonical metadata.
    raw_sum=$(sha256sum "$1") || fail 'Unable to hash bootstrap metadata'
    raw_sum=${raw_sum%% *}
    framed_sum=$(printf '%s\n' "$text" | sha256sum) || fail 'Unable to hash bootstrap framing'
    framed_sum=${framed_sum%% *}
    [ "$raw_sum" = "$framed_sum" ] || fail 'Noncanonical bootstrap bytes'
}
checksum() {
    sum=$(printf '%s\n' "$1" | sha256sum) || fail 'Unable to hash bootstrap metadata'
    sum=${sum%% *}
}
defaults() {
    printf '%s\n' '# homegate-backup-format: 2' '# plugin: homegate' '# schema: public-uci-v1' '# secrets: omitted' "config homegate 'main'" |
        lua "$codec" normalize 2>/dev/null
}
check_identity() {
    read_bounded "$1/identity" 512
    body=$text
    exec 8<"$1/identity" || fail 'Unable to read store identity'
    IFS= read -r format <&8 && IFS= read -r slug <&8 && IFS= read -r schema <&8 &&
        IFS= read -r path <&8 && IFS= read -r store_id <&8 && IFS= read -r digest <&8 || fail 'Incomplete store identity'
    if IFS= read -r extra <&8; then fail 'Unexpected store identity data'; fi
    exec 8<&-
    [ "$format:$slug:$schema:$path" = "HGSTORE1:homegate:public-uci-v1:$store" ] || fail 'Store identity mismatch'
    [ "${#store_id}" -eq 32 ] || fail 'Invalid store identity'
    case "$store_id" in *[!0-9a-f]*) fail 'Invalid store identity';; esac
    payload=$(printf '%s\n' HGSTORE1 homegate public-uci-v1 "$store" "$store_id")
    checksum "$payload"
    [ "$body" = "$(printf '%s\n' "$payload" "$sum")" ] || fail 'Invalid store identity checksum'
    read_bounded "$1/bootstrap-receipt" 512
    payload=$(printf '%s\n' HGBOOTSTRAP1 "$store" "$store_id")
    checksum "$payload"
    [ "$text" = "$(printf '%s\n' "$payload" "$sum")" ] || fail 'Invalid bootstrap receipt'
    private_file "$1/.lock" && private_file "$1/.supervisor.lock" || fail 'Unsafe bootstrap locks'
    [ "$(stat -c %s "$1/.lock")" -eq 0 ] && [ "$(stat -c %s "$1/.supervisor.lock")" -eq 0 ] || fail 'Invalid bootstrap locks'
}
check_stage() {
    private_dir "$stage" && private_dir "$stage/gen-1" && private_dir "$stage/gen-1/credentials" || fail 'Unsafe bootstrap stage'
    # Include hidden entries. Never follow a supplied checksum manifest or path.
    for item in "$stage/"* "$stage/".[!.]* "$stage/"..?*; do
        present "$item" || continue
        case "${item##*/}" in identity|bootstrap-receipt|.lock|.supervisor.lock|current|gen-1) ;; *) fail 'Unexpected bootstrap stage entry';; esac
    done
    for item in "$stage/gen-1/"* "$stage/gen-1/".[!.]* "$stage/gen-1/"..?*; do
        present "$item" || continue
        case "${item##*/}" in public.conf|parent|manifest|credentials) ;; *) fail 'Unexpected bootstrap generation entry';; esac
    done
    for item in "$stage/gen-1/credentials/"* "$stage/gen-1/credentials/".[!.]* "$stage/gen-1/credentials/"..?*; do
        present "$item" && fail 'Bootstrap credentials must be empty'
    done
    check_identity "$stage"
    read_bounded "$stage/current" 3; [ "$text" = 1 ] || fail 'Invalid bootstrap current pointer'
    read_bounded "$stage/gen-1/parent" 3; [ "$text" = 0 ] || fail 'Invalid bootstrap ancestry'
    read_bounded "$stage/gen-1/public.conf" 262144
    canonical=$(defaults) || fail 'Unable to check bootstrap defaults'
    [ "$text" = "$canonical" ] || fail 'Bootstrap defaults mismatch'
    read_bounded "$stage/gen-1/manifest" 512
    expected=$(cd "$stage/gen-1" && sha256sum public.conf parent) || fail 'Unable to check bootstrap generation'
    [ "$text" = "$expected" ] || fail 'Bootstrap integrity mismatch'
}
sync_stage() {
    fsync "$stage/identity" "$stage/bootstrap-receipt" "$stage/.lock" "$stage/.supervisor.lock" "$stage/current" \
        "$stage/gen-1/public.conf" "$stage/gen-1/parent" "$stage/gen-1/manifest" 2>/dev/null || fail 'Unable to synchronize bootstrap files'
    fsync "$stage/gen-1/credentials" "$stage/gen-1" "$stage" "$parent" 2>/dev/null || fail 'Unable to synchronize bootstrap directories'
}
existing_store() {
    private_dir "$store" || fail 'Unsafe existing store'
    check_identity "$store"
    # Keep FD6 across the checker. Active recovery is never cleared by bootstrap.
    "$engine" --persistent writer-check >/dev/null 2>&1
    result=$?
    case "$result" in 0) ;; 4) fail 'Existing store recovery or writer is busy' 4;; *) fail 'Existing store requires reconciliation';; esac
    fsync "$store/identity" "$store/bootstrap-receipt" "$store" "$parent" 2>/dev/null || fail 'Existing store durability is uncertain'
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"store-bootstrap","created":false,"baseline_ready":true,"legacy_migrated":false,"production_ready":false}\n'
}
[ "$#" -eq 1 ] || fail 'Only a fixed bootstrap command is allowed' 2
case "$1" in bootstrap|resume) action=$1;; *) fail 'Unsupported bootstrap command' 2;; esac
[ "$bootstrap_enabled" = true ] || fail 'Lifecycle bootstrap is not ready' 2
owner=$(id -u) || fail 'Unable to identify bootstrap owner'
[ "$owner" = 0 ] || fail 'Bootstrap requires root'
[ -d /etc ] && [ ! -L /etc ] || fail 'Unsafe persistent parent'
case "$(stat -c '%u:%a' /etc 2>/dev/null)" in "$owner:755"|"$owner:700") ;; *) fail 'Unsafe persistent parent';; esac
private_dir /var/run/homegate && private_file /var/run/homegate/frontend.lock || fail 'Lifecycle must establish the shared writer lock'
if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/6 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' /var/run/homegate/frontend.lock)" ]; then
    exec 6>>/var/run/homegate/frontend.lock || fail 'Unable to open shared writer lock'
fi
flock -n 6 || fail 'Shared writer is busy' 4
if ! present "$parent"; then
    [ "$action" = bootstrap ] || fail 'No bootstrap stage to resume'
    mkdir "$parent" 2>/dev/null || fail 'Unable to create private parent'
    fsync "$parent" /etc 2>/dev/null || fail 'Private parent durability is uncertain'
fi
private_dir "$parent" || fail 'Unsafe private parent'
fsync "$parent" /etc 2>/dev/null || fail 'Private parent durability is uncertain'
if present "$store"; then
    ! present "$stage" || fail 'Conflicting bootstrap stage and store'
    existing_store
    exit 0
fi
if present "$stage"; then
    [ "$action" = resume ] || fail 'Interrupted bootstrap requires explicit resume'
    check_stage
else
    [ "$action" = bootstrap ] || fail 'No bootstrap stage to resume'
    mkdir "$stage" 2>/dev/null || fail 'Unable to allocate bootstrap stage'
    fsync "$stage" "$parent" 2>/dev/null || fail 'Bootstrap stage durability is uncertain'
    mkdir "$stage/gen-1" "$stage/gen-1/credentials" || fail 'Unable to allocate bootstrap generation'
    defaults > "$stage/gen-1/public.conf" || fail 'Unable to create disabled bootstrap defaults'
    printf '%s\n' 0 > "$stage/gen-1/parent" || fail 'Unable to create bootstrap ancestry'
    (cd "$stage/gen-1" && sha256sum public.conf parent) > "$stage/gen-1/manifest" || fail 'Unable to seal bootstrap generation'
    printf '%s\n' 1 > "$stage/current" || fail 'Unable to create bootstrap pointer'
    (set -C; : > "$stage/.lock" && : > "$stage/.supervisor.lock") 2>/dev/null || fail 'Unable to create bootstrap locks'
    head -c 16 /dev/urandom > "$stage/.random" || fail 'Unable to obtain store randomness'
    private_file "$stage/.random" && [ "$(stat -c %s "$stage/.random")" -eq 16 ] || fail 'Insufficient store randomness'
    random_digest=$(sha256sum "$stage/.random") || fail 'Unable to hash store randomness'
    store_id=$(printf '%.32s' "${random_digest%% *}")
    rm -f "$stage/.random" || fail 'Unable to remove bootstrap random scratch'
    payload=$(printf '%s\n' HGSTORE1 homegate public-uci-v1 "$store" "$store_id")
    checksum "$payload"
    printf '%s\n' "$payload" "$sum" > "$stage/identity" || fail 'Unable to write store identity'
    payload=$(printf '%s\n' HGBOOTSTRAP1 "$store" "$store_id")
    checksum "$payload"
    printf '%s\n' "$payload" "$sum" > "$stage/bootstrap-receipt" || fail 'Unable to write bootstrap receipt'
    check_stage
fi
sync_stage
! present "$store" || fail 'Store appeared during bootstrap'
mv "$stage" "$store" 2>/dev/null || fail 'Unable to publish bootstrap directory'
# No cleanup on failure or signal: retain incomplete stage or published store.
fsync "$store" "$parent" 2>/dev/null || fail 'Published bootstrap durability is uncertain' 6
"$engine" --persistent writer-check >/dev/null 2>&1 || fail 'Published bootstrap validation failed'
printf '{"api_version":1,"prototype":true,"ok":true,"phase":"store-bootstrap","created":true,"baseline_ready":true,"legacy_migrated":false,"production_ready":false}\n'
