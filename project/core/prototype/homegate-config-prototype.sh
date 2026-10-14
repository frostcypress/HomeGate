#!/bin/sh
# Isolated transaction experiment; NOT an installer or production UCI importer.
# Default legacy main schema; --public-uci uses the shared six-type Lua codec.
# Production publication is gated off; only test copies enable isolated fixtures.
set -u
umask 077
export LC_ALL=C
scratch=
generation_dir=
published=false
keep_candidate=false
application_transaction=false
service_intent_transaction=false
projection_transaction=false
# Native Lua writers, the persistent namespace and lifecycle still need migration.
# No CLI argument or environment variable can enable production publication.
production_writes_enabled=false
persistent_namespace_enabled=false
orphan_recovery_enabled=false
service_actions_enabled=false
dns_recovery_read_enabled=false
persistent_mode=false
persistent_fence_present=false
persistent_fence_pending=false
projection_scratch=
journal_active=false
public_mode=false
public_limit=1024
credential_limit=16
if [ "${1:-}" = --persistent ]; then
    persistent_mode=true; public_mode=true; public_limit=262144; credential_limit=192; shift
elif [ "${1:-}" = --public-uci ]; then
    public_mode=true; public_limit=262144; credential_limit=192; shift
fi
if [ "$persistent_mode" = true ]; then
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    unset IPKG_INSTROOT INIT_TRACE LUA_INIT LUA_PATH LUA_CPATH
fi
codec=$(dirname "$0")/config-codec.lua
fail() {
    printf '{"api_version":1,"prototype":true,"ok":false,"phase":"config-transaction","error":"%s"}\n' "$1"
    exit "${2:-1}"
}
cleanup() {
    [ -z "$scratch" ] || rm -f "$scratch"
    [ -z "$projection_scratch" ] || rm -f "$projection_scratch"
    # Only files allocated by this invocation are removed. No recursive delete.
    if [ -n "$generation_dir" ] && [ "$published" = false ] && [ "$keep_candidate" = false ]; then
        for item in "$generation_dir/credentials/"*; do
            [ ! -e "$item" ] || rm -f "$item"
        done
        rm -f "$generation_dir/public.conf" "$generation_dir/parent" "$generation_dir/manifest" "$generation_dir/legacy.conf" "$generation_dir/source.conf"
        rmdir "$generation_dir/credentials" "$generation_dir" 2>/dev/null || :
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
number() {
    case "$1" in ''|*[!0-9]*) return 1;; esac
    [ "${#1}" -le 9 ] || return 1
    value=$(expr "$1" + 0) || [ "$value" = 0 ] || return 1
    [ "$value" -ge "$2" ] && [ "$value" -le "$3" ]
}
private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] &&
        [ "$(stat -c '%u:%a:%h' "$1" 2>/dev/null)" = "$owner:600:1" ]
}
private_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] &&
        [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "$owner:700" ]
}
path_safe() {
    case "$1" in /tmp/homegate-config-prototype-*) ;; *) return 1;; esac
    walk=
    old_ifs=$IFS
    IFS=/
    set -f
    for component in $1; do
        case "$component" in '') continue;; .|..) IFS=$old_ifs; set +f; return 1;; esac
        walk="$walk/$component"
        if [ -L "$walk" ]; then IFS=$old_ifs; set +f; return 1; fi
        if [ "$walk" != /tmp ] && [ "$walk" != "$1" ]; then
            if ! private_dir "$walk"; then IFS=$old_ifs; set +f; return 1; fi
        fi
    done
    IFS=$old_ifs
    set +f
}
allocate_scratch() {
    [ -z "$scratch" ] || fail 'Internal temporary file conflict'
    scratch="$store/.work.$$"
    (set -C; : > "$scratch") 2>/dev/null || fail 'Unable to allocate private file'
}
drop_scratch() { rm -f "$scratch" || fail 'Unable to remove private file'; scratch=; }
read_one() {
    private_file "$1" || fail 'Unsafe metadata file'
    [ "$(stat -c %s "$1")" -le "$2" ] || fail 'Oversized metadata file'
    one=$(cat "$1") || fail 'Unable to read metadata'
    # Equality below also rejects missing newline and multiple trailing newlines.
    [ "$(stat -c %s "$1")" -eq "$((${#one} + 1))" ] || fail 'Invalid metadata framing'
}
persistent_open() {
    # Migration/lifecycle must establish this namespace; a web request cannot
    # create directories, initialize identity, or replace existing lock files.
    [ "$persistent_namespace_enabled" = true ] || fail 'Persistent namespace is not ready' 2
    [ "$owner" = 0 ] || fail 'Persistent namespace requires root' 7
    [ -d /etc ] && [ ! -L /etc ] || fail 'Unsafe persistent parent' 7
    case "$(stat -c '%u:%a' /etc 2>/dev/null)" in "$owner:755"|"$owner:700") ;; *) fail 'Unsafe persistent parent' 7;; esac
    private_dir /etc/homegate && private_dir /etc/homegate/transactions || fail 'Unsafe persistent namespace' 7
    store=/etc/homegate/transactions
    read_one "$store/identity" 512
    identity_body=$one
    exec 8<"$store/identity" || fail 'Unable to read store identity' 7
    IFS= read -r identity_format <&8 && IFS= read -r identity_slug <&8 &&
        IFS= read -r identity_schema <&8 && IFS= read -r identity_path <&8 &&
        IFS= read -r store_identity <&8 && IFS= read -r identity_checksum <&8 || fail 'Incomplete store identity' 7
    if IFS= read -r extra <&8; then fail 'Unexpected store identity data' 7; fi
    exec 8<&-
    [ "$identity_format:$identity_slug:$identity_schema:$identity_path" = "HGSTORE1:homegate:public-uci-v1:$store" ] || fail 'Store identity mismatch' 7
    [ "${#store_identity}" -eq 32 ] || fail 'Invalid store identity' 7
    case "$store_identity" in *[!0-9a-f]*) fail 'Invalid store identity' 7;; esac
    identity_payload=$(printf '%s\n' HGSTORE1 homegate public-uci-v1 "$store" "$store_identity")
    identity_expected=$(printf '%s\n' "$identity_payload" | sha256sum) || fail 'Unable to verify store identity' 7
    identity_expected=${identity_expected%% *}
    [ "$identity_body" = "$(printf '%s\n' "$identity_payload" "$identity_expected")" ] || fail 'Invalid store identity framing' 7
    private_file "$store/.lock" && private_file "$store/.supervisor.lock" || fail 'Persistent locks require lifecycle initialization' 7
    private_dir /var/run/homegate && private_file /var/run/homegate/frontend.lock || fail 'Unsafe shared writer lock' 7
    if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/6 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' /var/run/homegate/frontend.lock)" ]; then
        exec 6>>/var/run/homegate/frontend.lock || fail 'Unable to open shared writer lock' 7
    fi
    flock -n 6 || fail 'Shared writer is busy' 4
    if [ -e "$store/bootstrap-pending" ] || [ -L "$store/bootstrap-pending" ]; then
        private_file "$store/bootstrap-pending" && [ "$(stat -c %s "$store/bootstrap-pending")" -le 64 ] || fail 'Unsafe bootstrap barrier' 7
        pending_expected=$(printf '%s\n' HGBOOTSTRAP-PENDING1 "$store_identity" | sha256sum) || fail 'Unable to check bootstrap barrier' 7
        pending_actual=$(sha256sum "$store/bootstrap-pending") || fail 'Unable to read bootstrap barrier' 7
        [ "${pending_expected%% *}" = "${pending_actual%% *}" ] || fail 'Invalid bootstrap barrier' 7
        fail 'Lifecycle initialization is not settled' 4
    fi
}
persistent_fence_payload() {
    printf '%s\n' HGWRITEFENCE1 "$store_identity" "$fence_base" "$fence_target" "$fence_token" "$1"
}
persistent_fence_body() {
    fence_payload=$(persistent_fence_payload "$1") || return 1
    fence_checksum=$(printf '%s\n' "$fence_payload" | sha256sum) || return 1
    fence_checksum=${fence_checksum%% *}
    printf '%s\n' "$fence_payload" "$fence_checksum"
}
persistent_fence_read() {
    [ "$persistent_mode" = true ] || return
    if [ ! -e "$store/write-fence" ] && [ ! -L "$store/write-fence" ]; then return; fi
    read_one "$store/write-fence" 512
    fence_body=$one
    exec 8<"$store/write-fence" || fail 'Unable to read persistent fence' 7
    IFS= read -r fence_format <&8 && IFS= read -r fence_identity <&8 &&
        IFS= read -r fence_base <&8 && IFS= read -r fence_target <&8 &&
        IFS= read -r fence_token <&8 && IFS= read -r fence_state <&8 &&
        IFS= read -r fence_digest <&8 || fail 'Incomplete persistent fence' 7
    if IFS= read -r extra <&8; then fail 'Unexpected persistent fence data' 7; fi
    exec 8<&-
    [ "$fence_format:$fence_identity" = "HGWRITEFENCE1:$store_identity" ] || fail 'Persistent fence identity mismatch' 7
    number "$fence_base" 1 32 && [ "$fence_base" = "$value" ] || fail 'Invalid fence baseline' 7
    number "$fence_target" 1 32 && [ "$fence_target" = "$value" ] && [ "$fence_target" -gt "$fence_base" ] || fail 'Invalid fence candidate' 7
    [ "${#fence_token}" -eq 32 ] || fail 'Invalid fence handle' 7
    case "$fence_token" in *[!0-9a-f]*) fail 'Invalid fence handle' 7;; esac
    case "$fence_state" in active|settled-applied|settled-restored) ;; *) fail 'Invalid fence state' 7;; esac
    [ "$fence_body" = "$(persistent_fence_body "$fence_state")" ] || fail 'Invalid persistent fence framing' 7
    validate_generation "$fence_base"; validate_generation "$fence_target"
    [ "$validated_parent" = "$fence_base" ] || fail 'Persistent fence ancestry mismatch' 7
    persistent_fence_present=true
    [ "$fence_state" != active ] || persistent_fence_pending=true
}
persistent_fence_write() {
    allocate_scratch
    persistent_fence_body "$1" > "$scratch" || fail 'Unable to write persistent fence' 7
    fsync "$scratch" 2>/dev/null || fail 'Unable to synchronize persistent fence' 7
    mv -f "$scratch" "$store/write-fence" || fail 'Unable to publish persistent fence' 7
    scratch=
    # A visible active fence retains the sealed target even on directory-sync
    # failure or SIGKILL before the application journal appears.
    keep_candidate=true
    fence_state=$1; persistent_fence_present=true
    fsync "$store" 2>/dev/null || fail 'Persistent fence durability is uncertain' 7
}
persistent_ready() {
    [ "$persistent_mode" = true ] || return
    [ "$journal_active" = false ] && [ "$persistent_fence_pending" = false ] || fail 'Persistent recovery barrier is active' 4
    # A settled receipt replaces the active fence only AFTER pending/application
    # removal was durably confirmed. Re-sync it before allowing another writer;
    # uncertainty about the final rename must never be inferred as readiness.
    if [ "$persistent_fence_present" = true ]; then
        fsync "$store/write-fence" "$store" 2>/dev/null || fail 'Persistent completion durability is uncertain' 7
    fi
    need_initialized
}
open_store() {
    store=${HOMEGATE_CONFIG_PROTO_STORE:-}
    owner=$(id -u) || fail 'Unable to identify owner'
    if [ "$persistent_mode" = true ]; then persistent_open
    else
        path_safe "$store" || fail 'Explicit safe prototype directory required' 2
        if [ ! -d "$store" ]; then mkdir "$store" 2>/dev/null || fail 'Unable to create private directory'; fi
    fi
    private_dir "$store" || fail 'Store must be private'
    workers_pending=false
    if [ -e "$store/worker" ] || [ -L "$store/worker" ]; then
        private_file "$store/worker" && [ "$(stat -c %s "$store/worker")" -le 512 ] || fail 'Unsafe worker lease'
        workers_pending=true
    fi
    if [ "$public_mode" = true ]; then
        case "$command" in status|export) ;;
            *)
                if [ ! -e "$store/.supervisor.lock" ] && [ ! -L "$store/.supervisor.lock" ]; then
                    (set -C; : > "$store/.supervisor.lock") 2>/dev/null || :
                fi
                private_file "$store/.supervisor.lock" || fail 'Unsafe supervisor lock'
                # An internal parent may lend its already-held flock through
                # FD 7. Other callers must acquire a new description of it.
                if [ "$(stat -L -c '%d:%i:%u:%a:%h' /proc/self/fd/7 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' "$store/.supervisor.lock")" ]; then
                    exec 7>>"$store/.supervisor.lock" || fail 'Unable to open supervisor lock'
                fi
                flock -n 7 || fail 'Worker supervisor is busy' 4
                if [ "$workers_pending" = true ]; then
                    case "$command" in apply-snapshot-read|restore-snapshot-read|apply-authorize|restore-authorize|apply-service-snapshot-read|restore-service-snapshot-read|service-intent-read) ;;
                        *) fail 'Worker quiescence has not been confirmed' 4;; esac
                fi;;
        esac
    fi
    if [ ! -e "$store/.lock" ] && [ ! -L "$store/.lock" ]; then
        (set -C; : > "$store/.lock") 2>/dev/null || :
    fi
    private_file "$store/.lock" || fail 'Unsafe lock file'
    exec 9>>"$store/.lock" || fail 'Unable to open lock'
    flock -n 9 || fail 'Configuration busy' 4
    abandoned_count=0
    for existing in "$store/.work."*; do
        [ -e "$existing" ] || [ -L "$existing" ] || continue
        private_file "$existing" || fail 'Unsafe abandoned private file'
        number "$(stat -c %s "$existing")" 0 "$((public_limit + 512))" || fail 'Oversized abandoned private file'
        abandoned_count=$((abandoned_count + 1))
        [ "$abandoned_count" -lt 32 ] || fail 'Prototype temporary capacity reached' 4
        [ "$persistent_mode" = false ] || fail 'Abandoned persistent transaction requires reconciliation' 7
    done
    head_revision=0
    max_revision=0
    for existing in "$store/gen-"*; do
        [ -e "$existing" ] || [ -L "$existing" ] || continue
        index=${existing##*/gen-}
        number "$index" 1 32 && [ "$index" = "$value" ] || fail 'Invalid generation name'
        private_dir "$existing" || fail 'Unsafe generation directory'
        [ "$persistent_mode" = false ] || validate_generation "$index"
        [ "$index" -le "$max_revision" ] || max_revision=$index
    done
    if [ -e "$store/current" ] || [ -L "$store/current" ]; then
        read_one "$store/current" 3
        number "$one" 1 32 && [ "$one" = "$value" ] || fail 'Invalid current generation'
        head_revision=$value
        validate_generation "$head_revision"
    elif [ "$max_revision" -ne 0 ]; then
        fail 'Interrupted initialization requires explicit recovery'
    fi
    persistent_fence_read
    journal_read
    if [ "$persistent_mode" = true ] && { [ -e "$store/dns-operation" ] || [ -L "$store/dns-operation" ]; }; then
        # Presence alone fences ALL mutations/lifecycle recovery, even malformed
        # or incomplete receipts. No environment or feature gate can bypass it.
        case "$command" in status|export|dns-recovery-check|dns-recovery-snapshot-read) ;;
            *) fail 'DNS operation requires explicit durable recovery' 4;; esac
    fi
    if [ "$persistent_mode" = true ] && { [ -e "$store/dns-settled" ] || [ -L "$store/dns-settled" ] ||
        [ -e "$store/dns-collection" ] || [ -L "$store/dns-collection" ] || [ -e "$store/.dns-collection-next" ] || [ -L "$store/.dns-collection-next" ]; }; then
        case "$command" in status|export|dns-recovery-check|dns-recovery-snapshot-read) ;;
            *) ash "$(dirname "$0")/homegate-dns-recovery.sh" archive-check >/dev/null 2>/dev/null || fail 'DNS collection requires durable recovery' 4;; esac
    fi
    if [ "$persistent_mode" = true ]; then
        if [ "$journal_active" = true ]; then
            [ "$persistent_fence_pending" = true ] && [ "$fence_base:$fence_target:$fence_token" = "$journal_base:$journal_target:$journal_token" ] || fail 'Application and persistent fence mismatch' 7
        elif [ "$persistent_fence_pending" = true ]; then
            case "$command" in status|export|recover-fence) ;; *) fail 'Persistent fence requires reconciliation' 7;; esac
        fi
        case "$command" in status|export|recover-application|recover-fence|service-apply|service-recover|apply-finish*|restore-finish*|projection-publish|apply-*-read|restore-*-read|apply-authorize|restore-authorize|service-intent-read) ;;
            *) persistent_ready;; esac
    fi
    if [ "$journal_active" = true ]; then
        case "$command" in status|export|recover-application|service-apply|service-recover|apply-finish|restore-finish|apply-finish-intent|restore-finish-intent|apply-finish-projection|restore-finish-projection|projection-publish|apply-snapshot-read|restore-snapshot-read|apply-authorize|restore-authorize|apply-service-snapshot-read|restore-service-snapshot-read|service-intent-read) ;;
            *) fail 'Application recovery barrier is active' 4;; esac
    fi
}
slot_valid() {
    case "$1" in aliyun|cloudflare|dnspod|huaweicloud) ;;
        ddns|web) [ "$public_mode" = true ] || return 1;; *) return 1;; esac
    if [ "$public_mode" = true ]; then
        case "$2" in ''|*[!a-zA-Z0-9_-]*) return 1;; esac
        [ "${#2}" -le 64 ] || return 1
    else
        case "$2" in ''|*[!a-zA-Z0-9_]*) return 1;; esac
        [ "${#2}" -le 32 ] || return 1
    fi
    case "$1:$3" in ddns:url|web:target) ;; ddns:*|web:*) return 1;;
        *:key_id|*:secret|*:account_id|*:endpoint) ;; *) return 1;; esac
}
vault_valid() {
    private_dir "$1" || fail 'Unsafe credential directory'
    allowed_slots=
    if [ "$public_mode" = true ]; then
        allowed_slots=$(lua "$codec" allowed "$1/../public.conf" 2>/dev/null) || fail 'Invalid credential binding'
    fi
    credential_count=0
    for item in "$1/"*; do
        [ -e "$item" ] || [ -L "$item" ] || continue
        name=${item##*/}
        provider=${name%%.*}
        remainder=${name#*.}
        account=${remainder%%.*}
        slot=${remainder#*.}
        slot_valid "$provider" "$account" "$slot" || fail 'Invalid credential slot'
        if [ "$public_mode" = true ]; then
            case "
$allowed_slots
" in *"
$name
"*) ;; *) fail 'Credential account binding mismatch';; esac
        fi
        private_file "$item" || fail 'Unsafe credential file'
        size=$(stat -c %s "$item") || fail 'Unable to inspect credentials'
        number "$size" 1 4096 || fail 'Credential size outside limit'
        credential_count=$((credential_count + 1))
        [ "$credential_count" -le "$credential_limit" ] || fail 'Too many credential slots'
    done
}
public_parse() {
    if [ "$public_mode" = true ]; then
        lua "$codec" normalize 2>/dev/null || fail 'Invalid public UCI configuration'
        return
    fi
    # Strict framed prototype format, not a parser for arbitrary UCI/JSON.
    # Never source or eval input. Unknown, reordered, duplicate or binary lines fail.
    IFS= read -r line && [ "$line" = 'homegate-prototype-config:1' ] || fail 'Invalid backup format'
    IFS= read -r line && [ "$line" = 'slug=homegate' ] || fail 'Wrong plugin slug'
    IFS= read -r line && [ "$line" = 'schema=main-public-v1' ] || fail 'Unsupported public schema'
    printf '%s\n' 'homegate-prototype-config:1' 'slug=homegate' 'schema=main-public-v1'
    for key in enabled access_enabled auto_firewall log_level log_max_lines ddns_interval renew_days https_port http_port proxy_https_port proxy_http_port; do
        IFS= read -r line || fail 'Incomplete public configuration'
        case "$line" in "$key="*) option=${line#*=};; *) fail 'Unexpected public field';; esac
        case "$key" in
            enabled|access_enabled|auto_firewall)
                case "$option" in 0|1) ;; *) fail 'Invalid public boolean';; esac
                [ "$key" = auto_firewall ] || option=0
                ;;
            log_level) case "$option" in debug|info|warn|error) ;; *) fail 'Invalid log level';; esac;;
            log_max_lines) number "$option" 64 20000 || fail 'Invalid log limit'; option=$value;;
            ddns_interval) number "$option" 60 999999999 || fail 'Invalid DDNS interval'; option=$value;;
            renew_days) number "$option" 1 3650 || fail 'Invalid renewal window'; option=$value;;
            *) number "$option" 0 65535 || fail 'Invalid port'; option=$value;;
        esac
        printf '%s=%s\n' "$key" "$option"
    done
    line=
    if IFS= read -r line || [ -n "$line" ]; then fail 'Trailing public data'; fi
}
public_valid() {
    private_file "$1" || fail 'Unsafe public config file'
    number "$(stat -c %s "$1")" 1 "$public_limit" || fail 'Public configuration size outside limit'
    # Check exact canonical bytes; NULs that ash read would discard are detected.
    canonical=$(public_parse < "$1") || fail 'Invalid public configuration'
    [ "$(stat -c %s "$1")" -eq "$((${#canonical} + 1))" ] || fail 'Noncanonical public framing'
    [ "$(cat "$1")" = "$canonical" ] || fail 'Noncanonical public configuration'
}
generation_manifest() {
    # Hash only known files in a validated private directory; never follow paths
    # from a supplied checksum manifest with sha256sum -c.
    (
        cd "$1" || exit 1
        sha256sum public.conf parent || exit 1
        [ ! -e legacy.conf ] || sha256sum legacy.conf || exit 1
        [ ! -e source.conf ] || sha256sum source.conf || exit 1
        for item in credentials/*; do
            [ ! -e "$item" ] || sha256sum "$item" || exit 1
        done
    )
}
validate_generation() {
    checked_dir="$store/gen-$1"
    private_dir "$checked_dir" || fail 'Missing private generation'
    for item in "$checked_dir/"*; do
        case "${item##*/}" in public.conf|parent|manifest|credentials) ;;
            legacy.conf|source.conf) [ "$public_mode" = true ] || fail 'Unexpected legacy backup'
                private_file "$item" && number "$(stat -c %s "$item")" 1 "$public_limit" || fail 'Unsafe legacy backup';;
            *) fail 'Unexpected generation entry';; esac
    done
    public_valid "$checked_dir/public.conf"
    read_one "$checked_dir/parent" 3
    number "$one" 0 31 && [ "$one" = "$value" ] && [ "$value" -lt "$1" ] || fail 'Invalid generation ancestry'
    validated_parent=$value
    vault_valid "$checked_dir/credentials"
    private_file "$checked_dir/manifest" || fail 'Unsafe integrity manifest'
    manifest_limit=4096; [ "$public_mode" = false ] || manifest_limit=65536
    [ "$(stat -c %s "$checked_dir/manifest")" -le "$manifest_limit" ] || fail 'Oversized integrity manifest'
    expected_manifest=$(generation_manifest "$checked_dir") || fail 'Unable to hash generation'
    [ "$(cat "$checked_dir/manifest")" = "$expected_manifest" ] || fail 'Generation integrity mismatch'
    [ "$(stat -c %s "$checked_dir/manifest")" -eq "$((${#expected_manifest} + 1))" ] || fail 'Invalid integrity framing'
}
begin_generation() {
    [ "$max_revision" -lt 32 ] || fail 'Prototype history capacity reached' 4
    new_revision=$((max_revision + 1))
    candidate_dir="$store/gen-$new_revision"
    mkdir "$candidate_dir" 2>/dev/null || fail 'Unable to allocate generation'
    generation_dir=$candidate_dir
    mkdir "$generation_dir/credentials" || fail 'Unable to allocate credential directory'
    printf '%s\n' "$head_revision" > "$generation_dir/parent" || fail 'Unable to write ancestry'
}
copy_vault() {
    [ "$1" -ne 0 ] || return 0
    vault_valid "$store/gen-$1/credentials"
    if [ "$public_mode" = true ]; then
        allowed_slots=$(lua "$codec" allowed "$generation_dir/public.conf" 2>/dev/null) || fail 'Invalid candidate credential binding'
    fi
    for item in "$store/gen-$1/credentials/"*; do
        [ -e "$item" ] || continue
        if [ "$public_mode" = true ]; then
            case "
$allowed_slots
" in *"
${item##*/}
"*) ;; *) continue;; esac
        fi
        cp "$item" "$generation_dir/credentials/" || fail 'Unable to copy credentials'
    done
}
seal_generation() {
    public_valid "$generation_dir/public.conf"
    vault_valid "$generation_dir/credentials"
    generation_manifest "$generation_dir" > "$generation_dir/manifest" || fail 'Unable to seal generation'
    validate_generation "$new_revision"
}
synchronize_generation() {
    if [ "$public_mode" = true ]; then
        # BusyBox 1.33.2 sync -f ignores syncfs errors. Use checked fsync.
        fsync "$generation_dir/public.conf" "$generation_dir/parent" "$generation_dir/manifest" 2>/dev/null || fail 'Unable to synchronize candidate files'
        [ ! -e "$generation_dir/legacy.conf" ] || fsync "$generation_dir/legacy.conf" 2>/dev/null || fail 'Unable to synchronize legacy backup'
        [ ! -e "$generation_dir/source.conf" ] || fsync "$generation_dir/source.conf" 2>/dev/null || fail 'Unable to synchronize source backup'
        for item in "$generation_dir/credentials/"*; do
            [ ! -e "$item" ] || fsync "$item" 2>/dev/null || fail 'Unable to synchronize credential file'
        done
        fsync "$generation_dir/credentials" "$generation_dir" 2>/dev/null || fail 'Unable to synchronize candidate directories'
    fi
}
publish_generation() {
    seal_generation
    synchronize_generation
    [ "$application_transaction" = false ] || journal_begin
    allocate_scratch
    printf '%s\n' "$new_revision" > "$scratch" || fail 'Unable to write current pointer'
    if [ "$public_mode" = true ]; then
        fsync "$scratch" 2>/dev/null || fail 'Unable to synchronize candidate pointer'
    fi
    mv -f "$scratch" "$store/current" || fail 'Unable to publish generation'
    scratch=
    published=true
    durability=rename-only-not-fsync
    if [ "$public_mode" = true ]; then
        fsync "$store" 2>/dev/null || fail 'Published pointer durability is uncertain' 6
        durability=fsync-barriers-not-device-verified
    fi
    if [ "$application_transaction" = true ]; then
        head_revision=$new_revision
        journal_write applying
        rm -f "$store/pending" 2>/dev/null || :
        printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"application_pending":true,"apply_handle":"%s","business_applied":false}\n' "$new_revision" "$journal_token"
        return
    fi
    printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"service_enabled":false,"durability":"%s"}\n' "$new_revision" "$durability"
}
need_initialized() { [ "$head_revision" -ne 0 ] || fail 'Initialize prototype store first' 2; }
new_token() {
    allocate_scratch
    head -c 16 /dev/urandom > "$scratch" || fail 'Unable to obtain confirmation randomness'
    [ "$(stat -c %s "$scratch")" -eq 16 ] || fail 'Insufficient confirmation randomness'
    random_digest=$(sha256sum "$scratch") || fail 'Unable to hash confirmation randomness'
    token=$(printf '%.32s' "${random_digest%% *}")
    drop_scratch
    [ "${#token}" -eq 32 ] || fail 'Invalid confirmation randomness'
    case "$token" in *[!0-9a-f]*) fail 'Invalid confirmation randomness';; esac
}
clock_now() {
    clock_line=$(cat /proc/uptime 2>/dev/null) || fail 'Unable to read monotonic clock'
    uptime=${clock_line%% *}
    uptime=${uptime%%.*}
    number "$uptime" 0 999999999 || fail 'Invalid monotonic clock'
    now=$value
    boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || fail 'Unable to read boot identity'
    [ "${#boot}" -eq 36 ] || fail 'Invalid boot identity'
    case "$boot" in *[!0-9a-f-]*) fail 'Invalid boot identity';; esac
}
digest_file() {
    digest=$(sha256sum "$1") || fail 'Unable to hash transaction data'
    digest=${digest%% *}
    [ "${#digest}" -eq 64 ] || fail 'Invalid transaction digest'
    case "$digest" in *[!0-9a-f]*) fail 'Invalid transaction digest';; esac
}
journal_read() {
    journal_active=false
    journal_format=HGAPPLICATION1
    journal_file="$store/application"
    case "${1:-}" in '') ;; anchor) journal_file="$store/application-anchor";; *) fail 'Invalid internal journal selector' 7;; esac
    if [ ! -e "$journal_file" ] && [ ! -L "$journal_file" ]; then return; fi
    [ "$public_mode" = true ] || fail 'Application journal requires full schema'
    read_one "$journal_file" 512
    journal_body=$one
    exec 8<"$journal_file" || fail 'Unable to read application journal'
    IFS= read -r journal_format <&8 && IFS= read -r journal_base <&8 &&
        IFS= read -r journal_target <&8 && IFS= read -r journal_token <&8 &&
        IFS= read -r journal_state <&8 && IFS= read -r journal_before <&8 &&
        IFS= read -r journal_after <&8 || fail 'Incomplete application journal'
    case "$journal_format" in
        HGAPPLICATION1) ;;
        HGAPPLICATION2|HGAPPLICATION3)
            IFS= read -r journal_boot_enabled <&8 && IFS= read -r journal_was_running <&8 &&
                IFS= read -r journal_intent_boot <&8 && IFS= read -r journal_checksum <&8 || fail 'Incomplete service intent'
            case "$journal_boot_enabled:$journal_was_running" in 0:0|0:1|1:0|1:1) ;; *) fail 'Invalid service intent';; esac;;
        *) fail 'Invalid application journal format';;
    esac
    if IFS= read -r extra <&8; then fail 'Unexpected application journal data'; fi
    exec 8<&-
    if [ "$journal_format" != HGAPPLICATION1 ]; then
        [ "${#journal_intent_boot}" -eq 36 ] || fail 'Invalid service boot identity'
        case "$journal_intent_boot" in *[!0-9a-f-]*) fail 'Invalid service boot identity';; esac
        [ "${#journal_checksum}" -eq 64 ] || fail 'Invalid service intent checksum'
        case "$journal_checksum" in *[!0-9a-f]*) fail 'Invalid service intent checksum';; esac
    fi
    number "$journal_base" 1 32 && [ "$journal_base" = "$value" ] || fail 'Invalid application baseline'
    number "$journal_target" 1 32 && [ "$journal_target" = "$value" ] &&
        [ "$journal_target" -gt "$journal_base" ] || fail 'Invalid application candidate'
    case "$journal_state" in prepared|applying|restoring|applied|restored) ;; *) fail 'Invalid application journal phase';; esac
    [ "${#journal_token}" -eq 32 ] || fail 'Invalid application handle'
    case "$journal_token" in *[!0-9a-f]*) fail 'Invalid application handle';; esac
    [ "${#journal_before}" -eq 64 ] && [ "${#journal_after}" -eq 64 ] || fail 'Invalid application binding'
    case "$journal_before$journal_after" in *[!0-9a-f]*) fail 'Invalid application binding';; esac
    framed=$(journal_body_write "$journal_state") || fail 'Unable to check application framing'
    [ "$journal_body" = "$framed" ] || fail 'Invalid application journal framing'
    validate_generation "$journal_base"
    journal_binding "$journal_base"
    [ "$digest" = "$journal_before" ] || fail 'Application baseline changed'
    validate_generation "$journal_target"
    [ "$validated_parent" = "$journal_base" ] || fail 'Invalid application ancestry'
    if [ "$journal_format" = HGAPPLICATION3 ]; then
        private_file "$store/gen-$journal_target/source.conf" || fail 'Missing bound source configuration'
        lua "$codec" source-baseline "$store/gen-$journal_target/source.conf" "$store/gen-$journal_base" 2>/dev/null || fail 'Source baseline does not match generation'
    fi
    journal_binding "$journal_target"
    [ "$digest" = "$journal_after" ] || fail 'Application candidate changed'
    case "$head_revision" in "$journal_base"|"$journal_target") ;; *) fail 'Application pointer is inconsistent';; esac
    case "$journal_state:$head_revision" in "applied:$journal_target"|"restored:$journal_base") ;;
        applied:*|restored:*) fail 'Completed application pointer is inconsistent';; esac
    journal_active=true
}
journal_binding() {
    manifest_body=$(cat "$store/gen-$1/manifest") || fail 'Unable to bind application generation'
    if [ "$journal_format" != HGAPPLICATION1 ]; then
        digest=$(printf '%s\n' "$journal_format" "$store" "$journal_intent_boot" "$journal_boot_enabled" "$journal_was_running" "$manifest_body" | sha256sum) || fail 'Unable to bind service intent'
    else
        digest=$(printf '%s\n%s\n' "$store" "$manifest_body" | sha256sum) || fail 'Unable to bind application store'
    fi
    digest=${digest%% *}
    [ "${#digest}" -eq 64 ] || fail 'Invalid application store binding'
    case "$digest" in *[!0-9a-f]*) fail 'Invalid application store binding';; esac
}
journal_payload_write() {
    printf '%s\n' "$journal_format" "$journal_base" "$journal_target" "$journal_token" "$1" "$journal_before" "$journal_after" || return 1
    if [ "$journal_format" != HGAPPLICATION1 ]; then printf '%s\n' "$journal_boot_enabled" "$journal_was_running" "$journal_intent_boot"; fi
}
journal_body_write() {
    journal_payload=$(journal_payload_write "$1") || return 1
    printf '%s\n' "$journal_payload" || return 1
    if [ "$journal_format" != HGAPPLICATION1 ]; then
        journal_checksum_value=$(printf '%s\n' "$journal_payload" | sha256sum) || return 1
        journal_checksum_value=${journal_checksum_value%% *}
        [ "${#journal_checksum_value}" -eq 64 ] || return 1
        case "$journal_checksum_value" in *[!0-9a-f]*) return 1;; esac
        printf '%s\n' "$journal_checksum_value"
    fi
}
journal_write() {
    allocate_scratch
    journal_body_write "$1" > "$scratch" || fail 'Unable to write application intent' 7
    fsync "$scratch" 2>/dev/null || fail 'Unable to synchronize application intent' 7
    mv -f "$scratch" "$store/application" || fail 'Unable to publish application intent' 7
    scratch=
    # From the first visible journal rename, cleanup must preserve its target,
    # even if the following directory barrier fails or the process is killed.
    keep_candidate=true
    journal_active=true
    journal_state=$1
    fsync "$store" 2>/dev/null || fail 'Application intent durability is uncertain' 7
}
persistent_anchor_write() {
    [ "$persistent_mode" = true ] || return
    clock_now
    allocate_scratch
    journal_body_write prepared > "$scratch" || fail 'Unable to write recovery anchor' 7
    fsync "$scratch" 2>/dev/null || fail 'Unable to synchronize recovery anchor' 7
    mv -f "$scratch" "$store/application-anchor" || fail 'Unable to publish recovery anchor' 7
    scratch=
    fsync "$store" 2>/dev/null || fail 'Recovery anchor durability is uncertain' 7
    digest_file "$store/application-anchor"
    anchor_payload=$(printf '%s\n' HGRECOVERY1 "$store_identity" "$boot" "$digest")
    anchor_checksum=$(printf '%s\n' "$anchor_payload" | sha256sum) || fail 'Unable to bind recovery anchor' 7
    anchor_checksum=${anchor_checksum%% *}
    allocate_scratch
    printf '%s\n' "$anchor_payload" "$anchor_checksum" > "$scratch" || fail 'Unable to write recovery anchor binding' 7
    fsync "$scratch" 2>/dev/null || fail 'Unable to synchronize recovery anchor binding' 7
    mv -f "$scratch" "$store/application-anchor-meta" || fail 'Unable to publish recovery anchor binding' 7
    scratch=
    fsync "$store" 2>/dev/null || fail 'Recovery anchor binding durability is uncertain' 7
}
persistent_anchor_restore() {
    [ "$journal_active" = false ] && [ "$persistent_fence_pending" = true ] || fail 'Orphan fence recovery is not applicable' 5
    clock_now
    private_file "$store/application-anchor" && [ "$(stat -c %s "$store/application-anchor")" -le 512 ] || fail 'Missing safe recovery anchor' 7
    digest_file "$store/application-anchor"
    anchor_payload=$(printf '%s\n' HGRECOVERY1 "$store_identity" "$boot" "$digest")
    anchor_checksum=$(printf '%s\n' "$anchor_payload" | sha256sum) || fail 'Unable to bind recovery anchor' 7
    anchor_checksum=${anchor_checksum%% *}
    anchor_expected=$(printf '%s\n' "$anchor_payload" "$anchor_checksum" | sha256sum) || fail 'Unable to check recovery anchor binding' 7
    private_file "$store/application-anchor-meta" && [ "$(stat -c %s "$store/application-anchor-meta")" -le 256 ] || fail 'Missing safe recovery anchor binding' 7
    digest_file "$store/application-anchor-meta"
    [ "$digest" = "${anchor_expected%% *}" ] || fail 'Recovery anchor identity or boot changed' 7
    journal_read anchor
    [ "$journal_active" = true ] && [ "$journal_state" = prepared ] || fail 'Invalid recovery anchor phase' 7
    [ "$fence_base:$fence_target:$fence_token" = "$journal_base:$journal_target:$journal_token" ] || fail 'Recovery anchor does not match active fence' 7
    anchor_canonical=$(journal_body_write prepared | sha256sum) || fail 'Unable to check recovery anchor framing' 7
    digest_file "$store/application-anchor"
    [ "$digest" = "${anchor_canonical%% *}" ] || fail 'Invalid recovery anchor bytes' 7
    # No guessed format or service intent: journal_read validates the original
    # HGAPPLICATION1/2/3 and immutable generations before restoring a pointer.
    journal_restore
}
persistent_anchor_bind() {
    [ "$persistent_mode" = true ] || return
    clock_now
    private_file "$store/application-anchor" && [ "$(stat -c %s "$store/application-anchor")" -le 512 ] || fail 'Missing bound recovery anchor' 7
    anchor_expected=$(journal_body_write prepared | sha256sum) || fail 'Unable to check bound recovery anchor' 7
    digest_file "$store/application-anchor"
    [ "$digest" = "${anchor_expected%% *}" ] || fail 'Recovery anchor does not match journal' 7
    anchor_payload=$(printf '%s\n' HGRECOVERY1 "$store_identity" "$boot" "$digest")
    anchor_checksum=$(printf '%s\n' "$anchor_payload" | sha256sum); anchor_checksum=${anchor_checksum%% *}
    anchor_expected=$(printf '%s\n' "$anchor_payload" "$anchor_checksum" | sha256sum) || fail 'Unable to check anchor identity' 7
    private_file "$store/application-anchor-meta" && [ "$(stat -c %s "$store/application-anchor-meta")" -le 256 ] || fail 'Missing bound recovery identity' 7
    digest_file "$store/application-anchor-meta"
    [ "$digest" = "${anchor_expected%% *}" ] || fail 'Recovery identity or boot changed' 7
}
journal_begin() {
    [ "$journal_active" = false ] || fail 'Application already pending' 4
    journal_format=HGAPPLICATION1
    if [ "$service_intent_transaction" = true ]; then
        journal_format=HGAPPLICATION2; journal_boot_enabled=$request_boot_enabled; journal_was_running=$request_was_running
        [ "$projection_transaction" = false ] || journal_format=HGAPPLICATION3
        clock_now; journal_intent_boot=$boot
    fi
    journal_base=$head_revision; journal_target=$new_revision
    journal_binding "$journal_base"; journal_before=$digest
    journal_binding "$journal_target"; journal_after=$digest
    new_token; journal_token=$token
    if [ "$persistent_mode" = true ]; then
        persistent_anchor_write
        fence_base=$journal_base; fence_target=$journal_target; fence_token=$journal_token
        persistent_fence_write active
        persistent_fence_pending=true
    fi
    journal_write prepared
}
journal_need() {
    [ "$journal_active" = true ] || fail 'No pending application' 5
    [ "$confirmation" = "$journal_token" ] || fail 'Application handle changed' 5
    persistent_anchor_bind
}
intent_ack_need() {
    if [ "$journal_format" != HGAPPLICATION1 ] && [ "$application_result" = success ]; then
        case "$command:$journal_format" in apply-finish-intent:HGAPPLICATION2|apply-finish-projection:HGAPPLICATION3) expected_running=0;; restore-finish-intent:HGAPPLICATION2|restore-finish-projection:HGAPPLICATION3) expected_running=$journal_was_running;;
            *) fail 'Service observations are required' 5;; esac
        # Imported candidates are always disabled. Preserve boot links but do
        # not start a previously stopped service or activate imported settings.
        [ "$observed_boot_enabled" = "$journal_boot_enabled" ] && [ "$observed_running" = "$expected_running" ] || fail 'Service observations do not match intent' 7
        clock_now
        [ "$boot" = "$journal_intent_boot" ] || fail 'Service intent requires cold-start reconciliation' 7
    else
        case "$command" in *-finish-intent|*-finish-projection) fail 'No bound service intent' 5;; esac
    fi
}
restore_pointer() {
    allocate_scratch
    printf '%s\n' "$journal_base" > "$scratch" || fail 'Unable to write recovery pointer' 7
    fsync "$scratch" 2>/dev/null || fail 'Unable to synchronize recovery pointer' 7
    mv -f "$scratch" "$store/current" || fail 'Unable to restore recovery pointer' 7
    scratch=
    head_revision=$journal_base
    fsync "$store" 2>/dev/null || fail 'Recovery pointer durability is uncertain' 7
}
journal_restore() {
    journal_write restoring
    restore_pointer
    printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"restoration_pending":true,"restore_handle":"%s","business_restored":false}\n' "$journal_base" "$journal_token"
}
journal_close() {
    # Recovery can return to the preview's original base. Remove and sync the
    # old preview before lifting the barrier, so that handle cannot replay.
    rm -f "$store/pending" || fail 'Unable to invalidate application preview' 7
    fsync "$store" 2>/dev/null || fail 'Preview invalidation durability is uncertain' 7
    rm -f "$store/application" || fail 'Unable to close application intent' 7
    journal_active=false
    fsync "$store" 2>/dev/null || fail 'Application completion durability is uncertain' 7
    if [ "$persistent_mode" = true ]; then
        case "$journal_state" in applied|restored) ;; *) fail 'Nonterminal persistent completion' 7;; esac
        persistent_fence_write "settled-$journal_state"
        persistent_fence_pending=false
    fi
}
private_snapshot() {
    [ -p /proc/self/fd/3 ] || fail 'Private reader requires inherited pipe' 2
    lua "$codec" snapshot "$store/gen-$head_revision" "$head_revision" 2>/dev/null || fail 'Unable to deliver private snapshot'
    printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"scope":"private-business-reader"}\n' "$head_revision"
}
baseline_fingerprint() {
    manifest_body=$(cat "$store/gen-$head_revision/manifest" 2>/dev/null) || fail 'Unable to read transaction baseline'
    fingerprint=$(printf '%s\n%s\n' "$store" "$manifest_body" | sha256sum) || fail 'Unable to bind transaction baseline'
    fingerprint=${fingerprint%% *}
    [ "${#fingerprint}" -eq 64 ] || fail 'Invalid baseline fingerprint'
}
full_plan_write() {
    clock_now; created=$now; deadline=$((created + 300)); plan_boot=$boot
    number "$deadline" 0 999999999 || fail 'Monotonic clock outside supported lifetime'
    baseline_fingerprint; plan_baseline=$fingerprint
    allocate_scratch
    printf '%s\n' "$plan_public" > "$scratch" || fail 'Unable to prepare public diff'
    digest_file "$scratch"; plan_digest=$digest
    diff=$(lua "$codec" diff "$store/gen-$head_revision/public.conf" "$scratch" 2>/dev/null) || fail 'Unable to compute public diff'
    drop_scratch
    credential_policy=retain-matching-resource
    if [ "$plan_kind" = migration ]; then
        digest_file "$store/gen-$plan_source/manifest"; plan_digest=$digest
        credential_policy=migrate-legacy-private-fields
    fi
    new_token
    allocate_scratch
    printf '%s\n' "$head_revision" "$token" "$plan_kind" "$plan_source" "$created" "$deadline" "$plan_boot" "$plan_baseline" "$plan_digest" "$plan_public" > "$scratch" || fail 'Unable to write public UCI plan'
    mv -f "$scratch" "$store/pending" || fail 'Unable to publish preview'
    scratch=
    printf '{"api_version":1,"prototype":true,"ok":true,"confirmation":"%s","base_revision":%s,"operation":"%s","expires_in":300,"can_commit":true,"service_enabled":false,"credentials_omitted":true,"credential_policy":"%s","scope":"public-uci-v1","changes":%s}\n' "$token" "$head_revision" "$plan_kind" "$credential_policy" "$diff"
}
plan_write() {
    if [ "$public_mode" = true ]; then full_plan_write; return; fi
    # All values below are bounded, validated decimal numbers or fixed enums.
    # No account names, opaque credentials, secret hashes or paths are exposed.
    # Build the whole response before publishing the plan or printing success.
    # A baseline read failure must emit one failure object, never half a JSON.
    before_public=$(cat "$store/gen-$head_revision/public.conf" 2>/dev/null) || fail 'Unable to read preview baseline'
    before_public=$(public_parse <<EOF
$before_public
EOF
    ) || fail 'Invalid preview baseline'
    before_rest=$before_public
    newline='
'
    changes=
    line_number=0
    while IFS= read -r after_line; do
        case "$before_rest" in
            *"$newline"*) before_line=${before_rest%%"$newline"*}; before_rest=${before_rest#*"$newline"};;
            *) before_line=$before_rest; before_rest=;;
        esac
        line_number=$((line_number + 1))
        [ "$line_number" -gt 3 ] || continue
        [ "$before_line" != "$after_line" ] || continue
        change_row=$(printf '{"field":"%s","before":"%s","after":"%s"}' "${after_line%%=*}" "${before_line#*=}" "${after_line#*=}")
        changes="${changes:+$changes,}$change_row"
    done <<EOF
$plan_public
EOF
    new_token
    allocate_scratch
    {
        printf '%s\n%s\n%s\n%s\n' "$head_revision" "$token" "$plan_kind" "$plan_source"
        printf '%s\n' "$plan_public"
    } > "$scratch" || fail 'Unable to write preview'
    mv -f "$scratch" "$store/pending" || fail 'Unable to publish preview'
    scratch=
    printf '{"api_version":1,"prototype":true,"ok":true,"confirmation":"%s","base_revision":%s,"operation":"%s","service_enabled":false,"credentials_omitted":true,"scope":"main-public-v1","changes":[%s]}\n' "$token" "$head_revision" "$plan_kind" "$changes"
}
plan_read() {
    private_file "$store/pending" || fail 'Missing safe preview' 5
    number "$(stat -c %s "$store/pending")" 1 "$((public_limit + 512))" || fail 'Invalid preview size'
    {
        IFS= read -r plan_base && IFS= read -r plan_token && IFS= read -r plan_kind && IFS= read -r plan_source || fail 'Invalid preview header'
        number "$plan_base" 1 32 && [ "$plan_base" = "$value" ] || fail 'Invalid preview base'
        [ "$plan_base" = "$head_revision" ] && [ "$plan_token" = "$confirmation" ] || fail 'Expired confirmation' 5
        case "$plan_kind" in import) [ "$plan_source" = 0 ] || fail 'Invalid import preview';;
            rollback) number "$plan_source" 1 32 && [ "$plan_source" = "$value" ] || fail 'Invalid rollback preview';;
            migration) [ "$public_mode" = true ] && [ "$head_revision" = 1 ] && number "$plan_source" 2 32 && [ "$plan_source" = "$value" ] || fail 'Invalid migration preview';;
            *) fail 'Invalid preview operation';; esac
        if [ "$public_mode" = true ]; then
            IFS= read -r created && IFS= read -r deadline && IFS= read -r plan_boot && IFS= read -r plan_baseline && IFS= read -r plan_digest || fail 'Incomplete public UCI plan'
            number "$created" 0 999999999 && [ "$created" = "$value" ] || fail 'Invalid preview timestamp'
            number "$deadline" 0 999999999 && [ "$deadline" = "$value" ] && [ "$deadline" -eq "$((created + 300))" ] || fail 'Invalid preview deadline'
            clock_now
            [ "$boot" = "$plan_boot" ] && [ "$now" -ge "$created" ] && [ "$now" -lt "$deadline" ] || fail 'Expired confirmation' 5
            baseline_fingerprint
            [ "$fingerprint" = "$plan_baseline" ] || fail 'Preview baseline changed' 5
        fi
        plan_public=$(public_parse) || fail 'Invalid preview configuration'
    } < "$store/pending"
    # Compare complete framing, including bytes read could discard.
    if [ "$public_mode" = true ]; then
        allocate_scratch
        printf '%s\n' "$plan_public" > "$scratch" || fail 'Unable to inspect preview candidate'
        digest_file "$scratch"; drop_scratch
        if [ "$plan_kind" = migration ]; then
            validate_generation "$plan_source"
            [ "$validated_parent" = "$head_revision" ] && [ -e "$store/gen-$plan_source/legacy.conf" ] || fail 'Invalid migration candidate'
            [ "$(cat "$store/gen-$plan_source/public.conf")" = "$plan_public" ] || fail 'Migration public candidate changed' 5
            digest_file "$store/gen-$plan_source/manifest"
        fi
        [ "$digest" = "$plan_digest" ] || fail 'Preview candidate changed' 5
        framed=$(printf '%s\n' "$plan_base" "$plan_token" "$plan_kind" "$plan_source" "$created" "$deadline" "$plan_boot" "$plan_baseline" "$plan_digest" "$plan_public")
    else
        framed=$(printf '%s\n%s\n%s\n%s\n%s' "$plan_base" "$plan_token" "$plan_kind" "$plan_source" "$plan_public")
    fi
    [ "$(stat -c %s "$store/pending")" -eq "$((${#framed} + 1))" ] && [ "$(cat "$store/pending")" = "$framed" ] || fail 'Invalid preview framing'
}
ancestor() {
    walker=$head_revision
    while [ "$walker" -ne 0 ]; do
        [ "$walker" != "$1" ] || return 0
        validate_generation "$walker"
        walker=$validated_parent
    done
    return 1
}

production_source_lock() {
    # Preserve a trusted borrowed descriptor. Opening a new description while
    # the native parent still holds FD6 would contend with that same parent.
    # Native/persistent gates remain off until lifecycle and business migrate.
    private_dir /var/run/homegate && private_file /var/run/homegate/frontend.lock || fail 'Unsafe legacy writer lock' 7
    if [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/6 2>/dev/null)" != "$(stat -c '%d:%i:%u:%a:%h' /var/run/homegate/frontend.lock)" ]; then
        exec 6>>/var/run/homegate/frontend.lock || fail 'Unable to open legacy writer lock' 7
    fi
    flock -n 6 || fail 'Legacy configuration writer is busy' 4
}
projection_source_check() {
    [ -d /etc ] && [ ! -L /etc ] && [ -d /etc/config ] && [ ! -L /etc/config ] || fail 'Unsafe configuration directory' 7
    case "$(stat -c '%u:%a' /etc/config 2>/dev/null)" in "$owner:700"|"$owner:755") ;; *) fail 'Unsafe configuration directory' 7;; esac
    private_file /etc/config/homegate || fail 'Source configuration must be private' 7
    number "$(stat -c %s /etc/config/homegate)" 1 "$public_limit" || fail 'Source configuration exceeds limit' 7
}
projection_capture() {
    projection_source_check
    source_identity=$(stat -c '%d:%i:%u:%a:%h:%s' /etc/config/homegate) || fail 'Unable to identify source configuration' 7
    head -c "$((public_limit + 1))" /etc/config/homegate > "$generation_dir/source.conf" || fail 'Unable to capture source configuration' 7
    private_file "$generation_dir/source.conf" && number "$(stat -c %s "$generation_dir/source.conf")" 1 "$public_limit" || fail 'Invalid source capture' 7
    lua "$codec" source-baseline "$generation_dir/source.conf" "$store/gen-$head_revision" 2>/dev/null || fail 'Source configuration differs from baseline' 7
    digest_file "$generation_dir/source.conf"; source_digest=$digest
    projection_source_check
    [ "$source_identity" = "$(stat -c '%d:%i:%u:%a:%h:%s' /etc/config/homegate)" ] || fail 'Source identity changed during capture' 7
    digest_file /etc/config/homegate
    [ "$digest" = "$source_digest" ] || fail 'Source configuration changed during capture' 7
}
projection_need() {
    journal_need
    [ "$journal_format" = HGAPPLICATION3 ] || fail 'No bound source projection' 5
    clock_now
    [ "$boot" = "$journal_intent_boot" ] || fail 'Source projection requires cold-start reconciliation' 7
}
projection_file_state() {
    projection_source_check
    digest_file "$store/gen-$journal_target/source.conf"; projection_base_digest=$digest
    digest_file "$store/gen-$journal_target/public.conf"; projection_target_digest=$digest
    digest_file /etc/config/homegate; projection_seen_digest=$digest
    case "$projection_seen_digest" in "$projection_base_digest"|"$projection_target_digest") ;;
        *) fail 'Configuration changed outside the source projection' 7;; esac
}
projection_publish() {
    projection_need
    case "$projection_role:$journal_state:$head_revision" in
        "apply:applying:$journal_target") projection_desired="$store/gen-$journal_target/public.conf";;
        "restore:restoring:$journal_base") projection_desired="$store/gen-$journal_target/source.conf";;
        *) fail 'Source projection phase is not ready' 5;; esac
    production_source_lock
    sample_service
    [ "$request_was_running" = 0 ] && [ "$request_boot_enabled" = "$journal_boot_enabled" ] || fail 'Service must be quiet with matching boot intent' 7
    projection_file_state
    digest_file "$projection_desired"; projection_desired_digest=$digest
    if [ "$projection_seen_digest" != "$projection_desired_digest" ]; then
        projection_scratch="/etc/config/.homegate-projection.$$"
        (set -C; : > "$projection_scratch") 2>/dev/null || fail 'Unable to allocate projection file' 7
        cat "$projection_desired" > "$projection_scratch" || fail 'Unable to stage configuration projection' 7
        private_file "$projection_scratch" || fail 'Unsafe projection file' 7
        digest_file "$projection_scratch"; [ "$digest" = "$projection_desired_digest" ] || fail 'Projection copy is incomplete' 7
        fsync "$projection_scratch" 2>/dev/null || fail 'Unable to synchronize projection file' 7
        projection_source_check; digest_file /etc/config/homegate
        [ "$digest" = "$projection_seen_digest" ] || fail 'Configuration changed before projection publication' 7
        mv -f "$projection_scratch" /etc/config/homegate || fail 'Unable to publish configuration projection' 7
        projection_scratch=
    fi
    fsync /etc/config/homegate /etc/config 2>/dev/null || fail 'Configuration projection durability is uncertain' 7
    projection_file_state
    [ "$projection_seen_digest" = "$projection_desired_digest" ] || fail 'Projection readback does not match generation' 7
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"bound-uci-projection","configuration_published":true,"business_applied":false}\n'
}
projection_observe_finish() {
    [ "$owner" = 0 ] || fail 'Production projection requires root' 2
    projection_need
    production_source_lock
    projection_file_state
    case "$command:$journal_state:$head_revision" in
        "apply-finish-projection:applying:$journal_target") projection_expected=$projection_target_digest;;
        "restore-finish-projection:restoring:$journal_base") projection_expected=$projection_base_digest;;
        *) fail 'Projection acknowledgement is stale' 5;; esac
    [ "$projection_seen_digest" = "$projection_expected" ] || fail 'Expected configuration projection is not published' 7
    sample_service
    # Re-read after actual two-state sampling, before the terminal journal.
    projection_file_state
    [ "$projection_seen_digest" = "$projection_expected" ] || fail 'Projection changed during observation' 7
    observed_boot_enabled=$request_boot_enabled; observed_running=$request_was_running
}
sample_service() {
    # Called after open_store + plan_read hold the configuration flock.
    # Only fixed production reads; neither publication nor service actions.
    allocate_scratch
    result=0
    setsid ash "$(dirname "$0")/homegate-service-observer-watchdog.sh" "$confirmation" 3>"$scratch" 6>&- 7>&- 8>&- 9>&- </dev/null >/dev/null 2>&1 || result=$?
    [ "$result" -eq 0 ] || fail 'Service state is unknown or unstable' 7
    read_one "$scratch" 64
    exec 8<"$scratch" || fail 'Unable to read service observation' 7
    IFS= read -r sample_format <&8 && IFS= read -r request_boot_enabled <&8 &&
        IFS= read -r request_was_running <&8 && IFS= read -r sample_boot <&8 || fail 'Incomplete service observation' 7
    if IFS= read -r extra <&8; then fail 'Unexpected service observation' 7; fi
    exec 8<&-
    [ "$sample_format" = HGSERVICE1 ] || fail 'Invalid service observation' 7
    case "$request_boot_enabled:$request_was_running" in 0:0|0:1|1:0|1:1) ;; *) fail 'Invalid service observation' 7;; esac
    expected=$(printf '%s\n' HGSERVICE1 "$request_boot_enabled" "$request_was_running" "$sample_boot")
    [ "$one" = "$expected" ] || fail 'Invalid service observation framing' 7
    clock_now
    [ "$sample_boot" = "$boot" ] || fail 'Service observation belongs to another boot' 7
    drop_scratch
}
service_preflight() {
    # Schema/generation/dependency precheck only; no claim of DNS/ACME health.
    projection_need
    production_source_lock
    projection_file_state
    [ ! -e /tmp/.homegate-package-upgrade-state ] && [ ! -L /tmp/.homegate-package-upgrade-state ] || fail 'Package lifecycle is active' 4
    for file in /etc/init.d/homegate /etc/rc.common /sbin/ubus /sbin/uci /usr/bin/homegate; do
        [ -f "$file" ] && [ ! -L "$file" ] && [ -x "$file" ] || fail 'Service dependency is unavailable' 7
        case "$(stat -c '%u:%a:%h' "$file")" in "$owner:700:1"|"$owner:755:1") ;; *) fail 'Unsafe service dependency' 7;; esac
    done
    service_action precheck
    projection_file_state
}
service_action() {
    result=0
    # Retain shared writer/supervisor locks in the independent watchdog, but
    # close the configuration lock and private output in the action family.
    setsid ash "$(dirname "$0")/homegate-service-observer-watchdog.sh" --action "$confirmation" "$1" 3>&- 8>&- 9>&- </dev/null >/dev/null 2>&1 || result=$?
    [ "$result" -eq 0 ] || fail 'Service command failed or timed out; recovery required' 7
}
service_transition() {
    service_preflight
    sample_service
    [ "$request_boot_enabled" = "$journal_boot_enabled" ] || fail 'Service boot intent changed' 7
    if [ "$request_was_running" = 1 ]; then service_action stop; fi
    sample_service
    [ "$request_was_running" = 0 ] && [ "$request_boot_enabled" = "$journal_boot_enabled" ] || fail 'Service did not become quiet' 7
    # Existing projection validates the exact source/target, publishes while
    # quiet and fsyncs the file and parent. Never change enable/disable links.
    projection_publish >/dev/null
    service_preflight
    if [ "$projection_role" = restore ] && [ "$journal_was_running" = 1 ]; then
        service_action start
    fi
    saved_command=$command
    command="$projection_role-finish-projection"
    application_result=success
    projection_observe_finish
    intent_ack_need
    command=$saved_command
    if [ "$projection_role" = apply ]; then journal_write applied; else journal_write restored; fi
    journal_close
    printf '{"api_version":1,"prototype":true,"ok":true,"scope":"fixed-service-transition","revision":%s,"application_pending":false,"service_observed":true,"business_applied":false}\n' "$head_revision"
}

[ "$#" -ge 1 ] || fail 'Missing prototype command' 2
command=$1
shift
if [ "$command" = version ]; then
    [ "$#" -eq 0 ] || fail 'Unexpected arguments' 2
    source_root=$(CDPATH= cd "$(dirname "$0")/../../.." && pwd) || fail 'Unable to locate source'
    IFS= read -r version < "$source_root/VERSION" || fail 'Missing version'
    IFS= read -r revision < "$source_root/RELEASE" || fail 'Missing revision'
    case "$version" in ''|*[!0-9.]*) fail 'Invalid source version';; esac
    number "$revision" 1 999999999 || fail 'Invalid source revision'
    printf '{"api_version":1,"prototype":true,"ok":true,"version":"%s-r%s","phase":"config-transaction"}\n' "$version" "$value"
    exit 0
fi
if [ "$persistent_mode" = true ] && [ "$command" = init ]; then fail 'Persistent bootstrap requires lifecycle migration' 2; fi
case "$command" in
    service-apply)
        [ "$persistent_mode" = true ] && [ "$service_actions_enabled" = true ] && [ "$production_writes_enabled" = true ] || fail 'Service migration is not ready' 2
        [ "$#" -eq 1 ] && [ "${#1}" -eq 32 ] || fail 'Expected internal application handle' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid application handle' 2;; esac
        confirmation=$1; projection_role=apply;;
    service-recover)
        [ "$persistent_mode" = true ] && [ "$service_actions_enabled" = true ] && [ "$production_writes_enabled" = true ] || fail 'Service migration is not ready' 2
        [ "$#" -eq 0 ] || fail 'Unexpected recovery arguments' 2
        projection_role=restore;;
    init|status|export|preview|cancel) [ "$#" -eq 0 ] || fail 'Unexpected arguments' 2;;
    writer-check) [ "$#" -eq 0 ] && [ "$persistent_mode" = true ] || fail 'Writer check requires persistent namespace' 2;;
    dns-recovery-check|dns-recovery-snapshot-read)
        [ "$#" -eq 0 ] && [ "$persistent_mode" = true ] && [ "$dns_recovery_read_enabled" = true ] || fail 'DNS recovery reader is not ready' 2;;
    migration-preview) [ "$#" -eq 0 ] && [ "$public_mode" = true ] || fail 'Migration requires full schema' 2;;
    snapshot-read) [ "$#" -eq 0 ] && [ "$public_mode" = true ] || fail 'Private reader requires full schema' 2;;
    recover-application) [ "$#" -eq 0 ] && [ "$public_mode" = true ] || fail 'Recovery requires full schema' 2;;
    recover-fence)
        [ "$#" -eq 0 ] && [ "$persistent_mode" = true ] && [ "$orphan_recovery_enabled" = true ] || fail 'Orphan recovery is not ready' 2;;
    rollback-preview) [ "$#" -eq 1 ] && number "$1" 1 32 && [ "$1" = "$value" ] || fail 'Expected generation number' 2;;
    commit-apply-projection|commit-apply-observed)
        [ "$public_mode" = true ] && [ "$#" -eq 1 ] && [ "${#1}" -eq 32 ] || fail 'Expected confirmation handle' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid confirmation handle' 2;; esac
        confirmation=$1; application_transaction=true; service_intent_transaction=true;;
    projection-publish)
        [ "$production_writes_enabled" = true ] || fail 'Production writer migration is incomplete' 2
        [ "$public_mode" = true ] && [ "$#" -eq 2 ] && [ "${#1}" -eq 32 ] || fail 'Expected projection handle and role' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid projection handle' 2;; esac
        case "$2" in apply|restore) ;; *) fail 'Invalid projection role' 2;; esac
        confirmation=$1; projection_role=$2;;
    apply-finish-projection|restore-finish-projection)
        [ "$production_writes_enabled" = true ] || fail 'Production writer migration is incomplete' 2
        [ "$public_mode" = true ] && [ "$#" -eq 1 ] && [ "${#1}" -eq 32 ] || fail 'Expected projection handle' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid projection handle' 2;; esac
        confirmation=$1; application_result=success;;
    commit-apply-intent)
        [ "$public_mode" = true ] && [ "$#" -eq 3 ] && [ "${#1}" -eq 32 ] || fail 'Expected service intent' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid confirmation handle' 2;; esac
        case "$2:$3" in 0:0|0:1|1:0|1:1) ;; *) fail 'Invalid service intent' 2;; esac
        confirmation=$1; request_boot_enabled=$2; request_was_running=$3
        application_transaction=true; service_intent_transaction=true;;
    apply-finish-intent|restore-finish-intent)
        [ "$public_mode" = true ] && [ "$#" -eq 3 ] && [ "${#1}" -eq 32 ] || fail 'Expected service observations' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid application handle' 2;; esac
        case "$2:$3" in 0:0|0:1|1:0|1:1) ;; *) fail 'Invalid service observations' 2;; esac
        confirmation=$1; observed_boot_enabled=$2; observed_running=$3; application_result=success;;
    commit|commit-apply|apply-snapshot-read|restore-snapshot-read|apply-authorize|restore-authorize|apply-service-snapshot-read|restore-service-snapshot-read|service-intent-read) [ "$#" -eq 1 ] && [ "${#1}" -eq 32 ] || fail 'Expected confirmation handle' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid confirmation handle' 2;; esac
        confirmation=$1
        if [ "$command" != commit ]; then [ "$public_mode" = true ] || fail 'Application requires full schema' 2; fi
        [ "$command" != commit-apply ] || application_transaction=true;;
    apply-finish|restore-finish) [ "$public_mode" = true ] && [ "$#" -eq 2 ] && [ "${#1}" -eq 32 ] || fail 'Expected application result' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid application handle' 2;; esac
        case "$2" in success|failure) ;; *) fail 'Invalid application result' 2;; esac
        confirmation=$1; application_result=$2;;
    credential-put|credential-delete) [ "$#" -eq 3 ] && slot_valid "$1" "$2" "$3" || fail 'Expected provider account slot' 2
        credential_name="$1.$2.$3";;
    *) fail 'Unsupported prototype command' 2;;
esac
open_store
case "$command" in
    service-apply)
        need_initialized
        service_transition;;
    service-recover)
        need_initialized
        [ "$journal_active" = true ] || fail 'Service journal requires reconciliation' 7
        confirmation=$journal_token
        projection_need
        # Validate context, files and boot before moving the generation pointer.
        service_preflight
        case "$journal_state" in applied|restored)
            terminal_state=$journal_state
            if [ "$journal_state" = applied ]; then projection_role=apply; journal_state=applying; else journal_state=restoring; fi
            command="$projection_role-finish-projection"; application_result=success
            projection_observe_finish; intent_ack_need
            journal_state=$terminal_state; journal_close
            printf '{"api_version":1,"prototype":true,"ok":true,"scope":"fixed-service-transition","application_pending":false,"service_observed":true,"business_applied":false}\n'
            exit 0;; esac
        journal_restore >/dev/null
        service_transition;;
    writer-check)
        # open_store already verified readiness while all three locks are held.
        printf '{"api_version":1,"prototype":true,"ok":true,"scope":"persistent-writer-barrier","write_ready":true}\n'
        ;;
    dns-recovery-check)
        printf '{"api_version":1,"prototype":true,"ok":true,"scope":"dns-recovery-reader","write_ready":false,"read_ready":true}\n'
        ;;
    init)
        [ "$head_revision" -eq 0 ] || fail 'Store already initialized' 4
        begin_generation
        if [ "$public_mode" = true ]; then
            printf '%s\n' '# homegate-backup-format: 2' '# plugin: homegate' '# schema: public-uci-v1' '# secrets: omitted' "config homegate 'main'" | public_parse > "$generation_dir/public.conf" || fail 'Unable to write UCI defaults'
        else
            printf '%s\n' 'homegate-prototype-config:1' 'slug=homegate' 'schema=main-public-v1' \
                'enabled=0' 'access_enabled=0' 'auto_firewall=1' 'log_level=info' 'log_max_lines=1024' \
                'ddns_interval=300' 'renew_days=30' 'https_port=443' 'http_port=0' \
                'proxy_https_port=10443' 'proxy_http_port=10080' > "$generation_dir/public.conf" || fail 'Unable to write defaults'
        fi
        publish_generation
        ;;
    status)
        need_initialized
        preview=false
        [ ! -e "$store/pending" ] || preview=true
        scope=main-public-v1; [ "$public_mode" = false ] || scope=public-uci-v1
        application_phase=none; [ "$journal_active" = false ] || application_phase=$journal_state
        intent_bound=false; [ "$journal_format" = HGAPPLICATION1 ] || intent_bound=true
        printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"preview_present":%s,"service_enabled":false,"history_capacity":32,"credential_capacity":%s,"scope":"%s","application_pending":%s,"application_phase":"%s","workers_pending":%s,"service_intent_bound":%s,"persistent_namespace":%s,"persistent_fence_pending":%s}\n' "$head_revision" "$preview" "$credential_limit" "$scope" "$journal_active" "$application_phase" "$workers_pending" "$intent_bound" "$persistent_mode" "$persistent_fence_pending"
        ;;
    export)
        need_initialized
        cat "$store/gen-$head_revision/public.conf" || fail 'Unable to export public config'
        ;;
    snapshot-read|dns-recovery-snapshot-read)
        need_initialized
        # Only an inherited pipe may receive private bytes. Never a path, RPC
        # response, terminal, or regular file. Hold the same flock throughout.
        private_snapshot
        ;;
    apply-snapshot-read|restore-snapshot-read|apply-authorize|restore-authorize|apply-service-snapshot-read|restore-service-snapshot-read|service-intent-read)
        need_initialized; journal_need
        case "$command:$journal_format" in
            apply-service-snapshot-read:HGAPPLICATION2|restore-service-snapshot-read:HGAPPLICATION2|service-intent-read:HGAPPLICATION2|apply-service-snapshot-read:HGAPPLICATION3|restore-service-snapshot-read:HGAPPLICATION3|service-intent-read:HGAPPLICATION3) ;;
            apply-snapshot-read:HGAPPLICATION1|restore-snapshot-read:HGAPPLICATION1|apply-authorize:HGAPPLICATION1|restore-authorize:HGAPPLICATION1) ;;
            *) fail 'Worker type does not match application intent' 5;;
        esac
        if [ "$command" = service-intent-read ]; then
            case "$journal_state:$head_revision" in
                "applying:$journal_target") expected_running=0;;
                "restoring:$journal_base") expected_running=$journal_was_running;;
                *) fail 'Service context is not ready' 5;;
            esac
            clock_now; same_boot=false; [ "$boot" != "$journal_intent_boot" ] || same_boot=true
            printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"scope":"internal-service-intent","phase":"%s","boot_enabled":%s,"baseline_running":%s,"expected_running":%s,"same_boot":%s}\n' "$head_revision" "$journal_state" "$journal_boot_enabled" "$journal_was_running" "$expected_running" "$same_boot"
        elif [ "$command" = apply-snapshot-read ] || [ "$command" = apply-authorize ] || [ "$command" = apply-service-snapshot-read ]; then
            [ "$journal_state" = applying ] && [ "$head_revision" = "$journal_target" ] || fail 'Application snapshot is not ready' 5
        else
            [ "$journal_state" = restoring ] && [ "$head_revision" = "$journal_base" ] || fail 'Recovery snapshot is not ready' 5
        fi
        case "$command" in service-intent-read) ;;
            *-authorize)
            printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"scope":"internal-worker-context"}\n' "$head_revision";;
            *) private_snapshot;; esac
        ;;
    projection-publish)
        need_initialized
        [ "$owner" = 0 ] || fail 'Production projection requires root' 2
        projection_publish
        ;;
    apply-finish|apply-finish-intent|apply-finish-projection)
        need_initialized; journal_need
        [ "$journal_state" = applying ] && [ "$head_revision" = "$journal_target" ] || fail 'Application acknowledgement is stale' 5
        [ "$command" != apply-finish-projection ] || projection_observe_finish
        intent_ack_need
        if [ "$application_result" = failure ]; then journal_restore
        else
            journal_write applied
            journal_close
            printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"application_pending":false,"worker_acknowledged":true}\n' "$head_revision"
        fi
        ;;
    restore-finish|restore-finish-intent|restore-finish-projection)
        need_initialized; journal_need
        [ "$journal_state" = restoring ] && [ "$head_revision" = "$journal_base" ] || fail 'Recovery acknowledgement is stale' 5
        [ "$command" != restore-finish-projection ] || projection_observe_finish
        intent_ack_need
        [ "$application_result" = success ] || fail 'Business restoration remains incomplete' 7
        journal_write restored
        journal_close
        printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"application_pending":false,"worker_acknowledged":true}\n' "$head_revision"
        ;;
    recover-application)
        need_initialized
        [ "$journal_active" = true ] || fail 'No pending application' 5
        persistent_anchor_bind
        case "$journal_state" in applied|restored)
            journal_close
            printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"application_pending":false,"worker_acknowledged":true}\n' "$head_revision";;
            *) journal_restore;; esac
        ;;
    recover-fence)
        need_initialized
        persistent_anchor_restore
        ;;
    preview)
        need_initialized
        allocate_scratch
        head -c "$((public_limit + 1))" > "$scratch" || fail 'Unable to read bounded backup'
        [ "$(stat -c %s "$scratch")" -le "$public_limit" ] || fail 'Backup exceeds limit'
        plan_public=$(public_parse < "$scratch") || fail 'Backup validation failed'
        # Require exact framing; canonical numeric normalization remains allowed.
        original=$(cat "$scratch") || fail 'Unable to read backup'
        [ "$(stat -c %s "$scratch")" -eq "$((${#original} + 1))" ] || fail 'Invalid backup framing'
        drop_scratch
        plan_kind=import; plan_source=0
        plan_write
        ;;
    migration-preview)
        need_initialized
        [ "$head_revision" = 1 ] || fail 'Migration requires untouched initial store' 4
        for item in "$store/gen-1/credentials/"*; do
            [ ! -e "$item" ] || fail 'Migration requires empty initial vault' 4
        done
        defaults=$(printf '%s\n' '# homegate-backup-format: 2' '# plugin: homegate' '# schema: public-uci-v1' '# secrets: omitted' "config homegate 'main'" | public_parse) || fail 'Unable to check migration baseline'
        [ "$(cat "$store/gen-1/public.conf")" = "$defaults" ] || fail 'Migration baseline is not default configuration' 4
        begin_generation
        head -c "$((public_limit + 1))" > "$generation_dir/legacy.conf" || fail 'Unable to read bounded legacy config'
        number "$(stat -c %s "$generation_dir/legacy.conf")" 1 "$public_limit" || fail 'Legacy configuration size outside limit'
        lua "$codec" migrate "$generation_dir/legacy.conf" "$generation_dir" 2>/dev/null || fail 'Legacy migration validation failed'
        seal_generation
        plan_public=$(cat "$generation_dir/public.conf") || fail 'Unable to read migration candidate'
        plan_kind=migration; plan_source=$new_revision
        plan_write
        # Retain sealed unpublished staging for confirmation; not an ancestor.
        generation_dir=
        ;;
    rollback-preview)
        need_initialized
        [ "$1" != "$head_revision" ] && ancestor "$1" || fail 'Rollback target is not prior committed ancestry' 5
        validate_generation "$1"
        plan_public=$(cat "$store/gen-$1/public.conf") || fail 'Unable to read rollback config'
        plan_kind=rollback; plan_source=$1
        plan_write
        ;;
    commit|commit-apply|commit-apply-intent|commit-apply-observed|commit-apply-projection)
        need_initialized
        plan_read
        case "$command" in
            commit-apply-projection) production_source_lock; sample_service; plan_read; projection_transaction=true;;
            commit-apply-observed) sample_service; plan_read;; esac
        if [ "$plan_kind" = rollback ]; then
            ancestor "$plan_source" || fail 'Rollback target is not committed ancestry' 5
            validate_generation "$plan_source"
            [ "$(cat "$store/gen-$plan_source/public.conf")" = "$plan_public" ] || fail 'Rollback config changed'
            copy_source=$plan_source
        elif [ "$plan_kind" = migration ]; then copy_source=$plan_source
        else copy_source=$head_revision; fi
        begin_generation
        printf '%s\n' "$plan_public" > "$generation_dir/public.conf" || fail 'Unable to write candidate config'
        copy_vault "$copy_source"
        [ "$projection_transaction" = false ] || projection_capture
        if [ "$plan_kind" = migration ]; then
            cp "$store/gen-$plan_source/legacy.conf" "$generation_dir/legacy.conf" || fail 'Unable to retain private migration backup'
        fi
        publish_generation
        # A crash before removing preview cannot replay it: base revision changed.
        rm -f "$store/pending" 2>/dev/null || :
        ;;
    cancel)
        need_initialized
        if [ -e "$store/pending" ] || [ -L "$store/pending" ]; then
            private_file "$store/pending" || fail 'Unsafe preview'
            rm -f "$store/pending" || fail 'Unable to cancel preview'
        fi
        printf '{"api_version":1,"prototype":true,"ok":true,"cancelled":true}\n'
        ;;
    credential-put|credential-delete)
        need_initialized
        begin_generation
        cp "$store/gen-$head_revision/public.conf" "$generation_dir/public.conf" || fail 'Unable to copy public config'
        copy_vault "$head_revision"
        if [ "$command" = credential-put ]; then
            head -c 4097 > "$generation_dir/credentials/$credential_name" || fail 'Unable to receive credentials'
            number "$(stat -c %s "$generation_dir/credentials/$credential_name")" 1 4096 || fail 'Credential size outside limit'
        else
            [ -f "$generation_dir/credentials/$credential_name" ] || fail 'Credential slot not configured' 2
            rm -f "$generation_dir/credentials/$credential_name" || fail 'Unable to remove candidate credential'
        fi
        publish_generation
        ;;
esac
