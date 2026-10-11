#!/bin/sh
# Isolated transaction experiment; NOT an installer or production UCI importer.
# Default legacy main schema; --public-uci uses the shared six-type Lua codec.
# Neither mode activates production services or modifies /etc/config.
set -u
umask 077
export LC_ALL=C
scratch=
generation_dir=
published=false
public_mode=false
public_limit=1024
credential_limit=16
if [ "${1:-}" = --public-uci ]; then
    public_mode=true; public_limit=262144; credential_limit=192; shift
fi
codec=$(dirname "$0")/config-codec.lua
fail() {
    printf '{"api_version":1,"prototype":true,"ok":false,"phase":"config-transaction","error":"%s"}\n' "$1"
    exit "${2:-1}"
}
cleanup() {
    [ -z "$scratch" ] || rm -f "$scratch"
    # Only files allocated by this invocation are removed. No recursive delete.
    if [ -n "$generation_dir" ] && [ "$published" = false ]; then
        for item in "$generation_dir/credentials/"*; do
            [ ! -e "$item" ] || rm -f "$item"
        done
        rm -f "$generation_dir/public.conf" "$generation_dir/parent" "$generation_dir/manifest" "$generation_dir/legacy.conf"
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
open_store() {
    store=${HOMEGATE_CONFIG_PROTO_STORE:-}
    owner=$(id -u) || fail 'Unable to identify owner'
    path_safe "$store" || fail 'Explicit safe prototype directory required' 2
    if [ ! -d "$store" ]; then mkdir "$store" 2>/dev/null || fail 'Unable to create private directory'; fi
    private_dir "$store" || fail 'Store must be private'
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
    done
    head_revision=0
    max_revision=0
    for existing in "$store/gen-"*; do
        [ -e "$existing" ] || [ -L "$existing" ] || continue
        index=${existing##*/gen-}
        number "$index" 1 32 && [ "$index" = "$value" ] || fail 'Invalid generation name'
        private_dir "$existing" || fail 'Unsafe generation directory'
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
            legacy.conf) [ "$public_mode" = true ] || fail 'Unexpected legacy backup'
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
publish_generation() {
    seal_generation
    if [ "$public_mode" = true ]; then
        # BusyBox 1.33.2 sync -f ignores syncfs errors. Use checked fsync.
        fsync "$generation_dir/public.conf" "$generation_dir/parent" "$generation_dir/manifest" 2>/dev/null || fail 'Unable to synchronize candidate files'
        [ ! -e "$generation_dir/legacy.conf" ] || fsync "$generation_dir/legacy.conf" 2>/dev/null || fail 'Unable to synchronize legacy backup'
        for item in "$generation_dir/credentials/"*; do
            [ ! -e "$item" ] || fsync "$item" 2>/dev/null || fail 'Unable to synchronize credential file'
        done
        fsync "$generation_dir/credentials" "$generation_dir" 2>/dev/null || fail 'Unable to synchronize candidate directories'
    fi
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
case "$command" in
    init|status|export|preview|cancel) [ "$#" -eq 0 ] || fail 'Unexpected arguments' 2;;
    migration-preview) [ "$#" -eq 0 ] && [ "$public_mode" = true ] || fail 'Migration requires full schema' 2;;
    rollback-preview) [ "$#" -eq 1 ] && number "$1" 1 32 && [ "$1" = "$value" ] || fail 'Expected generation number' 2;;
    commit) [ "$#" -eq 1 ] && [ "${#1}" -eq 32 ] || fail 'Expected confirmation handle' 2
        case "$1" in *[!0-9a-f]*) fail 'Invalid confirmation handle' 2;; esac
        confirmation=$1;;
    credential-put|credential-delete) [ "$#" -eq 3 ] && slot_valid "$1" "$2" "$3" || fail 'Expected provider account slot' 2
        credential_name="$1.$2.$3";;
    *) fail 'Unsupported prototype command' 2;;
esac
open_store
case "$command" in
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
        printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"preview_present":%s,"service_enabled":false,"history_capacity":32,"credential_capacity":%s,"scope":"%s"}\n' "$head_revision" "$preview" "$credential_limit" "$scope"
        ;;
    export)
        need_initialized
        cat "$store/gen-$head_revision/public.conf" || fail 'Unable to export public config'
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
    commit)
        need_initialized
        plan_read
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
