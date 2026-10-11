#!/bin/sh
# Isolated transaction experiment; NOT an installer or production UCI importer.
# Public schema covers main switches/limits/ports only. No business activation.
set -u
umask 077
export LC_ALL=C
scratch=
generation_dir=
published=false
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
        rm -f "$generation_dir/public.conf" "$generation_dir/parent" "$generation_dir/manifest"
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
        number "$(stat -c %s "$existing")" 0 4097 || fail 'Oversized abandoned private file'
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
    case "$1" in aliyun|cloudflare|dnspod|huaweicloud) ;; *) return 1;; esac
    case "$2" in ''|*[!a-zA-Z0-9_]*) return 1;; esac
    [ "${#2}" -le 32 ] || return 1
    case "$3" in key_id|secret|account_id|endpoint) ;; *) return 1;; esac
}
vault_valid() {
    private_dir "$1" || fail 'Unsafe credential directory'
    credential_count=0
    for item in "$1/"*; do
        [ -e "$item" ] || [ -L "$item" ] || continue
        name=${item##*/}
        provider=${name%%.*}
        remainder=${name#*.}
        account=${remainder%%.*}
        slot=${remainder#*.}
        slot_valid "$provider" "$account" "$slot" || fail 'Invalid credential slot'
        private_file "$item" || fail 'Unsafe credential file'
        size=$(stat -c %s "$item") || fail 'Unable to inspect credentials'
        number "$size" 1 4096 || fail 'Credential size outside limit'
        credential_count=$((credential_count + 1))
        [ "$credential_count" -le 16 ] || fail 'Too many credential slots'
    done
}
public_parse() {
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
    number "$(stat -c %s "$1")" 1 1024 || fail 'Public configuration size outside limit'
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
        for item in credentials/*; do
            [ ! -e "$item" ] || sha256sum "$item" || exit 1
        done
    )
}
validate_generation() {
    checked_dir="$store/gen-$1"
    private_dir "$checked_dir" || fail 'Missing private generation'
    for item in "$checked_dir/"*; do
        case "${item##*/}" in public.conf|parent|manifest|credentials) ;; *) fail 'Unexpected generation entry';; esac
    done
    public_valid "$checked_dir/public.conf"
    read_one "$checked_dir/parent" 3
    number "$one" 0 31 && [ "$one" = "$value" ] && [ "$value" -lt "$1" ] || fail 'Invalid generation ancestry'
    validated_parent=$value
    vault_valid "$checked_dir/credentials"
    private_file "$checked_dir/manifest" || fail 'Unsafe integrity manifest'
    [ "$(stat -c %s "$checked_dir/manifest")" -le 4096 ] || fail 'Oversized integrity manifest'
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
    for item in "$store/gen-$1/credentials/"*; do
        [ ! -e "$item" ] || cp "$item" "$generation_dir/credentials/" || fail 'Unable to copy credentials'
    done
}
publish_generation() {
    public_valid "$generation_dir/public.conf"
    vault_valid "$generation_dir/credentials"
    generation_manifest "$generation_dir" > "$generation_dir/manifest" || fail 'Unable to seal generation'
    validate_generation "$new_revision"
    allocate_scratch
    printf '%s\n' "$new_revision" > "$scratch" || fail 'Unable to write current pointer'
    mv -f "$scratch" "$store/current" || fail 'Unable to publish generation'
    scratch=
    published=true
    printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"service_enabled":false,"durability":"rename-only-not-fsync"}\n' "$new_revision"
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
plan_write() {
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
    number "$(stat -c %s "$store/pending")" 1 1200 || fail 'Invalid preview size'
    {
        IFS= read -r plan_base && IFS= read -r plan_token && IFS= read -r plan_kind && IFS= read -r plan_source || fail 'Invalid preview header'
        number "$plan_base" 1 32 && [ "$plan_base" = "$value" ] || fail 'Invalid preview base'
        [ "$plan_base" = "$head_revision" ] && [ "$plan_token" = "$confirmation" ] || fail 'Expired confirmation' 5
        case "$plan_kind" in import) [ "$plan_source" = 0 ] || fail 'Invalid import preview';;
            rollback) number "$plan_source" 1 32 && [ "$plan_source" = "$value" ] || fail 'Invalid rollback preview';;
            *) fail 'Invalid preview operation';; esac
        plan_public=$(public_parse) || fail 'Invalid preview configuration'
    } < "$store/pending"
    # Compare complete framing, including bytes read could discard.
    framed=$(printf '%s\n%s\n%s\n%s\n%s' "$plan_base" "$plan_token" "$plan_kind" "$plan_source" "$plan_public")
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
        printf '%s\n' 'homegate-prototype-config:1' 'slug=homegate' 'schema=main-public-v1' \
            'enabled=0' 'access_enabled=0' 'auto_firewall=1' 'log_level=info' 'log_max_lines=1024' \
            'ddns_interval=300' 'renew_days=30' 'https_port=443' 'http_port=0' \
            'proxy_https_port=10443' 'proxy_http_port=10080' > "$generation_dir/public.conf" || fail 'Unable to write defaults'
        publish_generation
        ;;
    status)
        need_initialized
        preview=false
        [ ! -e "$store/pending" ] || preview=true
        printf '{"api_version":1,"prototype":true,"ok":true,"revision":%s,"preview_present":%s,"service_enabled":false,"history_capacity":32,"credential_capacity":16,"scope":"main-public-v1"}\n' "$head_revision" "$preview"
        ;;
    export)
        need_initialized
        cat "$store/gen-$head_revision/public.conf" || fail 'Unable to export public config'
        ;;
    preview)
        need_initialized
        allocate_scratch
        head -c 1025 > "$scratch" || fail 'Unable to read bounded backup'
        [ "$(stat -c %s "$scratch")" -le 1024 ] || fail 'Backup exceeds limit'
        plan_public=$(public_parse < "$scratch") || fail 'Backup validation failed'
        # Require exact framing; canonical numeric normalization remains allowed.
        original=$(cat "$scratch") || fail 'Unable to read backup'
        [ "$(stat -c %s "$scratch")" -eq "$((${#original} + 1))" ] || fail 'Invalid backup framing'
        drop_scratch
        plan_kind=import; plan_source=0
        plan_write
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
        else copy_source=$head_revision; fi
        begin_generation
        printf '%s\n' "$plan_public" > "$generation_dir/public.conf" || fail 'Unable to write candidate config'
        copy_vault "$copy_source"
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
