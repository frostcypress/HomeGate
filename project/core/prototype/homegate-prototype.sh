#!/bin/sh
# Isolated control-plane prototype. Never installed by the production recipe.
# No business workers, network calls, service control or production writes.
set -u
umask 077
export LC_ALL=C
phase=prototype-control
temp_file=
fail() {
    # Messages and phase come only from literals, never UCI/CLI values.
    printf '{"api_version":1,"prototype":true,"ok":false,"phase":"%s","error":"%s"}\n' "$phase" "$1"
    exit "${2:-1}"
}
cleanup() { [ -z "$temp_file" ] || rm -f "$temp_file"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

number() {
    negative=false
    case "$1" in -*) digits=${1#-}; negative=true;; +*) digits=${1#+};; *) digits=$1;; esac
    case "$digits" in ''|*[!0-9]*) return 1;; esac
    [ "${#digits}" -le 9 ] || return 1
    # expr treats leading zeroes as decimal on BusyBox; no ash octal expansion.
    value=$(expr "$digits" + 0) || [ "$value" = 0 ] || return 1
    [ "$negative" = false ] || value=$((-value))
    [ "$value" -ge "$2" ] && [ "$value" -le "$3" ]
}
event_valid() {
    case "$1" in startup|config_changed|wan_changed|ddns_timer|acme_timer|access_timer|firewall_retry|proxy_retry|ddns_retry|acme_retry|access_retry) return 0;; esac
    return 1
}
queued_has() {
    for waiting in $queued; do
        [ "$waiting" = "$1" ] && return 0
    done
    return 1
}
path_no_links() {
    case "$1" in /*) ;; *) return 1;; esac
    walk=
    previous_ifs=$IFS
    IFS=/
    # Globbing is disabled before traversing caller-supplied components.
    set -f
    for component in $1; do
        case "$component" in '') continue;; .|..) IFS=$previous_ifs; set +f; return 1;; esac
        walk="$walk/$component"
        if [ -L "$walk" ]; then IFS=$previous_ifs; set +f; return 1; fi
    done
    IFS=$previous_ifs
    set +f
}
private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] &&
        [ "$(stat -c '%u:%a:%h' "$1" 2>/dev/null)" = "$owner:600:1" ]
}
state_open() {
    state=${HOMEGATE_PROTO_STATE:-}
    case "$state" in /tmp/homegate-prototype-*) ;; *) fail 'Explicit prototype /tmp directory required' 2;; esac
    path_no_links "$state" || fail 'Unsafe prototype directory'
    owner=$(id -u) || fail 'Unable to identify owner'
    parent=${state%/*}
    while [ "$parent" != /tmp ]; do
        [ "$(stat -c '%u:%a' "$parent" 2>/dev/null)" = "$owner:700" ] || fail 'Unsafe prototype parent'
        parent=${parent%/*}
    done
    if [ ! -d "$state" ]; then
        mkdir "$state" 2>/dev/null || fail 'Unable to create prototype directory'
    fi
    [ "$(stat -c '%u:%a' "$state" 2>/dev/null)" = "$owner:700" ] || fail 'Prototype directory must be private'
    lock_file="$state/.lock"
    if [ ! -e "$lock_file" ] && [ ! -L "$lock_file" ]; then
        (set -C; : > "$lock_file") 2>/dev/null || :
    fi
    private_file "$lock_file" || fail 'Unsafe lock file'
    exec 9>>"$lock_file" || fail 'Unable to open lock'
    # BusyBox 1.33.2 supports -n, but not util-linux flock -w.
    flock -n 9 || fail 'Prototype state busy' 4
    state_file="$state/control.state"
    generation=1
    sequence=0
    active=-
    queued=
    count=0
    if [ -e "$state_file" ] || [ -L "$state_file" ]; then
        private_file "$state_file" || fail 'Unsafe state file'
        size=$(stat -c %s "$state_file") || fail 'Unable to inspect state'
        number "$size" 1 512 || fail 'State size exceeds limit'
        {
            IFS= read -r generation && IFS= read -r sequence && IFS= read -r active || fail 'Invalid state header'
            number "$generation" 1 999999999 || fail 'Invalid generation'
            generation=$value
            number "$sequence" 0 999999999 || fail 'Invalid sequence'
            sequence=$value
            [ "$active" = "-" ] || event_valid "$active" || fail 'Invalid active event'
            [ "$active" = "-" ] || [ "$sequence" -gt 0 ] || fail 'Invalid active sequence'
            line=
            while IFS= read -r line || [ -n "$line" ]; do
                event_valid "$line" || fail 'Invalid queued event'
                if queued_has "$line"; then fail 'Duplicate queued event'; fi
                queued="${queued:+$queued }$line"
                count=$((count + 1))
                [ "$count" -le 8 ] || fail 'Queue size exceeds limit'
            done
        } < "$state_file"
    fi
}
state_save() {
    candidate="$state/.state.$$"
    (set -C; : > "$candidate") 2>/dev/null || fail 'Unable to allocate state file'
    temp_file=$candidate
    {
        printf '%s\n%s\n%s\n' "$generation" "$sequence" "$active"
        for event in $queued; do printf '%s\n' "$event"; done
    } > "$temp_file" || fail 'Unable to write state'
    mv -f "$temp_file" "$state_file" || fail 'Unable to publish state'
    temp_file=
}
summary() {
    busy=false
    [ "$active" = "-" ] || busy=true
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"%s","generation":%s,"pending":%s,"active":%s,"capacity":8}\n' "$phase" "$generation" "$count" "$busy"
}
get_option() {
    option=$(uci -c "$config_dir" -q get "homegate.main.$1" 2>/dev/null) || option=
    [ -n "$option" ] || option=$2
}
bool_option() {
    get_option "$1" "$2"
    option=${option#"${option%%[![:space:]]*}"}
    option=${option%"${option##*[![:space:]]}"}
    option=$(printf '%s' "$option" | tr '[:upper:]' '[:lower:]')
    case "$option" in 1|true|yes|on|enabled) option=true;; *) option=false;; esac
}
numeric_option() {
    get_option "$1" "$2"
    number "$option" "$3" "$4" || fail "$5"
    option=$value
}
config_check() {
    phase=prototype-config
    config_dir=${HOMEGATE_PROTO_CONFIG_DIR:-}
    [ -n "$config_dir" ] && path_no_links "$config_dir" || fail 'Explicit safe UCI directory required' 2
    [ -f "$config_dir/homegate" ] && [ ! -L "$config_dir/homegate" ] || fail 'Missing regular HomeGate config'
    section=$(uci -c "$config_dir" -q get homegate.main 2>/dev/null) || fail 'Unable to read HomeGate section'
    [ "$section" = homegate ] || fail 'Missing HomeGate main section'
    bool_option enabled 0; enabled=$option
    bool_option access_enabled 0; access_enabled=$option
    bool_option auto_firewall 1; auto_firewall=$option
    get_option log_level info
    level=$(printf '%s' "$option" | tr '[:upper:]' '[:lower:]')
    case "$level" in debug|info|warn|error) ;; *) fail 'Invalid log level';; esac
    numeric_option log_max_lines 1024 64 20000 'Invalid log limit'; log_limit=$option
    numeric_option ddns_interval 300 -999999999 999999999 'Invalid DDNS interval'; interval=$option
    [ "$interval" -ge 60 ] || interval=60
    numeric_option renew_days 30 1 3650 'Invalid renewal window'; renew=$option
    numeric_option https_port 443 0 65535 'Invalid HTTPS port'; https=$option
    numeric_option http_port 0 0 65535 'Invalid HTTP port'; http=$option
    numeric_option proxy_https_port 10443 0 65535 'Invalid proxy HTTPS port'; proxy_https=$option
    numeric_option proxy_http_port 10080 0 65535 'Invalid proxy HTTP port'; proxy_http=$option
    printf '{"api_version":1,"prototype":true,"ok":true,"phase":"%s","complete_validation":false,"coverage":"main-switches-limits-ports","main":{"enabled":%s,"access_enabled":%s,"auto_firewall":%s,"log_level":"%s","log_max_lines":%s,"ddns_interval":%s,"renew_days":%s,"https_port":%s,"http_port":%s,"proxy_https_port":%s,"proxy_http_port":%s}}\n' "$phase" "$enabled" "$access_enabled" "$auto_firewall" "$level" "$log_limit" "$interval" "$renew" "$https" "$http" "$proxy_https" "$proxy_http"
}

[ "$#" -ge 1 ] || fail 'Missing prototype command' 2
command=$1
shift
case "$command" in
    version)
        [ "$#" -eq 0 ] || fail 'Unexpected arguments' 2
        source_root=$(CDPATH= cd "$(dirname "$0")/../../.." && pwd) || fail 'Unable to locate source'
        IFS= read -r version < "$source_root/VERSION" || fail 'Missing version'
        IFS= read -r revision < "$source_root/RELEASE" || fail 'Missing revision'
        case "$version" in ''|*[!0-9.]*) fail 'Invalid source version';; esac
        number "$revision" 1 999999999 || fail 'Invalid source revision'
        printf '{"api_version":1,"prototype":true,"ok":true,"version":"%s-r%s","phase":"%s"}\n' "$version" "$value" "$phase"
        ;;
    check)
        [ "$#" -eq 0 ] || fail 'Unexpected arguments' 2
        config_check
        ;;
    state|advance|next)
        [ "$#" -eq 0 ] || fail 'Unexpected arguments' 2
        state_open
        case "$command" in
            state) summary;;
            advance)
                [ "$generation" -lt 999999999 ] || fail 'Generation exhausted'
                generation=$((generation + 1)); active=-; queued=; count=0
                state_save; summary
                ;;
            next)
                [ "$active" = "-" ] || fail 'Worker already active' 4
                if [ -z "$queued" ]; then
                    printf '{"api_version":1,"prototype":true,"ok":true,"claimed":false}\n'
                else
                    [ "$sequence" -lt 999999999 ] || fail 'Sequence exhausted'
                    active=${queued%% *}
                    if [ "$queued" = "$active" ]; then queued=; else queued=${queued#* }; fi
                    sequence=$((sequence + 1)); count=$((count - 1))
                    state_save
                    printf '{"api_version":1,"prototype":true,"ok":true,"claimed":true,"event":"%s","token":"g%ss%s","generation":%s}\n' "$active" "$generation" "$sequence" "$generation"
                fi
                ;;
        esac
        ;;
    submit)
        [ "$#" -eq 1 ] || fail 'Expected one event' 2
        event_valid "$1" || fail 'Unknown event' 2
        state_open
        if queued_has "$1"; then
            duplicate=true
        else
            [ "$count" -lt 8 ] || fail 'Queue full' 4
            queued="${queued:+$queued }$1"; count=$((count + 1)); duplicate=false
            state_save
        fi
        printf '{"api_version":1,"prototype":true,"ok":true,"deduplicated":%s,"pending":%s}\n' "$duplicate" "$count"
        ;;
    complete)
        [ "$#" -eq 1 ] || fail 'Expected one worker token' 2
        [ "${#1}" -le 22 ] || fail 'Invalid worker token' 2
        case "$1" in g*s*) ;; *) fail 'Invalid worker token' 2;; esac
        case "$1" in *[!gs0-9]*) fail 'Invalid worker token' 2;; esac
        state_open
        [ "$active" != "-" ] && [ "$1" = "g${generation}s${sequence}" ] || fail 'Stale worker token' 5
        active=-
        state_save
        printf '{"api_version":1,"prototype":true,"ok":true,"completed":true}\n'
        ;;
    *) fail 'Unsupported prototype command' 2;;
esac
