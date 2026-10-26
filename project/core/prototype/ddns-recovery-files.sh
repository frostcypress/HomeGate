# Internal bounded cache inspection. Caller supplies fixed private run and helpers.
ddns_cache_status() {
    drc_cache=$run/ddns-state;drc_state=absent;drc_count=0
    if exists "$drc_cache"; then
        private_dir "$drc_cache" || { printf 'unsafe\n';return; }
        drc_state=valid
        for drc_file in "$drc_cache/"* "$drc_cache/".[!.]* "$drc_cache/"..?*; do
            exists "$drc_file" || continue
            private_file "$drc_file" || { printf 'unsafe\n';return; }
            drc_name=${drc_file##*/};drc_limit=4096
            case "$drc_name" in .*.next|.*.result) drc_id=${drc_name#.};drc_id=${drc_id%.*};drc_state=incomplete;drc_limit=65536;;
                .*) printf 'unsafe\n';return;; *) drc_id=$drc_name;; esac
            case "$drc_id" in ''|*[!a-zA-Z0-9_-]*) printf 'unsafe\n';return;; esac
            [ "${#drc_id}" -le 64 ] && [ "$(stat -c %s "$drc_file")" -le "$drc_limit" ] || { printf 'unsafe\n';return; }
            drc_count=$((drc_count+1));[ "$drc_count" -le 192 ] || { printf 'unsafe\n';return; }
        done
    fi
    printf '%s\n' "$drc_state"
}
