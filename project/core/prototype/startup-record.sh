# Shared exact preparation/active intent frame. Source only from a fixed dir.
startup_record_expected() {
candidate_result=$(
    exec 3>&1
    {
        snapshot | lua "$dir/homegate-startup.lua" candidate-body "$revision" "$configuration" "$desired" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
        candidate_status=$?
        printf 'HGSTARTUPCANDIDATESTATUS:%s\n' "$candidate_status" >&3
    } | sha256sum
) || fail 'Intent candidate digest unavailable'
candidate_status=HGSTARTUPCANDIDATESTATUS:0
newline='
'
case "$candidate_result" in
    "$candidate_status$newline"*) candidate_sum=${candidate_result#"$candidate_status$newline"};;
    *"$newline$candidate_status") candidate_sum=${candidate_result%"$newline$candidate_status"};;
    *) fail 'Intent candidate producer failed';;
esac
case "$candidate_sum" in *'  -') candidate_sum=${candidate_sum%'  -'};; *) fail 'Invalid candidate digest';; esac
case "$candidate_sum" in ''|*[!0-9a-f]*) fail 'Invalid candidate digest';; esac
[ "${#candidate_sum}" -eq 64 ] || fail 'Invalid candidate digest'
record_payload=$(printf '%s\n' HGSTARTUPINTENT1 homegate "$revision" "$desired" "$configuration" "$source_stamp" "$store_stamp" "$candidate_sum")
record_sum=$(printf '%s\n' "$record_payload" | sha256sum) || fail 'Intent record checksum unavailable';record_sum=${record_sum%% *}
record_body=$(printf '%s\n' "$record_payload" "$record_sum")
expected_sum=$(printf '%s\n' "$record_body" | sha256sum) || fail 'Intent record checksum unavailable';expected_sum=${expected_sum%% *}
 }
startup_record_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ] &&
        [ "$(stat -c %s "$1")" -eq "$((${#record_body}+1))" ] || return 1
    sum=$(sha256sum "$1") && [ "${sum%% *}" = "$expected_sum" ]
}
startup_record_framed() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = "$owner:600:1" ] &&
        [ "$(stat -c %s "$1")" -le 4096 ] || return 1
    exec 8<"$1" || return 1;framed_body=;count=0
    while [ "$count" -lt 9 ];do
        IFS= read -r line <&8 || return 1
        case "$count:$line" in 0:HGSTARTUPINTENT1|1:homegate|3:enabled|3:disabled) ;;
          0:*|1:*|3:*) return 1;; esac
        framed_body=${framed_body:+"$framed_body
"}$line;count=$((count+1))
    done
    IFS= read -r framed_sum <&8 || return 1
    if IFS= read -r line <&8;then return 1;fi;exec 8<&-
    [ "${#framed_sum}" -eq 64 ] || return 1
    sum=$(printf '%s\n' "$framed_body" | sha256sum) && [ "${sum%% *}" = "$framed_sum" ] || return 1
    # Reject unterminated trailing bytes and embedded NULs as well as lines.
    framed_full=$(printf '%s\n%s' "$framed_body" "$framed_sum")
    [ "$(stat -c %s "$1")" -eq "$((${#framed_full}+1))" ] || return 1
    framed_hash=$(printf '%s\n' "$framed_full" | sha256sum) || return 1
    sum=$(sha256sum "$1") && [ "${sum%% *}" = "${framed_hash%% *}" ]
}
