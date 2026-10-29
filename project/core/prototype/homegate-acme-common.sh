# Shared fixed private ACME job checks. Source only from the installed directory.
hg_exists() { [ -e "$1" ] || [ -L "$1" ]; }
hg_dir() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
hg_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ] && [ "$(stat -c %s "$1")" -le "${2:-262144}" ]; }
hg_hex() { [ "${#1}" -eq "$2" ] || return 1;case "$1" in *[!0-9a-f]*) return 1;;esac; }
HG_STORE=/etc/homegate/transactions
HG_RUN=/var/run/homegate
HG_ROOT=/etc/homegate/acme/jobs
HG_PATH=$HG_ROOT/$HG_JOB
hg_bound() { hg_file "$2" 0 && [ "$(stat -c %s "$2")" -eq 0 ] && [ "$(stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/$1)" = "$(stat -c '%d:%i:%u:%a:%h' "$2")" ]; }
hg_binding() {
 for hg_member in /etc/config/homegate "$HG_STORE/identity" "$HG_STORE/current";do
  hg_file "$hg_member" || return 1
  stat -c '%d:%i:%u:%a:%h:%s' "$hg_member" && sha256sum "$hg_member" || return 1
 done
 hg_revision=$(lua "$HG_DIR/cloudflare-codec.lua" context < "$HG_STORE/current") || return 1
 hg_file "$HG_STORE/gen-$hg_revision/manifest" && sha256sum "$HG_STORE/gen-$hg_revision/manifest"
}
hg_scope() { ash "$HG_DIR/homegate-config-prototype.sh" --persistent runtime-startup-snapshot-read 3>&1 4>&- 5>&- 8>&- 9>&- >/dev/null 2>/dev/null | lua "$HG_DIR/homegate-acme.lua" scope "$1" 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; }
hg_seal() { (cd "$HG_PATH" && sha256sum scope.json binding mode); }
hg_job_check() {
 hg_hex "$HG_JOB" 32 && hg_dir /etc/homegate && hg_dir /etc/homegate/acme && hg_dir "$HG_ROOT" && hg_dir "$HG_PATH" || return 1
 for hg_member in scope.json binding mode seal;do hg_file "$HG_PATH/$hg_member" 16384 || return 1;done
 [ "$(cat "$HG_PATH/seal")" = "$(hg_seal)" ] && [ "$(stat -c %s "$HG_PATH/seal")" -eq "$(hg_seal | wc -c)" ] || return 1
 hg_bound 8 "$HG_PATH/lock" && hg_bound 6 "$HG_RUN/frontend.lock" && hg_bound 7 "$HG_STORE/.supervisor.lock" && flock -n 8 && flock -n 6 && flock -n 7
}
hg_source_guard() {
 hg_job_check && [ "$(hg_binding)" = "$(cat "$HG_PATH/binding")" ] &&
 ash "$HG_DIR/homegate-config-prototype.sh" --persistent writer-check >/dev/null 2>/dev/null
}
hg_guard() {
 hg_source_guard &&
 ash "$HG_DIR/homegate-startup-active.sh" check >/dev/null 2>/dev/null
}
hg_challenges() {
 set --
 hg_dir "$HG_PATH/challenges" || return 1
 for hg_member in "$HG_PATH/challenges/"*;do
  hg_exists "$hg_member" || continue
  hg_name=${hg_member##*/};hg_key=${hg_name%.json}
  [ "$hg_name" = "$hg_key.json" ] && hg_hex "$hg_key" 64 && hg_file "$hg_member" 4096 || return 1
  set -- "$@" "$hg_key"
 done
 lua "$HG_DIR/homegate-acme.lua" clean-check "$HG_JOB" "$@"
}

# A stopped/cold task must be explicitly cleaned before another order. Valid
# historical success receipts remain private and are never automatically purged.
hg_jobs_clear() (
 if ! hg_exists "$HG_ROOT";then exit 0;fi
 hg_dir "$HG_ROOT" || exit 1
 hg_count=0
 for hg_candidate in "$HG_ROOT/"*;do
  hg_exists "$hg_candidate" || continue;hg_count=$((hg_count+1));[ "$hg_count" -le 16 ] || exit 1
  HG_JOB=${hg_candidate##*/};HG_PATH=$hg_candidate;hg_hex "$HG_JOB" 32 && hg_dir "$HG_PATH" || exit 1
  for hg_member in scope.json binding mode seal;do hg_file "$HG_PATH/$hg_member" 16384 || exit 1;done
  [ "$(cat "$HG_PATH/seal")" = "$(hg_seal)" ] || exit 1
  hg_file "$HG_PATH/lock" 0 && [ "$(stat -c %s "$HG_PATH/lock")" -eq 0 ] || exit 1
  exec 4>>"$HG_PATH/lock";flock -n 4 || exit 1
  hg_challenges && hg_file "$HG_PATH/result" 16384 || exit 1
  lua "$HG_DIR/homegate-acme.lua" read-report "$HG_JOB" > /dev/null || exit 1
  lua "$HG_DIR/homegate-acme.lua" clear-result "$HG_JOB" > /dev/null || exit 1
  exec 4>&-
 done
)
hg_schedule_seal() { (cd "$HG_RUN/acme-schedule" && sha256sum scope.json binding token boot); }
hg_schedule_check() {
 hg_hex "$1" 32 && hg_dir "$HG_RUN/acme-schedule" && hg_bound 9 "$HG_RUN/acme-schedule.lock" && flock -n 9 || return 1
 for hg_member in scope.json binding token boot seal;do hg_file "$HG_RUN/acme-schedule/$hg_member" 16384 || return 1;done
 [ "$(cat "$HG_RUN/acme-schedule/token")" = "$1" ] && [ "$(cat "$HG_RUN/acme-schedule/seal")" = "$(hg_schedule_seal)" ] &&
 [ "$(cat "$HG_RUN/acme-schedule/boot")" = "$(cat /proc/sys/kernel/random/boot_id)" ] &&
 [ "$(cat "$HG_RUN/acme-schedule/binding")" = "$(hg_binding)" ] &&
 [ "$(lua "$HG_DIR/homegate-acme.lua" session-id)" = "$2" ] && ! hg_exists "$HG_RUN/acme-schedule/stop"
}
