#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

extract_block() {
  block="$1"; out="$2"
  awk -v name="$block" '
    $0 == "define Package/homegate/" name { in_block=1; next }
    in_block && /^endef$/ { exit }
    in_block { print }
  ' "$ROOT/project/core/Makefile" | sed 's/\$\$/\$/g' > "$out"
  chmod +x "$out"
  sh -n "$out"
}

PREINST="$TMP/preinst"; PRERM="$TMP/prerm"; POSTINST="$TMP/postinst"; POSTRM="$TMP/postrm"
extract_block preinst "$PREINST"
extract_block prerm "$PRERM"
extract_block postinst "$POSTINST"
extract_block postrm "$POSTRM"

LUCI_POSTRM="$TMP/luci-postrm"
awk '
  $0 == "define Package/luci-app-homegate/postrm" { in_block=1; next }
  in_block && /^endef$/ { exit }
  in_block { print }
' "$ROOT/project/luci/Makefile" | sed 's/\$\$/\$/g' > "$LUCI_POSTRM"
chmod +x "$LUCI_POSTRM"
sh -n "$LUCI_POSTRM"

PURGE_HELPER="$ROOT/project/core/files/usr/sbin/homegate-purge"
sh -n "$PURGE_HELPER"

# Static contract from 1.0.1 onward:
# - normal version upgrade preserves runtime intent and persistent data;
# - QWRT force-reinstall (remove -> install) preserves persistent data;
# - a real uninstall is FULL PURGE;
# - homegate-purge removes reverse dependents so Core postrm can finish the purge.
grep -q 'snapshot_kind=legacy_desired_state' "$PREINST"
grep -q 'uci -q get homegate.main.enabled' "$PREINST"
grep -q 'snapshot_kind=sdk_prerm' "$PRERM"
grep -q 'PKG_UPGRADE' "$PRERM"
grep -q 'HOMEGATE_PACKAGE_REINSTALL_REQUEST' "$PRERM"
grep -q -- '--force-reinstall' "$PRERM"
grep -q 'HOMEGATE_PACKAGE_CONFIG_STASH' "$PRERM"
grep -q 'cp -p.*config_file.*config_stash' "$PRERM"
! grep -q 'rm -rf.*runtime_dir' "$PRERM"
! grep -q 'rm -f.*log_file' "$PRERM"
grep -q 'HOMEGATE_PACKAGE_REINSTALL_REQUEST' "$POSTRM"
grep -q 'mv.*config_stash.*config_file' "$POSTRM"
grep -q 'rm -rf.*runtime_dir' "$POSTRM"
grep -q 'rm -f.*log_file' "$POSTRM"
grep -q 'rm -rf.*data_dir' "$POSTRM"
grep -q 'FULL PURGE' "$POSTRM"
grep -q 'force-removal-of-dependent-packages' "$PURGE_HELPER"
grep -q 'homegate-purge: root required' "$PURGE_HELPER"
grep -q 'HOMEGATE_PURGE_MARKER' "$PURGE_HELPER"
grep -q 'HOMEGATE_LUCI_PURGE_HELPER' "$LUCI_POSTRM"
grep -q 'HOMEGATE_LUCI_PURGE_DELAY' "$LUCI_POSTRM"
grep -q 'HOMEGATE_UNINSTALL_LOG' "$LUCI_POSTRM"
grep -q -- '--force-reinstall' "$LUCI_POSTRM"
grep -q 'DEPENDS:=+homegate' "$ROOT/project/luci/Makefile"
! awk '
  $0 == "define Package/luci-i18n-homegate-zh-cn" { in_block=1; next }
  in_block && /^endef$/ { exit }
  in_block { print }
' "$ROOT/project/luci/Makefile" | grep -q 'luci-app-homegate'

INIT="$ROOT/project/core/files/etc/init.d/homegate"
grep -q 'HOMEGATE_PACKAGE_UPGRADE_STATE' "$INIT"
! grep -q '^enable() {' "$INIT"
grep -q "grep -qx 'was_running=0'" "$INIT"
! grep -q 'pidof homegate.*return 0' "$INIT"

FAKEBIN="$TMP/bin"; mkdir -p "$FAKEBIN"
cat > "$FAKEBIN/pidof" <<'EOF_PID'
#!/bin/sh
[ "$1" = homegate ] || exit 1
count_file="$HOMEGATE_TEST_PIDOF_COUNT"
count=0
[ -f "$count_file" ] && count=$(cat "$count_file")
count=$((count + 1)); echo "$count" > "$count_file"
case "${HOMEGATE_TEST_PIDOF_MODE:-stopped}" in
  running) echo 12345; exit 0 ;;
  delayed)
    limit="${HOMEGATE_TEST_PIDOF_DELAY_CALLS:-2}"
    [ "$count" -le "$limit" ] && { echo 12345; exit 0; }
    exit 1 ;;
  *) exit 1 ;;
esac
EOF_PID
chmod +x "$FAKEBIN/pidof"
cat > "$FAKEBIN/sleep" <<'EOF_SLEEP'
#!/bin/sh
exit 0
EOF_SLEEP
chmod +x "$FAKEBIN/sleep"
cat > "$FAKEBIN/uci" <<'EOF_UCI'
#!/bin/sh
[ "$1" = "-q" ] && shift
[ "$1" = "get" ] && [ "$2" = "homegate.main.enabled" ] && {
  echo "${HOMEGATE_TEST_UCI_ENABLED:-1}"
  exit 0
}
exit 1
EOF_UCI
chmod +x "$FAKEBIN/uci"

FAKE_INIT="$TMP/homegate-init"
cat > "$FAKE_INIT" <<'EOF_INIT'
#!/bin/sh
case "$1" in
  enabled) [ "${HOMEGATE_TEST_INIT_ENABLED:-1}" = "1" ] ;;
  *) echo "init:$1" >> "$HOMEGATE_TEST_CALLS"; exit 0 ;;
esac
EOF_INIT
chmod +x "$FAKE_INIT"
FAKE_CORE="$TMP/homegate-core"
cat > "$FAKE_CORE" <<'EOF_CORE'
#!/bin/sh
echo "core:$1" >> "$HOMEGATE_TEST_CALLS"
exit 0
EOF_CORE
chmod +x "$FAKE_CORE"

TEST_PRERM="$TMP/prerm-test"
sed -e "s#/etc/init.d/homegate#$FAKE_INIT#g" -e "s#/usr/bin/homegate#$FAKE_CORE#g" "$PRERM" > "$TEST_PRERM"
chmod +x "$TEST_PRERM"

CALLS="$TMP/calls"; PIDCOUNT="$TMP/pidcount"; STATE="$TMP/package-upgrade-state"; INSTALLED="$TMP/homegate.control"
REINSTALL_REQ="$TMP/reinstall-request"; CONFIG="$TMP/etc/config/homegate"; STASH="$TMP/config-stash"
DATA="$TMP/etc/homegate"; RUNTIME="$TMP/var/run/homegate"; LOG="$TMP/var/log/homegate.log"; TEMPDIR="$TMP/tmp"
mkdir -p "$(dirname "$CONFIG")" "$(dirname "$LOG")" "$TEMPDIR"

run_preinst() {
  pid_mode="$1"; uci_enabled="$2"; action="${3:-upgrade}"
  HOMEGATE_PACKAGE_UPGRADE_STATE="$STATE" HOMEGATE_PACKAGE_INSTALLED_CONTROL="$INSTALLED" \
  HOMEGATE_PACKAGE_INIT="$FAKE_INIT" HOMEGATE_TEST_UCI_ENABLED="$uci_enabled" HOMEGATE_TEST_CALLS="$CALLS" \
  HOMEGATE_TEST_PIDOF_COUNT="$PIDCOUNT" HOMEGATE_TEST_PIDOF_MODE="$pid_mode" \
  PATH="$FAKEBIN:$PATH" "$PREINST" "$action" 1.0.0-1
}
run_prerm() {
  pid_mode="$1"; upgrade="$2"; opkg_cmd="${3:-opkg remove homegate}"; delay="${4:-2}"
  HOMEGATE_PACKAGE_UPGRADE_STATE="$STATE" HOMEGATE_PACKAGE_REINSTALL_REQUEST="$REINSTALL_REQ" \
  HOMEGATE_PACKAGE_OPKG_CMDLINE="$opkg_cmd" HOMEGATE_PACKAGE_CONFIG_FILE="$CONFIG" \
  HOMEGATE_PACKAGE_CONFIG_STASH="$STASH" HOMEGATE_PACKAGE_DATA_DIR="$DATA" \
  HOMEGATE_PACKAGE_RUNTIME_DIR="$RUNTIME" HOMEGATE_PACKAGE_LOG_FILE="$LOG" HOMEGATE_PACKAGE_TEMP_DIR="$TEMPDIR" \
  HOMEGATE_PACKAGE_INIT="$FAKE_INIT" HOMEGATE_TEST_CALLS="$CALLS" HOMEGATE_TEST_PIDOF_COUNT="$PIDCOUNT" \
  HOMEGATE_TEST_PIDOF_MODE="$pid_mode" HOMEGATE_TEST_PIDOF_DELAY_CALLS="$delay" PKG_UPGRADE="$upgrade" \
  PATH="$FAKEBIN:$PATH" "$TEST_PRERM" "${5:-remove}"
}
run_postrm() {
  action="${1:-remove}"; upgrade="${2:-0}"; mode="${3:-stopped}"; delay="${4:-2}"
  rm -f "$PIDCOUNT"
  HOMEGATE_PACKAGE_UPGRADE_STATE="$STATE" HOMEGATE_PACKAGE_REINSTALL_REQUEST="$REINSTALL_REQ" \
  HOMEGATE_PACKAGE_CONFIG_FILE="$CONFIG" HOMEGATE_PACKAGE_CONFIG_STASH="$STASH" \
  HOMEGATE_PACKAGE_DATA_DIR="$DATA" HOMEGATE_PACKAGE_RUNTIME_DIR="$RUNTIME" HOMEGATE_PACKAGE_LOG_FILE="$LOG" \
  HOMEGATE_PACKAGE_TEMP_DIR="$TEMPDIR" HOMEGATE_TEST_PIDOF_COUNT="$PIDCOUNT" \
  HOMEGATE_TEST_PIDOF_MODE="$mode" HOMEGATE_TEST_PIDOF_DELAY_CALLS="$delay" \
  PKG_UPGRADE="$upgrade" PATH="$FAKEBIN:$PATH" "$POSTRM" "$action"
}
run_start_service() {
  mode="$1"; uci_enabled="${2:-1}"
  HOMEGATE_PACKAGE_UPGRADE_STATE="$STATE" HOMEGATE_TEST_PIDOF_COUNT="$PIDCOUNT" \
  HOMEGATE_TEST_PIDOF_MODE="$mode" HOMEGATE_TEST_UCI_ENABLED="$uci_enabled" HOMEGATE_TEST_CALLS="$CALLS" \
  PATH="$FAKEBIN:$PATH" sh -c '
    procd_open_instance() { echo open_instance >> "$HOMEGATE_TEST_CALLS"; }
    procd_set_param() { echo "set_param:$*" >> "$HOMEGATE_TEST_CALLS"; }
    procd_close_instance() { echo close_instance >> "$HOMEGATE_TEST_CALLS"; }
    . "$1"
    start_service
  ' sh "$INIT"
}
assert_state() {
  r="$1"; kind="$2"
  grep -qx "was_running=$r" "$STATE"
  grep -qx "snapshot_kind=$kind" "$STATE"
}
reset_persistent() {
  rm -rf "$TMP/etc" "$TMP/var" "$STASH" "$REINSTALL_REQ" "$STATE" "$PIDCOUNT" "$TEMPDIR"
  mkdir -p "$(dirname "$CONFIG")" "$DATA/certs" "$DATA/access" "$RUNTIME" "$(dirname "$LOG")" "$TEMPDIR/homegate"
  printf 'config homegate main\n' > "$CONFIG"
  printf 'cert\n' > "$DATA/certs/fullchain.pem"
  printf 'access\n' > "$DATA/access/cache"
  printf 'runtime\n' > "$RUNTIME/state"
  printf 'log\n' > "$LOG"
  printf 'temp\n' > "$TEMPDIR/homegate/state"
}

# Fresh install has no prior control and must not create migration state.
: > "$CALLS"; rm -f "$PIDCOUNT" "$STATE" "$INSTALLED"
run_preinst stopped 1 install
[ ! -e "$STATE" ]

# First legacy -> SDK migration preserves established desired-state behavior.
: > "$INSTALLED"
rm -f "$PIDCOUNT" "$STATE"; run_preinst stopped 1 upgrade; assert_state 1 legacy_desired_state
rm -f "$PIDCOUNT" "$STATE"; run_preinst stopped 0 upgrade; assert_state 0 legacy_desired_state

# SDK-aware normal upgrade captures running state before stop and survives preinst.
for spec in 'stopped 0' 'delayed 1'; do
  set -- $spec; mode="$1"; expected_running="$2"
  : > "$CALLS"; rm -f "$PIDCOUNT" "$STATE"
  run_prerm "$mode" 1 'opkg install /tmp/homegate_1.0.1-1.ipk' 1 upgrade
  assert_state "$expected_running" sdk_prerm
  before=$(cat "$STATE")
  rm -f "$PIDCOUNT"
  run_preinst stopped 1 upgrade
  [ "$(cat "$STATE")" = "$before" ]
done

# start_service consumes upgrade marker and restores running/stopped state.
for r in 0 1; do
  : > "$CALLS"; rm -f "$PIDCOUNT" "$STATE"
  printf '%s\n' "was_running=$r" 'snapshot_kind=sdk_prerm' > "$STATE"
  run_start_service stopped 1
  [ ! -e "$STATE" ]
  if [ "$r" = 1 ]; then grep -q '^open_instance$' "$CALLS"; else ! grep -q '^open_instance$' "$CALLS"; fi
done

# QWRT force-reinstall is remove -> install but is NOT an uninstall: preserve
# /etc/config/homegate and /etc/homegate, while clearing runtime/log for the remove phase.
reset_persistent
: > "$CALLS"
run_prerm stopped 0 'opkg install --force-reinstall /tmp/homegate_1.0.1-1.ipk'
[ -f "$REINSTALL_REQ" ]
[ -f "$STASH" ]
[ -f "$CONFIG" ]
[ -f "$DATA/certs/fullchain.pem" ]
printf 'recreated-after-stop\n' > "$RUNTIME/firewall.json"
rm -f "$CONFIG"  # simulate opkg removing an unmodified conffile
run_postrm remove 0 delayed 2
[ -f "$CONFIG" ]
[ ! -e "$STASH" ]
[ ! -e "$REINSTALL_REQ" ]
[ -f "$DATA/certs/fullchain.pem" ]
[ -f "$DATA/access/cache" ]
[ ! -e "$RUNTIME" ]
[ ! -e "$LOG" ]

# Real uninstall is FULL PURGE. Nothing HomeGate owns persistently may survive.
reset_persistent
printf 'new-package-candidate\n' > "$CONFIG-opkg"
printf 'importing\n' > "$(dirname "$CONFIG")/.homegate.importing"
printf 'tmp\n' > "$TEMPDIR/homegate-before-import-123"
: > "$CALLS"
run_prerm stopped 0 'opkg remove --force-removal-of-dependent-packages homegate'
[ ! -e "$REINSTALL_REQ" ]
[ ! -e "$STASH" ]
run_postrm remove 0 delayed 1
[ ! -e "$CONFIG" ]
[ ! -e "$CONFIG-opkg" ]
[ ! -e "$(dirname "$CONFIG")/.homegate.importing" ]
[ ! -e "$DATA" ]
[ ! -e "$RUNTIME" ]
[ ! -e "$LOG" ]
[ ! -e "$TEMPDIR/homegate" ]
[ ! -e "$STATE" ]

# A postrm reached as part of a normal version upgrade must not perform remove cleanup.
reset_persistent
run_postrm upgrade 1 stopped
[ -e "$RUNTIME" ]
[ -e "$LOG" ]
[ -f "$CONFIG" ]
[ -f "$DATA/certs/fullchain.pem" ]

# No marker: fresh/manual start follows desired UCI state and declares procd.
: > "$CALLS"; rm -f "$PIDCOUNT" "$STATE"
run_start_service stopped 1
grep -q '^open_instance$' "$CALLS"
: > "$CALLS"; rm -f "$PIDCOUNT" "$STATE"
run_start_service stopped 0
! grep -q '^open_instance$' "$CALLS"

# Repeated start with existing daemon must still declare the full procd definition.
: > "$CALLS"; rm -f "$PIDCOUNT" "$STATE"
run_start_service running 1
grep -q '^open_instance$' "$CALLS"
grep -q '^close_instance$' "$CALLS"

# postinst waits out a retiring daemon and delegates start to default_postinst.
rm -f "$PIDCOUNT"
HOMEGATE_TEST_PIDOF_COUNT="$PIDCOUNT" HOMEGATE_TEST_PIDOF_MODE=delayed HOMEGATE_TEST_PIDOF_DELAY_CALLS=3 \
PATH="$FAKEBIN:$PATH" "$POSTINST"
[ "$(cat "$PIDCOUNT")" -ge 4 ]

# Offline/rootfs packaging must never touch the live test state.
reset_persistent
orig_cfg=$(sha256sum "$CONFIG" | awk '{print $1}')
IPKG_INSTROOT="$TMP/offline" HOMEGATE_PACKAGE_UPGRADE_STATE="$STATE" HOMEGATE_PACKAGE_INSTALLED_CONTROL="$INSTALLED" \
HOMEGATE_PACKAGE_INIT="$FAKE_INIT" HOMEGATE_TEST_CALLS="$CALLS" HOMEGATE_TEST_PIDOF_COUNT="$PIDCOUNT" \
HOMEGATE_TEST_PIDOF_MODE=stopped PATH="$FAKEBIN:$PATH" "$PREINST" upgrade 1.0.0-1
IPKG_INSTROOT="$TMP/offline" HOMEGATE_PACKAGE_UPGRADE_STATE="$STATE" HOMEGATE_PACKAGE_REINSTALL_REQUEST="$REINSTALL_REQ" \
HOMEGATE_PACKAGE_OPKG_CMDLINE='opkg remove homegate' HOMEGATE_PACKAGE_CONFIG_FILE="$CONFIG" HOMEGATE_PACKAGE_CONFIG_STASH="$STASH" \
HOMEGATE_PACKAGE_DATA_DIR="$DATA" HOMEGATE_PACKAGE_RUNTIME_DIR="$RUNTIME" HOMEGATE_PACKAGE_LOG_FILE="$LOG" HOMEGATE_PACKAGE_TEMP_DIR="$TEMPDIR" \
HOMEGATE_TEST_CALLS="$CALLS" HOMEGATE_TEST_PIDOF_COUNT="$PIDCOUNT" HOMEGATE_TEST_PIDOF_MODE=stopped \
PKG_UPGRADE=0 PATH="$FAKEBIN:$PATH" "$TEST_PRERM" remove
IPKG_INSTROOT="$TMP/offline" PATH="$FAKEBIN:$PATH" "$POSTINST"
IPKG_INSTROOT="$TMP/offline" HOMEGATE_PACKAGE_UPGRADE_STATE="$STATE" HOMEGATE_PACKAGE_REINSTALL_REQUEST="$REINSTALL_REQ" \
HOMEGATE_PACKAGE_CONFIG_FILE="$CONFIG" HOMEGATE_PACKAGE_CONFIG_STASH="$STASH" HOMEGATE_PACKAGE_DATA_DIR="$DATA" \
HOMEGATE_PACKAGE_RUNTIME_DIR="$RUNTIME" HOMEGATE_PACKAGE_LOG_FILE="$LOG" HOMEGATE_PACKAGE_TEMP_DIR="$TEMPDIR" \
HOMEGATE_TEST_PIDOF_COUNT="$PIDCOUNT" HOMEGATE_TEST_PIDOF_MODE=stopped PKG_UPGRADE=0 PATH="$FAKEBIN:$PATH" "$POSTRM" remove
[ "$(sha256sum "$CONFIG" | awk '{print $1}')" = "$orig_cfg" ]
[ -f "$DATA/certs/fullchain.pem" ]
[ -f "$RUNTIME/state" ]
[ -f "$LOG" ]

# Plain removal of the user-facing LuCI app schedules product-wide FULL PURGE
# after opkg releases its lock. Upgrade/force-reinstall/offline/purge-recursion do not.
FAKE_LUCI_PURGE="$TMP/fake-homegate-purge"
LUCI_PURGE_CALL="$TMP/luci-purge-call"
LUCI_PURGE_MARKER="$TMP/luci-purge-marker"
LUCI_PURGE_LOG="$TMP/luci-purge.log"
cat > "$FAKE_LUCI_PURGE" <<'EOF_LUCI_PURGE'
#!/bin/sh
printf 'called\n' >> "$HOMEGATE_TEST_LUCI_PURGE_CALL"
rm -f "$HOMEGATE_PURGE_MARKER"
exit 0
EOF_LUCI_PURGE
chmod +x "$FAKE_LUCI_PURGE"
run_luci_postrm() {
  action="$1"; upgrade="$2"; opkg_cmd="$3"; instroot="${4:-}"
  IPKG_INSTROOT="$instroot" PKG_UPGRADE="$upgrade" HOMEGATE_PACKAGE_OPKG_CMDLINE="$opkg_cmd" \
  HOMEGATE_PURGE_MARKER="$LUCI_PURGE_MARKER" HOMEGATE_LUCI_PURGE_HELPER="$FAKE_LUCI_PURGE" \
  HOMEGATE_LUCI_PURGE_DELAY=0 HOMEGATE_UNINSTALL_LOG="$LUCI_PURGE_LOG" \
  HOMEGATE_TEST_LUCI_PURGE_CALL="$LUCI_PURGE_CALL" "$LUCI_POSTRM" "$action"
}
wait_luci_purge() {
  n=0
  while [ ! -f "$LUCI_PURGE_CALL" ] && [ "$n" -lt 50 ]; do /bin/sleep 0.01 2>/dev/null || sleep 1; n=$((n+1)); done
}
rm -f "$LUCI_PURGE_CALL" "$LUCI_PURGE_MARKER"
run_luci_postrm remove 0 'opkg remove luci-app-homegate'
wait_luci_purge
grep -qx called "$LUCI_PURGE_CALL"
[ ! -e "$LUCI_PURGE_MARKER" ]

rm -f "$LUCI_PURGE_CALL" "$LUCI_PURGE_MARKER"
run_luci_postrm upgrade 1 'opkg install /tmp/luci-app-homegate_1.0.1-1_all.ipk'
sleep 0.05 2>/dev/null || true
[ ! -e "$LUCI_PURGE_CALL" ]

rm -f "$LUCI_PURGE_CALL" "$LUCI_PURGE_MARKER"
run_luci_postrm remove 0 'opkg install --force-reinstall /tmp/luci-app-homegate_1.0.1-1_all.ipk'
sleep 0.05 2>/dev/null || true
[ ! -e "$LUCI_PURGE_CALL" ]

printf 'purge=1\n' > "$LUCI_PURGE_MARKER"
rm -f "$LUCI_PURGE_CALL"
run_luci_postrm remove 0 'opkg remove --force-removal-of-dependent-packages homegate'
sleep 0.05 2>/dev/null || true
[ ! -e "$LUCI_PURGE_CALL" ]
rm -f "$LUCI_PURGE_MARKER"

rm -f "$LUCI_PURGE_CALL"
run_luci_postrm remove 0 'opkg remove luci-app-homegate' "$TMP/offline"
sleep 0.05 2>/dev/null || true
[ ! -e "$LUCI_PURGE_CALL" ]

# Exercise the real helper with controlled identity and isolated cache paths.
# Production root checks and purge behavior remain unchanged. Only this test
# copy redirects the helper's fixed cache paths into the mktemp sandbox.
FAKEHELPERBIN="$TMP/helper-bin"; mkdir -p "$FAKEHELPERBIN"
HELPER_ROOT="$TMP/helper-root"
TEST_HELPER="$TMP/homegate-purge-test"
sed -e "s#/tmp/luci-indexcache#$HELPER_ROOT/tmp/luci-indexcache#g" \
    -e "s#/tmp/luci-modulecache/#$HELPER_ROOT/tmp/luci-modulecache/#g" \
    -e "s#/usr/lib/lua/luci/view/homegate#$HELPER_ROOT/usr/lib/lua/luci/view/homegate#g" \
    "$PURGE_HELPER" > "$TEST_HELPER"
chmod +x "$TEST_HELPER"
sh -n "$TEST_HELPER"
cat > "$FAKEHELPERBIN/id" <<'EOF_ID'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = -u ] || exit 125
case "$HOMEGATE_TEST_UID" in 0|1000) printf '%s\n' "$HOMEGATE_TEST_UID" ;; *) exit 125 ;; esac
EOF_ID
cat > "$FAKEHELPERBIN/opkg" <<'EOF_OPKG'
#!/bin/sh
printf '%s\n' "$*" >> "$HOMEGATE_TEST_OPKG_CALL"
if [ "${1:-}" = "--help" ]; then
  echo '  --force-removal-of-dependent-packages'
  exit 0
fi
[ "$*" = 'remove --force-removal-of-dependent-packages homegate' ] || exit 125
# Prove the marker exists during removal, not merely before/after the test.
grep -qx 'purge=1' "$HOMEGATE_PURGE_MARKER" || exit 125
stat -c '%a' "$HOMEGATE_PURGE_MARKER" > "$HOMEGATE_TEST_MARKER_MODE"
exit "$HOMEGATE_TEST_OPKG_RESULT"
EOF_OPKG
chmod +x "$FAKEHELPERBIN/id" "$FAKEHELPERBIN/opkg"
OPKGCALL="$TMP/opkg-call"
HELPER_MARKER="$TMP/helper-purge-marker"
MARKER_MODE="$TMP/helper-marker-mode"
prepare_helper_cache() {
  mkdir -p "$HELPER_ROOT/tmp/luci-modulecache" "$HELPER_ROOT/usr/lib/lua/luci/view/homegate"
  printf 'cache\n' > "$HELPER_ROOT/tmp/luci-indexcache"
  printf 'module\n' > "$HELPER_ROOT/tmp/luci-modulecache/entry"
  rm -f "$OPKGCALL" "$HELPER_MARKER" "$MARKER_MODE"
}
run_helper() {
  HOMEGATE_TEST_UID="$1" HOMEGATE_TEST_OPKG_RESULT="$2" \
  HOMEGATE_TEST_OPKG_CALL="$OPKGCALL" HOMEGATE_PURGE_MARKER="$HELPER_MARKER" \
  HOMEGATE_TEST_MARKER_MODE="$MARKER_MODE" PATH="$FAKEHELPERBIN:$PATH" "$TEST_HELPER"
}

# Non-root must fail exactly before marker creation, opkg or cache cleanup.
prepare_helper_cache
if run_helper 1000 0 > "$TMP/helper-nonroot.log" 2>&1; then
  echo 'purge helper unexpectedly accepted non-root' >&2; exit 1
else
  rc=$?
fi
[ "$rc" -eq 1 ]
grep -qx 'homegate-purge: root required' "$TMP/helper-nonroot.log"
[ ! -e "$OPKGCALL" ] && [ ! -e "$HELPER_MARKER" ] && [ ! -e "$MARKER_MODE" ]
[ -f "$HELPER_ROOT/tmp/luci-indexcache" ] && [ -f "$HELPER_ROOT/tmp/luci-modulecache/entry" ]
[ -d "$HELPER_ROOT/usr/lib/lua/luci/view/homegate" ]
echo 'purge helper non-root rejection: PASS'

# Simulated root succeeds without elevating the actual test process.
prepare_helper_cache
run_helper 0 0
grep -qx -- '--help' "$OPKGCALL"
grep -qx 'remove --force-removal-of-dependent-packages homegate' "$OPKGCALL"
[ "$(wc -l < "$OPKGCALL")" -eq 2 ]
grep -qx '600' "$MARKER_MODE"
[ ! -e "$HELPER_MARKER" ]
[ ! -e "$HELPER_ROOT/tmp/luci-indexcache" ] && [ ! -e "$HELPER_ROOT/tmp/luci-modulecache/entry" ]
[ ! -d "$HELPER_ROOT/usr/lib/lua/luci/view/homegate" ]
echo 'purge helper simulated-root removal and marker cleanup: PASS'

# A failing opkg must propagate its exact status and still clean the marker;
# successful-uninstall cache cleanup must not run in this branch.
prepare_helper_cache
if run_helper 0 23; then
  echo 'purge helper swallowed opkg failure' >&2; exit 1
else
  rc=$?
fi
[ "$rc" -eq 23 ]
[ "$(wc -l < "$OPKGCALL")" -eq 2 ]
grep -qx 'remove --force-removal-of-dependent-packages homegate' "$OPKGCALL"
grep -qx '600' "$MARKER_MODE"
[ ! -e "$HELPER_MARKER" ]
[ -f "$HELPER_ROOT/tmp/luci-indexcache" ] && [ -f "$HELPER_ROOT/tmp/luci-modulecache/entry" ]
[ -d "$HELPER_ROOT/usr/lib/lua/luci/view/homegate" ]
echo 'purge helper opkg failure propagation and marker cleanup: PASS'

echo "package lifecycle smoke: PASS"
