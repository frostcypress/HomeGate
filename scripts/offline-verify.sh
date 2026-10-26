#!/bin/sh
# Verifier revision 3: configured APK architectures; retain private recorder paths.
# One command, no router configuration writes. Optional --dns prompts only for
# credentials and performs read-only zone discovery in a separate process.
set -u
set +x
umask 077
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${HOMEGATE_VERIFY_OUT:-"/tmp/homegate-verification-$(date +%Y%m%d-%H%M%S)-$$"}
mkdir -p "$OUT" || exit 1
chmod 700 "$OUT"
LOG="$OUT/verification.log"
PRIVATE=$(mktemp -d /tmp/homegate-verify-private-XXXXXX) || exit 1
TTY_HIDDEN=0
cleanup() { if [ "$TTY_HIDDEN" = 1 ];then stty echo </dev/tty 2>/dev/null || true;fi; rm -rf "$PRIVATE"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
FAILED=0
EXPECTED_VERSION=${HOMEGATE_VERIFY_EXPECTED_VERSION:-1.3.0-131}
record() { printf '%s\n' "$*" | tee -a "$LOG"; }
run() {
 name=$1; shift
 if "$@" >"$OUT/$name.log" 2>&1; then record "PASS $name"
 else FAILED=1; record "FAIL $name (see $name.log)"
 fi
}
inventory() {
 name=$1;shift
 if "$@" >"$OUT/$name.log" 2>&1;then record "INFO $name snapshot recorded (inspect JSON health fields)"
 else FAILED=1;record "FAIL $name snapshot command";fi
}
record 'HomeGate automatic verification: offline fixtures + read-only inventory'
record 'VERIFIER_REVISION 3'
record "UTC $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
if ! command -v homegate >/dev/null 2>&1; then record 'FAIL core-not-installed'; exit 1; fi
run core-version homegate version
if grep -Eq '"version"[[:space:]]*:[[:space:]]*"'"$EXPECTED_VERSION"'"' "$OUT/core-version.log"; then record 'PASS complete-core-release';else FAILED=1;record "FAIL complete-core-release expected=$EXPECTED_VERSION";fi
run isolated-frontend homegate selftest
run installed-config homegate check
inventory runtime-status homegate status
inventory network-status homegate network-resolve
inventory proxy-status homegate proxy-status
inventory access-status homegate access-status
inventory access-recent homegate access-recent
inventory firewall-status homegate firewall-status
inventory certificate-status homegate cert-status
inventory wol-status homegate wol-status
inventory board ubus call system board
if command -v apk >/dev/null 2>&1 && ! command -v opkg >/dev/null 2>&1; then
 run package-tool-default-architecture apk --print-arch
 if [ -r "$HERE/arm64-profile.sh" ];then
  . "$HERE/arm64-profile.sh"
  if hg_apk_arch >"$OUT/package-architecture-selection.log" 2>&1;then
   printf '%s\n' "$HG_ARCH" >"$OUT/package-architecture.log"
   record "INFO effective-APK-architecture $HG_ARCH source=$HG_ARCH_SOURCE default=$HG_DEFAULT_ARCH"
  else FAILED=1;record 'FAIL effective-APK-architecture';printf 'unknown\n' >"$OUT/package-architecture.log";fi
 else FAILED=1;record 'FAIL missing-architecture-helper';printf 'unknown\n' >"$OUT/package-architecture.log";fi
 actual_arch=$(cat "$OUT/package-architecture.log")
 expected_arch=${HOMEGATE_VERIFY_EXPECTED_ARCH:-$actual_arch}
 if command -v hg_supported_arch >/dev/null 2>&1 && hg_supported_arch "$actual_arch";then
  if [ "$actual_arch" = "$expected_arch" ] && [ "$(uname -m)" = aarch64 ];then record "PASS target-architecture $actual_arch";else FAILED=1;record "FAIL target-architecture actual=$actual_arch expected=$expected_arch kernel=$(uname -m)";fi
 else FAILED=1;record "FAIL unsupported-architecture $actual_arch";fi
 apk_version="${EXPECTED_VERSION%-*}-r${EXPECTED_VERSION##*-}"
 for package in homegate luci-app-homegate luci-i18n-homegate-zh-cn; do
  run "package-$package" apk list -I "$package"
  if grep -Eq "^$package-$apk_version([[:space:]]|$)" "$OUT/package-$package.log";then record "PASS release-$package";else FAILED=1;record "FAIL release-$package";fi
 done
 if grep -Eq "^homegate-$apk_version[[:space:]]+$actual_arch([[:space:]]|$)" "$OUT/package-homegate.log";then record 'PASS installed-core-architecture';else FAILED=1;record 'FAIL installed-core-architecture';fi
 if command -v ubus >/dev/null 2>&1; then run native-rpc-methods ubus -v list homegate
  if [ ! -s "$OUT/native-rpc-methods.log" ];then FAILED=1;record 'FAIL native-rpc-not-registered';fi
 fi
else
 run package-architecture opkg print-architecture
 for package in homegate luci-app-homegate luci-i18n-homegate-zh-cn; do
  run "package-$package" opkg status "$package"
  if grep -Fqx "Version: $EXPECTED_VERSION" "$OUT/package-$package.log";then record "PASS release-$package";else FAILED=1;record "FAIL release-$package";fi
 done
 installed_arch=$(sed -n 's/^Architecture: //p' "$OUT/package-homegate.log")
 case "$installed_arch" in aarch64|aarch64_generic|aarch64_cortex-a53|aarch64_cortex-a72)
  if [ "$(uname -m)" = aarch64 ] && awk -v a="$installed_arch" '$1=="arch" && $2==a {found=1} END{exit !found}' "$OUT/package-architecture.log";then record "PASS installed-core-architecture $installed_arch";else FAILED=1;record 'FAIL installed-core-architecture';fi;;
 *) FAILED=1;record "FAIL unsupported-installed-architecture $installed_arch";;esac
fi
for command in uci ubus ip ip6tables; do
 if command -v "$command" >/dev/null 2>&1; then record "PASS dependency-$command"
 else FAILED=1;record "FAIL dependency-$command";fi
done
if [ -d "$HERE/offline-tests" ]; then
 if (cd "$HERE" && sha256sum -c offline-tests.SHA256SUMS) >"$OUT/offline-test-integrity.log" 2>&1; then
  record 'PASS offline-test-integrity'
  for compressed in "$HERE"/offline-tests/*.test.gz; do
   [ -f "$compressed" ] || continue
   name=$(basename "$compressed" .test.gz)
   if gzip -dc "$compressed" >"$PRIVATE/core.test"; then
    chmod 700 "$PRIVATE/core.test"
    run "isolated-core-$name" env HOMEGATE_ACCESS_RECENT="$PRIVATE/access-$name.json" "$PRIVATE/core.test" -test.v -test.timeout=120s
   else FAILED=1;record "FAIL decompress-$name"
   fi
   rm -f "$PRIVATE/core.test"
  done
 else FAILED=1;record 'FAIL offline-test-integrity';fi
else record 'SKIP full-offline-core-suite: offline-tests folder absent';fi
if [ "${1:-}" = '--dns' ]; then
 if [ ! -r /dev/tty ]; then record 'SKIP live-DNS: no interactive terminal'
 else
  printf 'DNS provider (aliyun/cloudflare/dnspod/huaweicloud): ' >/dev/tty
  IFS= read -r provider </dev/tty
  key_id='';account_id='';endpoint=''
  if [ "$provider" != cloudflare ]; then printf 'Key ID: ' >/dev/tty;IFS= read -r key_id </dev/tty;fi
  printf 'Secret/token (hidden): ' >/dev/tty;stty -echo </dev/tty || exit 1;TTY_HIDDEN=1
  IFS= read -r secret </dev/tty;stty echo </dev/tty;TTY_HIDDEN=0;printf '\n' >/dev/tty
  if [ "$provider" = huaweicloud ]; then
   printf 'Account ID: ' >/dev/tty;IFS= read -r account_id </dev/tty
   printf 'DNS API endpoint: ' >/dev/tty;IFS= read -r endpoint </dev/tty
  fi
  printf '%s\n' "$provider" "$key_id" "$secret" "$account_id" "$endpoint" >"$PRIVATE/dns-input"
  run live-DNS-readonly homegate dns-check-private "$PRIVATE/dns-input"
  rm -f "$PRIVATE/dns-input";unset secret key_id account_id endpoint provider
 fi
else record 'SKIP live-DNS: run with --dns for optional credential input';fi
record 'SKIP real DNS writes/ACME issuance/external HTTPS/firewall changes/physical WOL: requires separate router acceptance; offline suite covers isolated logic'
record "RESULT failed=$FAILED"
record "REPORT_DIRECTORY $OUT"
tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
printf 'Report archive: %s.tar.gz\n' "$OUT"
exit "$FAILED"
