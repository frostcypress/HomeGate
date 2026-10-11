#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/build/local"
rm -rf "$OUT"
mkdir -p "$OUT"

cd "$ROOT/project/core/src"
go test ./...
go vet ./...
go build -buildvcs=false -trimpath -o "$OUT/homegate-native" ./cmd/homegate
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags='-s -w' -o "$OUT/homegate-arm64" ./cmd/homegate
file "$OUT/homegate-arm64"

sh -n "$ROOT/project/core/files/etc/init.d/homegate"
sh -n "$ROOT/project/core/files/etc/hotplug.d/iface/95-homegate"
sh -n "$ROOT/scripts/stage-into-sdk.sh"
sh -n "$ROOT/scripts/bootstrap-sdk.sh"
sh -n "$ROOT/scripts/build-in-sdk.sh"
sh -n "$ROOT/scripts/package-lifecycle-smoke.sh"
sh -n "$ROOT/scripts/ipk-format-smoke.sh"
sh -n "$ROOT/scripts/build-legacy-ipk.sh"
sh -n "$ROOT/scripts/proxy-hotpath-smoke.sh"
sh -n "$ROOT/scripts/ddns-network-hotpath-smoke.sh"
sh -n "$ROOT/scripts/acme-robustness-smoke.sh"
sh -n "$ROOT/scripts/firewall-runtime-hardening-smoke.sh"
sh -n "$ROOT/scripts/runtime-state-foundation-smoke.sh"
sh -n "$ROOT/scripts/status-truth-smoke.sh"
sh -n "$ROOT/scripts/dns-provider-boundary-smoke.sh"
sh -n "$ROOT/scripts/provider-contract-smoke.sh"
sh -n "$ROOT/scripts/scheduler-event-smoke.sh"
"$ROOT/scripts/recovery-isolation-smoke.sh"
sh -n "$ROOT/scripts/recovery-isolation-smoke.sh"
"$ROOT/scripts/generation-order-smoke.sh"
sh -n "$ROOT/scripts/generation-order-smoke.sh"
sh -n "$ROOT/scripts/wan-event-reconcile-smoke.sh"
sh -n "$ROOT/scripts/reconcile-idempotence-smoke.sh"
sh -n "$ROOT/scripts/daemon-startup-ownership-smoke.sh"
"$ROOT/scripts/firewall-startup-contract-smoke.sh"
sh -n "$ROOT/scripts/firewall-startup-contract-smoke.sh"
sh -n "$ROOT/scripts/certificate-store-selection-smoke.sh"
"$ROOT/scripts/certificate-identity-smoke.sh"
sh -n "$ROOT/scripts/certificate-identity-smoke.sh"
sh "$ROOT/scripts/package-lifecycle-smoke.sh"
sh "$ROOT/scripts/firewall-runtime-hardening-smoke.sh"
sh "$ROOT/scripts/runtime-state-foundation-smoke.sh"
sh "$ROOT/scripts/status-truth-smoke.sh"
"$ROOT/scripts/dns-provider-boundary-smoke.sh"
"$ROOT/scripts/provider-contract-smoke.sh"
"$ROOT/scripts/scheduler-event-smoke.sh"
"$ROOT/scripts/wan-event-reconcile-smoke.sh"
"$ROOT/scripts/reconcile-idempotence-smoke.sh"
"$ROOT/scripts/daemon-startup-ownership-smoke.sh"
"$ROOT/scripts/firewall-startup-contract-smoke.sh"
"$ROOT/scripts/certificate-store-selection-smoke.sh"
"$ROOT/scripts/certificate-identity-smoke.sh"

sh "$ROOT/scripts/version-contract-smoke.sh"
grep -q 'go build -buildvcs=false -trimpath' "$ROOT/project/core/Makefile"
grep -q '^define Package/homegate/conffiles$' "$ROOT/project/core/Makefile"
grep -q '^/etc/config/homegate$' "$ROOT/project/core/Makefile"
grep -q '^define Package/homegate/preinst$' "$ROOT/project/core/Makefile"
grep -q '^define Package/homegate/postinst$' "$ROOT/project/core/Makefile"
grep -q 'HOMEGATE_PACKAGE_UPGRADE_STATE' "$ROOT/project/core/Makefile"
grep -q 'while pidof homegate' "$ROOT/project/core/Makefile"
! awk '/^define Package\/homegate\/postinst$/{p=1;next} p&&/^endef$/{exit} p{print}' "$ROOT/project/core/Makefile" | grep -q '/etc/init.d/homegate start'
grep -q 'HOMEGATE_PACKAGE_UPGRADE_STATE' "$ROOT/project/core/files/etc/init.d/homegate"
grep -Fq 'include $(INCLUDE_DIR)/package.mk' "$ROOT/project/luci/Makefile"
grep -Fq '$(eval $(call BuildPackage,luci-app-homegate))' "$ROOT/project/luci/Makefile"
grep -Fq '$(eval $(call BuildPackage,luci-i18n-homegate-zh-cn))' "$ROOT/project/luci/Makefile"
grep -q 'network-resolve' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'recovery-status' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'dns-zones' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'dns-provider-status' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'cert-import' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'ddns-sync' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'ddns-delete' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'ddns-status' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'cert-status' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'cert-renew' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'proxy-status' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'access-status' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'access-update' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'access-refresh' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'access-clear-all' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'access-clear-entry' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'access-clear-denied' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'access-recent' "$ROOT/project/core/src/cmd/homegate/main.go"
! grep -q 'ReadRecentWithGeo' "$ROOT/project/core/src/internal/app/app.go"
! grep -q 'access.LoadPolicy' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'firewall-status' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'firewall-cleanup' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'wol-status' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'case "wol"' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q '0x0842' "$ROOT/project/core/src/internal/wol/wol.go"
grep -q 'procd_send_signal homegate' "$ROOT/project/core/files/etc/init.d/homegate"
grep -q 'firewall recovery scheduled' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'firewall.Retryable' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'pppoe-\*' "$ROOT/project/core/files/etc/hotplug.d/iface/95-homegate"
grep -q '^EXTRA_COMMANDS="network_changed"$' "$ROOT/project/core/files/etc/init.d/homegate"
grep -q "procd_send_signal homegate '\*' USR1" "$ROOT/project/core/files/etc/init.d/homegate"
grep -q '/etc/init.d/homegate network_changed' "$ROOT/project/core/files/etc/hotplug.d/iface/95-homegate"
! grep -q '/etc/init.d/homegate reload' "$ROOT/project/core/files/etc/hotplug.d/iface/95-homegate"

FAKE="$OUT/fakebin"
mkdir -p "$FAKE"
cat > "$FAKE/uci" <<'EOS'
#!/bin/sh
cat "$HOMEGATE_FAKE_UCI"
EOS
cat > "$FAKE/ip" <<'EOS'
#!/bin/sh
case "$*" in
  '-6 -o addr show scope global')
    cat <<'OUT'
12: pppoe-wan    inet6 2409:8a55:4f0c:353:7d9e:dab6:918d:f902/64 scope global dynamic
13: br-lan    inet6 2409:8a55:4f0c:354::1/64 scope global
OUT
    ;;
  '-6 route show default')
    echo 'default from 2409:8a55:4f0c:353::/64 via fe80::1 dev pppoe-wan proto static metric 512 pref medium'
    ;;
  *) exit 1 ;;
esac
EOS
cat > "$FAKE/ubus" <<'EOS'
#!/bin/sh
[ "$*" = 'call network.interface.wan6 status' ] || exit 1
echo '{"up":true,"l3_device":"eth4"}'
EOS
cat > "$FAKE/ip6tables" <<'EOS'
#!/bin/sh
case " $* " in
  *' -t nat -D PREROUTING -j HOMEGATE_NAT '*) echo "ip6tables v1.8.3 (legacy): Couldn't load target \`HOMEGATE_NAT':No such file or directory" >&2; exit 2 ;;
  *' -D INPUT -j HOMEGATE_INPUT '*) echo "ip6tables v1.8.3 (legacy): Couldn't load target \`HOMEGATE_INPUT':No such file or directory" >&2; exit 2 ;;
  *' -D '*) echo 'ip6tables: Bad rule (does a matching rule exist in that chain?).' >&2; exit 1 ;;
  *' -F '*|*' -X '*) echo 'ip6tables: No chain/target/match by that name.' >&2; exit 1 ;;
esac
exit 0
EOS
chmod +x "$FAKE/uci" "$FAKE/ip" "$FAKE/ubus" "$FAKE/ip6tables"

CFG="$OUT/config.txt"
cat > "$CFG" <<'EOS'
homegate.main=homegate
homegate.main.enabled='1'
homegate.main.log_level='error'
homegate.main.log_max_lines='64'
homegate.main.log_capture_errors='1'
homegate.main.wol_interface='br-lan'
homegate.main.last_wol_host='wol_test'
homegate.main.ddns_interval='300'
homegate.wol_test=wol_host
homegate.wol_test.name='Test host'
homegate.wol_test.mac='c8:7f:54:53:6b:80'
EOS
SYS="$OUT/sys-class-net"
mkdir -p "$SYS/br-lan/brif"
: > "$SYS/br-lan/brif/eth1"
: > "$SYS/br-lan/brif/eth3"

export HOMEGATE_FAKE_UCI="$CFG"
export HOMEGATE_RUNTIME_STATE="$OUT/runtime.json"
export HOMEGATE_LOG_PATH="$OUT/homegate.log"
export HOMEGATE_SYS_CLASS_NET="$SYS"
export HOMEGATE_DDNS_STATUS="$OUT/ddns.json"
export HOMEGATE_HOME_DIR="$OUT/home"
export HOMEGATE_PROXY_STATUS="$OUT/proxy.json"
export HOMEGATE_FIREWALL_STATUS="$OUT/firewall.json"
export HOMEGATE_FIREWALL_COMPAT_STATUS="$OUT/firewall.status"
export HOMEGATE_ACCESS_RECENT="$OUT/access.json"
export PATH="$FAKE:$PATH"

"$OUT/homegate-native" version | grep -q '"api_version":1'
"$OUT/homegate-native" status | grep -q '"phase":"common-runtime"'
"$OUT/homegate-native" network-resolve > "$OUT/network.json"
grep -q '"ok":true' "$OUT/network.json"
grep -q '"phase":"network-resolver"' "$OUT/network.json"
grep -q '"public_ipv6":"2409:8a55:4f0c:353:7d9e:dab6:918d:f902"' "$OUT/network.json"
grep -q '"device":"pppoe-wan"' "$OUT/network.json"
grep -q '"source":"public-ip"' "$OUT/network.json"
grep -q '"members":\["eth1","eth3"\]' "$OUT/network.json"

"$OUT/homegate-native" daemon >"$OUT/daemon.stdout" 2>"$OUT/daemon.stderr" &
pid=$!
for _ in $(seq 1 30); do
	[ -f "$OUT/runtime.json" ] && break
	sleep 0.1
done
[ -f "$OUT/runtime.json" ]
"$OUT/homegate-native" status | grep -q '"running":true'
for _ in $(seq 1 30); do
	[ -f "$OUT/ddns.json" ] && break
	sleep 0.1
done
[ -f "$OUT/ddns.json" ]
"$OUT/homegate-native" ddns-status | grep -Fq '"results":[]'
"$OUT/homegate-native" wol-status > "$OUT/wol-status.json"
grep -Fq '"phase":"wol"' "$OUT/wol-status.json"
grep -Fq '"selected_host":"wol_test"' "$OUT/wol-status.json"
grep -Fq '"mac":"C8:7F:54:53:6B:80"' "$OUT/wol-status.json"
"$OUT/homegate-native" cert-status > "$OUT/cert-status.json"
grep -Fq '"phase":"acme"' "$OUT/cert-status.json"
grep -Fq '"certificates":[]' "$OUT/cert-status.json"
"$OUT/homegate-native" proxy-status | grep -Fq '"enabled":0'
"$OUT/homegate-native" access-status > "$OUT/access-status.json"
grep -Fq '"enabled":false' "$OUT/access-status.json"
grep -Fq '"mode":"disabled"' "$OUT/access-status.json"
grep -Fq '"cache_valid":false' "$OUT/access-status.json"
grep -Fq '"cache_stale":false' "$OUT/access-status.json"
cat > "$OUT/config-empty-manual.txt" <<'EOS'
homegate.main=homegate
homegate.main.enabled='1'
homegate.main.log_level='info'
homegate.main.log_max_lines='64'
homegate.main.access_enabled='1'
homegate.main.access_allow=''
homegate.main.access_region=''
homegate.main.wol_interface='br-lan'
homegate.main.ddns_interval='300'
EOS
HOMEGATE_FAKE_UCI="$OUT/config-empty-manual.txt" "$OUT/homegate-native" access-status > "$OUT/access-status-empty-manual.json"
grep -Fq '"enabled":true' "$OUT/access-status-empty-manual.json"
grep -Fq '"mode":"manual"' "$OUT/access-status-empty-manual.json"
grep -Fq '"manual_prefixes":0' "$OUT/access-status-empty-manual.json"
cat > "$OUT/config-deny-disabled.txt" <<'EOS'
homegate.main=homegate
homegate.main.enabled='1'
homegate.main.log_level='info'
homegate.main.log_max_lines='64'
homegate.main.access_enabled='0'
homegate.main.access_allow=''
homegate.main.access_deny='2001:db8::1/128'
homegate.main.access_region=''
homegate.main.wol_interface='br-lan'
homegate.main.ddns_interval='300'
EOS
HOMEGATE_FAKE_UCI="$OUT/config-deny-disabled.txt" "$OUT/homegate-native" access-status > "$OUT/access-status-deny-disabled.json"
grep -Fq '"enabled":false' "$OUT/access-status-deny-disabled.json"
grep -Fq '"deny_prefixes":1' "$OUT/access-status-deny-disabled.json"
export HOMEGATE_FAKE_UCI="$CFG"
"$OUT/homegate-native" access-recent | grep -Fq '"entries":[]'
"$OUT/homegate-native" access-clear-all | grep -Fq '"entries":[]'
printf '%s\n' '192.0.2.1, 2001:db8::/32' > "$OUT/access-allow.txt"
"$OUT/homegate-native" access-validate-file "$OUT/access-allow.txt" | grep -Fq '"count":2'
"$OUT/homegate-native" firewall-status | grep -Fq '"active":false'
grep -Fq 'web inactive' "$OUT/firewall.status"

cat > "$CFG" <<'EOS'
homegate.main=homegate
homegate.main.enabled='1'
homegate.main.log_level='debug'
homegate.main.log_max_lines='64'
homegate.main.log_capture_errors='1'
homegate.main.wol_interface='br-lan'
homegate.main.last_wol_host='wol_test'
homegate.main.ddns_interval='600'
homegate.wol_test=wol_host
homegate.wol_test.name='Test host'
homegate.wol_test.mac='c8:7f:54:53:6b:80'
EOS
kill -HUP "$pid"
sleep 0.2
kill -0 "$pid"
grep -q 'configuration reloaded enabled=true log_level=debug log_max_lines=64 ddns_interval=600 renew_days=30 web_enabled=0' "$OUT/homegate.log"

kill -TERM "$pid"
wait "$pid"
[ ! -e "$OUT/runtime.json" ]
[ ! -s "$OUT/daemon.stdout" ]

"$ROOT/scripts/coldboot-retry-smoke.sh" "$OUT/homegate-native"
"$ROOT/scripts/theme-foundation-smoke.sh"
"$ROOT/scripts/ui-common-helper-smoke.sh"
"$ROOT/scripts/ui-dynamic-dom-smoke.sh"
"$ROOT/scripts/ui-public-desktop-geometry-smoke.sh"
"$ROOT/scripts/ui-action-column-contract-smoke.sh"
"$ROOT/scripts/ui-phase2c-smoke.sh"
"$ROOT/scripts/access-closure-smoke.sh"
"$ROOT/scripts/access-recent-hotpath-smoke.sh" "$OUT/homegate-native"
"$ROOT/scripts/access-region-cache-smoke.sh"
"$ROOT/scripts/core-runtime-transaction-smoke.sh"
"$ROOT/scripts/proxy-hotpath-smoke.sh"
"$ROOT/scripts/ddns-network-hotpath-smoke.sh"
"$ROOT/scripts/acme-robustness-smoke.sh"
"$ROOT/scripts/ui-access-desktop-geometry-smoke.sh"
"$ROOT/scripts/access-management-ui-smoke.sh"
"$ROOT/scripts/service-certificate-integration-smoke.sh"
"$ROOT/scripts/service-delete-lifecycle-smoke.sh"
"$ROOT/scripts/file-picker-ui-smoke.sh"
"$ROOT/scripts/ui-js-check.sh"
if command -v texluac >/dev/null 2>&1; then texluac -p "$ROOT/project/luci/lua/luasrc/controller/homegate.lua"; fi

echo "local phase-7 WOL checks: PASS"

# Release packaging contract: QWRT baseline expects legacy gzip-tar IPK outer format.
test -x "$ROOT/scripts/ipk-format-smoke.sh"
IPK_FIXTURE="$OUT/ipk-format-fixture"
rm -rf "$IPK_FIXTURE"
mkdir -p "$IPK_FIXTURE/control" "$IPK_FIXTURE/data"
printf '2.0\n' > "$IPK_FIXTURE/debian-binary"
printf 'Package: fixture\nVersion: 1\nArchitecture: all\n' > "$IPK_FIXTURE/control/control"
tar -czf "$IPK_FIXTURE/control.tar.gz" -C "$IPK_FIXTURE/control" ./control
tar -czf "$IPK_FIXTURE/data.tar.gz" -C "$IPK_FIXTURE/data" .
tar -czf "$IPK_FIXTURE/valid.ipk" -C "$IPK_FIXTURE" ./debian-binary ./control.tar.gz ./data.tar.gz
"$ROOT/scripts/ipk-format-smoke.sh" "$IPK_FIXTURE/valid.ipk" >/dev/null

# HomeGate release IPKs must carry conffiles + lifecycle scripts in control.tar.gz.
HG_FIX="$IPK_FIXTURE/homegate"
mkdir -p "$HG_FIX/control" "$HG_FIX/data/usr/bin" "$HG_FIX/data/etc/config" "$HG_FIX/data/etc/init.d" "$HG_FIX/data/etc/hotplug.d/iface"
printf '2.0\n' > "$HG_FIX/debian-binary"
cat > "$HG_FIX/control/control" <<'EOF_HG_CONTROL'
Package: homegate
Version: 0.5.0-test
Architecture: aarch64_cortex-a53
EOF_HG_CONTROL
printf '/etc/config/homegate\n' > "$HG_FIX/control/conffiles"
cat > "$HG_FIX/control/prerm" <<'EOF_HG_PRERM'
#!/bin/sh
/etc/init.d/homegate stop >/dev/null 2>&1 || true
/usr/bin/homegate firewall-cleanup >/dev/null 2>&1 || true
exit 0
EOF_HG_PRERM
cat > "$HG_FIX/control/postinst" <<'EOF_HG_POSTINST'
#!/bin/sh
/etc/init.d/homegate start >/dev/null 2>&1 || true
exit 0
EOF_HG_POSTINST
chmod +x "$HG_FIX/control/prerm" "$HG_FIX/control/postinst"
: > "$HG_FIX/data/usr/bin/homegate"
: > "$HG_FIX/data/etc/config/homegate"
: > "$HG_FIX/data/etc/init.d/homegate"
: > "$HG_FIX/data/etc/hotplug.d/iface/95-homegate"
tar -czf "$HG_FIX/control.tar.gz" -C "$HG_FIX/control" ./control ./conffiles ./postinst ./prerm
tar -czf "$HG_FIX/data.tar.gz" -C "$HG_FIX/data" ./usr/bin/homegate ./etc/config/homegate ./etc/init.d/homegate ./etc/hotplug.d/iface/95-homegate
tar -czf "$HG_FIX/valid-homegate.ipk" -C "$HG_FIX" ./debian-binary ./control.tar.gz ./data.tar.gz
"$ROOT/scripts/ipk-format-smoke.sh" "$HG_FIX/valid-homegate.ipk" >/dev/null

# Regression for rejected Core 0.5.0-45 packaging: control-only HomeGate IPKs must fail.
tar -czf "$HG_FIX/control-bad.tar.gz" -C "$HG_FIX/control" ./control
cp "$HG_FIX/control-bad.tar.gz" "$HG_FIX/control.tar.gz"
tar -czf "$HG_FIX/bad-homegate.ipk" -C "$HG_FIX" ./debian-binary ./control.tar.gz ./data.tar.gz
if "$ROOT/scripts/ipk-format-smoke.sh" "$HG_FIX/bad-homegate.ipk" >/dev/null 2>&1; then
    echo "HomeGate lifecycle metadata contract failed to reject missing conffiles/prerm/postinst" >&2
    exit 1
fi
if command -v ar >/dev/null 2>&1; then
    (cd "$IPK_FIXTURE" && ar rcs invalid-ar.ipk debian-binary control.tar.gz data.tar.gz)
    if "$ROOT/scripts/ipk-format-smoke.sh" "$IPK_FIXTURE/invalid-ar.ipk" >/dev/null 2>&1; then
        echo "IPK release-format contract failed to reject ar outer format" >&2
        exit 1
    fi
fi
echo "IPK release-format contract: PASS"
