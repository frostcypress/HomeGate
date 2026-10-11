#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${1:-"$ROOT/build/local/homegate-native"}
[ -x "$BIN" ] || { echo "native homegate binary missing: $BIN" >&2; exit 1; }

cd "$ROOT/project/core/src"
go test ./internal/firewall -run '^TestApplyRepeatedSameConfigLeavesSingleRuleSet$' -count=1
go test ./internal/proxy -run '^TestRepeatedSameConfigReusesListeners$' -count=1
go test ./internal/scheduler -run '^TestQueueDeduplicatesTimerKindsIndependently$' -count=1
go test ./internal/ddns -run '^TestSyncR6AliyunAAAAUnchanged$' -count=1
cd "$ROOT"

# All periodic module triggers must enter the shared scheduler first.  Business
# workers are only fed from scheduler event handlers, not directly from ticker
# receive cases.
grep -q 'case <-ddnsTicker.C:' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'submitEvent(scheduler.EventDDNSTimer)' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'case <-acmeTicker.C:' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'submitEvent(scheduler.EventACMETimer)' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'case <-accessTicker.C:' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'submitEvent(scheduler.EventAccessTimer)' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'case scheduler.EventDDNSTimer:' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'case scheduler.EventACMETimer:' "$ROOT/project/core/src/internal/app/app.go"
grep -q 'case scheduler.EventAccessTimer:' "$ROOT/project/core/src/internal/app/app.go"

OUT="$ROOT/build/reconcile-idempotence-smoke"
rm -rf "$OUT"
mkdir -p "$OUT/fakebin" "$OUT/sys/br-lan/brif" "$OUT/home"
: > "$OUT/sys/br-lan/brif/eth1"

PORT=$(python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind(('::1', 0))
print(s.getsockname()[1])
s.close()
PY
)

cat > "$OUT/config.txt" <<EOF_CFG
homegate.main=homegate
homegate.main.enabled='1'
homegate.main.log_level='debug'
homegate.main.log_max_lines='512'
homegate.main.log_capture_errors='1'
homegate.main.wol_interface='br-lan'
homegate.main.ddns_interval='300'
homegate.main.http_port='8080'
homegate.main.https_port='443'
homegate.main.proxy_http_port='$PORT'
homegate.main.proxy_https_port='10443'
homegate.main.auto_firewall='1'
homegate.web1=web_rule
homegate.web1.enabled='1'
homegate.web1.domain='test.local'
homegate.web1.target='http://127.0.0.1:9'
homegate.web1.https='0'
EOF_CFG

cat > "$OUT/fakebin/uci" <<'EOF_UCI'
#!/bin/sh
cat "$HOMEGATE_FAKE_UCI"
EOF_UCI
cat > "$OUT/fakebin/ip" <<'EOF_IP'
#!/bin/sh
if [ "$*" = '-6 -o addr show scope global' ]; then
	echo '26: pppoe-wan inet6 2409:8a55:4f0c:353::1234/64 scope global dynamic'
	exit 0
fi
if [ "$*" = '-6 route show default' ]; then
	echo 'default from 2409:8a55:4f0c:353::/64 via fe80::1 dev pppoe-wan metric 512'
	exit 0
fi
exit 1
EOF_IP
cat > "$OUT/fakebin/ubus" <<'EOF_UBUS'
#!/bin/sh
echo '{"up":true,"l3_device":"eth4"}'
EOF_UBUS
cat > "$OUT/fakebin/ip6tables" <<'EOF_IPT'
#!/bin/sh
echo "$*" >> "$HOMEGATE_IP6TABLES_LOG"
case " $* " in
	*' -D '*) echo 'ip6tables: Bad rule (does a matching rule exist in that chain?).' >&2; exit 1 ;;
	*' -F '*|*' -X '*) echo 'ip6tables: No chain/target/match by that name.' >&2; exit 1 ;;
esac
exit 0
EOF_IPT
chmod +x "$OUT/fakebin/"*

export HOMEGATE_FAKE_UCI="$OUT/config.txt"
export HOMEGATE_IP6TABLES_LOG="$OUT/ip6tables.log"
export HOMEGATE_RUNTIME_STATE="$OUT/runtime.json"
export HOMEGATE_LOG_PATH="$OUT/homegate.log"
export HOMEGATE_SYS_CLASS_NET="$OUT/sys"
export HOMEGATE_DDNS_STATUS="$OUT/ddns.json"
export HOMEGATE_HOME_DIR="$OUT/home"
export HOMEGATE_PROXY_STATUS="$OUT/proxy.json"
export HOMEGATE_FIREWALL_STATUS="$OUT/firewall.json"
export HOMEGATE_FIREWALL_COMPAT_STATUS="$OUT/firewall.status"
export HOMEGATE_DAEMON_LOCK="$OUT/daemon.lock"
export PATH="$OUT/fakebin:$PATH"

daemon=''
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$BIN" daemon >"$OUT/daemon.stdout" 2>"$OUT/daemon.stderr" &
daemon=$!

for _ in $(seq 1 50); do
	grep -q 'firewall active wan6=pppoe-wan source=public-ip' "$OUT/homegate.log" 2>/dev/null && break
	sleep 0.1
done
grep -q 'firewall active wan6=pppoe-wan source=public-ip' "$OUT/homegate.log"
pid_before=$daemon

# Repeating the same desired configuration must not churn listeners or change
# daemon identity.  Firewall idempotence itself is statefully checked above.
repeat_start=$(wc -l < "$OUT/homegate.log")
i=0
while [ "$i" -lt 5 ]; do
	before=$(grep -c 'configuration reloaded .*ddns_interval=300' "$OUT/homegate.log" 2>/dev/null || true)
	kill -HUP "$daemon"
	for _ in $(seq 1 50); do
		after=$(grep -c 'configuration reloaded .*ddns_interval=300' "$OUT/homegate.log" 2>/dev/null || true)
		[ "$after" -gt "$before" ] && break
		sleep 0.05
	done
	i=$((i + 1))
done
repeat_log="$OUT/repeated-reconcile.log"
tail -n +$((repeat_start + 1)) "$OUT/homegate.log" > "$repeat_log"
[ "$(grep -c 'configuration reloaded .*ddns_interval=300' "$repeat_log" 2>/dev/null || true)" -eq 5 ]
! grep -q 'Web HTTP internal listener .* enabled' "$repeat_log"
! grep -q 'Web HTTP internal listener stopped' "$repeat_log"
! grep -q 'Web HTTPS internal listener .* enabled' "$repeat_log"
! grep -q 'Web HTTPS internal listener stopped' "$repeat_log"
! grep -q 'scheduler queue full' "$repeat_log"
! grep -q 'context canceled' "$repeat_log"
kill -0 "$daemon"
[ "$pid_before" = "$daemon" ]

# Mix ConfigChanged and debounced WANChanged repeatedly while desired state
# advances.  The final actual/runtime status must match the latest desired
# config, with no event loss, listener churn, queue overflow or cancellation
# noise.
mixed_start=$(wc -l < "$OUT/homegate.log")
for interval in 301 302 303; do
	sed -i "s/homegate.main.ddns_interval='[0-9][0-9]*'/homegate.main.ddns_interval='$interval'/" "$OUT/config.txt"
	before_cfg=$(grep -c "configuration reloaded .*ddns_interval=$interval" "$OUT/homegate.log" 2>/dev/null || true)
	before_wan=$(grep -c 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' "$OUT/homegate.log" 2>/dev/null || true)
	i=0
	while [ "$i" -lt 25 ]; do
		kill -USR1 "$daemon"
		i=$((i + 1))
	done
	kill -HUP "$daemon"
	for _ in $(seq 1 80); do
		after_cfg=$(grep -c "configuration reloaded .*ddns_interval=$interval" "$OUT/homegate.log" 2>/dev/null || true)
		after_wan=$(grep -c 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' "$OUT/homegate.log" 2>/dev/null || true)
		[ "$after_cfg" -gt "$before_cfg" ] && [ "$after_wan" -gt "$before_wan" ] && break
		sleep 0.05
	done
	done_cfg=$(grep -c "configuration reloaded .*ddns_interval=$interval" "$OUT/homegate.log" 2>/dev/null || true)
	done_wan=$(grep -c 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' "$OUT/homegate.log" 2>/dev/null || true)
	[ "$done_cfg" -gt "$before_cfg" ]
	[ "$done_wan" -gt "$before_wan" ]
done

for _ in $(seq 1 50); do
	grep -q '"interval_seconds":303' "$OUT/ddns.json" 2>/dev/null && break
	sleep 0.05
done
grep -q '"interval_seconds":303' "$OUT/ddns.json"

mixed_log="$OUT/mixed.log"
tail -n +$((mixed_start + 1)) "$OUT/homegate.log" > "$mixed_log"
for interval in 301 302 303; do
	[ "$(grep -c "configuration reloaded .*ddns_interval=$interval" "$mixed_log" 2>/dev/null || true)" -eq 1 ]
done
[ "$(grep -c 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' "$mixed_log" 2>/dev/null || true)" -eq 3 ]
! grep -q 'scheduler queue full' "$mixed_log"
! grep -q 'context canceled' "$mixed_log"
! grep -q 'Web HTTP internal listener .* enabled' "$mixed_log"
! grep -q 'Web HTTP internal listener stopped' "$mixed_log"
kill -0 "$daemon"
[ "$pid_before" = "$daemon" ]

grep -q '"http_listening":true' "$OUT/proxy.json"
grep -q '"active":true' "$OUT/firewall.json"
grep -q "ok wan6=pppoe-wan source=public-ip http=8080->$PORT" "$OUT/firewall.status"

kill -TERM "$daemon"
wait "$daemon"
daemon=''
trap - EXIT INT TERM

echo 'reconcile idempotence / mixed-event smoke: PASS'
