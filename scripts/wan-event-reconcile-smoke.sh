#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${1:-"$ROOT/build/local/homegate-native"}
[ -x "$BIN" ] || { echo "native homegate binary missing: $BIN" >&2; exit 1; }

OUT="$ROOT/build/wan-event-reconcile-smoke"
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
homegate.main.log_max_lines='256'
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
line_before=$(wc -l < "$OUT/homegate.log")
ipt_before=$(wc -l < "$OUT/ip6tables.log")
kill -USR1 "$daemon"

for _ in $(seq 1 50); do
	tail -n +$((line_before + 1)) "$OUT/homegate.log" | grep -q 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' && break
	sleep 0.1
done

newlog="$OUT/new.log"
tail -n +$((line_before + 1)) "$OUT/homegate.log" > "$newlog"
grep -q 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' "$newlog"
! grep -q 'configuration reloaded' "$newlog"
[ "$(kill -0 "$daemon" 2>/dev/null; echo $?)" = "0" ]
[ "$pid_before" = "$daemon" ]
ipt_after=$(wc -l < "$OUT/ip6tables.log")
[ "$ipt_after" -gt "$ipt_before" ]

grep -q "ok wan6=pppoe-wan source=public-ip http=8080->$PORT" "$OUT/firewall.status"

# ConfigChanged and WANChanged are distinct control-plane events. Deliver them
# back-to-back and require both reconciles to happen without one consuming the
# other. WAN ingress is debounced, so the config commit may linearize first;
# either way the final WAN reconcile must use the committed current snapshot.
cross_line_before=$(wc -l < "$OUT/homegate.log")
sed -i "s/homegate.main.ddns_interval='300'/homegate.main.ddns_interval='301'/" "$OUT/config.txt"
kill -USR1 "$daemon"
kill -HUP "$daemon"
for _ in $(seq 1 60); do
	cross_log="$OUT/cross.log"
	tail -n +$((cross_line_before + 1)) "$OUT/homegate.log" > "$cross_log"
	grep -q 'configuration reloaded .*ddns_interval=301' "$cross_log" 2>/dev/null \
		&& grep -q 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' "$cross_log" 2>/dev/null \
		&& break
	sleep 0.1
done
cross_log="$OUT/cross.log"
tail -n +$((cross_line_before + 1)) "$OUT/homegate.log" > "$cross_log"
[ "$(grep -c 'configuration reloaded .*ddns_interval=301' "$cross_log" 2>/dev/null || true)" -eq 1 ]
[ "$(grep -c 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' "$cross_log" 2>/dev/null || true)" -eq 1 ]
! grep -q 'scheduler queue full' "$cross_log"
! grep -q 'context canceled' "$cross_log"
[ "$(kill -0 "$daemon" 2>/dev/null; echo $?)" = "0" ]

# A real hotplug transition can emit many notifications.  The Stage 8 ingress
# debounce must collapse a tight burst into one WAN reconcile rather than
# repeatedly advancing generation and canceling module work.
burst_line_before=$(wc -l < "$OUT/homegate.log")
i=0
while [ "$i" -lt 50 ]; do
	kill -USR1 "$daemon"
	i=$((i + 1))
done
sleep 1
burst_log="$OUT/burst.log"
tail -n +$((burst_line_before + 1)) "$OUT/homegate.log" > "$burst_log"
burst_reconciles=$(grep -c 'WAN reconciled firewall wan6=pppoe-wan source=public-ip' "$burst_log" 2>/dev/null || true)
[ "$burst_reconciles" -eq 1 ]
! grep -q 'configuration reloaded' "$burst_log"
! grep -q 'scheduler queue full' "$burst_log"
! grep -q 'context canceled' "$burst_log"
[ "$(kill -0 "$daemon" 2>/dev/null; echo $?)" = "0" ]

kill -TERM "$daemon"
wait "$daemon"
daemon=''
trap - EXIT INT TERM

echo "WAN event reconcile smoke: PASS"
