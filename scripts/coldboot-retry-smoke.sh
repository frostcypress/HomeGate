#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${1:-"$ROOT/build/local/homegate-native"}
[ -x "$BIN" ] || { echo "native homegate binary missing: $BIN" >&2; exit 1; }

OUT="$ROOT/build/coldboot-retry-smoke"
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
	[ -f "$HOMEGATE_NET_READY" ] && echo '26: pppoe-wan inet6 2409:8a55:4f0c:353::1234/64 scope global dynamic'
	exit 0
fi
if [ "$*" = '-6 route show default' ]; then
	[ -f "$HOMEGATE_NET_READY" ] && echo 'default from 2409:8a55:4f0c:353::/64 via fe80::1 dev pppoe-wan metric 512'
	exit 0
fi
exit 1
EOF_IP
cat > "$OUT/fakebin/ubus" <<'EOF_UBUS'
#!/bin/sh
echo '{"up":false,"l3_device":"eth4"}'
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
export HOMEGATE_NET_READY="$OUT/net-ready"
export HOMEGATE_IP6TABLES_LOG="$OUT/ip6tables.log"
export HOMEGATE_RUNTIME_STATE="$OUT/runtime.json"
export HOMEGATE_LOG_PATH="$OUT/homegate.log"
export HOMEGATE_SYS_CLASS_NET="$OUT/sys"
export HOMEGATE_DDNS_STATUS="$OUT/ddns.json"
export HOMEGATE_HOME_DIR="$OUT/home"
export HOMEGATE_PROXY_STATUS="$OUT/proxy.json"
export HOMEGATE_FIREWALL_STATUS="$OUT/firewall.json"
export HOMEGATE_FIREWALL_COMPAT_STATUS="$OUT/firewall.status"
export PATH="$OUT/fakebin:$PATH"

daemon=''
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$BIN" daemon >"$OUT/daemon.stdout" 2>"$OUT/daemon.stderr" &
daemon=$!

for _ in $(seq 1 30); do
	grep -q 'firewall recovery scheduled attempt=1/7 delay=2s' "$OUT/homegate.log" 2>/dev/null && break
	sleep 0.1
done
grep -q 'firewall recovery scheduled attempt=1/7 delay=2s' "$OUT/homegate.log"
grep -q 'no wan6 device' "$OUT/firewall.status"

touch "$OUT/net-ready"
for _ in $(seq 1 50); do
	grep -q 'firewall recovered wan6=pppoe-wan source=public-ip' "$OUT/homegate.log" 2>/dev/null && break
	sleep 0.1
done
grep -q 'firewall recovered wan6=pppoe-wan source=public-ip' "$OUT/homegate.log"
grep -q "ok wan6=pppoe-wan source=public-ip http=8080->$PORT" "$OUT/firewall.status"
grep -q -- "-i pppoe-wan -p tcp --dport 8080 -j REDIRECT --to-ports $PORT" "$OUT/ip6tables.log"

kill -TERM "$daemon"
wait "$daemon"
daemon=''
trap - EXIT INT TERM

echo "coldboot retry integration smoke: PASS"
