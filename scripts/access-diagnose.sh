#!/bin/sh
# Read-only HomeGate access/DDNS diagnostic. No credentials or configuration exports.
set -u
set +x
umask 077
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
CLIENT_IP=''
if [ "${1:-}" = '--client-ip' ]; then CLIENT_IP=${2:-}; shift 2 2>/dev/null || exit 2; fi
if [ "$#" -ne 0 ]; then echo 'Usage: sh homegate-access-diagnose.sh [--client-ip IP]' >&2; exit 2; fi
case "$CLIENT_IP" in *[!0-9a-fA-F:.]*) echo 'Client IP must be an IP address, not a URL' >&2;exit 2;; esac
OUT=$(mktemp -d /tmp/homegate-access-diagnostic-$(date +%Y%m%d-%H%M%S)-XXXXXX) || exit 1
chmod 700 "$OUT"
LOG="$OUT/diagnostic.log"
record() { printf '%s\n' "$*" | tee -a "$LOG"; }
bounded() {
 if command -v timeout >/dev/null 2>&1; then timeout 25 "$@"; else "$@"; fi
}
snapshot() {
 name=$1;shift
 if command -v "$1" >/dev/null 2>&1; then
  bounded "$@" >"$OUT/$name.log" 2>&1; rc=$?
  record "INFO $name exit=$rc (inspect log; exit 0 is not a business acceptance)"
 else record "SKIP $name missing=$1";fi
}
record 'HomeGate access diagnostic v2; read-only snapshots + public HTTP downloads'
record "UTC $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
record 'Scope: no install/restart/UCI writes/DNS writes/certificate issuance/firewall changes/WOL'
{
 printf 'provided_client_ip=%s\n' "$CLIENT_IP"
 printf 'ssh_connection=%s\n' "${SSH_CONNECTION:-unknown}"
 printf 'WARNING: SSH peer may be a LAN address or jump host; router egress IP is not the website visitor IP.\n'
} >"$OUT/client-context.log"
snapshot version homegate version
snapshot runtime homegate status
snapshot access-status homegate access-status
snapshot access-recent homegate access-recent
snapshot ddns-status homegate ddns-status
snapshot proxy-status homegate proxy-status
snapshot network-status homegate network-resolve
snapshot firewall-status homegate firewall-status
snapshot board ubus call system board
snapshot addresses ip -o addr show
snapshot routes-v4 ip route show
snapshot routes-v6 ip -6 route show
# Only the fixed access options; never export DNS account sections, keys or passwords.
if command -v uci >/dev/null 2>&1; then
 { for key in access_enabled access_region access_allow access_deny; do
    printf '%s=' "$key"; uci -q get "homegate.main.$key" || true
   done; } >"$OUT/access-options.log"
fi
HOME_DIR=${HOMEGATE_HOME_DIR:-/etc/homegate}
mkdir "$OUT/cache"
for key in CN CN-GD; do
 path="$HOME_DIR/access/regions/$key.cidr"
 if [ -f "$path" ]; then
  size=$(wc -c <"$path")
  { ls -ln "$path"; command -v sha256sum >/dev/null 2>&1 && sha256sum "$path"; } >"$OUT/cache/$key.metadata.log" 2>&1
  if [ "$size" -le 25165824 ]; then cp "$path" "$OUT/cache/$key.cidr";record "INFO cache-$key copied bytes=$size"
  else record "SKIP cache-$key exceeds 24MiB";fi
 else record "INFO cache-$key absent";fi
done
mkdir "$OUT/http"
fetch() {
 name=$1;url=$2;family=${3:-auto}
 body="$OUT/http/$name.body";meta="$OUT/http/$name.log"
 printf 'url=%s\nfamily=%s\n' "$url" "$family" >"$meta"
 if command -v curl >/dev/null 2>&1; then
  set --
  case "$family" in 4) set -- -4;;6) set -- -6;;esac
  # Bypass HTTP_PROXY variables only; VPN/default routing is intentionally observed.
  curl "$@" --noproxy '*' -L --silent --show-error --connect-timeout 8 --max-time 18 --max-filesize 25165824 \
   -D "$OUT/http/$name.headers" -o "$body" -w 'http_code=%{http_code}\nremote_ip=%{remote_ip}\n' "$url" >>"$meta" 2>&1;rc=$?
 elif command -v wget >/dev/null 2>&1; then
  if [ "$family" != auto ]; then record "SKIP $name forced family requires curl";return;fi
  if ! command -v timeout >/dev/null 2>&1; then record "SKIP $name wget needs timeout";return;fi
  timeout 22 wget -T 15 -O "$body" "$url" >>"$meta" 2>&1;rc=$?
 else record "SKIP $name no curl/wget";return;fi
 printf 'exit=%s\n' "$rc" >>"$meta"
 if [ "$rc" -eq 0 ] && ! grep -Eq '^http_code=[45][0-9][0-9]$' "$meta"; then
  record "INFO HTTP-$name downloaded (inspect HTTP status and content)"
 else record "WARN HTTP-$name download failed; see http/$name.log";fi
 if [ -f "$body" ]; then
  awk '/^[0-9][0-9.]*\/[0-9]+$/ {v4++} /^[0-9a-fA-F:]+\/[0-9]+$/ && /:/ {v6++} END{printf "cidr_ipv4_lines=%d\ncidr_ipv6_lines=%d\n",v4,v6}' "$body" >>"$meta"
  awk -F '|' '$1=="apnic" && $2=="CN" && ($7=="allocated" || $7=="assigned") {if($3=="ipv4")v4++;if($3=="ipv6")v6++} END{printf "apnic_cn_ipv4_records=%d\napnic_cn_ipv6_records=%d\n",v4,v6}' "$body" >>"$meta"
 fi
}
fetch cn-apnic 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'
fetch cn-ripe 'https://ftp.ripe.net/pub/stats/apnic/delegated-apnic-latest'
fetch router-egress-auto 'https://www.cloudflare.com/cdn-cgi/trace'
if command -v curl >/dev/null 2>&1; then
 fetch router-egress-v4 'https://www.cloudflare.com/cdn-cgi/trace' 4
 fetch router-egress-v6 'https://www.cloudflare.com/cdn-cgi/trace' 6
fi
{
 printf 'Router egress as observed by Cloudflare; loc is its IP geolocation, not physical location proof.\n'
 for name in auto v4 v6; do
  file="$OUT/http/router-egress-$name.body"
  if [ -f "$file" ];then printf '[%s]\n' "$name";grep -E '^(ip|loc|colo|warp)=' "$file" || true;fi
 done
 printf '\nClient IP country is not inferred from the router. Access-recent is authoritative for the peer seen by HomeGate.\n'
 printf 'DDNS maps names to addresses; it does not determine regional access decisions.\n'
 printf 'Without a real service request, these snapshots cannot prove an allow/deny result.\n'
} >"$OUT/egress-summary.log"
record 'INFO Report may contain IP addresses, domains and device info; no DNS credentials requested'
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/service-network-diagnostic.sh"
record 'INFO service HEAD probes are from router; use client scripts through the failing overseas node'
PARENT=$(dirname "$OUT");BASE=$(basename "$OUT");ARCHIVE="$OUT.tar.gz"
if tar -czf "$ARCHIVE" -C "$PARENT" "$BASE"; then
 chmod 600 "$ARCHIVE"
 record "REPORT $ARCHIVE"
 if command -v sha256sum >/dev/null 2>&1;then sha256sum "$ARCHIVE";fi
else record "FAIL archive; logs remain at $OUT";exit 1;fi
exit 0
