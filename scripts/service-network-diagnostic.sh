#!/bin/sh
# Source only from access-diagnose.sh. Read fixed non-secret UCI fields.
printf 'role=router\nRouter probes are not tests of the overseas client path.\n' >"$OUT/service-network-summary.log"
: >"$OUT/service-targets.txt"
if command -v uci >/dev/null 2>&1;then
 sections=$(uci -q show homegate | sed -n 's/^homegate\.\([^=]*\)=web_rule$/\1/p')
 index=0
 for section in $sections;do
  enabled=$(uci -q get "homegate.$section.enabled" || true)
  [ "$enabled" = 1 ] || continue
  domain=$(uci -q get "homegate.$section.domain" || true)
  case "$domain" in ''|*[!a-zA-Z0-9.-]*|-*|.*) record 'WARN invalid service domain skipped';continue;;esac
  https=$(uci -q get "homegate.$section.https" || true)
  if [ "$https" = 1 ];then scheme=https;port=$(uci -q get homegate.main.https_port || true)
  else scheme=http;port=$(uci -q get homegate.main.http_port || true);fi
  case "$port" in ''|*[!0-9]*) record 'WARN invalid service port skipped';continue;;esac
  [ "$port" -gt 0 ] && [ "$port" -le 65535 ] || continue
  index=$((index+1));[ "$index" -le 32 ] || { record 'WARN service probe limit 32';break; }
  url="$scheme://$domain:$port/"
  printf '%s\n' "$url" >>"$OUT/service-targets.txt"
  printf '\nservice=%s\n' "$url" >>"$OUT/service-network-summary.log"
  snapshot "service-$index-dns" nslookup "$domain"
  if command -v curl >/dev/null 2>&1;then
   for family in 4 6;do
    # HEAD: no credentials, no response bodies, certificate validation enabled.
    curl "-$family" --noproxy '*' --head --silent --show-error --connect-timeout 5 --max-time 10 \
      --output /dev/null --write-out 'http_code=%{http_code}\nremote_ip=%{remote_ip}\nremote_port=%{remote_port}\nssl_verify_result=%{ssl_verify_result}\n' "$url" >"$OUT/service-$index-ipv$family.log" 2>&1
    rc=$?;printf 'curl_exit=%s\n' "$rc" >>"$OUT/service-$index-ipv$family.log"
    printf 'ipv%s_exit=%s\n' "$family" "$rc" >>"$OUT/service-network-summary.log"
   done
  else record 'SKIP service-family-probes: curl missing';fi
 done
fi
snapshot listening-ports ss -lnt
if [ ! -s "$OUT/listening-ports.log" ];then snapshot listening-netstat netstat -lnt;fi
snapshot firewall-v6-rules ip6tables-save
snapshot firewall-v4-rules iptables-save
printf '\nInterpretation: curl 6=DNS failure, 7=connect failure, 28=timeout, 35=TLS handshake, 60=certificate verification. HTTP 401/403/404/405 still proves an HTTP response.\nNo access entry may also mean firewall/TLS failure before HTTP logging; it does not prove a policy decision.\nUnrestricted mode preserves explicit deny rules. Compare saved UCI, access-status and recent entries.\n' >>"$OUT/service-network-summary.log"
snapshot access-recent-after-probes homegate access-recent
