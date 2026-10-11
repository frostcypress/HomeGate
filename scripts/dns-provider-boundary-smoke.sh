#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CORE="$ROOT/project/core/src"

# ACME and DDNS share DNS-record capabilities through the neutral provider
# layer. ACME must not depend on the DDNS service package.
if grep -R 'homegate.local/homegate/internal/ddns' "$CORE/internal/acme" >/dev/null 2>&1; then
    echo "ACME still imports internal/ddns" >&2
    exit 1
fi

grep -q 'homegate.local/homegate/internal/dnsprovider' "$CORE/internal/acme/service.go"
grep -q 'homegate.local/homegate/internal/dnsprovider' "$CORE/internal/ddns/service.go"
grep -q 'type Provider interface' "$CORE/internal/dnsprovider/provider.go"
grep -q 'func New(account config.DNSAccount)' "$CORE/internal/dnsprovider/catalog.go"
grep -q 'func FullDomain(zone, host string)' "$CORE/internal/dnsprovider/provider.go"

# The concrete Aliyun provider lives only in the shared provider layer.
if find "$CORE/internal/ddns" "$CORE/internal/acme" -type f -name '*.go' -exec grep -l 'type AliyunProvider struct' {} + 2>/dev/null | grep . >/dev/null; then
    echo "Aliyun provider implementation leaked back into DDNS/ACME" >&2
    exit 1
fi

grep -q 'type AliyunProvider struct' "$CORE/internal/dnsprovider/aliyun.go"

echo "DNS provider boundary smoke: PASS"
