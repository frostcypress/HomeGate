#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CORE="$ROOT/project/core/src"

# Stage 7 round 1: provider capabilities and typed diagnostics are owned by the
# neutral provider package, while DDNS/ACME depend only on record operations.
grep -q 'type Capabilities struct' "$CORE/internal/dnsprovider/provider.go"
grep -q 'CapabilityCredentialsValidation' "$CORE/internal/dnsprovider/provider.go"
grep -q 'CapabilityZoneDiscovery' "$CORE/internal/dnsprovider/provider.go"
grep -q 'type ErrorKind string' "$CORE/internal/dnsprovider/provider.go"
grep -q 'ErrorAuthentication' "$CORE/internal/dnsprovider/provider.go"
grep -q 'ErrorRateLimit' "$CORE/internal/dnsprovider/provider.go"
grep -q 'ErrorPropagationPending' "$CORE/internal/dnsprovider/provider.go"
grep -q 'type RecordProvider interface' "$CORE/internal/dnsprovider/provider.go"
grep -q 'ValidateCredentials(context.Context) error' "$CORE/internal/dnsprovider/provider.go"
grep -q 'ListZones(context.Context) (\[\]string, error)' "$CORE/internal/dnsprovider/provider.go"

grep -q 'func (p \*AliyunProvider) Capabilities() Capabilities' "$CORE/internal/dnsprovider/aliyun.go"
grep -q 'func (p \*AliyunProvider) ValidateCredentials' "$CORE/internal/dnsprovider/aliyun.go"
grep -q 'func (p \*CloudflareProvider) ValidateCredentials' "$CORE/internal/dnsprovider/cloudflare.go"
grep -q 'func (p \*DNSPodProvider) ValidateCredentials' "$CORE/internal/dnsprovider/dnspod.go"
grep -q 'func (p \*HuaweiCloudProvider) ValidateCredentials' "$CORE/internal/dnsprovider/huaweicloud.go"
grep -q 'func ValidateCredentialShape' "$CORE/internal/dnsprovider/catalog.go"
grep -q 'func Definitions()' "$CORE/internal/dnsprovider/catalog.go"
grep -q 'classifyAliyunCode' "$CORE/internal/dnsprovider/aliyun.go"
grep -q 'ErrorNetworkUnavailable' "$CORE/internal/dnsprovider/aliyun.go"

grep -q 'type Provider = dnsprovider.RecordProvider' "$CORE/internal/ddns/service.go"
grep -q 'type ProviderFactory = dnsprovider.RecordFactory' "$CORE/internal/acme/service.go"
grep -q 'dns-provider-catalog' "$CORE/cmd/homegate/main.go"
grep -q 'dns-provider-status' "$CORE/cmd/homegate/main.go"
grep -q 'func (a App) DNSProviderStatus' "$CORE/internal/app/app.go"
grep -q 'json:"error_kind,omitempty"' "$CORE/internal/ddns/service.go"
grep -q 'json:"provider_code,omitempty"' "$CORE/internal/acme/service.go"

# Provider implementation must not reintroduce the credential-bearing signed
# request URL into transport error messages.
! grep -q 'ue.URL' "$CORE/internal/dnsprovider/aliyun.go"

echo "HomeGate 1.1 provider contract smoke: PASS"
