#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CORE="$ROOT/project/core/src"
APP="$ROOT/project/luci"
PRESET="$CORE/internal/acmeca/preset.go"
PUBLIC="$APP/lua/luasrc/view/homegate/public.htm"
CONTROLLER="$APP/lua/luasrc/controller/homegate.lua"

grep -q 'CA          string' "$CORE/internal/config/config.go"
grep -q 'Environment string' "$CORE/internal/config/config.go"
grep -q 'ca = "letsencrypt"' "$CORE/internal/config/config.go"
! grep -q 'Directory   string' "$CORE/internal/config/config.go"
! grep -q 'EABKID' "$CORE/internal/config/config.go"
! grep -q 'EABHMACKey' "$CORE/internal/config/config.go"

grep -q 'LetsEncryptProduction' "$PRESET"
grep -q 'LetsEncryptStaging' "$PRESET"
grep -q 'Name: "letsencrypt"' "$PRESET"
! grep -qi 'zerossl' "$PRESET"
! grep -qi 'google' "$PRESET"
! grep -q 'Name: "custom"' "$PRESET"
! grep -q 'EABRequired' "$PRESET"
! grep -q 'ValidateEAB' "$PRESET"
grep -q 'func Resolve' "$PRESET"

grep -q 'source = "local"' "$CONTROLLER"
grep -q '/usr/bin/homegate cert-import' "$CONTROLLER"
grep -q 'id="hg-public-local-cert"' "$PUBLIC"
grep -q 'id="hg-public-local-key"' "$PUBLIC"
! grep -qi 'zerossl' "$CONTROLLER"
! grep -qi 'zerossl' "$PUBLIC"
! grep -qi 'EAB' "$CONTROLLER"
! grep -qi 'EAB' "$PUBLIC"
! grep -q 'hg-public-directory' "$PUBLIC"
! grep -q 'cert_directory' "$PUBLIC"
! grep -q 'CERT_ENV_CUSTOM' "$CONTROLLER"

grep -q 'accountStatePath' "$CORE/internal/acme/client.go"
grep -q 'JWKThumbprint' "$CORE/internal/acme/client.go"
! grep -q 'externalAccountBinding' "$CORE/internal/acme/client.go"
! grep -q 'EABCredentials' "$CORE/internal/acme/client.go"
grep -q 'acmeca.Resolve' "$CORE/internal/acme/service.go"
grep -q 'acme-ca-catalog' "$CORE/cmd/homegate/main.go"
grep -q 'acme-ca-status' "$CORE/cmd/homegate/main.go"
grep -q 'func ProbeCA' "$CORE/internal/acme/probe.go"
grep -q 'Direct.*json:"direct"' "$CORE/internal/app/app.go"
grep -q 'transport.Proxy = nil' "$CORE/internal/acme/client.go"

(
  cd "$CORE"
  go test ./internal/acmeca ./internal/acme ./internal/config
)

echo "HomeGate 1.1 Let's Encrypt-only ACME contract smoke: PASS"
