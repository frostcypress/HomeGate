#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CTRL="$ROOT/project/luci/lua/luasrc/controller/homegate.lua"
VIEW="$ROOT/project/luci/lua/luasrc/view/homegate/public.htm"
COMMON="$ROOT/project/luci/lua/luasrc/view/homegate/common.htm"
PO="$ROOT/project/luci/common/po/zh_Hans/homegate.po"
MF="$ROOT/project/luci/Makefile"
COREMF="$ROOT/project/core/Makefile"

# Candidate boundary.
VERSION=$(sed -n 's/^HOMEGATE_VERSION:=//p' "$ROOT/homegate-version.mk" | head -n1)
RELEASE=$(sed -n 's/^HOMEGATE_RELEASE:=//p' "$ROOT/homegate-version.mk" | head -n1)
[ -n "$VERSION" ] && [ -n "$RELEASE" ]
grep -Fq 'include $(TOPDIR)/homegate-version.mk' "$MF"
grep -Fq 'PKG_VERSION:=$(HOMEGATE_VERSION)' "$MF"
grep -Fq 'PKG_RELEASE:=$(HOMEGATE_RELEASE)' "$MF"
grep -Fq 'PKG_PO_VERSION:=$(PKG_VERSION)-$(PKG_RELEASE)' "$MF"
grep -Fq 'include $(TOPDIR)/homegate-version.mk' "$COREMF"
grep -Fq 'PKG_VERSION:=$(HOMEGATE_VERSION)' "$COREMF"
grep -Fq 'PKG_RELEASE:=$(HOMEGATE_RELEASE)' "$COREMF"
! grep -R -q 'XHR\.post' "$ROOT/project/luci"

# Main page stays service-centric; no standalone certificate table/modal.
grep -q '<h3><%:Service List%></h3>' "$VIEW"
! grep -q '<h3><%:SSL/TLS Certificates%></h3>' "$VIEW"
! grep -q 'hg-certstore-table' "$VIEW"
! grep -q 'id="hg-public-cert-modal"' "$VIEW"

# Primary domain is provider-discovered, not a free-form text input.
grep -q 'id="hg-public-zone"' "$VIEW"
grep -q 'disabled="disabled"' "$VIEW"
grep -q 'Detecting Primary Domains' "$VIEW"
grep -q 'api/dns_zones' "$VIEW"
grep -q 'function hgPublicLoadZones' "$VIEW"
grep -q 'XHR.get(.*{account:accountId}' "$VIEW"
grep -q 'function api_dns_zones' "$CTRL"
grep -q 'dns-zones ' "$CTRL"
! grep -q 'id="hg-public-zone"[^>]*type="text"' "$VIEW"

# Certificate source has exactly the two user-facing modes agreed for 0.5.0-62.
grep -q '<%:Certificate Source%>' "$VIEW"
grep -q '<option value="auto"><%:Automatic Management%></option>' "$VIEW"
grep -q '<option value="local"><%:Local Upload%></option>' "$VIEW"
! grep -q '<%:Use Existing Certificate%>' "$VIEW"
! grep -q 'value="existing"' "$VIEW"

# Scope is a global read-only viewer. Items have no click/select handler and
# contain only coverage strings; service status/age is rendered beside Access Address.
grep -q '<%:Certificate Scope%>' "$VIEW"
grep -q 'id="hg-public-cert-scope-trigger"' "$VIEW"
grep -q 'id="hg-public-cert-scope-menu"' "$VIEW"
grep -q 'function hgPublicBuildCertificateScopeMenu' "$VIEW"
grep -q "row.className='hg-cert-scope-item'" "$VIEW"
grep -q "row.setAttribute('role','listitem')" "$VIEW"
grep -q '.hg-cert-scope-item' "$COMMON"
python3 - "$VIEW" <<'PY'
from pathlib import Path
import re, sys
s=Path(sys.argv[1]).read_text()
m=re.search(r'function hgPublicBuildCertificateScopeMenu\(\)\{(.*?)\nfunction ', s, re.S)
assert m, 'scope menu builder missing'
b=m.group(1)
for forbidden in ('hgPublicCerts', '.days', 'renew_state', 'identity_valid', 'use_count', '.onclick', 'ChooseCertificate'):
    assert forbidden not in b, f'read-only scope viewer leaked behavior/details: {forbidden}'
assert "if(!c.enabled)continue" in b
assert "row.textContent=label" in b
print('read-only certificate scope viewer: PASS')
PY

# Automatic mode creates/reuses nearest parent + one-label wildcard. Reuse is
# ACME-only, while identity ownership is global so local uploads cannot be silently
# consumed or duplicated by a newly-created automatic certificate.
grep -q 'local function automatic_certificate_scope' "$CTRL"
grep -Fq 'vault.chenos.cn     -> chenos.cn, *.chenos.cn' "$CTRL"
grep -Fq 'api.home.chenos.cn  -> home.chenos.cn, *.home.chenos.cn' "$CTRL"
grep -q 'local function certificate_acme_matches' "$CTRL"
grep -q 'find_automatic_shared_certificate(cur, zone, domain, cert_environment, cert_ca)' "$CTRL"
grep -q 'automatic_certificate_create_domains(cur, zone, domain, cert_environment, cert_ca)' "$CTRL"
grep -Fq 'source = "acme"' "$CTRL"
grep -q 'enabled_certificate_pattern_owner(cur, base, "")' "$CTRL"
grep -q 'enabled_certificate_pattern_owner(cur, wildcard, "")' "$CTRL"
grep -q 'certificate_acme_matches(required_owner, ca, environment)' "$CTRL"
grep -q 'Automatic certificate conflicts with an existing certificate identity' "$CTRL"


# 1.1: CA + environment belong to each automatic certificate resource.
# Old resources default to Let's Encrypt production; custom directory identity
# is intentionally absent because other CAs are handled through local upload.
grep -q 'Environment string.*json:"environment"' "$ROOT/project/core/src/internal/config/config.go"
grep -q 'DefaultCertificateEnvironment = CertificateEnvProduction' "$ROOT/project/core/src/internal/config/config.go"
grep -q 'acmeca.Resolve(cc.CA, cc.Environment)' "$ROOT/project/core/src/internal/acme/service.go"
grep -q 'environment = cert_environment' "$CTRL"
grep -q "data-cert-environment" "$VIEW"
grep -q "p+'cert_environment'" "$VIEW"
grep -q 'data-production=' "$VIEW"
grep -q 'data-staging=' "$VIEW"
! grep -q 'hg-public-directory' "$VIEW"
! grep -q 'cur:set("homegate", "main", "acme_directory"' "$CTRL"

# Existing DNS accounts are references, not per-service mutable fields. Saving
# a service must not rename/re-key/re-secret a shared account.
! grep -Fq 'upsert_section(cur, "dns_account", account_id, {name = domain' "$CTRL"
grep -q 'Existing DNS accounts are shared resources' "$CTRL"
grep -Fq 'account_name = existing and trim(existing.name)' "$CTRL"
grep -Fq 'account_name = provider_display_name(values.provider, catalog)' "$CTRL"
grep -Fq 'provider = values.provider' "$CTRL"

# Local upload is a distinct source: pair validation/import is delegated to Core,
# no private key is echoed, and local resources never enter automatic ACME renewal.
grep -q 'cert-import ' "$CTRL"
grep -q 'source = "local"' "$CTRL"
grep -q 'local_cert_pem' "$VIEW"
grep -q 'local_key_pem' "$VIEW"
grep -q 'Certificate File' "$VIEW"
grep -q 'Private Key File' "$VIEW"
grep -q 'class="hg-file-native"' "$VIEW"
grep -q 'function hgPublicChooseFile' "$VIEW"
! grep -q 'hg-resource-delete' "$VIEW"
grep -q 'certificate_source(previous) == "local"' "$CTRL"
grep -q 'certificate_use_count(cur, cert_id) <= 1' "$CTRL"
grep -q 'cleanup_local_certificate_files' "$CTRL"
grep -q 'strings.EqualFold(strings.TrimSpace(cert.Source), "local")' "$ROOT/project/core/src/internal/acme/service.go"
grep -q 'local certificate is not ACME-managed' "$ROOT/project/core/src/internal/acme/service.go"

# Provider discovery and local-certificate Core commands retain machine-readable stdout.
grep -q 'case "dns-zones"' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'case "cert-import"' "$ROOT/project/core/src/cmd/homegate/main.go"
grep -q 'api.WriteJSON(os.Stdout, report)' "$ROOT/project/core/src/cmd/homegate/main.go"

# Source-level shared-scope examples.
python3 - <<'PY'
def scope(zone, domain):
    zone=zone.strip().lower().rstrip('.')
    domain=domain.strip().lower().rstrip('.')
    if domain==zone:
        base=zone
    elif domain.endswith('.'+zone):
        base=domain.split('.',1)[1]
    else:
        return None
    return [base, '*.'+base]
assert scope('chenos.cn','vault.chenos.cn') == ['chenos.cn','*.chenos.cn']
assert scope('chenos.cn','home.chenos.cn') == ['chenos.cn','*.chenos.cn']
assert scope('chenos.cn','api.home.chenos.cn') == ['home.chenos.cn','*.home.chenos.cn']
assert scope('chenos.cn','v1.api.home.chenos.cn') == ['api.home.chenos.cn','*.api.home.chenos.cn']
assert scope('chenos.cn','chenos.cn') == ['chenos.cn','*.chenos.cn']
print('automatic shared-scope examples: PASS')
PY

# Chinese wording: all three core labels/options are four Chinese characters.
grep -A1 'msgid "Certificate Source"' "$PO" | grep -q 'msgstr "证书来源"'
grep -A1 'msgid "Automatic Management"' "$PO" | grep -q 'msgstr "自动管理"'
grep -A1 'msgid "Local Upload"' "$PO" | grep -q 'msgstr "本地上传"'
grep -A1 'msgid "Certificate Scope"' "$PO" | grep -q 'msgstr "证书范围"'

if command -v texluac >/dev/null 2>&1; then texluac -p "$CTRL"; fi
"$ROOT/scripts/ui-js-check.sh" >/dev/null

echo "HomeGate $VERSION service/certificate integration smoke: PASS"
