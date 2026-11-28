#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VIEW="$ROOT/project/luci/lua/luasrc/view/homegate"
COMMON="$VIEW/common.htm"
WOL="$VIEW/wol.htm"
PUBLIC="$VIEW/public.htm"
BASIC="$VIEW/basic.htm"

# These selectors had no HTML/JS references in 0.5.0-48; keep them gone instead of
# allowing old compatibility debris to creep back into the generic theme foundation.
for dead in hg-btn-6 hg-ok hg-error hg-inline-note hg-modal-close hg-inline-control hg-inline-form hg-section-last; do
    if grep -R -q "\.${dead}\>" "$VIEW"; then
        echo "ui phase2c smoke: dead selector returned: $dead" >&2
        exit 1
    fi
done

# Closed modal state belongs to first-paint markup; pages no longer mutate it in startup JS.
grep -Fq 'id="hg-basic-log-modal" aria-hidden="true" onclick="hgModalBackdrop(event)"' "$BASIC"
grep -Fq 'id="hg-public-access-modal" class="hg-modal-backdrop" aria-hidden="true" onclick="hgModalBackdrop(event)"' "$PUBLIC"
grep -Fq 'id="hg-public-modal" aria-hidden="true" onclick="hgModalBackdrop(event)"' "$PUBLIC"
grep -Fq 'id="hg-wol-modal" aria-hidden="true" onclick="hgModalBackdrop(event)"' "$WOL"
for page in "$BASIC" "$PUBLIC" "$WOL"; do
    ! grep -Fq "setAttribute('aria-hidden','true')" "$page"
done

# WOL first render and JS redraw now use the same index-based edit/delete contract.
! grep -q 'function hgWolOpenEdit' "$WOL"
! grep -q 'function hgWolDelete(btn)' "$WOL"
grep -Fq 'onclick="hgWolOpenIndex(<%=i-1%>)"' "$WOL"
grep -Fq 'onclick="hgWolDeleteIndex(<%=i-1%>)"' "$WOL"
grep -q 'function hgWolOpenIndex' "$WOL"
grep -q 'function hgWolDeleteIndex' "$WOL"

# Access rules are staged through hidden allow/deny editors; no legacy raw textarea contract returns.
! grep -q 'editor.oninput=hgPublicAccessSyncAllow' "$PUBLIC"
grep -q 'id="hg-public-access-allow-editor"' "$PUBLIC"
grep -q 'id="hg-public-access-deny-editor"' "$PUBLIC"
! grep -q 'function hgPublicAccessRenderAllowList' "$PUBLIC"
grep -q 'function hgPublicAccessRenderRecent' "$PUBLIC"

echo 'ui phase2c dead-code/render-state smoke: PASS'
