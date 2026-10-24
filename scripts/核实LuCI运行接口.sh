#!/bin/sh
# Read-only interface inventory. Never execute HomeGate, call ubus methods,
# print sessions/configuration, install packages, or change service state.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
case "${1:-}" in
    --help)
        printf '%s\n' 'Usage: sh scripts/核实LuCI运行接口.sh' \
            'Run locally on the intended OpenWrt target. Inventory only, not acceptance.' \
            'No secrets, session values, configuration contents or ubus method calls.'
        exit 0 ;;
    '') [ "$#" -eq 0 ] || exit 2 ;;
    *) printf '%s\n' 'unexpected argument' >&2; exit 2 ;;
esac
printf '%s\n' 'schema=homegate-luci-interface-inventory-v1' 'acceptance=false' 'production_ready=false'
if [ ! -r /etc/openwrt_release ]; then
    printf '%s\n' 'scope=not-openwrt' 'result=target-required'
    exit 2
fi
printf '%s\n' 'scope=target-read-only'
printf '\n[packages]\n'
if command -v opkg >/dev/null 2>&1; then
    opkg list-installed | awk '$1 ~ /^(lua|luci-base|luci-compat|luci-lua-runtime|luci-theme-bootstrap|luci-lib-nixio|luci-lib-jsonc|rpcd|rpcd-mod-ucode|ucode|ucode-mod-fs)$/ {print}'
elif command -v apk >/dev/null 2>&1; then
    printf '%s\n' 'apk-present; use the existing device inventory for package versions'
else
    printf '%s\n' 'package-manager=unavailable'
fi
printf '\n[lua-interfaces]\n'
if command -v lua >/dev/null 2>&1; then
    if ! lua - 2>/dev/null <<'LUA'
print('lua=' .. _VERSION)
local requirements = {
 {'luci.http', {'getenv', 'formvalue', 'status', 'prepare_content', 'write'}},
 {'luci.dispatcher', {'entry', 'call', 'post'}},
 {'luci.template', {'render'}},
 {'luci.jsonc', {'parse', 'stringify'}},
 {'luci.sys', {'exec'}},
 {'nixio', {'open', 'open_flags'}},
 {'nixio.fs', {'mkdir', 'unlink', 'rmdir'}},
 {'nixio.util', {}}
}
for _, item in ipairs(requirements) do
 local ok, m = pcall(require, item[1])
 local loaded = ok and (#item[2]==0 or type(m)=='table')
 print(item[1] .. '=' .. (loaded and 'loadable' or 'unavailable'))
 if ok and type(m)=='table' then
  for _, name in ipairs(item[2]) do
   print(item[1] .. '.' .. name .. '=' .. (type(m[name])=='function' and 'function' or 'unavailable'))
  end
 end
end
print('http-session-csrf-and-file-method-semantics=not-tested')
LUA
    then printf '%s\n' 'lua-probe=failed'; fi
else
    printf '%s\n' 'lua=unavailable'
fi
printf '\n[ucode-fs-imports]\n'
if command -v ucode >/dev/null 2>&1; then
    if ! ucode -e 'import { mkdir, open, unlink, rmdir, popen } from "fs"; print("fs-imports=available\n");' 2>/dev/null; then
        printf '%s\n' 'fs-imports=unavailable'
    fi
else
    printf '%s\n' 'ucode=unavailable'
fi
printf '\n[fixed-path-presence]\n'
for item in /usr/lib/lua/luci/controller/homegate_ddns.lua \
    /usr/lib/lua/luci/model/homegate/backup.lua \
    /usr/lib/lua/luci/model/homegate/ddns.lua \
    /usr/lib/lua/luci/view/homegate/ddns.htm \
    /usr/share/rpcd/ucode/homegate-ddns \
    /usr/share/rpcd/acl.d/homegate-ddns.json \
    /usr/libexec/homegate/ddns-ui /proc/sys/kernel/random/uuid; do
    if [ -r "$item" ]; then printf '%s=present\n' "$item"; else printf '%s=absent\n' "$item"; fi
done
printf '\n[ubus-signatures-only]\n'
if command -v ubus >/dev/null 2>&1; then
    for object in session homegate_ddns; do
        printf 'object=%s\n' "$object"
        if ! ubus -t 3 -v list "$object" 2>/dev/null; then printf '%s\n' 'signature-query=unavailable'; fi
    done
else
    printf '%s\n' 'ubus=unavailable'
fi
printf '\n[result]\n'
printf '%s\n' 'result=inventory-only' 'rpcd-session-acl=not-tested' \
    'real-http-post-csrf=not-tested' 'candidate-execution=not-tested' 'production_ready=false'
