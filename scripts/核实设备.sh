#!/bin/sh
# Read-only: no HomeGate UCI, credentials, private keys or network changes.
set -u
export LC_ALL=C
section() { printf '\n[%s]\n' "$1"; }
section release
if [ -r /etc/openwrt_release ]; then cat /etc/openwrt_release; else printf 'unknown\n'; fi
section kernel
uname -sr
section machine
uname -m
section package_manager
for tool in opkg apk; do
    if command -v "$tool" >/dev/null 2>&1; then
        command -v "$tool"
        "$tool" --version 2>&1
    fi
done
section package_architectures
if command -v opkg >/dev/null 2>&1; then opkg print-architecture; fi
if command -v apk >/dev/null 2>&1; then
    apk --print-arch
    if [ -r /etc/apk/arch ]; then cat /etc/apk/arch; fi
fi
section luci_packages
if command -v opkg >/dev/null 2>&1; then
    opkg list-installed | awk '$1 ~ /^(luci-base|luci-compat|luci-lua-runtime|luci-theme-bootstrap|rpcd|rpcd-mod-ucode|ucode|lua|libuci|libubus)$/ {print}'
elif command -v apk >/dev/null 2>&1; then
    apk list --installed 2>/dev/null | awk '$1 ~ /^(luci-base|luci-compat|luci-lua-runtime|luci-theme-bootstrap|rpcd|rpcd-mod-ucode|ucode|lua|libuci|libubus)-/ {print}'
fi
section frontend_paths
for item in /usr/lib/lua/luci/dispatcher.lua /www/luci-static/resources/view.js /usr/share/ucode/luci/dispatcher.uc; do
    if [ -r "$item" ]; then printf '%s\n' "$item"; fi
done
section available_tools
for tool in uci ubus ucode lua openssl curl nginx nft ip6tables etherwake; do
    command -v "$tool" 2>/dev/null || :
done
section memory
awk '/^(MemTotal|MemAvailable|MemFree|SwapTotal):/ {print}' /proc/meminfo
section storage
df -k / /overlay /tmp 2>/dev/null || df -k / /tmp
section status
printf 'SDK, ABI, firmware customization, browser compatibility and resource budget require separate verification.\n'
