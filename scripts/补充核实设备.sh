#!/bin/sh
# Read-only local inventory. No package installation, service control,
# network access, UCI export, repository URLs or secret/key contents.
set -u
export LC_ALL=C
section() { printf '\n[%s]\n' "$1"; }
section model
for item in /tmp/sysinfo/model /tmp/sysinfo/board_name; do
    if [ -r "$item" ]; then
        printf '%s: ' "$item"
        cat "$item"
        printf '\n'
    fi
done
if [ -r /proc/device-tree/model ]; then
    printf 'device_tree_model: '
    tr -d '\000' < /proc/device-tree/model
    printf '\n'
fi
section dependency_packages
if command -v opkg >/dev/null 2>&1; then
    opkg list-installed | awk '$1 ~ /^(kernel|libc|libgcc[^ ]*|libstdcpp[^ ]*|libubox[^ ]*|libubus[^ ]*|libuci[^ ]*|libblobmsg[^ ]*|libjson[^ ]*|liblua[^ ]*|libustream[^ ]*|libopenssl[^ ]*|libmbedtls[^ ]*|libwolfssl[^ ]*|libcurl[^ ]*|curl|openssl-util|ca-bundle|ca-certificates|busybox|jsonfilter|jshn|ucode[^ ]*|rpcd[^ ]*|uhttpd[^ ]*|firewall|firewall4|iptables[^ ]*|ip6tables[^ ]*|nftables[^ ]*|kmod-nft[^ ]*|kmod-ipt[^ ]*|nginx[^ ]*|acme[^ ]*|etherwake|wakeonlan|homegate)$/ {print}'
else
    printf 'opkg unavailable; this supplement is for the reported QWRT/IPK target\n'
fi
section loader_files
for item in /lib/ld-* /lib/libc.so* /lib/libuClibc*; do
    if [ -e "$item" ] || [ -L "$item" ]; then ls -ld "$item"; fi
done
section elf_header
if command -v readelf >/dev/null 2>&1; then
    readelf -h /bin/busybox
    readelf -l /bin/busybox | awk '/interpreter/ {print}'
else
    printf 'readelf unavailable; do not install it solely for this report\n'
fi
section tool_versions
if command -v busybox >/dev/null 2>&1; then
    busybox 2>&1 | awk 'NR <= 2 {print}'
    printf 'selected_busybox_applets:\n'
    busybox --list | awk '/^(ash|awk|flock|httpd|ip|logger|nc|sha256sum|timeout|wget)$/ {print}'
fi
if command -v openssl >/dev/null 2>&1; then openssl version; fi
if command -v curl >/dev/null 2>&1; then curl --version; fi
if command -v ip6tables >/dev/null 2>&1; then ip6tables --version; fi
if command -v nft >/dev/null 2>&1; then nft --version; fi
section frontend_components
for item in /usr/lib/lua/luci/cbi.lua /usr/lib/lua/luci/template.lua /usr/lib/lua/luci/jsonc.so /usr/lib/lua/luci/jsonc.lua /usr/share/libubox/jshn.sh /www/luci-static/resources/view.js /usr/share/ucode/luci/dispatcher.uc; do
    if [ -r "$item" ]; then printf '%s\n' "$item"; fi
done
section firewall_components
for tool in fw3 fw4 nginx acme.sh etherwake wakeonlan jsonfilter ucode; do
    command -v "$tool" 2>/dev/null || :
done
section status
printf 'Component presence is inventory only; SDK match, active firewall integration, Lua rendering and resource peaks still need verification.\n'
