#!/bin/sh
# Fixed public package/tool metadata only; no configuration, service or writes.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
printf '[native_install_inventory]\nformat=homegate-native-install-inventory-v1\nread_only=true\nacceptance=false\n'
if [ ! -r /etc/openwrt_release ] || ! command -v opkg >/dev/null 2>&1;then
 printf 'status=target-required\n';exit 2
fi
printf '\n[package_architectures]\n'
opkg print-architecture || exit 2
printf '\n[installed_package_metadata]\n'
# No Conffiles, descriptions, credentials or UCI content are exported. Preserve
# wrapped package fields, including actual virtual provider declarations.
metadata=$(opkg status) || exit 2
[ -n "$metadata" ] || exit 2
printf '%s\n' "$metadata" | awk '
 /^[A-Za-z][A-Za-z0-9-]*:/ {keep=($0 ~ /^(Package|Version|Status|Architecture|Provides|Depends|Conflicts):/);if(keep)print;next}
 /^[ \t]/ {if(keep)print;next}
 /^$/ {print;keep=0}
'
printf '\n[commands]\n'
for tool in ash lua uci ubus curl openssl sha256sum stat fsync flock ip ip6tables opkg mkdir mv rm sleep cat;do
 if path=$(command -v "$tool" 2>/dev/null);then printf 'tool=%s;path=%s\n' "$tool" "$path";else printf 'tool=%s;path=missing\n' "$tool";fi
done
printf '\n[fixed_framework_files]\n'
for path in /etc/rc.common /lib/functions.sh /lib/functions/procd.sh /etc/init.d/homegate /usr/lib/lua/luci/jsonc.so /usr/lib/lua/nixio.so /usr/lib/lua/nixio/fs.lua;do
 if [ -f "$path" ];then printf 'file=%s;state=present\n' "$path";else printf 'file=%s;state=missing\n' "$path";fi
done
printf '\n[boundary]\nMetadata only. No opkg update/install/remove, UCI reads, config hashes, process/service calls or version probe repeated. No installation authorization.\n'
