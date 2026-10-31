#!/bin/sh
# Read-only fixed library inventory; no install, UCI, services or network.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C
section() { printf '\n[%s]\n' "$1"; }
section native_abi_probe
printf 'format=homegate-native-abi-v1\nmode=read-only\nacceptance=false\nproduction_ready=false\n'
if [ ! -r /etc/openwrt_release ] || ! command -v opkg >/dev/null 2>&1;then
 printf 'status=target-required\n';exit 2
fi
printf 'status=collected\n'
section release
awk '/^DISTRIB_(ID|RELEASE|REVISION|TARGET|ARCH)=/ {print}' /etc/openwrt_release
section kernel
uname -sr
section package_architectures
opkg print-architecture
section dependency_packages
opkg list-installed | awk '$1 ~ /^(kernel|libc|libgcc[^ ]*|lua|liblua[^ ]*|libopenssl[^ ]*|libpcre[^ ]*|libubox[^ ]*|libubus[^ ]*|libuci[^ ]*|luci-base|luci-lib-nixio|luci-lib-jsonc|procd|opkg|ip6tables[^ ]*|kmod-ipt[^ ]*)$/ {print}'
for path in /bin/busybox /lib/ld-musl-aarch64.so.1 /lib/libc.so /usr/lib/libssl.so.3 /usr/lib/libcrypto.so.3 /usr/lib/libssl.so.1.1 /usr/lib/libcrypto.so.1.1 /usr/lib/libpcre2-8.so.0;do
 section "elf:$path"
 if [ ! -f "$path" ];then printf 'state=missing\n';continue;fi
 printf 'state=present\n'
 if command -v stat >/dev/null 2>&1;then stat -Lc 'identity_before=%d:%i:%u:%a:%s' "$path" 2>/dev/null || printf 'identity_before=unknown\n';fi
 if command -v sha256sum >/dev/null 2>&1;then sha256sum "$path";else printf 'sha256=unavailable\n';fi
 if command -v od >/dev/null 2>&1;then
  printf 'elf_header_hex=';od -An -v -tx1 -N64 "$path" 2>/dev/null | tr -d ' \n';printf '\n'
 else printf 'elf_header_hex=unavailable\n';fi
 if command -v readelf >/dev/null 2>&1;then
  readelf -h "$path" 2>/dev/null | awk '/Class:|Data:|Machine:/ {print}'
  readelf -d "$path" 2>/dev/null | awk '/\(NEEDED\)|\(SONAME\)/ {if(++n<=64)print}'
  readelf --dyn-syms --wide "$path" 2>/dev/null | awk '/X509_check_ip|SSL_CTX_new|OPENSSL_init_ssl/ {if(++n<=24)print}'
 else printf 'dynamic_metadata=unavailable; use a trusted host tool on public ELF library copies; do not install readelf solely for this probe\n';fi
 if command -v stat >/dev/null 2>&1;then stat -Lc 'identity_after=%d:%i:%u:%a:%s' "$path" 2>/dev/null || printf 'identity_after=unknown\n';fi
done
section boundary
printf 'Collection only. Package names and ELF headers do not establish ABI. No target verification or deployment authorization granted.\n'
