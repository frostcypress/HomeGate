#!/bin/sh
# Temporary version-only load evidence. Never install or start a service.
set -eu
[ "$#" -eq 0 ] || exit 2
unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
cd -P "$(dirname "$0")"
printf '[native_component_probe]\nformat=homegate-native-component-v1\nacceptance=false\nproduction_ready=false\n'
printf 'supervisor=private-static-v1\nlimit_seconds_per_component=10\n'
if [ ! -r /etc/openwrt_release ] || ! command -v opkg >/dev/null 2>&1; then
    printf 'status=target-required\n'
    exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    printf 'status=required-existing-tool-unavailable\nmissing_tool=sha256sum\n'
    exit 2
fi
if [ ! -x ./probe-run ]; then
    printf 'status=private-supervisor-unavailable\n'
    exit 2
fi
if ! sha256sum -c ./SHA256SUMS; then
    printf 'status=package-integrity-failed\n'
    exit 2
fi
status=0
printf '\n[nginx_version_only]\n'
rc=0
./probe-run --nginx 2>&1 || rc=$?
printf 'exit_code=%s\n' "$rc"
[ "$rc" -eq 0 ] || status=1
printf '\n[wol_version_only]\n'
rc=0
./probe-run --wol 2>&1 || rc=$?
printf 'exit_code=%s\n' "$rc"
[ "$rc" -eq 0 ] || status=1
printf '\n[boundary]\nVersion-only loading; no config, listeners, service, WOL packet or installation requested. Function, privilege-drop and resource acceptance remain pending.\n'
exit "$status"
