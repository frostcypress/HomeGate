#!/bin/sh
set -eu

IPK="${1:-}"
[ -n "$IPK" ] && [ -f "$IPK" ] || { echo "usage: $0 <homegate.ipk>" >&2; exit 2; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

case "$(file -b "$IPK" 2>/dev/null || true)" in
  *gzip*) gzip -dc "$IPK" | tar -xf - -C "$TMP" ;;
  *) (cd "$TMP" && ar x "$IPK") ;;
esac
[ -f "$TMP/control.tar.gz" ] || { echo "missing control.tar.gz" >&2; exit 1; }
[ -f "$TMP/data.tar.gz" ] || { echo "missing data.tar.gz" >&2; exit 1; }
mkdir "$TMP/control" "$TMP/data"
tar -xzf "$TMP/control.tar.gz" -C "$TMP/control"
tar -xzf "$TMP/data.tar.gz" -C "$TMP/data"

for f in control conffiles preinst postinst postinst-pkg prerm prerm-pkg postrm; do
  [ -f "$TMP/control/$f" ] || { echo "missing lifecycle file: $f" >&2; exit 1; }
done
grep -qx '/etc/config/homegate' "$TMP/control/conffiles"
grep -Fq 'if [ "$(uci -q get homegate.main.enabled 2>/dev/null)" = "1" ]; then' "$TMP/control/preinst"
! grep -Fq 'if [ "" = "1" ]; then' "$TMP/control/preinst"
grep -Fq 'snapshot_kind=legacy_desired_state' "$TMP/control/preinst"
grep -Fq 'snapshot_kind=sdk_prerm' "$TMP/control/prerm-pkg"
grep -Fq 'HOMEGATE_PACKAGE_REINSTALL_REQUEST' "$TMP/control/prerm-pkg"
grep -Fq -- '--force-reinstall' "$TMP/control/prerm-pkg"
grep -Fq 'HOMEGATE_PACKAGE_CONFIG_STASH' "$TMP/control/prerm-pkg"
! grep -Fq 'rm -rf "${runtime_dir}"' "$TMP/control/prerm-pkg"
grep -Fq 'HOMEGATE_PACKAGE_REINSTALL_REQUEST' "$TMP/control/postrm"
grep -Fq 'FULL PURGE' "$TMP/control/postrm"
grep -Fq 'rm -rf "${data_dir}"' "$TMP/control/postrm"
grep -Fq 'config_stash' "$TMP/control/postrm"
grep -Fq 'is_upgrade' "$TMP/control/postrm"
grep -Fq 'while pidof homegate' "$TMP/control/postrm"
grep -Fq 'rm -rf "${runtime_dir}"' "$TMP/control/postrm"
grep -Fq 'rm -f "${log_file}"' "$TMP/control/postrm"
[ -x "$TMP/data/usr/sbin/homegate-purge" ]
grep -Fq 'force-removal-of-dependent-packages' "$TMP/data/usr/sbin/homegate-purge"
sh -n "$TMP/control/preinst"
sh -n "$TMP/control/postinst-pkg"
sh -n "$TMP/control/prerm-pkg"
sh -n "$TMP/control/postrm"
sh -n "$TMP/data/usr/sbin/homegate-purge"
echo "SDK package lifecycle audit: PASS"
