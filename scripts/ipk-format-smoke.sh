#!/bin/sh
set -eu

ipk="${1:-}"
[ -n "$ipk" ] || { echo "usage: $0 <homegate.ipk>" >&2; exit 2; }
[ -f "$ipk" ] || { echo "missing ipk: $ipk" >&2; exit 2; }

# QWRT/OpenWrt target compatibility baseline for this project uses the
# legacy gzip-compressed tar outer container, not Debian ar.
magic="$(od -An -tx1 -N2 "$ipk" | tr -d ' \n')"
[ "$magic" = "1f8b" ] || {
    echo "ipk outer format must be gzip-tar (magic 1f8b), got $magic" >&2
    exit 1
}

members="$(tar -tzf "$ipk" | sed 's#^\./##')"
for want in debian-binary control.tar.gz data.tar.gz; do
    printf '%s\n' "$members" | grep -qx "$want" || {
        echo "missing outer member: $want" >&2
        exit 1
    }
done

count="$(printf '%s\n' "$members" | grep -Ec '^(debian-binary|control\.tar\.gz|data\.tar\.gz)$')"
[ "$count" -eq 3 ] || {
    echo "unexpected duplicate/missing required outer members" >&2
    exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

tar -xzf "$ipk" -C "$tmp"
[ "$(cat "$tmp/debian-binary")" = "2.0" ] || {
    echo "invalid debian-binary" >&2
    exit 1
}
gzip -t "$tmp/control.tar.gz"
gzip -t "$tmp/data.tar.gz"
control_members="$(tar -tzf "$tmp/control.tar.gz" | sed 's#^\./##')"
data_members="$(tar -tzf "$tmp/data.tar.gz" | sed 's#^\./##')"
printf '%s\n' "$control_members" >/dev/null
printf '%s\n' "$data_members" >/dev/null

tar -xzf "$tmp/control.tar.gz" -C "$tmp"
pkg_name="$(sed -n 's/^Package:[[:space:]]*//p' "$tmp/control" | head -n1)"
if [ "$pkg_name" = "homegate" ]; then
    for want in control conffiles postinst prerm; do
        printf '%s\n' "$control_members" | grep -qx "$want" || {
            echo "homegate control archive missing lifecycle member: $want" >&2
            exit 1
        }
    done
    grep -qx '/etc/config/homegate' "$tmp/conffiles" || {
        echo "homegate conffiles contract missing /etc/config/homegate" >&2
        exit 1
    }
    # Legacy pre-SDK packages embedded package lifecycle bodies directly in
    # postinst/prerm. Standard OpenWrt/ImmortalWrt BuildPackage wraps those
    # entry points with default_postinst/default_prerm and stores the package
    # bodies as postinst-pkg/prerm-pkg. Accept both layouts so this smoke test
    # remains a negative-regression gate for old packages while validating
    # the official SDK output correctly.
    postinst_body="$tmp/postinst"
    prerm_body="$tmp/prerm"
    standard_sdk=0
    if printf '%s\n' "$control_members" | grep -qx 'postinst-pkg' || \
       printf '%s\n' "$control_members" | grep -qx 'prerm-pkg'; then
        standard_sdk=1
        for want in preinst postinst-pkg prerm-pkg postrm; do
            printf '%s\n' "$control_members" | grep -qx "$want" || {
                echo "homegate standard SDK lifecycle missing: $want" >&2
                exit 1
            }
        done
        grep -q 'default_postinst' "$tmp/postinst" || {
            echo "homegate standard SDK postinst wrapper missing default_postinst" >&2
            exit 1
        }
        grep -q 'default_prerm' "$tmp/prerm" || {
            echo "homegate standard SDK prerm wrapper missing default_prerm" >&2
            exit 1
        }
        grep -q 'HOMEGATE_PACKAGE_UPGRADE_STATE' "$tmp/preinst" || {
            echo "homegate standard SDK preinst missing lifecycle state preservation" >&2
            exit 1
        }
        grep -q 'was_running=' "$tmp/preinst" || {
            echo "homegate standard SDK preinst missing upgrade running-state preservation" >&2
            exit 1
        }
        postinst_body="$tmp/postinst-pkg"
        prerm_body="$tmp/prerm-pkg"
        ! grep -q '/etc/init.d/homegate start' "$postinst_body" || {
            echo "homegate standard SDK postinst-pkg must delegate start to default_postinst" >&2
            exit 1
        }
        sh -n "$tmp/preinst"
        sh -n "$tmp/postinst-pkg"
        sh -n "$tmp/prerm-pkg"
    fi
    if [ "$standard_sdk" -eq 0 ]; then
        grep -q '/etc/init.d/homegate stop' "$prerm_body" || {
            echo "homegate legacy prerm missing stop contract" >&2
            exit 1
        }
        grep -q '/usr/bin/homegate firewall-cleanup' "$prerm_body" || {
            echo "homegate legacy prerm missing firewall cleanup contract" >&2
            exit 1
        }
        grep -q '/etc/init.d/homegate start' "$postinst_body" || {
            echo "homegate legacy postinst missing start contract" >&2
            exit 1
        }
    else
        # Stage 10 accepted lifecycle: default_prerm owns the canonical init stop.
        # HomeGate's prerm-pkg only snapshots upgrade state; true-remove runtime/log
        # cleanup happens in postrm after the standard stop has fully completed.
        grep -q 'PKG_UPGRADE' "$prerm_body" || {
            echo "homegate standard SDK prerm-pkg missing upgrade-state contract" >&2
            exit 1
        }
        grep -q 'was_running=' "$prerm_body" || {
            echo "homegate standard SDK prerm-pkg missing running-state snapshot" >&2
            exit 1
        }
        ! grep -q '/etc/init.d/homegate stop' "$prerm_body" || {
            echo "homegate standard SDK prerm-pkg must delegate stop to default_prerm" >&2
            exit 1
        }
        grep -q 'runtime_dir=' "$tmp/postrm" || {
            echo "homegate standard SDK postrm missing final runtime cleanup" >&2
            exit 1
        }
        grep -q 'log_file=' "$tmp/postrm" || {
            echo "homegate standard SDK postrm missing final log cleanup" >&2
            exit 1
        }
        sh -n "$tmp/postrm"
    fi
    sh -n "$tmp/prerm"
    sh -n "$tmp/postinst"
    for want in usr/bin/homegate etc/config/homegate etc/init.d/homegate etc/hotplug.d/iface/95-homegate; do
        printf '%s\n' "$data_members" | grep -qx "$want" || {
            echo "homegate data archive missing payload: $want" >&2
            exit 1
        }
    done
fi

echo "ipk outer-format smoke: PASS"
