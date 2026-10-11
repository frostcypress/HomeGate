include $(TOPDIR)/rules.mk
include $(TOPDIR)/homegate-version.mk

PKG_NAME:=homegate
PKG_VERSION:=$(HOMEGATE_VERSION)
PKG_RELEASE:=$(HOMEGATE_RELEASE)
PKG_LICENSE:=MIT AND Apache-2.0
PKG_LICENSE_FILES:=LICENSE Apache-2.0.txt
PKG_MAINTAINER:=HomeGate contributors

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

# The Go binary is already intentionally stripped by `go build -ldflags='-s -w'`.
# OpenWrt/ImmortalWrt rstrip/sstrip changes its bytes after Build/Compile, breaking
# HomeGate's reproducible release contract. Keep the exact SDK-built Go artifact.
RSTRIP:=:

define Package/homegate
  SECTION:=net
  CATEGORY:=Network
  TITLE:=HomeGate core service
  DEPENDS:=+uci +ubus +ip +ip6tables +ca-bundle
endef

define Package/homegate/description
 HomeGate core runtime for DDNS, ACME, reverse proxy, access restriction and Wake-on-LAN.
 Phase 6 adds the validated HTTPS reverse proxy and IPv6 firewall lifecycle on top of DDNS and ACME.
 Phase 6b adds bounded cold-boot firewall recovery while PPPoE IPv6 is still coming up.
 Phase 7 migrates r6 Wake-on-LAN with raw Ethernet 0x0842 plus UDP broadcast, using the common LAN resolver for bridge members.
 It uses no external etherwake helper and preserves the legacy CLI contract used by the frozen r6 LuCI controller.
endef

define Package/homegate/conffiles
/etc/config/homegate
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/src/. $(PKG_BUILD_DIR)/
	$(CP) $(CURDIR)/../../LICENSE $(PKG_BUILD_DIR)/LICENSE
	$(CP) ./files/usr/share/licenses/homegate/Apache-2.0.txt $(PKG_BUILD_DIR)/Apache-2.0.txt
endef

define Build/Compile
	( cd $(PKG_BUILD_DIR); \
		CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -buildvcs=false -trimpath -ldflags='-s -w -X main.version=$(PKG_VERSION)-$(PKG_RELEASE)' -o homegate ./cmd/homegate )
endef

define Package/homegate/install
	$(INSTALL_DIR) $(1)/usr/share/licenses/homegate
	$(INSTALL_DATA) ./files/usr/share/licenses/homegate/* $(1)/usr/share/licenses/homegate/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/homegate $(1)/usr/bin/homegate
	$(INSTALL_DIR) $(1)/etc/config
	sed 's/@HOMEGATE_VERSION@/$(PKG_VERSION)-$(PKG_RELEASE)/g' ./files/etc/config/homegate > $(1)/etc/config/homegate
	chmod 600 $(1)/etc/config/homegate
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/homegate $(1)/etc/init.d/homegate
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/95-homegate $(1)/etc/hotplug.d/iface/95-homegate
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/homegate-purge $(1)/usr/sbin/homegate-purge
endef

define Package/homegate/preinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	state="$${HOMEGATE_PACKAGE_UPGRADE_STATE:-/tmp/.homegate-package-upgrade-state}"
	installed="$${HOMEGATE_PACKAGE_INSTALLED_CONTROL:-/usr/lib/opkg/info/homegate.control}"
	init="$${HOMEGATE_PACKAGE_INIT:-/etc/init.d/homegate}"

	# opkg normal-upgrade order is OLD prerm -> NEW preinst. SDK-aware old
	# packages (53+) persist the exact boot/running state from prerm *before*
	# stopping the daemon. Never overwrite that authoritative snapshot here.
	if [ ! -f "$${state}" ] && [ -f "$${installed}" ]; then
		case "$${1:-}" in
			upgrade)
				# Legacy packages (<=52, including accepted 49) did not persist
				# process state before their prerm stopped HomeGate. That lost bit
				# cannot be reconstructed here. Preserve the established legacy
				# upgrade behavior instead: desired UCI enabled => restart.
				if [ "$$(uci -q get homegate.main.enabled 2>/dev/null)" = "1" ]; then
					was_running=1
				else
					was_running=0
				fi
				snapshot_kind=legacy_desired_state
				;;
			*)
				if pidof homegate >/dev/null 2>&1; then
					was_running=1
				else
					was_running=0
				fi
				snapshot_kind=direct
				;;
		esac
		{
			echo "was_running=$${was_running}"
			echo "snapshot_kind=$${snapshot_kind}"
		} > "$${state}"
	fi
}
exit 0
endef

define Package/homegate/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	state="$${HOMEGATE_PACKAGE_UPGRADE_STATE:-/tmp/.homegate-package-upgrade-state}"
	config_file="$${HOMEGATE_PACKAGE_CONFIG_FILE:-/etc/config/homegate}"
	config_stash="$${HOMEGATE_PACKAGE_CONFIG_STASH:-/tmp/.homegate-package-config-stash}"
	reinstall_req="$${HOMEGATE_PACKAGE_REINSTALL_REQUEST:-/tmp/.homegate-reinstall-request}"

	# QWRT's `opkg install --force-reinstall` is a remove -> install path and
	# does not set PKG_UPGRADE=1. Detect that explicit command so reinstall
	# remains data-preserving while a real uninstall is intentionally destructive.
	opkg_cmd="$${HOMEGATE_PACKAGE_OPKG_CMDLINE:-}"
	if [ -z "$${opkg_cmd}" ] && [ -n "$${PPID:-}" ] && [ -r "/proc/$${PPID}/cmdline" ]; then
		opkg_cmd="$$(tr '\000' ' ' < "/proc/$${PPID}/cmdline" 2>/dev/null || true)"
	fi
	is_force_reinstall=0
	case " $${opkg_cmd} " in
		*" --force-reinstall "*) is_force_reinstall=1 ;;
	esac

	if [ "$${PKG_UPGRADE:-0}" = "1" ] || [ "$${1:-}" = "upgrade" ]; then
		if pidof homegate >/dev/null 2>&1; then
			was_running=1
		else
			was_running=0
		fi
		{
			echo "was_running=$${was_running}"
			echo "snapshot_kind=sdk_prerm"
		} > "$${state}"
		rm -f "$${reinstall_req}" "$${config_stash}"
	else
		rm -f "$${state}"
		if [ "$${is_force_reinstall}" = "1" ]; then
			umask 077
			printf '%s\n' 'reinstall=1' > "$${reinstall_req}"
			rm -f "$${config_stash}"
			if [ -f "$${config_file}" ]; then
				cp -p "$${config_file}" "$${config_stash}"
			fi
		else
			# Product contract from 1.0.1 onward: a real uninstall means FULL PURGE.
			rm -f "$${reinstall_req}" "$${config_stash}"
		fi
	fi
}
exit 0
endef

define Package/homegate/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# Older packages may return from stop before their daemon has completed its
	# bounded shutdown barrier. Wait before default_postinst invokes init start.
	n=0
	while pidof homegate >/dev/null 2>&1 && [ "$${n}" -lt 30 ]; do
		sleep 1
		n=$$((n + 1))
	done
}
exit 0
endef

define Package/homegate/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	state="$${HOMEGATE_PACKAGE_UPGRADE_STATE:-/tmp/.homegate-package-upgrade-state}"
	config_file="$${HOMEGATE_PACKAGE_CONFIG_FILE:-/etc/config/homegate}"
	config_stash="$${HOMEGATE_PACKAGE_CONFIG_STASH:-/tmp/.homegate-package-config-stash}"
	reinstall_req="$${HOMEGATE_PACKAGE_REINSTALL_REQUEST:-/tmp/.homegate-reinstall-request}"
	data_dir="$${HOMEGATE_PACKAGE_DATA_DIR:-/etc/homegate}"
	runtime_dir="$${HOMEGATE_PACKAGE_RUNTIME_DIR:-/var/run/homegate}"
	log_file="$${HOMEGATE_PACKAGE_LOG_FILE:-/var/log/homegate.log}"
	temp_dir="$${HOMEGATE_PACKAGE_TEMP_DIR:-/tmp}"

	# A package postrm may also be called for a normal version upgrade. Only a
	# true remove / force-reinstall remove phase reaches cleanup below.
	is_upgrade=0
	[ "$${PKG_UPGRADE:-0}" = "1" ] && is_upgrade=1
	[ "$${1:-}" = "upgrade" ] && is_upgrade=1

	if [ "$${is_upgrade}" != "1" ]; then
		n=0
		while pidof homegate >/dev/null 2>&1 && [ "$${n}" -lt 30 ]; do
			sleep 1
			n=$$((n + 1))
		done

		# Runtime/log are never retained across a remove phase.
		rm -rf "$${runtime_dir}"
		rm -f "$${log_file}"

		if [ -f "$${reinstall_req}" ]; then
			# Force-reinstall is maintenance, not uninstall: preserve persistent
			# data and restore an unmodified conffile if opkg removed it.
			if [ -f "$${config_stash}" ]; then
				if [ ! -f "$${config_file}" ]; then
					mkdir -p "$$(dirname "$${config_file}")"
					mv "$${config_stash}" "$${config_file}"
				else
					rm -f "$${config_stash}"
				fi
			fi
			rm -f "$${reinstall_req}"
		else
			# FULL PURGE: leave the router as if HomeGate had never owned state.
			config_dir="$$(dirname "$${config_file}")"
			rm -f "$${config_file}" "$${config_file}-opkg" "$${config_stash}"
			rm -f "$${config_dir}/.homegate.importing"
			rm -rf "$${data_dir}"
			rm -rf "$${temp_dir}/homegate" "$${temp_dir}/homegate-frontend-jobs"
			rm -rf "$${temp_dir}"/homegate-access-validate-* "$${temp_dir}"/homegate-before-import-* "$${temp_dir}"/homegate-import-*
			rm -rf "$${temp_dir}"/homegate-local-cert-* "$${temp_dir}"/homegate-local-key-* "$${temp_dir}"/homegate-local-validate-*
			rm -f "$${state}" "$${config_stash}" "$${reinstall_req}" "$${temp_dir}/.homegate-purge-request"
		fi
	fi
}
exit 0
endef

$(eval $(call BuildPackage,homegate))
