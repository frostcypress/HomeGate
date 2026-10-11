include $(TOPDIR)/rules.mk
include $(TOPDIR)/homegate-version.mk
# Frontend choice is independent of SDK package format.
HOMEGATE_LUCI_VARIANT?=lua
ifeq ($(filter $(HOMEGATE_LUCI_VARIANT),lua js),)
  $(error HOMEGATE_LUCI_VARIANT must be lua or js)
endif
ifeq ($(HOMEGATE_LUCI_VARIANT),js)
  HOMEGATE_WEB_DEPENDS:=+rpcd +rpcd-mod-ucode +ucode +ucode-mod-fs
else
  HOMEGATE_WEB_DEPENDS:=+luci-compat
endif

PKG_NAME:=luci-app-homegate
PKG_VERSION:=$(HOMEGATE_VERSION)
PKG_RELEASE:=$(HOMEGATE_RELEASE)
PKG_PO_VERSION:=$(PKG_VERSION)-$(PKG_RELEASE)
PKG_MAINTAINER:=HomeGate contributors
PKG_LICENSE:=Apache-2.0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-homegate
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for HomeGate
  PKGARCH:=all
  DEPENDS:=+homegate +luci-base $(HOMEGATE_WEB_DEPENDS)
endef

define Package/luci-app-homegate/description
 LuCI support for HomeGate.
endef

define Package/luci-i18n-homegate-zh-cn
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=4. Translations
  TITLE:=Translation for luci-app-homegate - Simplified Chinese
  PKGARCH:=all
  # Depend on Core rather than the app package so a plain `opkg remove
  # luci-app-homegate` is not blocked by the installed zh-cn package. The
  # app postrm then schedules product-wide purge after the current opkg
  # transaction releases its lock.
  DEPENDS:=+homegate
endef

define Package/luci-i18n-homegate-zh-cn/description
 Simplified Chinese translation for luci-app-homegate.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
endef

define Build/Compile
	python3 $(CURDIR)/common/tools/po2lmo.py \
		$(CURDIR)/common/po/zh_Hans/homegate.po \
		$(PKG_BUILD_DIR)/homegate.zh-cn.lmo
endef

ifeq ($(HOMEGATE_LUCI_VARIANT),js)
define Package/luci-app-homegate/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./js/htdocs/. $(1)/www/
	$(CP) ./js/root/. $(1)/
	$(CP) ./common/root/. $(1)/
endef
else
define Package/luci-app-homegate/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./lua/luasrc/controller/homegate.lua $(1)/usr/lib/lua/luci/controller/homegate.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/homegate
	$(INSTALL_DATA) ./lua/luasrc/view/homegate/*.htm $(1)/usr/lib/lua/luci/view/homegate/
	$(CP) ./common/root/* $(1)/
endef
endif

define Package/luci-app-homegate/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	# The product's user-facing package is luci-app-homegate. A real removal of
	# that package must therefore mean FULL PURGE, not "UI only". Because this
	# script runs while opkg still owns its package lock, schedule the Core purge
	# immediately after the current transaction exits rather than nesting opkg.
	is_upgrade=0
	[ "$${PKG_UPGRADE:-0}" = "1" ] && is_upgrade=1
	[ "$${1:-}" = "upgrade" ] && is_upgrade=1

	opkg_cmd="$${HOMEGATE_PACKAGE_OPKG_CMDLINE:-}"
	if [ -z "$${opkg_cmd}" ] && [ -n "$${PPID:-}" ] && [ -r "/proc/$${PPID}/cmdline" ]; then
		opkg_cmd="$$(tr '\000' ' ' < "/proc/$${PPID}/cmdline" 2>/dev/null || true)"
	fi
	is_force_reinstall=0
	case " $${opkg_cmd} " in
		*" --force-reinstall "*) is_force_reinstall=1 ;;
	esac

	if [ "$${is_upgrade}" != "1" ] && [ "$${is_force_reinstall}" != "1" ]; then
		purge_marker="$${HOMEGATE_PURGE_MARKER:-/tmp/.homegate-purge-request}"
		purge_helper="$${HOMEGATE_LUCI_PURGE_HELPER:-/usr/sbin/homegate-purge}"
		purge_delay="$${HOMEGATE_LUCI_PURGE_DELAY:-2}"
		purge_log="$${HOMEGATE_UNINSTALL_LOG:-/tmp/homegate-uninstall.log}"
		# If the app is being removed as a reverse dependent of an already-running
		# homegate-purge transaction, the marker suppresses a recursive purge.
		if [ ! -f "$${purge_marker}" ] && [ -x "$${purge_helper}" ]; then
			umask 077
			printf '%s\n' 'purge=1' > "$${purge_marker}"
			(
				sleep "$${purge_delay}"
				"$${purge_helper}" >>"$${purge_log}" 2>&1
			) </dev/null >/dev/null 2>&1 &
		fi
	fi
}
exit 0
endef

define Package/luci-app-homegate/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	(. /etc/uci-defaults/99-homegate-luci-languages) && rm -f /etc/uci-defaults/99-homegate-luci-languages
	rm -f /tmp/luci-indexcache
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null
}
exit 0
endef

define Package/luci-i18n-homegate-zh-cn/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/homegate.zh-cn.lmo $(1)/usr/lib/lua/luci/i18n/homegate.zh-cn.lmo
	$(CP) ./common/root-i18n/* $(1)/
endef

define Package/luci-i18n-homegate-zh-cn/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	(. /etc/uci-defaults/luci-i18n-homegate-zh-cn) && rm -f /etc/uci-defaults/luci-i18n-homegate-zh-cn
	rm -f /tmp/luci-indexcache
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-homegate))
$(eval $(call BuildPackage,luci-i18n-homegate-zh-cn))
