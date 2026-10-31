include $(TOPDIR)/rules.mk
include $(TOPDIR)/homegate-version.mk
PKG_NAME:=homegate-native-candidate
PKG_VERSION:=$(HOMEGATE_VERSION)
PKG_RELEASE:=$(HOMEGATE_RELEASE)
PKG_LICENSE:=MIT GPL-3.0
PKGARCH:=all
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
include $(INCLUDE_DIR)/package.mk

define Package/homegate-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=HomeGate native candidate core
  DEPENDS:=+lua +luci-lib-jsonc +luci-lib-nixio +curl +ca-bundle +openssl-util +flock +coreutils-stat +ip-full +ubus +homegate-nginx +homegate-wol
  # Runtime virtual providers are resolved by opkg. Auto-selecting either here
  # makes this SDK generate a self-referential provider comparison in Kconfig.
  EXTRA_DEPENDS:=busybox, ip6tables
  CONFLICTS:=homegate homegate-engineering-core
  PKGARCH:=all
endef
define Package/homegate-core/conffiles
/etc/config/homegate
endef
define Package/luci-app-homegate
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=HomeGate native candidate LuCI
  DEPENDS:=+homegate-core +luci-base +luci-lib-nixio
  EXTRA_DEPENDS:=homegate-core (= $(PKG_VERSION)-r$(PKG_RELEASE))
  PKGARCH:=all
endef
define Package/luci-i18n-homegate-zh-cn
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=HomeGate Simplified Chinese
  DEPENDS:=+homegate-core +luci-app-homegate
  EXTRA_DEPENDS:=homegate-core (= $(PKG_VERSION)-r$(PKG_RELEASE)), luci-app-homegate (= $(PKG_VERSION)-r$(PKG_RELEASE))
  PKGARCH:=all
endef
define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./payload/. $(PKG_BUILD_DIR)/
endef
define Build/Compile
	python3 ./tools/po2lmo.py ./po/zh_Hans/homegate.po $(PKG_BUILD_DIR)/homegate.zh-cn.lmo
endef
define Package/homegate-core/install
	$(CP) $(PKG_BUILD_DIR)/core/. $(1)/
endef
define Package/luci-app-homegate/install
	$(CP) $(PKG_BUILD_DIR)/web/. $(1)/
endef
define Package/luci-i18n-homegate-zh-cn/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/homegate.zh-cn.lmo $(1)/usr/lib/lua/luci/i18n/homegate.zh-cn.lmo
endef

# Preinst/postrm must be self-contained because runtime files are not installed
# yet, or have already been removed. The stager inserts their literal bodies.
define Package/homegate-core/preinst
@HOMEGATE_PREINST@
endef
define Package/homegate-core/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || exec ash /usr/libexec/homegate/native-package.sh prerm "$${1:-}"
exit 0
endef
define Package/homegate-core/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || exec ash /usr/libexec/homegate/native-package.sh postinst
exit 0
endef
define Package/homegate-core/postrm
@HOMEGATE_POSTRM@
endef
$(eval $(call BuildPackage,homegate-core))
$(eval $(call BuildPackage,luci-app-homegate))
$(eval $(call BuildPackage,luci-i18n-homegate-zh-cn))
