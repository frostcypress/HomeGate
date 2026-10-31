include $(TOPDIR)/rules.mk
include $(TOPDIR)/homegate-version.mk

PKG_NAME:=homegate-engineering
PKG_VERSION:=$(HOMEGATE_VERSION)
PKG_RELEASE:=$(HOMEGATE_RELEASE)
PKG_LICENSE:=MIT GPL-3.0
PKGARCH:=all
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/homegate-engineering-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=HomeGate isolated manual DDNS engineering core
  DEPENDS:=+busybox +lua +luci-lib-jsonc +luci-lib-nixio +curl +ca-bundle +openssl-util +flock +coreutils-stat +ip-full +ubus +ip6tables +homegate-nginx +homegate-wol
  PKGARCH:=all
endef

define Package/homegate-engineering-core/conffiles
/etc/config/homegate_engineering
endef

define Package/homegate-engineering-core/prerm
#!/bin/sh
# Refuse removing executable files while a session or durable operation needs
# them. The SDK's wrapper preserves this return code. Never erase user state.
[ -z "$${IPKG_INSTROOT}" ] || exit 0
store=/etc/homegate-engineering/transactions
[ -e "$$store" ] || [ -L "$$store" ] || exit 0
if [ ! -d /var/run/homegate-engineering ];then
  /usr/bin/homegate-engineering prepare >/dev/null 2>&1 || exit 4
fi
/usr/bin/homegate-engineering access-stop --confirm >/dev/null 2>&1 || exit 4
/usr/bin/homegate-engineering access-quiescent >/dev/null 2>&1 || exit 4
/usr/bin/homegate-engineering proxy-stop --confirm >/dev/null 2>&1 || exit 4
/usr/bin/homegate-engineering proxy-quiescent >/dev/null 2>&1 || exit 4
/usr/bin/homegate-engineering acme-schedule-stop --confirm >/dev/null 2>&1 || exit 4
ash /usr/libexec/homegate-engineering/project/core/prototype/homegate-acme-schedule.sh quiescent >/dev/null 2>&1 || exit 4
if [ -e /var/run/homegate-engineering/ddns-schedule ] || [ -L /var/run/homegate-engineering/ddns-schedule ];then
  /usr/bin/homegate-engineering schedule-stop --confirm >/dev/null 2>&1 || exit 4
fi
/usr/bin/homegate-engineering schedule-quiescent >/dev/null 2>&1 || exit 4
exit 0
endef

define Package/luci-app-homegate-engineering
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=HomeGate engineering configuration and DDNS LuCI
  DEPENDS:=+homegate-engineering-core +luci-base +luci-lib-nixio
  PKGARCH:=all
endef

define Package/luci-i18n-homegate-engineering-zh-cn
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=HomeGate engineering Simplified Chinese
  DEPENDS:=+homegate-engineering-core
  PKGARCH:=all
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./payload/. $(PKG_BUILD_DIR)/
endef

define Build/Compile
	python3 ./tools/po2lmo.py ./po/zh_Hans/engineering.po $(PKG_BUILD_DIR)/homegate_engineering.zh-cn.lmo
endef

define Package/homegate-engineering-core/install
	$(INSTALL_DIR) $(1)/usr/libexec/homegate-engineering $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/runtime/. $(1)/usr/libexec/homegate-engineering/
	chmod 700 $(1)/usr/libexec/homegate-engineering
	$(INSTALL_BIN) ./files/homegate-engineering $(1)/usr/bin/homegate-engineering
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/homegate_engineering.config $(1)/etc/config/homegate_engineering
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/homegate-engineering.init $(1)/etc/init.d/homegate-engineering
	$(INSTALL_BIN) ./files/95-homegate-engineering $(1)/etc/hotplug.d/iface/95-homegate-engineering
	$(INSTALL_DIR) $(1)/usr/share/licenses/homegate-engineering $(1)/usr/share/doc/homegate-engineering
	$(INSTALL_DATA) ./payload/LICENSE $(1)/usr/share/licenses/homegate-engineering/LICENSE
	$(INSTALL_DATA) ./README.md $(1)/usr/share/doc/homegate-engineering/README.md
endef

define Package/luci-app-homegate-engineering/install
	$(CP) $(PKG_BUILD_DIR)/webroot/. $(1)/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller $(1)/usr/lib/lua/luci/view/homegate_engineering
	$(INSTALL_DATA) ./files/controller.lua $(1)/usr/lib/lua/luci/controller/homegate_engineering.lua
	$(INSTALL_DATA) ./files/overview.htm $(1)/usr/lib/lua/luci/view/homegate_engineering/overview.htm
endef

define Package/luci-i18n-homegate-engineering-zh-cn/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/homegate_engineering.zh-cn.lmo $(1)/usr/lib/lua/luci/i18n/homegate_engineering.zh-cn.lmo
endef

$(eval $(call BuildPackage,homegate-engineering-core))
$(eval $(call BuildPackage,luci-app-homegate-engineering))
$(eval $(call BuildPackage,luci-i18n-homegate-engineering-zh-cn))
