include $(TOPDIR)/rules.mk
PKG_NAME:=homegate-wol
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
include $(INCLUDE_DIR)/package.mk
define Package/homegate-wol
  SECTION:=net
  CATEGORY:=Network
  TITLE:=HomeGate private raw and UDP wake transport
  DEPENDS:=+libc
endef
define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/send.c ./LICENSE $(PKG_BUILD_DIR)/
endef
define Build/Configure
endef
define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -DHOMEGATE_WOL_VERSION='"$(PKG_VERSION)-r$(PKG_RELEASE)"' -std=c11 -Wall -Wextra -Werror -o $(PKG_BUILD_DIR)/send $(PKG_BUILD_DIR)/send.c $(TARGET_LDFLAGS)
endef
define Package/homegate-wol/install
	$(INSTALL_DIR) $(1)/usr/libexec/homegate-wol
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/send $(1)/usr/libexec/homegate-wol/send
	$(INSTALL_DIR) $(1)/usr/share/licenses/homegate-wol
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/homegate-wol/LICENSE
endef
define Build/InstallDev
	$(call Package/homegate-wol/install,$(1))
endef

$(eval $(call BuildPackage,homegate-wol))
