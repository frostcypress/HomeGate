# Dedicated component; no system nginx executable, service or config replaced.
include $(TOPDIR)/rules.mk

PKG_NAME:=homegate-nginx
PKG_VERSION:=1.30.6
PKG_RELEASE:=2
PKG_SOURCE:=nginx-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://nginx.org/download/
PKG_HASH:=3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8
PKG_BUILD_DIR:=$(BUILD_DIR)/nginx-$(PKG_VERSION)
PKG_LICENSE:=BSD-2-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/homegate-nginx
  SECTION:=net
  CATEGORY:=Network
  TITLE:=HomeGate private TLS proxy component
  URL:=https://nginx.org/
  DEPENDS:=+libopenssl +libpcre2 +libpthread
endef

CONFIGURE_CMD:=./configure
CONFIGURE_VARS += CONFIG_BIG_ENDIAN=$(CONFIG_BIG_ENDIAN)
# Replace autotools defaults: nginx rejects --host/--target/--build.
# Keep unknown nginx configure options fatal; never apply ignore-options patch.
CONFIGURE_ARGS := \
  --build=homegate-ip-san-v1 \
  --crossbuild=Linux::$(ARCH) \
  --prefix=/usr/libexec/homegate-nginx \
  --sbin-path=/usr/libexec/homegate-nginx/nginx \
  --conf-path=/etc/homegate-engineering/nginx-unused.conf \
  --error-log-path=stderr \
  --http-log-path=/dev/null \
  --pid-path=/var/run/homegate-engineering/nginx-unused.pid \
  --lock-path=/var/run/homegate-engineering/nginx-unused.lock \
  --user=nobody --group=nogroup \
  --with-cc="$(TARGET_CC)" \
  --with-cc-opt="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
  --with-ld-opt="$(TARGET_LDFLAGS)" \
  --with-http_ssl_module \
  --without-http_gzip_module \
  --without-http_autoindex_module \
  --without-http_ssi_module

define Package/homegate-nginx/install
	$(INSTALL_DIR) $(1)/usr/libexec/homegate-nginx
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/objs/nginx $(1)/usr/libexec/homegate-nginx/nginx
	$(INSTALL_DIR) $(1)/usr/share/licenses/homegate-nginx
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/homegate-nginx/LICENSE
endef

$(eval $(call BuildPackage,homegate-nginx))
