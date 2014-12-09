include $(TOPDIR)/rules.mk


PKG_NAME:=wsapi
PKG_VERSION:=1.5.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=ee910fb6428631cea430216138d0e34ef93022ad
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_SOURCE_URL:=https://github.com/keplerproject/$(PKG_NAME).git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk


define Package/wsapi
  SUBMENU:=Lua
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Lua WSAPI Module
  URL:=http://nginx.org/
  DEPENDS:= +lua
endef

define Package/wsapi/description
 wsapi ...
endef

define Build/Configure

	mkdir -p $(PKG_INSTALL_DIR)/usr/sbin
	mkdir -p $(PKG_INSTALL_DIR)/usr/lib
	(\
		cd $(PKG_BUILD_DIR) &&	\
		echo "CFLAGS=$(TARGET_CFLAGS) -fPIC" > config && \
		echo "CC=$(TARGET_CC)" >> config && \
		echo "LIB_OPTION= -shared" >> config && \
		echo "LUA_DIR= $(PKG_INSTALL_DIR)" >> config &&\
		echo "BIN_DIR= $(PKG_INSTALL_DIR)/usr/sbin" >> config && \
		echo "LUA_LIBDIR= $(PKG_INSTALL_DIR)/usr/lib" >> config \
	)
endef
define Build/Compile
	( \
		cd $(PKG_BUILD_DIR) && \
		make && \
		make install-fcgi && \
		make install \
	)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/* $(1)/usr/sbin/
endef


$(eval $(call BuildPackage,$(PKG_NAME)))
