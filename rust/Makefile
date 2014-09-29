include $(TOPDIR)/rules.mk

PKG_NAME:=rust
PKG_VERSION:=0.11.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=e31680ac2d2f246fedfd6ac2f02a1d38fbd6f613
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_SOURCE_URL:=https://github.com/rust-lang/$(PKG_NAME).git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/$(PKG_NAME)-$(PKG_VERSION)

PKG_BUILD_PARALLEL:=1
HOST_BUILD_PARALLEL:=1
HOST_BUILD_DEPENDS:= python/host python/bzip2/host


include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/host-build.mk

define Package/rust
  SUBMENU:=RUST
  CATEGORY:=Languages
  TITLE:=The Rust Programming Language
  URL:=http://www.rust-lang.org/
endef

define Package/rust/description
  Rust is a systems programming language that runs blazingly fast, prevents almost all crashes*, and eliminates data races. 
endef



define Build/Configure
	cd $(PKG_BUILD_DIR) &&	./configure \
		$(CONFIGURE_VARS)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)
endef

define Build/InstallDev

endef

define Package/rust/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/lua $(1)/usr/bin/
endef

RUST_HOST_NAME:=$(shell echo $(GNU_HOST_NAME) | awk 'BEGIN{FS="-"} {print $$1"-unknown-"$$2"-"$$3}')

HOST_CONFIGURE_VARS = \
	--target=$(REAL_GNU_TARGET_NAME) \
	--host=$(RUST_HOST_NAME) \
	--build=$(RUST_HOST_NAME) \
	--prefix=$(STAGING_DIR_HOST) \
	--disable-jemalloc \
	--disable-docs
	

define Host/Configure
	CC=$(HOSTCC_NOCACHE)
	cd $(HOST_BUILD_DIR) &&	./configure \
		$(HOST_CONFIGURE_VARS)
endef

define Host/Compile
	( \
		cd $(HOST_BUILD_DIR) && $(MAKE) \
	 )
endef

define Host/Install
	(cd $(HOST_BUILD_DIR) && $(MAKE) install)
endef

$(eval $(call HostBuild))
$(eval $(call BuildPackage,rust))
