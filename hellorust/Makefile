include $(TOPDIR)/rules.mk

PKG_NAME:=hellorust
PKG_VERSION:=0.0.1
PKG_RELEASE:=1


PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)


include $(INCLUDE_DIR)/package.mk

define Package/hellorust
  SUBMENU:=RUST
  CATEGORY:=Languages
  TITLE:=The hellorust Programming Language
  URL:=http://www.rust-lang.org/
endef

define Package/hellorust/description
  Rust is a systems programming language that runs blazingly fast, prevents almost all crashes*, and eliminates data races. 
endef



#编译准备工作,复制源码到目标目录
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -R ./src/* $(PKG_BUILD_DIR)/
	$(Build/Patch)
endef

define Build/Configure

endef

define Build/Compile
	( \
		cd $(PKG_BUILD_DIR) && \
		export LD_LIBRARY_PATH=$(STAGING_DIR_HOST)/lib:$(LD_LIBRARY_PATH) &&\
		rustc \
			-L $(STAGING_DIR_HOST)/lib/rustlib \
			--target=$(REAL_GNU_TARGET_NAME) \
			-C target-cpu=mips32r2 \
			-C linker=$(REAL_GNU_TARGET_NAME)-gcc \
			hellorust.rs \
	)
endef

define Build/InstallDev

endef

define Package/hellorust/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/lua $(1)/usr/bin/
endef


$(eval $(call BuildPackage,hellorust))
