#
# Copyright (C) 2013-2199 bywayboy<bywayboy@qq.com>
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libuv
PKG_VERSION:=0.11.29
PKG_RELEASE:=1
PKG_REV:=1


PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

PKG_BUILD_DEPENDS:= +libpthread

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk


define Package/libuv
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=libuv network library
  URL:=https://github.com/joyent/libuv
  DEPENDS:= +libpthread
endef

define Package/libuv/description
 A C++ non-blocking network library for multi-threaded server in Linux
endef

#编译准备工作,复制源码到目标目录
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -R ./src/* $(PKG_BUILD_DIR)/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/*.h $(1)/usr/include/

	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/*.so* $(1)/usr/lib/
endef

#[安装(编译)时执行的脚本 记得加上#!/bin/sh 没有就空着]
define Package/libuv/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libuv.so* $(1)/usr/lib/
endef


# [安装前执行的脚本 记得加上#!/bin/sh 没有就空着]
define Package/libuv/preinst
 
endef


#[安装后执行的脚本 记得加上#!/bin/sh 没有就空着]
define Package/libuv/postinst

endef

#[删除前执行的脚本 记得加上#!/bin/sh 没有就空着]
define Package/libuv/prerm

endef

#[删除后执行的脚本 记得加上#!/bin/sh 没有就空着] 
define Package/libuv/postrm

endef


$(eval $(call BuildPackage,libuv)) 