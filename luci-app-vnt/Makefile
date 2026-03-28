#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_VERSION:=1.2.16
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for vnt
LUCI_DEPENDS:=+kmod-tun +luci-compat
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-vnt
define Package/$(PKG_NAME)/conffiles
/etc/config/vnt
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
