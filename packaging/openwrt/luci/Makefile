# Copyright 2024 ruhop contributors
# Licensed under the Apache License, Version 2.0
#
# This is the OpenWRT package Makefile for luci-app-ruhop

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for Ruhop VPN
LUCI_DESCRIPTION:=Web interface for configuring Ruhop VPN (UDP-based VPN with port hopping)
LUCI_DEPENDS:=+ruhop +luci-base
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-ruhop
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=ruhop contributors

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildance
$(eval $(call BuildPackage,luci-app-ruhop))
