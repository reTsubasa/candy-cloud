include $(TOPDIR)/rules.mk

PKG_NAME:=candy-client
PKG_VERSION:=0.3.4
# OpenWrt requires a package revision. This is internal metadata, not part of
# the Candy product version shown to users.
PKG_RELEASE:=13

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/candy-client
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Candy QUIC client
  DEPENDS:=+libgcc +kmod-tun +kmod-nft-tproxy +kmod-nf-tproxy
endef

define Package/candy-client/description
  Candy 0.3.4 OpenWrt client with auditable BBR fallback and automatic recovery.
endef

define Package/candy-client/conffiles
/etc/config/candy
endef

define Build/Prepare
	@echo "candy-cloud OpenWrt snapshot is archived and cannot be built; use candy-runtime OpenWrt packages" >&2
	@false
endef

define Package/candy-client/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(CARGO_TARGET)/release/client-cli $(1)/usr/bin/candy-client
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(CARGO_TARGET)/release/candy-netd $(1)/usr/bin/candy-netd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(CARGO_TARGET)/release/candy-sdwan $(1)/usr/bin/candy-sdwan
	ln -sf candy-client $(1)/usr/bin/client-cli
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./candy.init $(1)/etc/init.d/candy
	$(SED) 's|^CANDY_VERSION=.*|CANDY_VERSION=$$$${CANDY_VERSION:-$(PKG_VERSION)}|' $(1)/etc/init.d/candy
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./candy.config $(1)/etc/config/candy
	$(INSTALL_DIR) $(1)/usr/share/candy/rulesets
	$(INSTALL_DATA) ./rulesets/cn-ip.cidr $(1)/usr/share/candy/rulesets/cn-ip.cidr
	$(INSTALL_DATA) ./rulesets/gfwlist.domains $(1)/usr/share/candy/rulesets/gfwlist.domains
endef


define Package/candy-client/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
if ! id candy-sdwan >/dev/null 2>&1; then
	adduser -S -D -H -s /bin/false candy-sdwan >/dev/null 2>&1 || exit 1
fi
if [ -f /etc/init.d/candy.apk-new ]; then
	cp /etc/init.d/candy.apk-new /etc/init.d/candy
	chmod 0755 /etc/init.d/candy
	rm -f /etc/init.d/candy.apk-new
fi
mkdir -p /var/lib/candy/epochs /var/lib/candy/policy-cache /var/lib/candy/grant-cache
chmod 0700 /var/lib/candy /var/lib/candy/epochs /var/lib/candy/policy-cache /var/lib/candy/grant-cache
exit 0
endef

define Package/candy-client/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
if [ -x /etc/init.d/candy ]; then
	/etc/init.d/candy disable >/dev/null 2>&1 || true
	/etc/init.d/candy stop >/dev/null 2>&1 || exit 1
fi
# Identity, signed caches, netd journal, and epoch files are deliberately kept.
exit 0
endef

$(eval $(call BuildPackage,candy-client))
