# Candy SD-WAN OpenWrt integration

> **Archived compatibility snapshot.** This directory is not a deployable
> release source and is intentionally blocked by the package Makefile. Use
> `reTsubasa/candy-runtime/openwrt/client/packages` as the only OpenWrt
> source of truth. The snapshot requires legacy Core packages that are no
> longer present in the current repositories and does not provide the
> Runtime 0.4.x IPv6/provider/fail-open contract.

This directory is the historical OpenWrt productization slice of the Candy SD-WAN
project. It is intentionally kept separate from the Cloud control plane while
sharing the same signed route-contract and `cloud_grant_v1` delivery contract.

Source: `reTsubasa/candy-openwrt`, revision `1a2b860`.

Included components:

- `candy-client/`: package build, UCI bootstrap, procd lifecycle, and the
  unprivileged `candy-sdwan` supervisor integration;
- `luci-app-candy/`: runtime status and package UI, including signed policy,
  active Hub, route generation, attachment epoch, MTU, and failover state;
- `scripts/`: focused static and JavaScript/Lua checks for this integration.

The Rust protocol, packet engine, authentication, and signed route codecs stay
in the Candy Core repository. This directory does not fork those contracts.

## Verification

From this directory, run:

```sh
scripts/verify.sh
```

Set `CANDY_CORE_SRC` to a Candy Core checkout when the Rust package-version
probe should run as well. Without it, `verify.sh` still runs all OpenWrt
productization and LuCI checks and explicitly skips only that cross-repository
probe.

SDK and target-hardware gates remain in the source OpenWrt repository because
they require an external SDK or device. IPv6 is intentionally not included in
this delivery.
