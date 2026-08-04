#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$root/scripts/openwrt_sdwan_productization_test.sh"
if [ -n "${CANDY_CORE_SRC:-}" ]; then
    "$root/scripts/openwrt_candy_init_config_test.sh"
else
    CANDY_SKIP_RUST_CONFIG_CHECK=1 "$root/scripts/openwrt_candy_init_config_test.sh"
fi
"$root/scripts/openwrt_candy_luci_package_test.sh"

printf '%s\n' '{"suite":"candy_cloud_openwrt_sdwan","ipv6":false,"status":"passed"}'
