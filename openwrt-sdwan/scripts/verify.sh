#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$root/scripts/openwrt_sdwan_productization_test.sh"
"$root/scripts/openwrt_candy_init_config_test.sh"
"$root/scripts/openwrt_candy_luci_package_test.sh"

printf '%s\n' '{"suite":"candy_cloud_openwrt_sdwan","ipv6":false,"status":"passed"}'
