#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
installer="$script_dir/install-core-cloud-module.sh"

for command in jq sha256sum tar usign; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "SKIP: required command is missing: $command"
    exit 0
  }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
USIGN_PASSWORD='' usign -G -s "$work/test-release.sec" -p "$work/test-release.pub" -c 'installer test key'
test_fingerprint=$(usign -F -p "$work/test-release.pub")
stage="$work/stage"
mkdir "$stage"
printf 'test cloud module\n' > "$stage/libcandy_core_cloud.so"
module_sha=$(sha256sum "$stage/libcandy_core_cloud.so" | awk '{print $1}')
module_size=$(wc -c < "$stage/libcandy_core_cloud.so" | tr -d ' ')
jq -n --arg sha "$module_sha" --argjson size "$module_size" '{
  schema_version: 1,
  release_kind: "candy-core",
  module: {
    version: "0.3.11",
    abi_version: 1,
    library: "libcandy_core_cloud.so",
    wire_protocol: "0.3",
    build_request_schema: "candy-core-cloud-build-v1"
  },
  artifact: {
    kind: "shared-library",
    name: "libcandy_core_cloud.so",
    sha256: $sha,
    size_bytes: $size,
    target: "x86_64-unknown-linux-gnu",
    target_os: "linux",
    target_arch: "x86_64",
    libc: "glibc"
  }
}' > "$stage/manifest.json"
USIGN_PASSWORD='' usign -S -s "$work/test-release.sec" -m "$stage/manifest.json" -x "$stage/manifest.sig"
tar -czf "$work/module.tar.gz" -C "$stage" libcandy_core_cloud.so manifest.json manifest.sig
bundle_sha=$(sha256sum "$work/module.tar.gz" | awk '{print $1}')

CORE_MODULE_BUNDLE="$work/module.tar.gz" \
CORE_MODULE_BUNDLE_SHA256="$bundle_sha" \
CORE_MODULE_VERSION=0.3.11 \
CORE_MODULE_SHA256="$module_sha" \
CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
CORE_MODULE_INSTALL_ROOT="$work/install" \
  "$installer" >/dev/null
test -f "$work/install/0.3.11/libcandy_core_cloud.so"
test "$(stat -f '%Lp' "$work/install/0.3.11/libcandy_core_cloud.so" 2>/dev/null || stat -c '%a' "$work/install/0.3.11/libcandy_core_cloud.so")" = 555

jq '.release_kind = "candy-core-cloud-module" | .module.version = "0.3.10" | .artifact.kind = "shared-module"' \
  "$stage/manifest.json" > "$stage/legacy-manifest.json"
mv "$stage/legacy-manifest.json" "$stage/manifest.json"
USIGN_PASSWORD='' usign -S -s "$work/test-release.sec" -m "$stage/manifest.json" -x "$stage/manifest.sig"
tar -czf "$work/legacy-module.tar.gz" -C "$stage" libcandy_core_cloud.so manifest.json manifest.sig
legacy_bundle_sha=$(sha256sum "$work/legacy-module.tar.gz" | awk '{print $1}')
CORE_MODULE_BUNDLE="$work/legacy-module.tar.gz" \
CORE_MODULE_BUNDLE_SHA256="$legacy_bundle_sha" \
CORE_MODULE_VERSION=0.3.10 \
CORE_MODULE_SHA256="$module_sha" \
CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
CORE_MODULE_INSTALL_ROOT="$work/legacy-install" \
  "$installer" >/dev/null
test -f "$work/legacy-install/0.3.10/libcandy_core_cloud.so"

jq '.module.version = "0.3.10"' "$work/install/0.3.11/manifest.json" > "$stage/manifest.json"
USIGN_PASSWORD='' usign -S -s "$work/test-release.sec" -m "$stage/manifest.json" -x "$stage/manifest.sig"
tar -czf "$work/canonical-0.3.10.tar.gz" -C "$stage" libcandy_core_cloud.so manifest.json manifest.sig
canonical_0310_bundle_sha=$(sha256sum "$work/canonical-0.3.10.tar.gz" | awk '{print $1}')
CORE_MODULE_BUNDLE="$work/canonical-0.3.10.tar.gz" \
CORE_MODULE_BUNDLE_SHA256="$canonical_0310_bundle_sha" \
CORE_MODULE_VERSION=0.3.10 \
CORE_MODULE_SHA256="$module_sha" \
CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
CORE_MODULE_INSTALL_ROOT="$work/canonical-0.3.10-install" \
  "$installer" >/dev/null
test -f "$work/canonical-0.3.10-install/0.3.10/libcandy_core_cloud.so"

if CORE_MODULE_BUNDLE="$work/legacy-module.tar.gz" \
  CORE_MODULE_BUNDLE_SHA256="$legacy_bundle_sha" \
  CORE_MODULE_VERSION=0.3.11 \
  CORE_MODULE_SHA256="$module_sha" \
  CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
  CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
  CORE_MODULE_INSTALL_ROOT="$work/rejected-legacy-new-version" \
  "$installer" >/dev/null 2>&1; then
  printf '%s\n' 'legacy release contract was accepted for a new Core version' >&2
  exit 1
fi

cp "$work/module.tar.gz" "$work/tampered.tar.gz"
printf 'x' >> "$work/tampered.tar.gz"
if CORE_MODULE_BUNDLE="$work/tampered.tar.gz" \
  CORE_MODULE_BUNDLE_SHA256="$bundle_sha" \
  CORE_MODULE_VERSION=0.3.11 \
  CORE_MODULE_SHA256="$module_sha" \
  CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
  CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
  CORE_MODULE_INSTALL_ROOT="$work/rejected" \
  "$installer" >/dev/null 2>&1; then
  printf '%s\n' 'tampered module bundle was accepted' >&2
  exit 1
fi

if CORE_MODULE_BUNDLE="$work/module.tar.gz" \
  CORE_MODULE_BUNDLE_SHA256=not-a-digest \
  CORE_MODULE_VERSION=0.3.11 \
  CORE_MODULE_SHA256="$module_sha" \
  CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
  CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
  CORE_MODULE_INSTALL_ROOT="$work/rejected-digest" \
  "$installer" >/dev/null 2>&1; then
  printf '%s\n' 'invalid bundle digest was accepted' >&2
  exit 1
fi

if CORE_MODULE_BUNDLE="$work/module.tar.gz" \
  CORE_MODULE_BUNDLE_SHA256="$bundle_sha" \
  CORE_MODULE_VERSION=latest \
  CORE_MODULE_SHA256="$module_sha" \
  CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
  CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
  CORE_MODULE_INSTALL_ROOT="$work/rejected-version" \
  "$installer" >/dev/null 2>&1; then
  printf '%s\n' 'non-semantic module version was accepted' >&2
  exit 1
fi

if CORE_MODULE_BUNDLE="$work/module.tar.gz" \
  CORE_MODULE_BUNDLE_SHA256="$bundle_sha" \
  CORE_MODULE_VERSION=0.3.11 \
  CORE_MODULE_SHA256="$module_sha" \
  CORE_MODULE_TARGET=riscv64-unknown-linux-gnu \
  CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
  CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
  CORE_MODULE_INSTALL_ROOT="$work/rejected-target" \
  "$installer" >/dev/null 2>&1; then
  printf '%s\n' 'unsupported module target was accepted' >&2
  exit 1
fi

mkdir "$work/real-install-root"
ln -s "$work/real-install-root" "$work/install-root-link"
if CORE_MODULE_BUNDLE="$work/module.tar.gz" \
  CORE_MODULE_BUNDLE_SHA256="$bundle_sha" \
  CORE_MODULE_VERSION=0.3.11 \
  CORE_MODULE_SHA256="$module_sha" \
  CORE_MODULE_PUBLIC_KEY="$work/test-release.pub" \
  CORE_MODULE_KEY_FINGERPRINT="$test_fingerprint" \
  CORE_MODULE_INSTALL_ROOT="$work/install-root-link" \
  "$installer" >/dev/null 2>&1; then
  printf '%s\n' 'symlinked module install root was accepted' >&2
  exit 1
fi

printf '%s\n' 'Core Cloud module installer tests passed'
