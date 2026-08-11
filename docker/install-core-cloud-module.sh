#!/bin/sh
set -eu
umask 022

fail() {
  printf '%s\n' "install-core-cloud-module: $*" >&2
  exit 1
}

for command in jq sha256sum tar usign; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

: "${CORE_MODULE_BUNDLE:?CORE_MODULE_BUNDLE is required}"
: "${CORE_MODULE_BUNDLE_SHA256:?CORE_MODULE_BUNDLE_SHA256 is required}"
: "${CORE_MODULE_VERSION:?CORE_MODULE_VERSION is required}"
: "${CORE_MODULE_SHA256:?CORE_MODULE_SHA256 is required}"
: "${CORE_MODULE_PUBLIC_KEY:?CORE_MODULE_PUBLIC_KEY is required}"

target=${CORE_MODULE_TARGET:-x86_64-unknown-linux-gnu}
install_root=${CORE_MODULE_INSTALL_ROOT:-/opt/candy/cores}
expected_key_fingerprint=${CORE_MODULE_KEY_FINGERPRINT:-d78de22abfca5b57}

case "$CORE_MODULE_VERSION" in
  ''|*[!0-9A-Za-z._-]*) fail "invalid module version" ;;
esac
test "${#CORE_MODULE_VERSION}" -le 64 || fail "module version is too long"
jq -en --arg version "$CORE_MODULE_VERSION" \
  '$version | test("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")' >/dev/null ||
  fail "module version must be a semantic version"
test "$target" = x86_64-unknown-linux-gnu || fail "unsupported module target: $target"
case "$install_root" in
  /*) ;;
  *) fail "module install root must be absolute" ;;
esac

is_sha256() {
  test "${#1}" -eq 64 || return 1
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
    *) return 0 ;;
  esac
}
is_sha256 "$CORE_MODULE_BUNDLE_SHA256" || fail "bundle digest must be a lowercase SHA-256 value"
is_sha256 "$CORE_MODULE_SHA256" || fail "module digest must be a lowercase SHA-256 value"

test -f "$CORE_MODULE_BUNDLE" || fail "module bundle does not exist"
test -f "$CORE_MODULE_PUBLIC_KEY" || fail "Core release public key does not exist"

actual_fingerprint=$(usign -F -p "$CORE_MODULE_PUBLIC_KEY")
test "$actual_fingerprint" = "$expected_key_fingerprint" ||
  fail "unexpected Core release public key fingerprint: $actual_fingerprint"

actual_bundle_sha=$(sha256sum "$CORE_MODULE_BUNDLE" | awk '{print $1}')
test "$actual_bundle_sha" = "$CORE_MODULE_BUNDLE_SHA256" || fail "module bundle digest mismatch"

work=$(mktemp -d)
installing=''
cleanup() {
  status=$?
  trap - EXIT INT TERM
  test -z "$installing" || rm -rf -- "$installing"
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM
members="$work/members"
expected_members="$work/expected-members"
tar -tzf "$CORE_MODULE_BUNDLE" | LC_ALL=C sort > "$members"
printf '%s\n' libcandy_core_cloud.so manifest.json manifest.sig | LC_ALL=C sort > "$expected_members"
cmp -s "$expected_members" "$members" || fail "module bundle contains an unexpected member set"

stage="$work/stage"
mkdir -m 0700 "$stage"
tar -xzf "$CORE_MODULE_BUNDLE" --no-same-owner --no-same-permissions -C "$stage"
for member in libcandy_core_cloud.so manifest.json manifest.sig; do
  test -f "$stage/$member" && test ! -L "$stage/$member" || fail "invalid bundle member: $member"
done

usign -V -q -p "$CORE_MODULE_PUBLIC_KEY" -m "$stage/manifest.json" -x "$stage/manifest.sig" ||
  fail "Core module manifest signature is invalid"

jq -e \
  --arg version "$CORE_MODULE_VERSION" \
  --arg target "$target" \
  --arg module_sha "$CORE_MODULE_SHA256" \
  '
    .schema_version == 1 and
    (
      ($version == "0.3.10" and .release_kind == "candy-core-cloud-module" and .artifact.kind == "shared-module") or
      (.release_kind == "candy-core" and .artifact.kind == "shared-library")
    ) and
    .module.version == $version and
    .module.abi_version == 1 and
    .module.library == "libcandy_core_cloud.so" and
    .module.wire_protocol == "0.3" and
    .module.build_request_schema == "candy-core-cloud-build-v1" and
    .artifact.name == "libcandy_core_cloud.so" and
    .artifact.sha256 == $module_sha and
    .artifact.target == $target and
    .artifact.target_os == "linux" and
    .artifact.libc == "glibc" and
    (.artifact.size_bytes | type == "number" and . > 0)
  ' "$stage/manifest.json" >/dev/null || fail "Core module manifest contract mismatch"

actual_module_sha=$(sha256sum "$stage/libcandy_core_cloud.so" | awk '{print $1}')
test "$actual_module_sha" = "$CORE_MODULE_SHA256" || fail "Core module digest mismatch"
actual_module_size=$(wc -c < "$stage/libcandy_core_cloud.so" | tr -d ' ')
manifest_module_size=$(jq -er '.artifact.size_bytes' "$stage/manifest.json")
test "$actual_module_size" = "$manifest_module_size" || fail "Core module size mismatch"

destination="$install_root/$CORE_MODULE_VERSION"
mkdir -p "$install_root"
test ! -L "$install_root" || fail "module install root must not be a symlink"
test ! -e "$destination" && test ! -L "$destination" ||
  fail "refusing to replace an installed Core module version"
installing="$install_root/.installing-$CORE_MODULE_VERSION-$$"
test ! -e "$installing" && test ! -L "$installing" || fail "temporary install path already exists"
mkdir -m 0755 "$installing"
install -m 0555 "$stage/libcandy_core_cloud.so" "$installing/libcandy_core_cloud.so"
install -m 0444 "$stage/manifest.json" "$installing/manifest.json"
install -m 0444 "$stage/manifest.sig" "$installing/manifest.sig"
installed_module_sha=$(sha256sum "$installing/libcandy_core_cloud.so" | awk '{print $1}')
test "$installed_module_sha" = "$CORE_MODULE_SHA256" || fail "installed Core module digest mismatch"
mv "$installing" "$destination"
installing=''

printf '%s\n' "$destination/libcandy_core_cloud.so"
