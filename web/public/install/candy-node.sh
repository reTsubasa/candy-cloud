#!/bin/sh
set -eu

MAX_BOOTSTRAP_BASE64_BYTES=24576
MAX_MANIFEST_BYTES=65536
MAX_RUNTIME_BYTES=268435456
INSTALL_LOG=${CANDY_INSTALL_LOG:-/var/log/candy/node-install.log}
ACTIVE_SERVER=/opt/candy/current/candy-server

log() {
	printf '%s level=%s stage=%s message=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$3" >&2
	if [ "${CANDY_INSTALL_TEST_MODE:-0}" != 1 ]; then
		install_log_dir=${INSTALL_LOG%/*}
		[ "$install_log_dir" = "$INSTALL_LOG" ] && install_log_dir=.
		mkdir -p "$install_log_dir" 2>/dev/null || true
		printf '%s level=%s stage=%s message=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$3" >>"$INSTALL_LOG" 2>/dev/null || true
	fi
}

fail() {
	log error failure "$*"
	exit 1
}

need_command() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print tolower($1) }'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{ print tolower($1) }'
	else
		return 1
	fi
}

file_size() {
	wc -c <"$1" | tr -d ' '
}

json_string() {
	key=$2
	sed -n 's/^[[:space:]]*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"\\]*\)"[[:space:]]*,\{0,1\}[[:space:]]*$/\1/p' "$1" | head -n 1
}

json_number() {
	key=$2
	sed -n 's/^[[:space:]]*"'"$key"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*,\{0,1\}[[:space:]]*$/\1/p' "$1" | head -n 1
}

valid_sha256() {
	[ "${#1}" -eq 64 ] || return 1
	case "$1" in *[!0-9a-fA-F]*) return 1 ;; esac
}

download() {
	url=$1
	destination=$2
	case "$url" in https://*) ;; *) fail "download URL must use HTTPS" ;; esac
	case "$url" in *' '*|*'\t'*|*'\r'*|*'\n'*|*'\\'*|*'"'*|*"'"*) fail "download URL contains an invalid character" ;; esac
	if command -v curl >/dev/null 2>&1; then
		curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
			--tlsv1.2 --connect-timeout 15 --max-time 600 "$url" -o "$destination"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only -O "$destination" "$url"
	else
		fail "curl or wget is required"
	fi
}

validate_cloud_address() {
	case "$1" in https://*) ;; *) fail "Cloud address must use HTTPS" ;; esac
	authority=${1#https://}
	authority=${authority%%/*}
	[ -n "$authority" ] || fail "Cloud address is missing a host"
	case "$authority" in *@*) fail "Cloud address must not contain user information" ;; esac
	case "$1" in *' '*|*'\t'*|*'\r'*|*'\n'*|*'\\'*|*'"'*|*"'"*) fail "Cloud address contains an invalid character" ;; esac
}

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	rm -rf "$work_dir"
	exit "$status"
}

[ "${1:-}" = --bootstrap-base64-stdin ] && [ "$#" -eq 1 ] || fail "usage: candy-node.sh --bootstrap-base64-stdin"
if [ "${CANDY_INSTALL_TEST_MODE:-0}" != 1 ]; then
	[ "$(id -u)" -eq 0 ] || fail "run this installer through sudo"
fi
need_command uname
need_command tar
need_command awk
need_command sed
need_command base64

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/candy-node-install.XXXXXX") || fail "could not create a private work directory"
chmod 0700 "$work_dir"
bootstrap_file=$work_dir/candy-node-bootstrap.json
manifest_file=$work_dir/install-manifest.json
runtime_bundle=$work_dir/runtime.tar.gz
trap cleanup EXIT HUP INT TERM

encoded=$(dd bs=24577 count=1 2>/dev/null)
[ -n "$encoded" ] || fail "Bootstrap payload is empty"
[ "${#encoded}" -le "$MAX_BOOTSTRAP_BASE64_BYTES" ] || fail "Bootstrap payload is too large"
case "$encoded" in *[!A-Za-z0-9+/=]*) fail "Bootstrap payload is not valid Base64" ;; esac
printf '%s' "$encoded" | base64 -d >"$bootstrap_file" 2>/dev/null || fail "Bootstrap payload could not be decoded"
chmod 0600 "$bootstrap_file"
bootstrap_size=$(file_size "$bootstrap_file")
[ "$bootstrap_size" -gt 0 ] && [ "$bootstrap_size" -le 16384 ] || fail "Bootstrap document is outside the size limit"
grep -Eq '"schema_version"[[:space:]]*:[[:space:]]*1' "$bootstrap_file" || fail "unsupported Bootstrap document"
cloud_address=$(sed -n 's/^.*"cloud_address"[[:space:]]*:[[:space:]]*"\([^"\\]*\)".*$/\1/p' "$bootstrap_file" | head -n 1)
[ -n "$cloud_address" ] || fail "Bootstrap document is missing the Cloud address"
cloud_address=${cloud_address%/}
validate_cloud_address "$cloud_address"

installed_server=${CANDY_SERVER_BIN:-$ACTIVE_SERVER}
runtime_bin_dir=${CANDY_RUNTIME_BIN_DIR:-/usr/local/bin}
runtime_libexec_dir=${CANDY_RUNTIME_LIBEXEC_DIR:-/usr/local/libexec}
systemd_unit_dir=${CANDY_SYSTEMD_UNIT_DIR:-/etc/systemd/system}
tmpfiles_policy=${CANDY_TMPFILES_POLICY:-/usr/lib/tmpfiles.d/candy.conf}
installed_sdwan_runtime=${CANDY_SDWAN_RUNTIME_PATH:-$runtime_libexec_dir/candy-sdwan-runtime}
installed_enroll_client=${CANDY_ENROLL_CLIENT_PATH:-$runtime_libexec_dir/candy-cloud-enroll}
installed_server_supports_bootstrap=0
installed_runtime_complete=1
if [ -n "$installed_server" ] && [ -x "$installed_server" ]; then
	# A pre-0.4 server launcher treats an unknown `bootstrap` argument as
	# ordinary server options and reports a misleading missing-Core error.
	# Only reuse an existing installation when its public product command
	# explicitly advertises the file-based enrollment contract.
	if "$installed_server" --help 2>&1 | grep -F 'candy-server bootstrap FILE' >/dev/null 2>&1; then
		installed_server_supports_bootstrap=1
	fi
fi
for executable in \
	"$runtime_bin_dir/candy-core-manager" \
	"$runtime_libexec_dir/serverd-linux" \
	"$installed_sdwan_runtime" \
	"$runtime_libexec_dir/candy-sdwan-agent" \
	"$runtime_libexec_dir/candy-netd" \
	"$installed_enroll_client" \
	"$runtime_libexec_dir/candy-cloud-sync" \
	"$runtime_libexec_dir/candy-server-health-check"; do
	[ -f "$executable" ] && [ -x "$executable" ] && [ ! -L "$executable" ] || installed_runtime_complete=0
done
for policy in \
	"$systemd_unit_dir/candy-server.service" \
	"$systemd_unit_dir/candy-netd.service" \
	"$systemd_unit_dir/candy-cloud-sync.service" \
	"$systemd_unit_dir/candy-cloud-sync.timer" \
	"$tmpfiles_policy"; do
	[ -f "$policy" ] && [ ! -L "$policy" ] || installed_runtime_complete=0
done
if [ "$installed_server_supports_bootstrap" -eq 1 ] && [ "$installed_runtime_complete" -eq 1 ]; then
	log info enrollment "Candy is already installed; using the existing Runtime"
	if ! "$installed_server" bootstrap "$bootstrap_file"; then
		fail "Cloud enrollment failed; the existing Runtime remains installed and existing network state was not changed"
	fi
	exit 0
fi
if [ -n "$installed_server" ] && [ -x "$installed_server" ]; then
	log info upgrade "Existing Candy Runtime is incomplete or incompatible; upgrading it before registration"
fi

case "$(uname -s)" in Linux) ;; *) fail "automatic installation supports Linux only" ;; esac
case "$(uname -m)" in
	x86_64|amd64) architecture=x86_64 ;;
	aarch64|arm64) architecture=aarch64 ;;
	*) fail "unsupported processor architecture: $(uname -m)" ;;
esac

manifest_url=$cloud_address/install/manifests/linux-$architecture.json
log info manifest "requesting the architecture-bound installation manifest"
download "$manifest_url" "$manifest_file"
manifest_size=$(file_size "$manifest_file")
[ "$manifest_size" -gt 0 ] && [ "$manifest_size" -le "$MAX_MANIFEST_BYTES" ] || fail "installation manifest is outside the size limit"
[ "$(json_number "$manifest_file" schema_version)" = 1 ] || fail "unsupported installation manifest"
[ "$(json_string "$manifest_file" platform)" = linux ] || fail "installation manifest targets another platform"
[ "$(json_string "$manifest_file" architecture)" = "$architecture" ] || fail "installation manifest targets another architecture"
runtime_version=$(json_string "$manifest_file" runtime_version)
runtime_url=$(json_string "$manifest_file" runtime_url)
runtime_sha256=$(json_string "$manifest_file" runtime_sha256)
runtime_size=$(json_number "$manifest_file" runtime_size)
[ -n "$runtime_version" ] && [ -n "$runtime_url" ] || fail "installation manifest is incomplete"
case "$runtime_url" in /*) runtime_url=$cloud_address$runtime_url ;; esac
valid_sha256 "$runtime_sha256" || fail "installation manifest has an invalid Runtime digest"
case "$runtime_size" in ''|*[!0-9]*) fail "installation manifest has an invalid Runtime size" ;; esac
[ "$runtime_size" -gt 0 ] && [ "$runtime_size" -le "$MAX_RUNTIME_BYTES" ] || fail "Runtime artifact is outside the size limit"

log info download "downloading Candy Runtime $runtime_version for $architecture"
download "$runtime_url" "$runtime_bundle"
[ "$(file_size "$runtime_bundle")" = "$runtime_size" ] || fail "Runtime artifact size does not match the manifest"
[ "$(sha256_file "$runtime_bundle")" = "$(printf '%s' "$runtime_sha256" | tr 'A-F' 'a-f')" ] || fail "Runtime artifact SHA-256 does not match the manifest"

stage=$work_dir/stage
mkdir -p "$stage"
tar -tvzf "$runtime_bundle" | awk '
	BEGIN { ok = 1; count = 0 }
	{
		kind = substr($1, 1, 1)
		name = $NF
		gsub(/^\.\//, "", name)
		if (kind != "-" && kind != "d") ok = 0
		if (name ~ /^\// || name ~ /(^|\/)\.\.($|\/)/) ok = 0
		count++
	}
	END { exit (ok && count > 0 && count <= 100) ? 0 : 1 }
' || fail "Runtime archive contains unsafe or excessive entries"
tar -xzf "$runtime_bundle" -C "$stage" --no-same-owner --no-same-permissions
for member in \
	usr/local/bin/candy-server \
	usr/local/bin/candy-core-manager \
	usr/local/libexec/serverd-linux \
	usr/local/libexec/candy-sdwan-runtime \
	usr/local/libexec/candy-sdwan-agent \
	usr/local/libexec/candy-netd \
	usr/local/libexec/candy-cloud-enroll \
	usr/local/libexec/candy-cloud-sync \
	usr/local/libexec/candy-server-health-check \
	systemd/candy-server.service \
	systemd/candy-netd.service \
	systemd/candy-cloud-sync.service \
	systemd/candy-cloud-sync.timer \
	systemd/candy.tmpfiles \
	install/upgrade-candy-server.sh \
	RUNTIME-RELEASE \
	RUNTIME-ARCH; do
	[ -f "$stage/$member" ] && [ ! -L "$stage/$member" ] || fail "Runtime archive is missing $member"
done

candidate_upgrader=$stage/install/upgrade-candy-server.sh
[ -x "$candidate_upgrader" ] || fail "Runtime archive upgrader is not executable"
log info upgrade "installing Candy Runtime $runtime_version through the bundle transaction"
if ! sh "$candidate_upgrader" \
	--bundle-file "$runtime_bundle" \
	--sha256 "$runtime_sha256" \
	--version "$runtime_version"; then
	fail "Runtime transaction failed; Cloud enrollment was not attempted and the previous Runtime state was restored"
fi
[ -f "$ACTIVE_SERVER" ] && [ -x "$ACTIVE_SERVER" ] ||
	fail "Runtime transaction completed without activating $ACTIVE_SERVER; Cloud enrollment was not attempted"

log info enrollment "registering the node with Candy Cloud"
if ! "$ACTIVE_SERVER" bootstrap "$bootstrap_file"; then
	fail "Cloud enrollment failed after the Runtime transaction committed; the Runtime remains installed and enrollment can be retried with a valid Bootstrap document"
fi
status=$("$ACTIVE_SERVER" sdwan status) ||
	fail "Runtime is installed and enrollment was submitted, but node status could not be read"
printf '%s' "$status" | grep -q '"state":"registered"' ||
	fail "Runtime is installed, but node registration did not reach the registered state"
printf '%s' "$status" | grep -q '"state":"stopped"' ||
	fail "Runtime is installed and the node is registered, but SD-WAN did not remain stopped"
log info complete "Candy Runtime $runtime_version installed; node registered with SD-WAN stopped"
