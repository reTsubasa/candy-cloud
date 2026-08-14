#!/bin/sh
set -eu

MAX_BOOTSTRAP_BASE64_BYTES=24576
MAX_MANIFEST_BYTES=65536
MAX_RUNTIME_BYTES=268435456
INSTALL_LOG=${CANDY_INSTALL_LOG:-/var/log/candy/node-install.log}
COMMITTED=0
CHANGED=0
NETD_WAS_ACTIVE=0
NETD_WAS_ENABLED=0
NETD_STARTED=0

log() {
	printf '%s level=%s stage=%s message=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$3" >&2
	if [ "${CANDY_INSTALL_TEST_MODE:-0}" != 1 ]; then
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

restore_file() {
	path=$1
	backup=$backup_dir$path
	if [ -e "$backup" ] || [ -L "$backup" ]; then
		mkdir -p "${path%/*}"
		cp -a "$backup" "$path"
	else
		rm -f "$path"
	fi
}

backup_file() {
	path=$1
	if [ -e "$path" ] || [ -L "$path" ]; then
		mkdir -p "$backup_dir${path%/*}"
		cp -a "$path" "$backup_dir$path"
	fi
}

rollback() {
	[ "$CHANGED" -eq 1 ] || return 0
	log warn rollback "restoring the Runtime state that existed before this installation"
	for path in \
		/usr/local/bin/candy-server \
		/usr/local/bin/candy-core-manager \
		/usr/local/libexec/serverd-linux \
		/usr/local/libexec/candy-sdwan-runtime \
		/usr/local/libexec/candy-sdwan-agent \
		/usr/local/libexec/candy-netd \
		/usr/local/libexec/candy-cloud-enroll \
		/usr/local/libexec/candy-server-health-check \
		/etc/systemd/system/candy-netd.service \
		/etc/systemd/system/candy-sdwan.service \
		/usr/lib/sysusers.d/candy.conf \
		/usr/lib/tmpfiles.d/candy.conf; do
		restore_file "$path" || true
	done
	if [ "$NETD_STARTED" -eq 1 ] && [ "$NETD_WAS_ACTIVE" -eq 0 ]; then
		systemctl stop candy-netd.service >/dev/null 2>&1 || true
	fi
	if [ "$NETD_STARTED" -eq 1 ] && [ "$NETD_WAS_ENABLED" -eq 0 ]; then
		systemctl disable candy-netd.service >/dev/null 2>&1 || true
	fi
	systemctl daemon-reload >/dev/null 2>&1 || true
}

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$status" -ne 0 ] && [ "$COMMITTED" -eq 0 ]; then
		rollback
	fi
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
need_command systemctl

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/candy-node-install.XXXXXX") || fail "could not create a private work directory"
chmod 0700 "$work_dir"
backup_dir=$work_dir/backup
bootstrap_file=$work_dir/candy-node-bootstrap.json
manifest_file=$work_dir/install-manifest.json
runtime_bundle=$work_dir/runtime.tar.gz
mkdir -p "$backup_dir"
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

installed_server=${CANDY_SERVER_BIN:-$(command -v candy-server 2>/dev/null || true)}
installed_sdwan_runtime=${CANDY_SDWAN_RUNTIME_PATH:-/usr/local/libexec/candy-sdwan-runtime}
installed_enroll_client=${CANDY_ENROLL_CLIENT_PATH:-/usr/local/libexec/candy-cloud-enroll}
if [ -n "$installed_server" ] && [ -x "$installed_server" ] && [ -x "$installed_sdwan_runtime" ] && [ -x "$installed_enroll_client" ]; then
	log info enrollment "Candy is already installed; using the existing Runtime"
	"$installed_server" bootstrap "$bootstrap_file"
	COMMITTED=1
	exit 0
fi

case "$(uname -s)" in Linux) ;; *) fail "automatic installation supports Linux only" ;; esac
case "$(uname -m)" in
	x86_64|amd64) architecture=x86_64 ;;
	aarch64|arm64) architecture=aarch64 ;;
	*) fail "unsupported processor architecture: $(uname -m)" ;;
esac
need_command install
need_command systemd-sysusers
need_command systemd-tmpfiles

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
	usr/local/libexec/candy-sdwan-runtime \
	usr/local/libexec/candy-sdwan-agent \
	usr/local/libexec/candy-netd \
	usr/local/libexec/candy-cloud-enroll \
	systemd/candy-netd.service \
	systemd/candy-sdwan.service \
	systemd/candy.sysusers \
	systemd/candy.tmpfiles; do
	[ -f "$stage/$member" ] && [ ! -L "$stage/$member" ] || fail "Runtime archive is missing $member"
done

for path in \
	/usr/local/bin/candy-server \
	/usr/local/bin/candy-core-manager \
	/usr/local/libexec/serverd-linux \
	/usr/local/libexec/candy-sdwan-runtime \
	/usr/local/libexec/candy-sdwan-agent \
	/usr/local/libexec/candy-netd \
	/usr/local/libexec/candy-cloud-enroll \
	/usr/local/libexec/candy-server-health-check \
	/etc/systemd/system/candy-netd.service \
	/etc/systemd/system/candy-sdwan.service \
	/usr/lib/sysusers.d/candy.conf \
	/usr/lib/tmpfiles.d/candy.conf; do
	backup_file "$path"
done
CHANGED=1
install -d -m 0755 /usr/local/bin /usr/local/libexec /etc/systemd/system /usr/lib/sysusers.d /usr/lib/tmpfiles.d
install -m 0755 "$stage/usr/local/bin/candy-server" /usr/local/bin/candy-server
for name in serverd-linux candy-sdwan-runtime candy-sdwan-agent candy-netd candy-cloud-enroll candy-server-health-check; do
	[ ! -f "$stage/usr/local/libexec/$name" ] || install -m 0755 "$stage/usr/local/libexec/$name" "/usr/local/libexec/$name"
done
[ ! -f "$stage/usr/local/bin/candy-core-manager" ] || install -m 0755 "$stage/usr/local/bin/candy-core-manager" /usr/local/bin/candy-core-manager
install -m 0644 "$stage/systemd/candy-netd.service" /etc/systemd/system/candy-netd.service
install -m 0644 "$stage/systemd/candy-sdwan.service" /etc/systemd/system/candy-sdwan.service
install -m 0644 "$stage/systemd/candy.sysusers" /usr/lib/sysusers.d/candy.conf
install -m 0644 "$stage/systemd/candy.tmpfiles" /usr/lib/tmpfiles.d/candy.conf
systemd-sysusers /usr/lib/sysusers.d/candy.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/candy.conf
systemctl daemon-reload
systemctl is-active --quiet candy-netd.service && NETD_WAS_ACTIVE=1 || true
systemctl is-enabled --quiet candy-netd.service && NETD_WAS_ENABLED=1 || true
systemctl enable --now candy-netd.service
NETD_STARTED=1
systemctl is-active --quiet candy-netd.service || fail "candy-netd did not become active"

log info enrollment "registering the node with Candy Cloud"
/usr/local/bin/candy-server bootstrap "$bootstrap_file"
status=$(/usr/local/bin/candy-server sdwan status)
printf '%s' "$status" | grep -q '"state":"registered"' || fail "node registration did not reach the registered state"
printf '%s' "$status" | grep -q '"state":"stopped"' || fail "SD-WAN did not remain stopped after registration"
COMMITTED=1
log info complete "Candy Runtime $runtime_version installed; node registered with SD-WAN stopped"
