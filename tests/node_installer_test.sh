#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
installer=$root/web/public/install/candy-node.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/candy-node-installer-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fail() { printf '%s\n' "node_installer_test: $*" >&2; exit 1; }

bin=$tmp/bin
mkdir -p "$bin"
calls=$tmp/calls
cat >"$bin/systemctl" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$bin/candy-server" <<'EOF'
#!/bin/sh
if [ "${1:-}" = --help ]; then
	printf '%s\n' '  candy-server bootstrap FILE'
	exit 0
fi
printf '<%s>' "$@" >>"$FAKE_CALLS"
printf '\n' >>"$FAKE_CALLS"
[ "$1" = bootstrap ]
[ -f "$2" ]
grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$2" >/dev/null
EOF
cat >"$bin/candy-sdwan-runtime" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$bin/candy-cloud-enroll" <<'EOF'
#!/bin/sh
exit 0
EOF
for name in candy-core-manager serverd-linux candy-sdwan-agent candy-netd candy-cloud-sync candy-server-health-check; do
	cp "$bin/candy-cloud-enroll" "$bin/$name"
done
unit_dir=$tmp/units
mkdir -p "$unit_dir"
for name in candy-server.service candy-netd.service candy-cloud-sync.service candy-cloud-sync.timer; do
	printf '%s\n' '# fixture' >"$unit_dir/$name"
done
printf '%s\n' '# fixture' >"$tmp/candy.tmpfiles"
chmod 0755 "$bin"/* "$installer"

bootstrap='{"schema_version":1,"cloud_address":"https://cloud.example.test","bootstrap_code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-01T00:00:00Z"}'
encoded=$(printf '%s' "$bootstrap" | base64 | tr -d '\n')
FAKE_CALLS=$calls CANDY_INSTALL_TEST_MODE=1 CANDY_SERVER_BIN=$bin/candy-server \
	CANDY_RUNTIME_BIN_DIR=$bin CANDY_RUNTIME_LIBEXEC_DIR=$bin CANDY_SYSTEMD_UNIT_DIR=$unit_dir \
	CANDY_TMPFILES_POLICY=$tmp/candy.tmpfiles \
	CANDY_SDWAN_RUNTIME_PATH=$bin/candy-sdwan-runtime CANDY_ENROLL_CLIENT_PATH=$bin/candy-cloud-enroll \
	PATH=$bin:$PATH "$installer" --bootstrap-base64-stdin >"$tmp/out" 2>"$tmp/err" <<EOF
$encoded
EOF
grep -F '<bootstrap><' "$calls" >/dev/null || fail "installed Runtime was not used for Bootstrap"
if grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$tmp/out" "$tmp/err" >/dev/null; then
	fail "Bootstrap credential leaked to installer output"
fi

insecure=$(printf '%s' "$bootstrap" | sed 's#https://#http://#' | base64 | tr -d '\n')
if FAKE_CALLS=$calls CANDY_INSTALL_TEST_MODE=1 CANDY_SERVER_BIN=$bin/candy-server \
	CANDY_RUNTIME_BIN_DIR=$bin CANDY_RUNTIME_LIBEXEC_DIR=$bin CANDY_SYSTEMD_UNIT_DIR=$unit_dir \
	CANDY_TMPFILES_POLICY=$tmp/candy.tmpfiles \
	CANDY_SDWAN_RUNTIME_PATH=$bin/candy-sdwan-runtime CANDY_ENROLL_CLIENT_PATH=$bin/candy-cloud-enroll \
	PATH=$bin:$PATH "$installer" --bootstrap-base64-stdin >/dev/null 2>&1 <<EOF
$insecure
EOF
then
	fail "insecure Bootstrap Cloud address was accepted"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	stage=$tmp/runtime-stage
	mkdir -p "$stage/usr/local/bin" "$stage/usr/local/libexec" "$stage/systemd" "$stage/install" "$stage/etc/candy"
cat >"$stage/usr/local/bin/candy-server" <<'EOF'
#!/bin/sh
[ "${1:-}" != --help ] || {
	printf '%s\n' '  candy-server bootstrap FILE'
	exit 0
}
case "$1" in
	bootstrap)
		printf 'launcher=%s action=bootstrap\n' "$0" >>/fixture/product-calls
		[ -f "$2" ] && [ ! -L "$2" ]
		[ "$(stat -c %a "$2")" = 600 ]
		grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$2" >/dev/null
		[ "${CANDY_FAIL_BOOTSTRAP:-0}" != 1 ] || exit 1
		;;
	sdwan) [ "$2" = status ]; printf '%s\n' '{"schema_version":1,"registration":{"state":"registered"},"runtime":{"state":"stopped"}}' ;;
	*) exit 64 ;;
esac
EOF
	for name in serverd-linux candy-sdwan-runtime candy-sdwan-agent candy-netd candy-cloud-enroll candy-cloud-sync candy-server-health-check; do
		cat >"$stage/usr/local/libexec/$name" <<'EOF'
#!/bin/sh
exit 0
EOF
	done
	cat >"$stage/usr/local/bin/candy-core-manager" <<'EOF'
#!/bin/sh
exit 0
EOF
	for name in candy-server.service candy-netd.service candy-cloud-sync.service candy-cloud-sync.timer candy.tmpfiles; do
		printf '%s\n' '# fixture' >"$stage/systemd/$name"
	done
	cat >"$stage/install/upgrade-candy-server.sh" <<'EOF'
#!/bin/sh
set -eu
bundle=
sha256=
version=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--bundle-file) shift; bundle=$1 ;;
		--sha256) shift; sha256=$1 ;;
		--version) shift; version=$1 ;;
		*) exit 64 ;;
	esac
	shift
done
[ -f "$bundle" ] && [ ! -L "$bundle" ]
[ "$(sha256sum "$bundle" | awk '{print $1}')" = "$sha256" ]
[ "$version" = "$(tar -xOzf "$bundle" ./RUNTIME-RELEASE | tr -d '\r\n')" ]
printf 'bundle=%s sha256=%s version=%s\n' "$bundle" "$sha256" "$version" >>/fixture/upgrade-calls
[ "${CANDY_FAIL_UPGRADE:-0}" != 1 ] || exit 70
release=/opt/candy/releases/$version-fixture
mkdir -p "$release" /opt/candy
tar -xOzf "$bundle" ./usr/local/bin/candy-server >"$release/candy-server"
chmod 0755 "$release/candy-server"
ln -sfn "$release" /opt/candy/current
EOF
	cat >"$stage/install/install-candy-server.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
	printf '%s\n' '0.4.0-test' >"$stage/RUNTIME-RELEASE"
	printf '%s\n' 'x86_64' >"$stage/RUNTIME-ARCH"
	printf '%s\n' '0.4.0' >"$stage/VERSION"
	printf '%s\n' 'fixture' >"$stage/README.md"
	printf '%s\n' '# fixture' >"$stage/etc/candy/server.toml.example"
	printf '%s\n' '# fixture' >"$stage/etc/candy/cloud-sync.env.example"
	chmod 0755 "$stage/usr/local/bin"/* "$stage/usr/local/libexec"/* "$stage/install"/*
	tar -czf "$tmp/runtime.tar.gz" -C "$stage" .
	runtime_size=$(wc -c <"$tmp/runtime.tar.gz" | tr -d ' ')
	runtime_sha=$(sha256sum "$tmp/runtime.tar.gz" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$tmp/runtime.tar.gz" | awk '{print $1}')
	cat >"$tmp/manifest.json" <<EOF
{
  "schema_version": 1,
  "platform": "linux",
  "architecture": "x86_64",
  "runtime_version": "0.4.0-test",
  "runtime_url": "/install/artifacts/runtime.tar.gz",
  "runtime_sha256": "$runtime_sha",
  "runtime_size": $runtime_size
}
EOF
	mkdir -p "$tmp/container-bin"
	cat >"$tmp/container-bin/curl" <<'EOF'
#!/bin/sh
output=
url=
location=0
redirect_protocol=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--location) location=1 ;;
		--proto-redir) shift; redirect_protocol=$1 ;;
		-o) shift; output=$1 ;;
		https://*) url=$1 ;;
	esac
	shift
done
[ "$location" = 1 ] || exit 65
[ "$redirect_protocol" = '=https' ] || exit 65
case "$url" in
	*/install/manifests/linux-x86_64.json) cp /fixture/manifest.json "$output" ;;
	*/install/artifacts/runtime.tar.gz) cp /fixture/runtime.tar.gz "$output" ;;
	*) exit 22 ;;
esac
EOF
	chmod 0755 "$tmp/container-bin"/*
	container_bootstrap=$(printf '%s' "$bootstrap" | base64 | tr -d '\n')
	docker run --rm -i --platform linux/amd64 \
		-v "$tmp:/fixture" -v "$installer:/installer:ro" \
		-e PATH=/fixture/container-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		debian:bookworm-slim sh -eu -c '
			mkdir -p /opt/candy/releases/partial /usr/local/libexec
			cp /fixture/runtime-stage/usr/local/bin/candy-server /opt/candy/releases/partial/candy-server
			chmod 0755 /opt/candy/releases/partial/candy-server
			ln -s /opt/candy/releases/partial /opt/candy/current
			cp /fixture/runtime-stage/usr/local/libexec/candy-sdwan-runtime /usr/local/libexec/candy-sdwan-runtime
			cp /fixture/runtime-stage/usr/local/libexec/candy-cloud-enroll /usr/local/libexec/candy-cloud-enroll
			CANDY_INSTALL_LOG=/fixture/fresh-log/node-install.log /installer --bootstrap-base64-stdin
			test -L /opt/candy/current
			test -x /opt/candy/current/candy-server
			test ! -e /usr/local/bin/candy-server
			grep -F bootstrap /fixture/product-calls >/dev/null
			grep -F "launcher=/opt/candy/current/candy-server" /fixture/product-calls >/dev/null
			grep -F "version=0.4.0-test" /fixture/upgrade-calls >/dev/null
			grep -F "incomplete or incompatible" /fixture/fresh-log/node-install.log >/dev/null
		' >"$tmp/container.out" 2>"$tmp/container.err" <<EOF
$container_bootstrap
EOF
	[ -s "$tmp/fresh-log/node-install.log" ] || fail "fresh installation did not create its log directory"
	if grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$tmp/container.out" "$tmp/container.err" "$tmp/fresh-log/node-install.log" >/dev/null 2>&1; then
		fail "Bootstrap credential leaked during fresh installation"
	fi
	rm -rf "$tmp/fresh-log"
	if grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$tmp/upgrade-calls" >/dev/null 2>&1; then
		fail "Bootstrap credential leaked to the Runtime transaction"
	fi
	rm -f "$tmp/product-calls" "$tmp/upgrade-calls" "$tmp/install.log"
	docker run --rm -i --platform linux/amd64 \
		-v "$tmp:/fixture" -v "$installer:/installer:ro" \
		-e CANDY_FAIL_BOOTSTRAP=1 \
		-e PATH=/fixture/container-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		debian:bookworm-slim sh -eu -c '
			if CANDY_INSTALL_LOG=/fixture/install.log /installer --bootstrap-base64-stdin; then exit 1; fi
			test -L /opt/candy/current
			test -x /opt/candy/current/candy-server
			grep -F "Runtime remains installed" /fixture/install.log >/dev/null
		' \
		>"$tmp/failure.out" 2>"$tmp/failure.err" <<EOF
$container_bootstrap
EOF
	if grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$tmp/failure.out" "$tmp/failure.err" "$tmp/install.log" >/dev/null 2>&1; then
		fail "Bootstrap credential leaked after enrollment failure"
	fi

	rm -f "$tmp/product-calls" "$tmp/upgrade-calls" "$tmp/install.log"
	docker run --rm -i --platform linux/amd64 \
		-v "$tmp:/fixture" -v "$installer:/installer:ro" \
		-e CANDY_FAIL_UPGRADE=1 \
		-e PATH=/fixture/container-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		debian:bookworm-slim sh -eu -c '
			if CANDY_INSTALL_LOG=/fixture/install.log /installer --bootstrap-base64-stdin; then exit 1; fi
			test ! -e /opt/candy/current
			test ! -e /fixture/product-calls
			grep -F "Cloud enrollment was not attempted" /fixture/install.log >/dev/null
		' >"$tmp/upgrade-failure.out" 2>"$tmp/upgrade-failure.err" <<EOF
$container_bootstrap
EOF
fi

printf '%s\n' "Candy node installer tests passed"
