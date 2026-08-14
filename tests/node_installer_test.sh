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
chmod 0755 "$bin"/* "$installer"

bootstrap='{"schema_version":1,"cloud_address":"https://cloud.example.test","bootstrap_code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-01T00:00:00Z"}'
encoded=$(printf '%s' "$bootstrap" | base64 | tr -d '\n')
FAKE_CALLS=$calls CANDY_INSTALL_TEST_MODE=1 CANDY_SERVER_BIN=$bin/candy-server \
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
	CANDY_SDWAN_RUNTIME_PATH=$bin/candy-sdwan-runtime CANDY_ENROLL_CLIENT_PATH=$bin/candy-cloud-enroll \
	PATH=$bin:$PATH "$installer" --bootstrap-base64-stdin >/dev/null 2>&1 <<EOF
$insecure
EOF
then
	fail "insecure Bootstrap Cloud address was accepted"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	stage=$tmp/runtime-stage
	mkdir -p "$stage/usr/local/bin" "$stage/usr/local/libexec" "$stage/systemd"
	cat >"$stage/usr/local/bin/candy-server" <<'EOF'
#!/bin/sh
case "$1" in
	bootstrap) printf '%s\n' bootstrap >>/fixture/product-calls; [ "${CANDY_FAIL_BOOTSTRAP:-0}" != 1 ] || exit 1; rm -f "$2" ;;
	sdwan) [ "$2" = status ]; printf '%s\n' '{"schema_version":1,"registration":{"state":"registered"},"runtime":{"state":"stopped"}}' ;;
	*) exit 64 ;;
esac
EOF
	for name in serverd-linux candy-sdwan-runtime candy-sdwan-agent candy-netd candy-cloud-enroll candy-server-health-check; do
		cat >"$stage/usr/local/libexec/$name" <<'EOF'
#!/bin/sh
exit 0
EOF
	done
	cat >"$stage/usr/local/bin/candy-core-manager" <<'EOF'
#!/bin/sh
exit 0
EOF
	for name in candy-netd.service candy-sdwan.service candy.sysusers candy.tmpfiles; do
		printf '%s\n' '# fixture' >"$stage/systemd/$name"
	done
	chmod 0755 "$stage/usr/local/bin"/* "$stage/usr/local/libexec"/*
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
while [ "$#" -gt 0 ]; do
	case "$1" in -o) shift; output=$1 ;; https://*) url=$1 ;; esac
	shift
done
case "$url" in
	*/install/manifests/linux-x86_64.json) cp /fixture/manifest.json "$output" ;;
	*/install/artifacts/runtime.tar.gz) cp /fixture/runtime.tar.gz "$output" ;;
	*) exit 22 ;;
esac
EOF
	cat >"$tmp/container-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>/fixture/systemctl-calls
case "$1" in
	is-active) test -f /fixture/netd-active ;;
	is-enabled) test -f /fixture/netd-enabled ;;
	enable) touch /fixture/netd-active /fixture/netd-enabled ;;
	stop) rm -f /fixture/netd-active ;;
	disable) rm -f /fixture/netd-enabled ;;
	*) exit 0 ;;
esac
EOF
	for name in systemd-sysusers systemd-tmpfiles; do
		cat >"$tmp/container-bin/$name" <<'EOF'
#!/bin/sh
exit 0
EOF
	done
	chmod 0755 "$tmp/container-bin"/*
	container_bootstrap=$(printf '%s' "$bootstrap" | base64 | tr -d '\n')
	docker run --rm -i --platform linux/amd64 \
		-v "$tmp:/fixture" -v "$installer:/installer:ro" \
		-e PATH=/fixture/container-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		debian:bookworm-slim sh -eu -c '
			CANDY_INSTALL_LOG=/fixture/install.log /installer --bootstrap-base64-stdin
			test -x /usr/local/bin/candy-server
			test -x /usr/local/libexec/candy-cloud-enroll
			grep -F bootstrap /fixture/product-calls >/dev/null
			grep -F "enable --now candy-netd.service" /fixture/systemctl-calls >/dev/null
		' >"$tmp/container.out" 2>"$tmp/container.err" <<EOF
$container_bootstrap
EOF
	if grep -F 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$tmp/container.out" "$tmp/container.err" "$tmp/install.log" >/dev/null 2>&1; then
		fail "Bootstrap credential leaked during fresh installation"
	fi
	rm -f "$tmp/netd-active" "$tmp/netd-enabled" "$tmp/systemctl-calls" "$tmp/product-calls" "$tmp/install.log"
	if docker run --rm -i --platform linux/amd64 \
		-v "$tmp:/fixture" -v "$installer:/installer:ro" \
		-e CANDY_FAIL_BOOTSTRAP=1 \
		-e PATH=/fixture/container-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		debian:bookworm-slim sh -eu -c 'CANDY_INSTALL_LOG=/fixture/install.log /installer --bootstrap-base64-stdin' \
		>"$tmp/failure.out" 2>"$tmp/failure.err" <<EOF
$container_bootstrap
EOF
	then
		fail "fresh installation unexpectedly succeeded after enrollment failure"
	fi
	[ ! -e "$tmp/netd-active" ] || fail "failed installation left candy-netd running"
	[ ! -e "$tmp/netd-enabled" ] || fail "failed installation left candy-netd enabled"
	grep -F 'stop candy-netd.service' "$tmp/systemctl-calls" >/dev/null || fail "failed installation did not stop newly started candy-netd"
	grep -F 'disable candy-netd.service' "$tmp/systemctl-calls" >/dev/null || fail "failed installation did not restore the netd enablement state"
fi

printf '%s\n' "Candy node installer tests passed"
