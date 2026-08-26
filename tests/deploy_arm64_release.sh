#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
script="$root/scripts/deploy-arm64-release.sh"
arm_workflow="$root/.github/workflows/release-arm64-images.yml"
x86_workflow="$root/.github/workflows/release-x86-images.yml"

test -x "$script"
sh -n "$script"

for required in \
	'$(uname -m)" = aarch64' \
	'sha256sum -c "$checksum"' \
	'.architecture == "arm64"' \
	'docker image inspect "$ref"' \
	'compose.arm64.release.yml' \
	'core_version=$(jq -r' \
	'CANDY_CLOUD_REVISION: $revision' \
	'CANDY_CORE_VERSION: $core_version' \
	'chown 65532:65532' \
	'chmod 0400' \
	'trap '\''on_exit $?'\'' EXIT' \
	'rollback_deployment()' \
	'previous Cloud release restored' \
	'compose.arm64.release.yml.previous' \
	'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --quick --hex-blob --routines --events --databases "$MYSQL_DATABASE"' \
	'pre-migration MySQL backup is incomplete; refusing to run migrations' \
	'sha256sum -c rollback.sha256' \
	'refusing destructive recovery' \
	'DROP DATABASE IF EXISTS' \
	'web-volume.tar.gz' \
	'restore_web_volume()' \
	'compose stop reverse-proxy cloud-api cloud-identity cloud-auth cloud-worker cloud-web' \
	'compose up -d --no-deps --force-recreate' \
	'compose run --rm migrate' \
	'GRANT DELETE ON \`$MYSQL_DATABASE\`.\`runtime_projection_transport_catalog\`' \
	'web_source_container=$(docker create "$web_image")' \
	'docker cp "$web_source_container:/srv/." "$web_stage/"' \
	'--volumes-from "$web_container"' \
	'-v "$web_stage:/image-web:ro" busybox:1.37.0-musl' \
	'cp -R /image-web/assets/. /srv/assets/' \
	'mv /srv/.index.html.new /srv/index.html' \
	'one or more Cloud services did not become healthy'; do
	grep -F -- "$required" "$script" >/dev/null || {
		echo "deploy_arm64_release: missing invariant: $required" >&2
		exit 1
	}
done

line_of() {
	grep -nF -- "$1" "$script" | head -1 | cut -d: -f1
}

assert_before() {
	first=$(line_of "$1")
	second=$(line_of "$2")
	[ -n "$first" ] && [ -n "$second" ] && [ "$first" -lt "$second" ] || {
		echo "deploy_arm64_release: transaction order is invalid: $1 must precede $2" >&2
		exit 1
	}
}

assert_before 'mysqldump -uroot' 'transaction_started=1'
assert_before 'web-volume.tar.gz -C /srv' 'transaction_started=1'
assert_before 'sha256sum compose.arm64.release.yml.previous' 'transaction_started=1'
assert_before 'trap '\''on_exit $?'\'' EXIT' 'transaction_started=1'
assert_before 'transaction_started=1' 'compose run --rm migrate'
assert_before 'compose stop reverse-proxy cloud-api cloud-identity cloud-auth cloud-worker cloud-web' 'compose run --rm migrate'
assert_before 'migration_started=1' 'compose run --rm migrate'
assert_before 'compose run --rm migrate' 'GRANT DELETE ON \`$MYSQL_DATABASE\`.\`runtime_projection_transport_catalog\`'
reconcile_line=$(line_of 'GRANT DELETE ON \`$MYSQL_DATABASE\`.\`runtime_projection_transport_catalog\`')
start_line=$(grep -n '^[[:space:]]*compose up -d$' "$script" | cut -d: -f1)
[ -n "$reconcile_line" ] && [ -n "$start_line" ] && [ "$reconcile_line" -lt "$start_line" ] || {
	echo "deploy_arm64_release: privilege reconciliation must precede service startup" >&2
	exit 1
}

for workflow in "$arm_workflow" "$x86_workflow"; do
	grep -F 'CORE_MODULE_VERSION: 0.3.25' "$workflow" >/dev/null
	grep -F 'CORE_MODULE_INPUT_TAG: core-v0.3.25' "$workflow" >/dev/null
	grep -F 'RUNTIME_RELEASE_TAG: runtime-v0.4.0-r72' "$workflow" >/dev/null
	grep -F 'runtime:{release_tag:$runtime_release_tag}' "$workflow" >/dev/null
done

if grep -Eq 'docker volume rm|rm -rf .*secrets|docker compose down.*-v' "$script"; then
	echo "deploy_arm64_release: rollback path may delete persistent data or secrets" >&2
	exit 1
fi

echo "deploy_arm64_release: ok"
