#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
script="$root/scripts/deploy-arm64-release.sh"

test -x "$script"
sh -n "$script"

for required in \
	'$(uname -m)" = aarch64' \
	'sha256sum -c "$checksum"' \
	'.architecture == "arm64"' \
	'docker image inspect "$ref"' \
	'compose.arm64.release.yml' \
	'chown 65532:65532' \
	'chmod 0400' \
	'compose run --rm migrate' \
	'--volumes-from "$web_container"' \
	'cp -R "$stage/assets/." /srv/assets/' \
	'mv /srv/.index.html.new /srv/index.html' \
	'did not become healthy'; do
	grep -F -- "$required" "$script" >/dev/null || {
		echo "deploy_arm64_release: missing invariant: $required" >&2
		exit 1
	}
done

echo "deploy_arm64_release: ok"
