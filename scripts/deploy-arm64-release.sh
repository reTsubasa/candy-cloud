#!/bin/sh
set -eu

repository=${CANDY_CLOUD_REPOSITORY:-reTsubasa/candy-cloud}
release_tag=
deployment_dir=

usage() {
	cat <<'EOF'
usage: deploy-arm64-release.sh --tag TAG --deployment-dir DIR

Downloads one immutable Candy Cloud ARM64 Release, verifies and loads all six
images, applies least-privilege secret ownership, then starts and verifies the
existing compose.arm64.yml deployment.

Environment:
  CANDY_CLOUD_REPOSITORY  GitHub owner/repository (default reTsubasa/candy-cloud)
EOF
}

fail() { printf '%s\n' "deploy-arm64-release: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
	case "$1" in
		--tag) shift; [ "$#" -gt 0 ] || fail "--tag requires a value"; release_tag=$1 ;;
		--deployment-dir) shift; [ "$#" -gt 0 ] || fail "--deployment-dir requires a value"; deployment_dir=$1 ;;
		-h|--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
	shift
done

case "$release_tag" in cloud-arm64-[0-9a-f][0-9a-f]*) ;; *) fail "--tag must be a cloud-arm64-<revision> Release" ;; esac
[ -n "$deployment_dir" ] || fail "--deployment-dir is required"
[ "$(uname -s)" = Linux ] || fail "target must run Linux"
[ "$(uname -m)" = aarch64 ] || fail "target must be native ARM64"
for command in curl docker jq sha256sum; do
	command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
[ "$(id -u)" -eq 0 ] || fail "run this deployment script as root"

deployment_dir=$(CDPATH= cd -- "$deployment_dir" && pwd)
cd "$deployment_dir"
[ -f compose.arm64.yml ] || fail "compose.arm64.yml is missing"
[ -f deploy.env ] || fail "deploy.env is missing"
[ -d secrets ] || fail "secrets directory is missing"

revision=${release_tag#cloud-arm64-}
archive="candy-cloud-arm64-$revision.tar.gz"
checksum="$archive.sha256"
manifest="candy-cloud-arm64-$revision.json"
release_override=compose.arm64.release.yml
base_url="https://github.com/$repository/releases/download/$release_tag"

umask 077
curl --fail --location --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors \
	--connect-timeout 15 --max-time 900 --output "$archive.part" "$base_url/$archive"
mv "$archive.part" "$archive"
curl --fail --location --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors \
	--connect-timeout 15 --max-time 120 --output "$checksum" "$base_url/$checksum"
curl --fail --location --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors \
	--connect-timeout 15 --max-time 120 --output "$manifest" "$base_url/$manifest"

sha256sum -c "$checksum"
jq -e --arg revision "$revision" --arg repository "$repository" '
	.schema_version == 1 and
	.architecture == "arm64" and
	.source.repository == $repository and
	(.source.commit | startswith($revision)) and
	.images == ["migrate", "cloud-api", "cloud-identity", "cloud-auth", "cloud-worker", "cloud-web"]
' "$manifest" >/dev/null || fail "Release manifest is invalid"
core_version=$(jq -r '.core.version' "$manifest")

docker load -i "$archive"
for image in migrate cloud-api cloud-identity cloud-auth cloud-worker cloud-web; do
	ref="candy-cloud-$image:arm64-$revision"
	[ "$(docker image inspect "$ref" --format '{{.Architecture}}')" = arm64 ] ||
		fail "$ref is not an ARM64 image"
done

cat >"$release_override" <<EOF
services:
  migrate:
    image: candy-cloud-migrate:arm64-$revision
  cloud-api:
    image: candy-cloud-cloud-api:arm64-$revision
    environment:
      CANDY_CLOUD_REVISION: $revision
      CANDY_CORE_VERSION: $core_version
  cloud-identity:
    image: candy-cloud-cloud-identity:arm64-$revision
  cloud-auth:
    image: candy-cloud-cloud-auth:arm64-$revision
  cloud-worker:
    image: candy-cloud-cloud-worker:arm64-$revision
  cloud-web:
    image: candy-cloud-cloud-web:arm64-$revision
EOF
chmod 0644 "$release_override"

# Services run as uid 65532. Keep private material readable only by that uid;
# public certificates remain readable by the reverse proxy and API services.
chmod 0755 secrets
for file in cloud-api-auth-private.pem cloud-signing.key device-ca.key; do
	[ -f "secrets/$file" ] || fail "secrets/$file is missing"
	chown 65532:65532 "secrets/$file"
	chmod 0400 "secrets/$file"
done
for file in cloud-api-auth-public.pem device-ca.pem; do
	[ -f "secrets/$file" ] || fail "secrets/$file is missing"
	chown root:root "secrets/$file"
	chmod 0444 "secrets/$file"
done

compose() {
	docker compose --env-file deploy.env -f compose.arm64.yml -f "$release_override" "$@"
}
compose run --rm migrate
compose up -d

# The reverse proxy serves a Compose-managed named volume. Docker initializes
# that volume only once, so container recreation alone cannot activate a new
# web image. Extract the image payload before mounting the target volume;
# mounting it at /srv would otherwise hide the image's own files. Copy hashed
# assets first and replace index.html last, preserving old assets for browsers
# that still have the previous document open.
web_container=$(compose ps -q cloud-web)
[ -n "$web_container" ] || fail "cloud-web container was not created"
web_image="candy-cloud-cloud-web:arm64-$revision"
web_source_container=$(docker create "$web_image")
web_stage=$(mktemp -d /tmp/candy-web.XXXXXX)
cleanup_web_stage() {
	docker rm -f "$web_source_container" >/dev/null 2>&1 || true
	rm -rf "$web_stage"
}
trap cleanup_web_stage EXIT INT TERM
docker cp "$web_source_container:/srv/." "$web_stage/"
docker rm "$web_source_container" >/dev/null
web_source_container=
test -s "$web_stage/index.html" || fail "cloud-web image is missing index.html"
test -d "$web_stage/assets" || fail "cloud-web image is missing assets"

docker run --rm --volumes-from "$web_container" \
	-v "$web_stage:/image-web:ro" busybox:1.37.0-musl sh -eu -c '
		test -s /image-web/index.html
		test -d /image-web/assets
		mkdir -p /srv/assets
		cp -R /image-web/assets/. /srv/assets/
		for file in /image-web/*; do
			name=${file##*/}
			[ "$name" = index.html ] && continue
			[ "$name" = assets ] && continue
			cp -R "$file" /srv/
		done
		cp /image-web/index.html /srv/.index.html.new
		mv /srv/.index.html.new /srv/index.html
	'
cleanup_web_stage
trap - EXIT INT TERM

for service in cloud-api cloud-identity cloud-auth cloud-worker cloud-web; do
	container=$(compose ps -q "$service")
	[ -n "$container" ] || fail "$service container was not created"
	for attempt in $(seq 1 36); do
		health=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
		[ "$health" = healthy ] && break
		if [ "$health" = exited ] || [ "$health" = dead ]; then
			fail "$service stopped during startup"
		fi
		[ "$attempt" -lt 36 ] || fail "$service did not become healthy"
		sleep 5
	done
done

printf '%s\n' "Candy Cloud $release_tag is running on native ARM64."
