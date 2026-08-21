#!/bin/sh
set -eu

repository=${CANDY_CLOUD_REPOSITORY:-reTsubasa/candy-cloud}
release_tag=
deployment_dir=
transaction_started=0
transaction_finished=0
migration_started=0
web_mutated=0
web_source_container=
web_stage=

usage() {
	cat <<'EOF'
usage: deploy-arm64-release.sh --tag TAG --deployment-dir DIR

Downloads one immutable Candy Cloud ARM64 Release, verifies and loads all six
images, snapshots the existing database, web volume, and image mapping, then
starts and verifies the existing compose.arm64.yml deployment. A failed or
interrupted transaction restores the complete previous deployment.

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
[ -f compose.arm64.yml ] && [ ! -L compose.arm64.yml ] || fail "compose.arm64.yml must be a regular file"
[ -f deploy.env ] && [ ! -L deploy.env ] || fail "deploy.env must be a regular file"
[ -d secrets ] && [ ! -L secrets ] || fail "secrets must be a real directory"

revision=${release_tag#cloud-arm64-}
archive="candy-cloud-arm64-$revision.tar.gz"
checksum="$archive.sha256"
manifest="candy-cloud-arm64-$revision.json"
release_override=compose.arm64.release.yml
base_url="https://github.com/$repository/releases/download/$release_tag"
backup_root=$deployment_dir/backups

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

compose() {
	docker compose --env-file deploy.env -f compose.arm64.yml -f "$release_override" "$@"
}

service_healthy() {
	service=$1
	container=$(compose ps -q "$service")
	[ -n "$container" ] || return 1
	health=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}') || return 1
	[ "$health" = healthy ]
}

wait_services_healthy() {
	for service in cloud-api cloud-identity cloud-auth cloud-worker cloud-web; do
		container=$(compose ps -q "$service")
		[ -n "$container" ] || return 1
		for attempt in $(seq 1 36); do
			health=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}') || return 1
			[ "$health" = healthy ] && break
			[ "$health" != exited ] && [ "$health" != dead ] || return 1
			[ "$attempt" -lt 36 ] || return 1
			sleep 5
		done
	done
}

restore_database() {
	[ -s "$database_backup" ] || return 1
	compose exec -T mysql sh -eu -c '
		case "$MYSQL_DATABASE" in ""|*[!A-Za-z0-9_]*) exit 1 ;; esac
		exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS \`$MYSQL_DATABASE\`"
	' || return 1
	compose exec -T mysql sh -eu -c 'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD"' <"$database_backup"
}

restore_web_volume() {
	[ -s "$web_backup" ] || return 1
	docker run --rm \
		-v "$web_volume:/srv" \
		-v "$transaction_dir:/backup:ro" \
		busybox:1.37.0-musl sh -eu -c '
			find /srv -mindepth 1 -maxdepth 1 -exec rm -rf {} +
			tar -xzf /backup/web-volume.tar.gz -C /srv
		'
}

cleanup_transient() {
	[ -z "$web_source_container" ] || docker rm -f "$web_source_container" >/dev/null 2>&1 || true
	[ -z "$web_stage" ] || rm -rf "$web_stage"
}

rollback_deployment() {
	rollback_failed=0
	printf '%s\n' "deploy-arm64-release: deployment failed; restoring the previous Cloud release" >&2
	if ! (cd "$transaction_dir" && sha256sum -c rollback.sha256 >/dev/null); then
		printf '%s\n' "deploy-arm64-release: ERROR rollback assets failed checksum validation; refusing destructive recovery" >&2
		return 1
	fi
	compose stop reverse-proxy cloud-api cloud-identity cloud-auth cloud-worker cloud-web >/dev/null 2>&1 || rollback_failed=1
	override_restore_tmp=$transaction_dir/compose.arm64.release.yml.restore
	cp "$previous_override" "$override_restore_tmp" && chmod 0644 "$override_restore_tmp" &&
		mv -f "$override_restore_tmp" "$release_override" || rollback_failed=1
	if [ "$migration_started" = 1 ]; then
		restore_database || rollback_failed=1
	fi
	if [ "$web_mutated" = 1 ]; then
		restore_web_volume || rollback_failed=1
	fi
	compose up -d --no-deps --force-recreate cloud-api cloud-identity cloud-auth cloud-worker cloud-web >/dev/null 2>&1 || rollback_failed=1
	compose start reverse-proxy >/dev/null 2>&1 || rollback_failed=1
	wait_services_healthy || rollback_failed=1
	if [ "$rollback_failed" = 0 ]; then
		printf '%s\n' "deploy-arm64-release: previous Cloud release restored; recovery assets retained in $transaction_dir" >&2
		return 0
	fi
	printf '%s\n' "deploy-arm64-release: ERROR rollback failed; stop deployment and reconcile from $transaction_dir" >&2
	return 1
}

on_exit() {
	status=$1
	trap - EXIT HUP INT TERM
	cleanup_transient
	if [ "$transaction_started" = 1 ] && [ "$transaction_finished" = 0 ]; then
		rollback_deployment || status=1
	fi
	exit "$status"
}
trap 'on_exit $?' EXIT
trap 'exit 130' HUP INT TERM

# A production upgrade needs a concrete rollback release. Refuse to run a
# migration when the previous immutable image mapping cannot be restored.
[ -f "$release_override" ] && [ ! -L "$release_override" ] ||
	fail "$release_override must be an existing regular rollback definition"
for service in mysql cloud-api cloud-identity cloud-auth cloud-worker cloud-web; do
	service_healthy "$service" || fail "current $service service is not healthy; refusing to snapshot an unsafe baseline"
done
reverse_proxy_container=$(compose ps -q reverse-proxy)
if [ -z "$reverse_proxy_container" ] ||
	[ "$(docker inspect "$reverse_proxy_container" --format '{{.State.Status}}')" != running ]; then
	fail "current reverse-proxy service is not running"
fi

if [ -e "$backup_root" ] || [ -L "$backup_root" ]; then
	[ -d "$backup_root" ] && [ ! -L "$backup_root" ] || fail "backups must be a real directory"
else
	mkdir -m 0700 "$backup_root"
fi
chmod 0700 "$backup_root"
transaction_dir=$backup_root/deploy-$revision-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -m 0700 "$transaction_dir"
previous_override=$transaction_dir/compose.arm64.release.yml.previous
database_backup=$transaction_dir/mysql-before.sql
web_backup=$transaction_dir/web-volume.tar.gz
rollback_checksums=$transaction_dir/rollback.sha256
cp -p "$release_override" "$previous_override"
chmod 0600 "$previous_override"

# MySQL DDL can commit implicitly. A complete logical backup is therefore a
# hard precondition, not an optional convenience. The dump includes CREATE
# DATABASE so rollback can drop all partially migrated state before import.
compose exec -T mysql sh -eu -c '
	case "$MYSQL_DATABASE" in ""|*[!A-Za-z0-9_]*) exit 1 ;; esac
	exec mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --quick --hex-blob --routines --events --databases "$MYSQL_DATABASE"
' >"$database_backup" || fail "could not create the pre-migration MySQL backup"
chmod 0600 "$database_backup"
if ! [ -s "$database_backup" ] || ! grep -F 'Current Database:' "$database_backup" >/dev/null; then
	fail "pre-migration MySQL backup is incomplete; refusing to run migrations"
fi

old_web_container=$(compose ps -q cloud-web)
web_volume=$(docker inspect "$old_web_container" --format '{{range .Mounts}}{{if eq .Destination "/srv"}}{{.Name}}{{end}}{{end}}')
[ -n "$web_volume" ] || fail "cloud-web does not use a named /srv volume"
docker run --rm \
	-v "$web_volume:/srv:ro" \
	-v "$transaction_dir:/backup" \
	busybox:1.37.0-musl sh -eu -c 'tar -czf /backup/web-volume.tar.gz -C /srv .' ||
	fail "could not snapshot the Cloud web volume"
chmod 0600 "$web_backup"
[ -s "$web_backup" ] || fail "Cloud web volume snapshot is empty"
(cd "$transaction_dir" &&
	sha256sum compose.arm64.release.yml.previous mysql-before.sql web-volume.tar.gz >rollback.sha256 &&
	sha256sum -c rollback.sha256 >/dev/null) || fail "rollback snapshot checksum validation failed"
chmod 0600 "$rollback_checksums"

new_override=$transaction_dir/compose.arm64.release.yml.new
cat >"$new_override" <<EOF
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
chmod 0644 "$new_override"

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

transaction_started=1
mv -f "$new_override" "$release_override"
migration_started=1
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
docker cp "$web_source_container:/srv/." "$web_stage/"
docker rm "$web_source_container" >/dev/null
web_source_container=
test -s "$web_stage/index.html" || fail "cloud-web image is missing index.html"
test -d "$web_stage/assets" || fail "cloud-web image is missing assets"

web_mutated=1
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
rm -rf "$web_stage"
web_stage=

wait_services_healthy || fail "one or more Cloud services did not become healthy"

transaction_finished=1
printf '%s\n' "Candy Cloud $release_tag is running on native ARM64."
