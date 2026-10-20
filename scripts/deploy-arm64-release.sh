#!/bin/sh
set -eu

release_repository=${CANDY_RELEASE_REPOSITORY:-reTsubasa/candy-release}
source_repository=${CANDY_CLOUD_SOURCE_REPOSITORY:-reTsubasa/candy-cloud}
release_tag=
deployment_dir=
transaction_started=0
transaction_finished=0
migration_started=0
web_mutated=0
web_source_container=
web_stage=
deployment_mode=maintenance
proxy_switched=0
canonical_mutated=0
candidate_names=

usage() {
	cat <<'EOF'
usage: deploy-arm64-release.sh --tag TAG --deployment-dir DIR

Downloads one immutable Candy Cloud ARM64 Release, verifies and loads all six
images, snapshots the existing database, web volume, and image mapping, then
starts and verifies the existing compose.arm64.yml deployment. A failed or
interrupted transaction restores the previous deployment. An exact schema
match uses ready candidates and a graceful Caddy switch. Schema changes use
the backed-up maintenance transaction.

  CANDY_CLOUD_DRAIN_SECONDS    Overlap before retiring old HTTP services (default 30, max 300)

Environment:
  CANDY_RELEASE_REPOSITORY      GitHub owner/repository holding signed releases
                                (default reTsubasa/candy-release)
  CANDY_CLOUD_SOURCE_REPOSITORY GitHub owner/repository expected in the signed
                                manifest (default reTsubasa/candy-cloud)
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
for command in curl docker jq sha256sum flock; do
	command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
[ "$(id -u)" -eq 0 ] || fail "run this deployment script as root"

deployment_dir=$(CDPATH= cd -- "$deployment_dir" && pwd)
cd "$deployment_dir"
exec 9>.deployment.lock
flock -n 9 || fail "another Cloud deployment is in progress"
recovery_marker=$deployment_dir/.deployment-recovery-required
[ ! -e "$recovery_marker" ] && [ ! -L "$recovery_marker" ] ||
	fail "previous rollback requires manual recovery; inspect $recovery_marker before deploying"
drain_seconds=${CANDY_CLOUD_DRAIN_SECONDS:-30}
case "$drain_seconds" in ''|*[!0-9]*) fail "invalid drain timeout" ;; esac
[ "$drain_seconds" -ge 1 ] && [ "$drain_seconds" -le 300 ] || fail "drain timeout must be 1..300 seconds"
[ -f compose.arm64.yml ] && [ ! -L compose.arm64.yml ] || fail "compose.arm64.yml must be a regular file"
[ -f deploy.env ] && [ ! -L deploy.env ] || fail "deploy.env must be a regular file"
[ -d secrets ] && [ ! -L secrets ] || fail "secrets must be a real directory"

revision=${release_tag#cloud-arm64-}
archive="candy-cloud-arm64-$revision.tar.gz"
checksum="$archive.sha256"
manifest="candy-cloud-arm64-$revision.json"
release_override=compose.arm64.release.yml
base_url="https://github.com/$release_repository/releases/download/$release_tag"
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
jq -e --arg revision "$revision" --arg source_repository "$source_repository" '
	.schema_version == 1 and
	.architecture == "arm64" and
	.source.repository == $source_repository and
	(.source.commit | startswith($revision)) and
	.images == ["migrate", "cloud-api", "cloud-identity", "cloud-auth", "cloud-worker", "cloud-web"]
' "$manifest" >/dev/null || fail "Release manifest is invalid"
core_version=$(jq -r '.core.version' "$manifest")
core_bundle_sha=$(jq -r '.core.bundle_sha256' "$manifest")
core_module_sha=$(jq -r '.core.module_sha256' "$manifest")
case "$core_bundle_sha" in ''|*[!0-9a-f]*) fail "Release manifest has invalid Core bundle binding" ;; esac
case "$core_module_sha" in ''|*[!0-9a-f]*) fail "Release manifest has invalid Core module binding" ;; esac
[ "${#core_bundle_sha}" -eq 64 ] || fail "Release manifest has invalid Core bundle binding"
[ "${#core_module_sha}" -eq 64 ] || fail "Release manifest has invalid Core module binding"

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

wait_container_healthy() {
	container=$1
	for attempt in $(seq 1 36); do
		health=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}') || return 1
		[ "$health" = healthy ] && return 0
		[ "$health" != exited ] && [ "$health" != dead ] || return 1
		[ "$attempt" -lt 36 ] || return 1
		sleep 5
	done
}

wait_services_healthy() {
	for service in cloud-api cloud-identity cloud-auth cloud-worker cloud-web; do
		container=$(compose ps -q "$service")
		[ -n "$container" ] && wait_container_healthy "$container" || return 1
	done
}

remove_candidates() {
	candidate_cleanup_failed=0
	remaining_candidates=
	for candidate in $candidate_names; do
		if docker rm -f "$candidate" >/dev/null 2>&1; then
			continue
		fi
		# A failed create, or an earlier cleanup, may have left no container.
		# Distinguish that from a Docker error and still attempt every peer.
		if remaining_id=$(docker ps -aq --filter "name=^/$candidate\$"); then
			[ -n "$remaining_id" ] || continue
		fi
		candidate_cleanup_failed=1
		remaining_candidates="$remaining_candidates $candidate"
	done
	candidate_names=$remaining_candidates
	return "$candidate_cleanup_failed"
}

reload_proxy() {
	proxy_config=$1
	docker cp "$proxy_config" "$reverse_proxy_container:/tmp/candy-deploy-Caddyfile" || return 1
	docker exec "$reverse_proxy_container" caddy validate --config /tmp/candy-deploy-Caddyfile --adapter caddyfile || return 1
	docker exec "$reverse_proxy_container" caddy reload --config /tmp/candy-deploy-Caddyfile --adapter caddyfile
}

rolling_services() {
	# New HTTP processes receive no public requests until all are ready. They
	# share the unchanged schema and the existing TLS terminator and secrets.
	for service in cloud-api cloud-identity cloud-auth; do
		candidate="candy-next-$revision-$service"
		candidate_names="$candidate_names $candidate"
		compose run -d --no-deps --name "$candidate" "$service" >/dev/null || return 1
		wait_container_healthy "$candidate" || return 1
	done
	sed -e "s/cloud-api:8080/candy-next-$revision-cloud-api:8080/g" \
		-e "s/cloud-identity:8082/candy-next-$revision-cloud-identity:8082/g" \
		-e "s/cloud-auth:8081/candy-next-$revision-cloud-auth:8081/g" \
		"$proxy_backup" >"$transaction_dir/Caddyfile.candidates" || return 1
	# Set before the reload: a lost admin response may still have switched it.
	proxy_switched=1
	reload_proxy "$transaction_dir/Caddyfile.candidates" || return 1
	# Bound the lifetime of requests still handled by the old processes.
	sleep "$drain_seconds"
	canonical_mutated=1
	compose up -d --no-deps --force-recreate cloud-api cloud-identity cloud-auth cloud-worker cloud-web || return 1
	wait_services_healthy || return 1
	reload_proxy "$proxy_backup" || return 1
	proxy_switched=0
	sleep "$drain_seconds"
	remove_candidates
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
		-e DEPLOYMENT_MODE="$deployment_mode" busybox:1.37.0-musl sh -eu -c '
			if [ "$DEPLOYMENT_MODE" = rolling ]; then
				mkdir /tmp/previous-web
				tar -xzf /backup/web-volume.tar.gz -C /tmp/previous-web
				test -s /tmp/previous-web/index.html
				for file in /tmp/previous-web/*; do
					[ "${file##*/}" = index.html ] || cp -R "$file" /srv/
				done
				cp /tmp/previous-web/index.html /srv/.index.html.rollback
				mv /srv/.index.html.rollback /srv/index.html
			else
				find /srv -mindepth 1 -maxdepth 1 -exec rm -rf {} +
				tar -xzf /backup/web-volume.tar.gz -C /srv
			fi
		'
}

cleanup_transient() {
	[ -z "$web_source_container" ] || docker rm -f "$web_source_container" >/dev/null 2>&1 || true
	[ -z "$web_stage" ] || rm -rf "$web_stage"
	rm -f ".schema-check-$$.log" ".schema-check-$$.yml"
}

rollback_deployment() {
	rollback_failed=0
	printf '%s\n' "deploy-arm64-release: deployment failed; restoring the previous Cloud release" >&2
	if ! (cd "$transaction_dir" && sha256sum -c rollback.sha256 >/dev/null); then
		printf '%s\n' "deploy-arm64-release: ERROR rollback assets failed checksum validation; refusing destructive recovery" >&2
		return 1
	fi
	if [ "$deployment_mode" = maintenance ]; then
		compose stop reverse-proxy cloud-api cloud-identity cloud-auth cloud-worker cloud-web >/dev/null 2>&1 || rollback_failed=1
	fi
	override_restore_tmp=$transaction_dir/compose.arm64.release.yml.restore
	cp "$previous_override" "$override_restore_tmp" && chmod 0644 "$override_restore_tmp" &&
		mv -f "$override_restore_tmp" "$release_override" || rollback_failed=1
	if [ "$migration_started" = 1 ]; then
		restore_database || rollback_failed=1
	fi
	if [ "$web_mutated" = 1 ]; then
		restore_web_volume || rollback_failed=1
	fi
	if [ "$canonical_mutated" = 1 ]; then
		compose up -d --no-deps --force-recreate cloud-api cloud-identity cloud-auth cloud-worker cloud-web >/dev/null 2>&1 || rollback_failed=1
	fi
	wait_services_healthy || rollback_failed=1
	if [ "$deployment_mode" = rolling ]; then
		# Keep candidates alive if restoring the canonical services failed.
		if [ "$rollback_failed" = 0 ]; then
			if [ "$proxy_switched" = 1 ]; then
				reload_proxy "$proxy_backup" || rollback_failed=1
			fi
			if [ "$rollback_failed" = 0 ]; then
				proxy_switched=0
				sleep "$drain_seconds"
				remove_candidates || rollback_failed=1
			fi
		fi
	else
		compose start reverse-proxy >/dev/null 2>&1 || rollback_failed=1
	fi
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
		if ! rollback_deployment; then
			# Active Caddy state may still reference candidates. Refuse another
			# transaction until an operator reconciles the running deployment.
			printf '%s\n' "transaction=$transaction_dir" "mode=$deployment_mode" "recovery_required=1" >"$recovery_marker" || true
			status=1
		fi
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

# This gate runs the new migrator without performing any writes. Errors fail
# closed; only an explicit schema difference selects maintenance mode.
schema_check_container="candy-schema-$revision-$$"
# Compose supplies the existing database network and migrator credentials;
# override only this one-off container's executable with the target image.
cat >".schema-check-$$.yml" <<EOF
services:
  migrate:
    image: candy-cloud-migrate:arm64-$revision
EOF
if docker compose --env-file deploy.env -f compose.arm64.yml -f "$release_override" \
	-f ".schema-check-$$.yml" run --rm --no-deps --name "$schema_check_container" migrate --check-schema \
	>".schema-check-$$.log" 2>&1; then
	deployment_mode=rolling
else
	schema_status=$?
	if [ "$schema_status" != 3 ]; then
		cat ".schema-check-$$.log" >&2
		rm -f ".schema-check-$$.log" ".schema-check-$$.yml"
		fail "could not verify target database schema"
	fi
fi
rm -f ".schema-check-$$.log" ".schema-check-$$.yml"
printf '%s\n' "deploy-arm64-release: mode=$deployment_mode"

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
proxy_backup=$transaction_dir/Caddyfile.previous
docker cp "$reverse_proxy_container:/etc/caddy/Caddyfile" "$proxy_backup"
# Refuse an unrecognized proxy mapping before any service is replaced.
for upstream in cloud-api:8080 cloud-identity:8082 cloud-auth:8081; do
	grep -F "reverse_proxy $upstream" "$proxy_backup" >/dev/null || fail "unsupported reverse-proxy upstream mapping"
done

(cd "$transaction_dir" &&
	sha256sum compose.arm64.release.yml.previous mysql-before.sql web-volume.tar.gz Caddyfile.previous >rollback.sha256 &&
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
      CORE_MODULE_VERSION: $core_version
      CORE_MODULE_BUNDLE_SHA256: $core_bundle_sha
      CORE_MODULE_SHA256: $core_module_sha
  cloud-identity:
    image: candy-cloud-cloud-identity:arm64-$revision
  cloud-auth:
    image: candy-cloud-cloud-auth:arm64-$revision
  cloud-worker:
    image: candy-cloud-cloud-worker:arm64-$revision
    environment:
      CANDY_CORE_VERSION: $core_version
      CORE_MODULE_VERSION: $core_version
      CORE_MODULE_BUNDLE_SHA256: $core_bundle_sha
      CORE_MODULE_SHA256: $core_module_sha
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

# Quiesce every process that can read or mutate control-plane state before
# migrations schedule work for the new release. In particular, an old worker
# must never claim a generation whose catalog is only understood by the new
# worker. MySQL remains online for migration and transactional rollback.
if [ "$deployment_mode" = maintenance ]; then
	canonical_mutated=1
	compose stop reverse-proxy cloud-api cloud-identity cloud-auth cloud-worker cloud-web
	# Capture the final state after every writer has stopped. Restoring the
	# earlier online backup would lose writes accepted during preflight.
	quiesced_database_backup=$transaction_dir/mysql-quiesced.sql
	compose exec -T mysql sh -eu -c '
		case "$MYSQL_DATABASE" in ""|*[!A-Za-z0-9_]*) exit 1 ;; esac
		exec mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --quick --hex-blob --routines --events --databases "$MYSQL_DATABASE"
	' >"$quiesced_database_backup" || fail "could not snapshot the quiesced database"
	grep -F 'Current Database:' "$quiesced_database_backup" >/dev/null || fail "quiesced database backup is incomplete"
	(cd "$transaction_dir" && sha256sum compose.arm64.release.yml.previous mysql-before.sql mysql-quiesced.sql web-volume.tar.gz Caddyfile.previous >rollback.sha256.next && sha256sum -c rollback.sha256.next >/dev/null) || fail "quiesced rollback snapshot validation failed"
	mv "$transaction_dir/rollback.sha256.next" "$rollback_checksums"
	database_backup=$quiesced_database_backup
fi

mv -f "$new_override" "$release_override"
if [ "$deployment_mode" = maintenance ]; then
	migration_started=1
	compose run --rm migrate
fi
# The entrypoint initializes users only when MySQL creates a fresh data
# directory. Reconcile release-required grants after every migration so an
# existing data volume does not depend on its originally mounted init script.
compose exec -T mysql sh -eu -c '
	case "$MYSQL_DATABASE" in ""|*[!A-Za-z0-9_]*) exit 1 ;; esac
	exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "GRANT DELETE ON \`$MYSQL_DATABASE\`.\`runtime_projection_transport_catalog\` TO '\''cloud_auth'\''@'\''%'\''"
'
if [ "$deployment_mode" = rolling ]; then
	rolling_services || fail "rolling service handoff failed"
else
	compose up -d
fi

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
