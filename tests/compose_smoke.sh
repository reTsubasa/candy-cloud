#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$project_dir"

compose_config=$(docker compose --env-file .env.example config)
printf '%s\n' "$compose_config" | awk '
  /^  cloud-worker:$/ { worker = 1; next }
  worker && /^  [[:alnum:]_-]+:$/ { worker = 0 }
  worker && /CANDY_ROUTE_SIGNING_KEY_ID: route-signing-1/ { key_id = 1 }
  worker && /CANDY_ROUTE_SIGNING_KEY_HEX: "?0*1"?$/ { key_hex = 1 }
  END { exit (key_id && key_hex) ? 0 : 1 }
' || {
  echo "cloud-worker route-signing environment is missing from rendered Compose configuration" >&2
  exit 1
}
printf '%s\n' "$compose_config" | awk '
  /^  cloud-worker:$/ { worker = 1; next }
  worker && /^  [[:alnum:]_-]+:$/ { worker = 0 }
  worker && /target: runtime-core/ { target = 1 }
  worker && /CORE_MODULE_VERSION: 0.3.10/ { version = 1 }
  worker && /CORE_MODULE_TARGET: x86_64-unknown-linux-gnu/ { architecture = 1 }
  worker && /CORE_MODULE_BUNDLE_URL:/ { url = 1 }
  worker && /CORE_MODULE_BUNDLE_SHA256: b41806ff17359a9ec8151deb61b206403ec01b14aaffd8f7d456111ab0cc042d/ { bundle = 1 }
  worker && /CORE_MODULE_SHA256: 54c1e6a1f61ef0b28208d5dec13ce7b1351922478987b5eac3ac9a06f183c478/ { module = 1 }
  END { exit (target && version && architecture && !url && bundle && module) ? 0 : 1 }
' || {
  echo "cloud-worker verified Core module build contract is missing" >&2
  exit 1
}

grep -F 'core_release_tag="core-v${CORE_MODULE_VERSION}"' \
  docker/rust-service.Dockerfile >/dev/null || {
  echo "new Core modules are not pinned to the unified Core release tag" >&2
  exit 1
}
grep -F 'core_module_asset="candy-core-${CORE_MODULE_VERSION}-cloud-abi-${CORE_MODULE_TARGET}.tar.gz"' \
  docker/rust-service.Dockerfile >/dev/null || {
  echo "new Core modules do not use the unified Cloud ABI asset name" >&2
  exit 1
}
if grep -F 'core_release_tag="core-cloud-module-v${CORE_MODULE_VERSION}"' \
  docker/rust-service.Dockerfile >/dev/null; then
  echo "Docker build still defaults to the retired standalone Core module release" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker daemon is not running"
  exit 0
fi

project_name="candy-cloud-smoke-$$"
export CANDY_CLOUD_MYSQL_VOLUME="${project_name}_candy-cloud-mysql-data"
export CANDY_CLOUD_WEB_VOLUME="${project_name}_candy-cloud-web-assets"
compose() { docker compose --project-name "$project_name" --env-file .env.example "$@"; }
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if test "$status" -ne 0; then
    compose ps -a >&2 || :
    compose logs --no-color mysql migrate cloud-worker >&2 || :
  fi
  compose down --volumes || :
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
compose up -d --build cloud-worker

mysql_id=$(compose ps -q mysql)
worker_id=$(compose ps -q cloud-worker)
migrate_id=$(compose ps -aq migrate)
test -n "$mysql_id"
test -n "$worker_id"
test -n "$migrate_id"
test "$(docker inspect --format '{{.State.ExitCode}}' "$migrate_id")" = 0

health=''
for _ in $(seq 1 90); do
  health=$(docker inspect --format '{{.State.Health.Status}}' "$worker_id")
  case "$health" in
    healthy) break ;;
    unhealthy)
      docker logs "$worker_id" >&2
      exit 1
      ;;
  esac
  if test "$(docker inspect --format '{{.State.Running}}' "$worker_id")" != true; then
    docker logs "$worker_id" >&2
    exit 1
  fi
  sleep 1
done
test "$health" = healthy
test "$(docker inspect --format '{{.RestartCount}}' "$worker_id")" = 0
worker_image=$(docker inspect --format '{{.Image}}' "$worker_id")
test "$(docker image inspect --format '{{.Architecture}}' "$worker_image")" = amd64
module_path=/opt/candy/cores/0.3.10/libcandy_core_cloud.so
test "$(docker exec "$worker_id" sha256sum "$module_path" | awk '{print $1}')" = \
  54c1e6a1f61ef0b28208d5dec13ce7b1351922478987b5eac3ac9a06f183c478
manifest_path=/opt/candy/cores/0.3.10/manifest.json
manifest=$(docker exec "$worker_id" sed -e ':a' -e 'N' -e '$!ba' -e 's/[[:space:]]//g' "$manifest_path")
printf '%s\n' "$manifest" | grep -F '"release_kind":"candy-core"' >/dev/null
printf '%s\n' "$manifest" | grep -F '"commit":"a2ace9cb524dc5fcc2e01481ba9d515588a61936"' >/dev/null
printf '%s\n' "$manifest" | grep -F '"target":"x86_64-unknown-linux-gnu"' >/dev/null
printf '%s\n' "$manifest" | grep -F '"target_arch":"x86_64"' >/dev/null
printf '%s\n' "$manifest" | grep -F '"libc":"glibc"' >/dev/null
worker_logs=$(docker logs "$worker_id" 2>&1)
printf '%s\n' "$worker_logs" | grep -F '"event":"core_module_ready"' >/dev/null
printf '%s\n' "$worker_logs" | grep -F '"module_version":"0.3.10"' >/dev/null
docker volume inspect "${project_name}_candy-cloud-mysql-data" >/dev/null
