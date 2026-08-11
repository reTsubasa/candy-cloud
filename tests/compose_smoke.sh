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
  worker && /CORE_MODULE_BUNDLE_URL:/ { url = 1 }
  worker && /CORE_MODULE_BUNDLE_SHA256: 891fc81bbd258a364d138788660214a05d8819df0c896cd8a61d971bfed0564c/ { bundle = 1 }
  worker && /CORE_MODULE_SHA256: 54c1e6a1f61ef0b28208d5dec13ce7b1351922478987b5eac3ac9a06f183c478/ { module = 1 }
  END { exit (target && version && !url && bundle && module) ? 0 : 1 }
' || {
  echo "cloud-worker verified Core module build contract is missing" >&2
  exit 1
}

grep -F 'https://github.com/reTsubasa/candy-release/releases/download/core-cloud-module-v${CORE_MODULE_VERSION}/candy-core-cloud-module-${CORE_MODULE_VERSION}-${CORE_MODULE_TARGET}.tar.gz' \
  docker/rust-service.Dockerfile >/dev/null || {
  echo "Core module source is not pinned to the formal candy-release asset path" >&2
  exit 1
}

if ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker daemon is not running"
  exit 0
fi

project_name="candy-cloud-smoke-$$"
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
docker volume inspect "${project_name}_candy-cloud-mysql-data" >/dev/null
