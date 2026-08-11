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
