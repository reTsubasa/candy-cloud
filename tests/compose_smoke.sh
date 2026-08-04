#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$project_dir"

docker compose --env-file .env.example config >/dev/null

if ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker daemon is not running"
  exit 0
fi

docker compose --env-file .env.example up -d mysql
cleanup() { docker compose --env-file .env.example down; }
trap cleanup EXIT INT TERM

container_id=$(docker compose --env-file .env.example ps -q mysql)
test -n "$container_id"
health=''
for _ in $(seq 1 60); do
  health=$(docker inspect --format '{{.State.Health.Status}}' "$container_id")
  case "$health" in
    healthy) break ;;
    unhealthy)
      docker logs "$container_id" >&2
      exit 1
      ;;
  esac
  sleep 1
done
test "$health" = healthy
docker volume inspect candy-cloud_candy-cloud-mysql-data >/dev/null
