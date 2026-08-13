#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

for command in curl docker jq openssl python3; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "SKIP: demo_compose_e2e requires $command"
    exit 0
  }
done
docker info >/dev/null 2>&1 || {
  echo 'SKIP: Docker daemon is not running'
  exit 0
}

work=$(mktemp -d "${TMPDIR:-/tmp}/candy-cloud-demo-e2e.XXXXXX")
project="candy-cloud-demo-e2e-$$"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
cleanup() {
  status=$?
  trap - EXIT INT TERM
  CANDY_CLOUD_DEMO_STATE_DIR="$work/state" CANDY_CLOUD_DEMO_PROJECT="$project" \
    CLOUD_DEMO_PORT="$port" bin/candy-cloud-demo down >/dev/null 2>&1 || :
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT INT TERM

CANDY_CLOUD_DEMO_STATE_DIR="$work/state" CANDY_CLOUD_DEMO_PROJECT="$project" \
  CLOUD_DEMO_PORT="$port" bin/candy-cloud-demo up >/dev/null

base="http://localhost:$port"
curl --silent --fail "$base/" | grep -F '<div id="root"></div>' >/dev/null
test "$(curl --silent --fail "$base/identity/health/ready")" = ready
test "$(curl --silent --fail "$base/api/health/ready")" = ready

login=$(curl --silent --fail -H 'Content-Type: application/json' \
  --data '{"email":"demo-owner@candy.local","password":"Candy-Demo-2026!","device_label":"Demo Compose E2E"}' \
  "$base/identity/v1/auth/login")
printf '%s' "$login" | jq -e '
  .token_type == "Bearer" and
  (.access_token | length > 0) and
  (.refresh_token | length > 0) and
  .membership.organization_name == "Candy Demo" and
  .membership.role == "ORGANIZATION_OWNER"
' >/dev/null

echo 'demo_compose_e2e: ok'
