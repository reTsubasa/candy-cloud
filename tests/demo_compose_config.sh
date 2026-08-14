#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

command -v docker >/dev/null 2>&1 || {
	echo "SKIP: docker is unavailable"
	exit 0
}

work=$(mktemp -d "${TMPDIR:-/tmp}/candy-cloud-demo-config.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

for file in cloud-signing.key device-ca.pem device-ca.key cloud-api-auth-public.pem cloud-api-auth-private.pem cloud-tls.pem cloud-tls.key; do
	: > "$work/$file"
done

MYSQL_ROOT_PASSWORD=test \
MYSQL_MIGRATOR_PASSWORD=test \
MYSQL_API_PASSWORD=test \
MYSQL_IDENTITY_PASSWORD=test \
MYSQL_AUTH_PASSWORD=test \
MYSQL_WORKER_PASSWORD=test \
CANDY_ROUTE_SIGNING_KEY_ID=test-route \
CANDY_ROUTE_SIGNING_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000001 \
CORE_MODULE_VERSION=0.3.10 \
CORE_MODULE_BUNDLE_SHA256=b41806ff17359a9ec8151deb61b206403ec01b14aaffd8f7d456111ab0cc042d \
CORE_MODULE_SHA256=54c1e6a1f61ef0b28208d5dec13ce7b1351922478987b5eac3ac9a06f183c478 \
CLOUD_SIGNING_KEY_ID=test-grant \
CLOUD_ISSUER_ID=00000000-0000-0000-0000-000000000001 \
CLOUD_ENVIRONMENT_ID=00000000-0000-0000-0000-000000000002 \
CLOUD_API_AUTH_ISSUER=https://demo.candy.local \
CLOUD_API_AUTH_AUDIENCE=candy-cloud-management \
CLOUD_SIGNING_KEY_FILE="$work/cloud-signing.key" \
CLOUD_DEVICE_CA_CERT_FILE="$work/device-ca.pem" \
CLOUD_DEVICE_CA_KEY_FILE="$work/device-ca.key" \
CLOUD_API_AUTH_PUBLIC_KEY_FILE="$work/cloud-api-auth-public.pem" \
CLOUD_IDENTITY_SIGNING_KEY_FILE="$work/cloud-api-auth-private.pem" \
CLOUD_IDENTITY_VERIFICATION_KEY_FILE="$work/cloud-api-auth-public.pem" \
CLOUD_TLS_CERTIFICATE_FILE="$work/cloud-tls.pem" \
CLOUD_TLS_KEY_FILE="$work/cloud-tls.key" \
docker compose -f docker-compose.yml -f docker-compose.demo.yml config > "$work/rendered.yml"

MYSQL_ROOT_PASSWORD=test \
MYSQL_MIGRATOR_PASSWORD=test \
MYSQL_API_PASSWORD=test \
MYSQL_IDENTITY_PASSWORD=test \
MYSQL_AUTH_PASSWORD=test \
MYSQL_WORKER_PASSWORD=test \
CANDY_ROUTE_SIGNING_KEY_ID=test-route \
CANDY_ROUTE_SIGNING_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000001 \
CORE_MODULE_VERSION=0.3.10 \
CORE_MODULE_BUNDLE_SHA256=b41806ff17359a9ec8151deb61b206403ec01b14aaffd8f7d456111ab0cc042d \
CORE_MODULE_SHA256=54c1e6a1f61ef0b28208d5dec13ce7b1351922478987b5eac3ac9a06f183c478 \
CLOUD_SIGNING_KEY_ID=test-grant \
CLOUD_ISSUER_ID=00000000-0000-0000-0000-000000000001 \
CLOUD_ENVIRONMENT_ID=00000000-0000-0000-0000-000000000002 \
CLOUD_API_AUTH_ISSUER=https://demo.candy.local \
CLOUD_API_AUTH_AUDIENCE=candy-cloud-management \
CLOUD_SIGNING_KEY_FILE="$work/cloud-signing.key" \
CLOUD_DEVICE_CA_CERT_FILE="$work/device-ca.pem" \
CLOUD_DEVICE_CA_KEY_FILE="$work/device-ca.key" \
CLOUD_API_AUTH_PUBLIC_KEY_FILE="$work/cloud-api-auth-public.pem" \
CLOUD_IDENTITY_SIGNING_KEY_FILE="$work/cloud-api-auth-private.pem" \
CLOUD_IDENTITY_VERIFICATION_KEY_FILE="$work/cloud-api-auth-public.pem" \
CLOUD_TLS_CERTIFICATE_FILE="$work/cloud-tls.pem" \
CLOUD_TLS_KEY_FILE="$work/cloud-tls.key" \
CLOUD_DEMO_TLS_PORT=8443 \
docker compose -f docker-compose.yml -f docker-compose.demo.yml -f docker-compose.demo-tls.yml config > "$work/rendered-tls.yml"

grep -F 'CLOUD_IDENTITY_ENVIRONMENT: development' "$work/rendered.yml" >/dev/null
grep -F 'CLOUD_DEV_DEMO_ENABLED: "1"' "$work/rendered.yml" >/dev/null
grep -F 'CLOUD_DEV_DEMO_EMAIL: demo-owner@candy.local' "$work/rendered.yml" >/dev/null
grep -F 'CLOUD_DEV_DEMO_PASSWORD: Candy-Demo-2026!' "$work/rendered.yml" >/dev/null
grep -F 'CLOUD_IDENTITY_EMAIL_WEBHOOK_URL: ""' "$work/rendered.yml" >/dev/null
grep -F 'published: "8088"' "$work/rendered.yml" >/dev/null
grep -F 'published: "8443"' "$work/rendered-tls.yml" >/dev/null
grep -F 'published: "8088"' "$work/rendered-tls.yml" >/dev/null
grep -F 'target: /etc/caddy/Caddyfile' "$work/rendered-tls.yml" >/dev/null

echo 'demo_compose_config: ok'
