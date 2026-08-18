#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

for command in curl docker jq openssl python3; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "compose_saas_identity_e2e: missing required command: $command" >&2
    exit 1
  }
done
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker daemon is not running"
  exit 0
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/candy-cloud-saas-e2e.XXXXXX")
chmod 0755 "$work"
secrets="$work/secrets"
mkdir -m 0700 "$secrets"
project="candy-cloud-saas-e2e-$$"
export COMPOSE_PARALLEL_LIMIT=${COMPOSE_PARALLEL_LIMIT:-2}
export CANDY_CLOUD_MYSQL_VOLUME="${project}_candy-cloud-mysql-data"
export CANDY_CLOUD_WEB_VOLUME="${project}_candy-cloud-web-assets"
available_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
https_port=${CANDY_CLOUD_E2E_HTTPS_PORT:-$(available_port)}
webhook_port=${CANDY_CLOUD_E2E_WEBHOOK_PORT:-$(available_port)}
webhook_authorization="Bearer candy-e2e-$$"
webhook_pid=''

compose() {
  docker compose --project-name "$project" --env-file "$work/e2e.env" \
    -f docker-compose.yml -f "$work/compose.override.yml" "$@"
}
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if test "$status" -ne 0; then
    compose ps -a >&2 || :
    compose logs --no-color reverse-proxy cloud-api cloud-identity cloud-auth migrate mysql >&2 || :
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || :
  if test -n "$webhook_pid"; then
    kill "$webhook_pid" >/dev/null 2>&1 || :
    wait "$webhook_pid" 2>/dev/null || :
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

openssl genpkey -algorithm ED25519 -out "$secrets/cloud-api-auth-private.pem" >/dev/null 2>&1
openssl pkey -in "$secrets/cloud-api-auth-private.pem" -pubout \
  -out "$secrets/cloud-api-auth-public.pem" >/dev/null 2>&1
openssl rand 32 > "$secrets/cloud-signing.key"
chmod 0400 "$secrets/cloud-api-auth-private.pem" "$secrets/cloud-api-auth-public.pem" \
  "$secrets/cloud-signing.key"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=Candy E2E Device CA' \
  -keyout "$secrets/device-ca.key" -out "$secrets/device-ca.pem" >/dev/null 2>&1
chmod 0400 "$secrets/device-ca.key"
chmod 0444 "$secrets/device-ca.pem"

cat > "$work/device-client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:candy:device:00000000-0000-0000-0000-000000000010,URI:candy:device-key:00000000-0000-0000-0000-000000000011,URI:candy:environment:e2e,URI:candy:assurance:A1
EOF
openssl req -newkey rsa:2048 -nodes -subj '/CN=Candy E2E Device' \
  -keyout "$work/device-client.key" -out "$work/device-client.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$work/device-client.csr" \
  -CA "$secrets/device-ca.pem" -CAkey "$secrets/device-ca.key" -CAcreateserial \
  -extfile "$work/device-client.ext" -out "$work/device-client.pem" >/dev/null 2>&1

cat > "$work/tls.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1
EOF
openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "$secrets/cloud-tls.key" -out "$work/cloud-tls.csr" >/dev/null 2>&1
openssl x509 -req -days 2 -sha256 -in "$work/cloud-tls.csr" \
  -signkey "$secrets/cloud-tls.key" -extfile "$work/tls.ext" \
  -out "$secrets/cloud-tls.pem" >/dev/null 2>&1
chmod 0400 "$secrets/cloud-tls.key"
chmod 0444 "$secrets/cloud-tls.pem"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=Candy E2E Webhook CA' \
  -keyout "$work/webhook-ca.key" -out "$work/webhook-ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=host.docker.internal' \
  -keyout "$work/webhook.key" -out "$work/webhook.csr" >/dev/null 2>&1
openssl x509 -req -days 2 -sha256 -in "$work/webhook.csr" \
  -CA "$work/webhook-ca.pem" -CAkey "$work/webhook-ca.key" -CAcreateserial \
  -extfile "$work/tls.ext" -out "$work/webhook.pem" >/dev/null 2>&1
cat /etc/ssl/cert.pem "$work/webhook-ca.pem" > "$work/identity-ca-bundle.pem"
chmod 0444 "$work/identity-ca-bundle.pem"

python3 tests/https_webhook.py --port "$webhook_port" \
  --cert "$work/webhook.pem" --key "$work/webhook.key" \
  --authorization "$webhook_authorization" &
webhook_pid=$!
for _ in $(seq 1 30); do
  curl --silent --fail --cacert "$work/webhook-ca.pem" \
    "https://localhost:$webhook_port/health" >/dev/null && break
  sleep 1
done
curl --silent --fail --cacert "$work/webhook-ca.pem" \
  "https://localhost:$webhook_port/health" >/dev/null

cat > "$work/e2e.env" <<EOF
MYSQL_DATABASE=candy_cloud_e2e
MYSQL_ROOT_PASSWORD=e2e-root-password
MYSQL_MIGRATOR_PASSWORD=e2e-migrator-password
MYSQL_API_PASSWORD=e2e-api-password
MYSQL_IDENTITY_PASSWORD=e2e-identity-password
MYSQL_AUTH_PASSWORD=e2e-auth-password
MYSQL_WORKER_PASSWORD=e2e-worker-password
CANDY_ROUTE_SIGNING_KEY_ID=e2e-route
CANDY_ROUTE_SIGNING_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000001
CORE_MODULE_VERSION=0.3.12
CORE_MODULE_BUNDLE_SHA256=619aaf91b727cc5db5992ef0dd20f0c646c7ac2a9846b6252cf8eb692e664a32
CORE_MODULE_SHA256=892d8ac2432af15609b33da8b616ddcc7e1c47821e3d5fbad5941342caef37ec
CLOUD_SIGNING_KEY_FILE=$secrets/cloud-signing.key
CLOUD_SIGNING_KEY_ID=e2e-grant
CLOUD_ISSUER_ID=00000000-0000-0000-0000-000000000001
CLOUD_ENVIRONMENT_ID=00000000-0000-0000-0000-000000000002
CLOUD_DEVICE_CA_CERT_FILE=$secrets/device-ca.pem
CLOUD_DEVICE_CA_KEY_FILE=$secrets/device-ca.key
CLOUD_DEVICE_CA_KEY_ID=e2e-device-ca
CLOUD_ENVIRONMENT=e2e
CLOUD_API_AUTH_PUBLIC_KEY_FILE=$secrets/cloud-api-auth-public.pem
CLOUD_IDENTITY_SIGNING_KEY_FILE=$secrets/cloud-api-auth-private.pem
CLOUD_IDENTITY_VERIFICATION_KEY_FILE=$secrets/cloud-api-auth-public.pem
CLOUD_IDENTITY_SIGNING_KEY_ID=e2e-management
CLOUD_API_AUTH_ISSUER=https://localhost:$https_port/identity
CLOUD_API_AUTH_AUDIENCE=candy-cloud-management
CLOUD_IDENTITY_ACCESS_TTL_SECONDS=900
CLOUD_IDENTITY_REFRESH_TTL_SECONDS=2592000
CLOUD_IDENTITY_VERIFICATION_TTL_SECONDS=86400
CLOUD_IDENTITY_RESET_TTL_SECONDS=900
CLOUD_IDENTITY_EMAIL_WEBHOOK_URL=https://host.docker.internal:$webhook_port/candy-identity
CLOUD_IDENTITY_EMAIL_WEBHOOK_AUTHORIZATION=$webhook_authorization
CLOUD_TLS_CERTIFICATE_FILE=$secrets/cloud-tls.pem
CLOUD_TLS_KEY_FILE=$secrets/cloud-tls.key
CLOUD_HTTPS_PORT=$https_port
EOF
cat > "$work/compose.override.yml" <<EOF
services:
  migrate:
    image: candy-cloud-saas-e2e-migrate:local
  cloud-api:
    image: candy-cloud-saas-e2e-cloud-api:local
  cloud-identity:
    image: candy-cloud-saas-e2e-cloud-identity:local
    environment:
      SSL_CERT_FILE: /run/test-secrets/identity-ca-bundle.pem
    volumes:
      - $work:/run/test-secrets:ro
  reverse-proxy:
    image: caddy:2.9-alpine
    ports: !override
      - "$https_port:443/tcp"
  cloud-auth:
    image: candy-cloud-saas-e2e-cloud-auth:local
  cloud-web:
    image: candy-cloud-saas-e2e-cloud-web:local
EOF

# Compose Bake may compile every Rust service concurrently and exhaust a
# developer workstation. Build explicitly in dependency order, then start the
# exact same images without allowing Compose to trigger a parallel rebuild.
if test "${CANDY_CLOUD_E2E_SKIP_BUILD:-0}" != 1; then
  for service in cloud-web migrate cloud-api cloud-identity cloud-auth; do
    compose build "$service"
  done
fi
compose up -d --no-build reverse-proxy

published_endpoint=$(compose port reverse-proxy 443)
test -n "$published_endpoint" || {
  echo "compose_saas_identity_e2e: reverse-proxy port 443 was not published" >&2
  exit 1
}
published_port=${published_endpoint##*:}
test "$published_port" = "$https_port" || {
  echo "compose_saas_identity_e2e: expected HTTPS port $https_port, got $published_endpoint" >&2
  exit 1
}
base="https://localhost:$published_port"
for _ in $(seq 1 120); do
  curl --silent --fail --cacert "$secrets/cloud-tls.pem" "$base/identity/health/ready" >/dev/null && break
  sleep 1
done
curl --silent --fail --cacert "$secrets/cloud-tls.pem" "$base/identity/health/ready" >/dev/null
curl --silent --fail --cacert "$secrets/cloud-tls.pem" "$base/api/health/ready" >/dev/null

headers="$work/headers"
body="$work/body"
request() {
  method=$1
  path=$2
  data=${3:-}
  shift 3 || true
  : > "$headers"
  : > "$body"
  if test -n "$data"; then
    curl --silent --show-error --cacert "$secrets/cloud-tls.pem" \
      -D "$headers" -o "$body" -X "$method" -H 'Content-Type: application/json' \
      "$@" --data "$data" "$base$path" || true
  else
    curl --silent --show-error --cacert "$secrets/cloud-tls.pem" \
      -D "$headers" -o "$body" -X "$method" "$@" "$base$path" || true
  fi
  awk '/^HTTP\// { status = $2 } END { print status }' "$headers"
}
expect_status() {
  actual=$1
  expected=$2
  test "$actual" = "$expected" || {
    echo "expected HTTP $expected, got $actual: $(cat "$body")" >&2
    exit 1
  }
}

email="owner-$$@example.test"
password='Candy-E2E-password-2026'
registration=$(jq -nc --arg email "$email" --arg password "$password" \
  '{email:$email,password:$password,display_name:"E2E Owner",organization_name:"E2E Workspace"}')
expect_status "$(request POST /identity/v1/auth/register "$registration")" 202
jq -e '.message == "verification_required"' "$body" >/dev/null

login=$(jq -nc --arg email "$email" --arg password "$password" \
  '{email:$email,password:$password,device_label:"before-verification"}')
expect_status "$(request POST /identity/v1/auth/login "$login")" 401
jq -e '.code == "invalid_credentials"' "$body" >/dev/null

for _ in $(seq 1 30); do
  messages=$(curl --silent --fail --cacert "$work/webhook-ca.pem" \
    "https://localhost:$webhook_port/messages")
  token=$(printf '%s' "$messages" | jq -r --arg email "$email" \
    '[.[] | select(.recipient == $email and .purpose == "verify_email")][-1].token // empty')
  test -n "$token" && break
  sleep 1
done
test -n "${token:-}"
verify=$(jq -nc --arg token "$token" '{token:$token}')
expect_status "$(request POST /identity/v1/auth/verify-email "$verify")" 200
verified_session=$(cat "$body")
access=$(printf '%s' "$verified_session" | jq -er .access_token)
refresh=$(printf '%s' "$verified_session" | jq -er .refresh_token)
tenant=$(printf '%s' "$verified_session" | jq -er .membership.tenant_id)

expect_status "$(request GET "/api/v1/tenants/$tenant/sites" '' \
  -H "Authorization: Bearer $access")" 200
jq -e '.schema_version == 1 and (.items | type == "array")' "$body" >/dev/null

expect_status "$(request GET "/api/v1/tenants/$tenant/sites" '' \
  --cert "$work/device-client.pem" --key "$work/device-client.key")" 401
expect_status "$(request GET /auth/v1/runtime/capabilities '')" 401
expect_status "$(request GET /auth/v1/runtime/capabilities '' \
  -H 'X-Candy-Verified-Device-Certificate-Der: forged')" 401
expect_status "$(request GET /auth/v1/runtime/capabilities '' \
  --cert "$work/device-client.pem" --key "$work/device-client.key")" 401

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=untrusted-client' \
  -keyout "$work/untrusted-client.key" -out "$work/untrusted-client.pem" >/dev/null 2>&1
untrusted_code=$(curl --silent --cacert "$secrets/cloud-tls.pem" \
  --cert "$work/untrusted-client.pem" --key "$work/untrusted-client.key" \
  -o "$body" -w '%{http_code}' "$base/auth/v1/runtime/capabilities" || true)
test "$untrusted_code" = 000 || test "$untrusted_code" = 400 || test "$untrusted_code" = 403

refresh_body=$(jq -nc --arg token "$refresh" '{refresh_token:$token}')
expect_status "$(request POST /identity/v1/auth/refresh "$refresh_body")" 200
rotated=$(cat "$body")
rotated_access=$(printf '%s' "$rotated" | jq -er .access_token)
rotated_refresh=$(printf '%s' "$rotated" | jq -er .refresh_token)
test "$rotated_refresh" != "$refresh"

expect_status "$(request POST /identity/v1/auth/refresh "$refresh_body")" 401
jq -e '.code == "invalid_credentials"' "$body" >/dev/null
rotated_refresh_body=$(jq -nc --arg token "$rotated_refresh" '{refresh_token:$token}')
expect_status "$(request POST /identity/v1/auth/refresh "$rotated_refresh_body")" 401

expect_status "$(request POST /identity/v1/auth/login "$login")" 200
login_session=$(cat "$body")
login_access=$(printf '%s' "$login_session" | jq -er .access_token)
login_refresh=$(printf '%s' "$login_session" | jq -er .refresh_token)
expect_status "$(request GET /identity/v1/auth/sessions '' \
  -H "Authorization: Bearer $login_access")" 200
expect_status "$(request POST /identity/v1/auth/logout '{}' \
  -H "Authorization: Bearer $login_access")" 200
jq -e '.message == "signed_out"' "$body" >/dev/null
expect_status "$(request GET /identity/v1/auth/sessions '' \
  -H "Authorization: Bearer $login_access")" 401
expect_status "$(request GET "/api/v1/tenants/$tenant/sites" '' \
  -H "Authorization: Bearer $login_access")" 401
logout_refresh=$(jq -nc --arg token "$login_refresh" '{refresh_token:$token}')
expect_status "$(request POST /identity/v1/auth/refresh "$logout_refresh")" 401

unknown_email="unknown-$$@example.test"
unknown_login=$(jq -nc --arg email "$unknown_email" --arg password "$password" \
  '{email:$email,password:$password,device_label:"enumeration-check"}')
for _ in $(seq 1 5); do
  expect_status "$(request POST /identity/v1/auth/login "$unknown_login")" 401
  jq -e '.code == "invalid_credentials"' "$body" >/dev/null
done
expect_status "$(request POST /identity/v1/auth/login "$unknown_login")" 429
jq -e '.code == "rate_limited"' "$body" >/dev/null
retry_after=$(awk 'tolower($1) == "retry-after:" { gsub("\r", "", $2); print $2 }' "$headers")
test -n "$retry_after" && test "$retry_after" -ge 1 && test "$retry_after" -le 900

audit_count=$(compose exec -T mysql mysql -N -B \
  -uroot -pe2e-root-password candy_cloud_e2e \
  -e "SELECT COUNT(*) FROM audit_events WHERE action = 'IDENTITY_LOGIN_REJECTED'")
test "$audit_count" -ge 5

web_headers=$(curl --silent --show-error --cacert "$secrets/cloud-tls.pem" -D - -o /dev/null "$base/")
printf '%s' "$web_headers" | grep -i '^strict-transport-security: max-age=31536000; includeSubDomains' >/dev/null
printf '%s' "$web_headers" | grep -i '^content-security-policy:' >/dev/null
if printf '%s' "$web_headers" | grep -i '^server:' >/dev/null; then
  echo "reverse proxy exposed the Server header" >&2
  exit 1
fi

echo "Candy Cloud SaaS identity Compose E2E passed"
