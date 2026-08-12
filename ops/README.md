# Candy Cloud Compose Operations

Candy Cloud uses one Compose project with an independent MySQL instance. MySQL is not published to the host network; only `reverse-proxy` publishes ports.

The Phase 1 SQLx build uses the private Compose network without database TLS. Before moving MySQL outside that network or to a managed service, enable a SQLx TLS backend and require certificate verification; external plaintext database connections are not supported.

## Bootstrap

```bash
cp .env.example .env
mkdir -p secrets backups
openssl rand 32 > secrets/cloud-signing.key
chmod 600 .env secrets/cloud-signing.key
docker compose up -d mysql
docker compose --profile ops run --rm migrate
docker compose up -d
```

The migration job uses `cloud_migrator`. Application services use separate least-privilege accounts and never run migrations during startup.

## Backup and restore check

```bash
./docker/backup.sh
BACKUP_FILE=./backups/candy-cloud-YYYYMMDDTHHMMSSZ.sql ./docker/restore-smoke.sh
```

Backups and signing keys must remain mode `0600`. MySQL data and backup files use separate storage locations.

## SaaS identity release gate

Run `tests/compose_saas_identity_e2e.sh` before an identity or reverse-proxy
release. The gate creates disposable Ed25519 identity keys, Grant key material,
TLS certificates and a Device CA, then exercises registration, verified-email
session issuance, login, refresh rotation/reuse detection, management API
authorization and logout against the real Compose MySQL deployment. It also
asserts that management JWT and device mTLS credentials cannot cross API
boundaries. All generated credentials and the database volume are deleted when
the test exits.

The production transactional-email webhook must use HTTPS. Private or
enterprise webhook CAs belong in the operating-system trust store used by
`cloud-identity`; do not disable certificate verification.

## Failure behavior

When MySQL is unavailable, new writes and Grant issuance fail closed. Existing unexpired Grants remain locally verifiable by Candy Cloud Server and the customer data plane does not depend on this Compose stack.

## Kubernetes boundary

Do not add Kubernetes until multi-node high availability, cross-region placement, automatic scaling, or Compose operations become a demonstrated bottleneck. Services must remain stateless and workers must use database leases so deployment can migrate without changing API or Grant contracts.
