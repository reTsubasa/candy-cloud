# Candy Cloud

The authoritative product and CPU support status is maintained in
[`docs/product-platform-matrix.md`](docs/product-platform-matrix.md).

独立的 Candy Cloud 控制面，产品版本 `0.1.0`。控制面负责 AAA、租户、设备、订阅、权益和 Grant 签发，不承载客户数据面流量。

- Candy Core Cloud ABI profile: `0.3.14` from the unified signed release
  `core-v0.3.14`
- wire line: `0.3`
- auth profile: `cloud_grant_v1`
- runtime: Rust + Axum + Tokio + SQLx/MySQL
- deployment: Docker Compose with an independent MySQL instance

产品入口统一使用 Candy Cloud Server / Client / Runtime；Core 中的历史 crate 名称不作为产品名。

## Local checks

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 tests/api_contract.py
(cd web && corepack pnpm install --frozen-lockfile && corepack pnpm run build)
tests/sdwan_route_contract.sh
docker compose config
```

## Management console

The Arco Design React console is served by the reverse proxy at `/`. It has a
first-party Candy Cloud account flow: registration creates an organization and
its first tenant, then Identity issues short-lived EdDSA management access
tokens and rotating opaque refresh credentials. Human account identity and
device mTLS identity are separate trust planes. Browser credentials are held
only in `sessionStorage`, never in `localStorage`.

Set `CLOUD_IDENTITY_SIGNING_KEY_FILE` to a deployment-private Ed25519 PEM and
`CLOUD_IDENTITY_VERIFICATION_KEY_FILE` to its public PEM. The public PEM must
be the exact same key configured as `CLOUD_API_AUTH_PUBLIC_KEY_FILE`; use a
different keypair from the Cloud Grant-signing key. The complete V1 management,
identity, enrollment, Grant, and Runtime synchronization contract is available
in [`docs/openapi-v1.yaml`](docs/openapi-v1.yaml) and
[`docs/api-contract.md`](docs/api-contract.md).

Production also requires `CLOUD_IDENTITY_EMAIL_WEBHOOK_URL`: an HTTPS
transactional-mail adapter that receives the one-time verification or reset
token and constructs the customer-facing link. Its `purpose` field may be
`verify_email`, `reset_password`, or `organization_invitation`. Verification links must target
`https://<cloud-host>/?verify_email=<token>`. The service will not start in
production without it, so account recovery cannot silently degrade.
Production and staging additionally reject placeholder or local identity
issuers. Startup signs and verifies a probe JWT, so mismatched management
signing and verification keys fail before the service becomes ready.

Reset links target `https://<cloud-host>/?reset_password=<token>`. Organization
invitation links target `https://<cloud-host>/?accept_invitation=<token>`; the
recipient must sign in with the invited email before accepting, which prevents
an invitation from taking over a different account identity.

For a disposable development environment, an already-verified owner account
can be bootstrapped through the normal account, organization, tenant, and RBAC
tables:

```bash
CLOUD_ENVIRONMENT=development
CLOUD_DEV_DEMO_ENABLED=1
CLOUD_DEV_DEMO_EMAIL=demo-owner@candy.local
CLOUD_DEV_DEMO_PASSWORD='inject-a-local-password-of-at-least-12-bytes'
```

The bootstrap is idempotent and refreshes the injected password while revoking
old sessions on restart. The email defaults to `demo-owner@candy.local`; the
password has no default and is never written to the image or logs. Enabling the
bootstrap in production, staging, or E2E makes `cloud-identity` refuse to start.

The repository also includes an explicit Demo Compose overlay with a built-in
workspace and login:

```text
Organization: Candy Demo
Email:        demo-owner@candy.local
Password:     Candy-Demo-2026!
```

Start the complete isolated Demo stack with one command:

```bash
bin/candy-cloud-demo up
```

The fixed credential exists only in that Demo overlay. The production Compose
file has no default Demo password, and Identity refuses the overlay unless its
environment is exactly `development`. The command creates deployment-local
keys and random database passwords under the ignored
`.candy-cloud-demo.local/` directory, uses the dedicated `candy-cloud-demo`
Compose project, and serves the console at `http://localhost:8088`. Use
`bin/candy-cloud-demo web` rebuilds and activates only the current Web source,
without rebuilding Rust services. Use `status`, `logs`, or `down` to inspect or
stop the stack. `reset` also removes the Demo database volume.

For local UI development:

```bash
cd web
corepack pnpm install --frozen-lockfile
corepack pnpm run dev
```

## SD-WAN signed control

`cloud-worker` compiles one immutable Segment topology into one signed
`SegmentRouteSnapshotV1` and every device-specific `SiteRouteProjectionV1`.
The complete publication is committed in one MySQL transaction. TUN Grants use
the `private.tun.connect` permission and bind the exact projection id,
generation, and content hash; ordinary `private.connect` Grants retain their
existing bytes and carry no route policy.

Route-signing and Grant-signing keys are separate. Private key bytes are loaded
only by their owning service and are never stored in route tables, audit rows,
logs, or API responses.

## Repository layout

`crates/` and `tests/` contain the Cloud SD-WAN control-plane publication,
validation, and Core interoperability implementation. The OpenWrt delivery
slice is kept under [`openwrt-sdwan/`](openwrt-sdwan/); it contains the package,
procd, LuCI, and focused productization checks without copying the Core
protocol implementation.

The project is pinned to the signed Candy Core Cloud ABI profile `0.3.14` from
the unified `core-v0.3.14` release (source revision
`d49ebed945c2d3b4f2701148dc126e556bb04620`) and wire line `0.3`.
Cloud never checks out or compiles the private Core repository. Service images
load the signed, versioned `libcandy_core_cloud.so` module only from the formal
`candy-release` `core-v<version>` release. Cloud ABI profiles do not form a
separate Core product line.

The supported production Cloud bundle is native Linux x86-64. A native ARM64
workflow is retained for the aarch64 control-plane target and consumes the
same signed `core-v0.3.14` Cloud ABI release. It runs automatically for
relevant changes on `main` and can also be started manually; it never checks
out or builds the private Core repository and cannot publish a Cloud bundle
containing a standalone Core artifact.

After that central release exists, an immutable ARM64 bundle can be deployed
from a prepared directory containing `compose.arm64.yml`, `deploy.env`, and
`secrets/`:

```bash
sudo scripts/deploy-arm64-release.sh \
  --tag cloud-arm64-<source-revision> \
  --deployment-dir /opt/candy-cloud
```

The script verifies the checksum and manifest, checks all six images are ARM64,
applies least-privilege secret ownership for the container UID, runs migrations,
starts Compose, and waits for every application health check. The installer
accepts only the signed `release_kind=candy-core` shared-library manifest from
the central `candy-release` repository. Historical standalone Core-module
releases are not compatibility inputs and are never consumed. IPv6 remains
outside this delivery; Mesh precedes dynamic routing in the expansion sequence.
