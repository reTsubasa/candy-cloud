# Candy Cloud V1 API and Runtime Integration Contract

The normative HTTP description is [`openapi-v1.yaml`](openapi-v1.yaml). This
guide explains the lifecycle, trust boundaries, retry rules, and fail-open or
fail-closed decisions that are difficult to express in OpenAPI alone.

Candy Cloud `0.1.x` exposes versioned APIs under `/v1`. The version identifies
the HTTP and JSON contract; Core-signed objects retain their own wire line and
object version. A normal Candy data-plane connection does not call Cloud.

## Deployment paths

The reference reverse proxy exposes three path prefixes and strips them before
forwarding:

| Public path | Internal service | Identity |
| --- | --- | --- |
| `/api/v1/tenants/...` | `cloud-api:8080/v1/tenants/...` | EdDSA management bearer JWT |
| `/identity/v1/auth/...` | `cloud-identity:8082/v1/auth/...` | Candy Cloud human account identity |
| `/auth/v1/enrollment/...` | `cloud-auth:8081/v1/enrollment/...` | single-use node join code, then key proof |
| `/auth/v1/access-grants` | `cloud-auth:8081/v1/access-grants` | Candy Device CA mTLS |
| `/auth/v1/runtime/...` | `cloud-auth:8081/v1/runtime/...` | Candy Device CA mTLS |

Health routes exist on both services. Use `/api/health/ready` for management
readiness, `/identity/health/ready` for human identity, and `/auth/health/ready`
for enrollment, Grant, and Runtime delivery.

## Identity and security boundaries

- Every tenant belongs to one organization and every device belongs to one
  tenant. Cross-tenant access is denied before storage is touched.
- Management JWTs are EdDSA tokens with configured issuer and audience. They
  must contain bounded `sub`, `organization_id`, `tenant_id`, `role`, `exp`,
  `nbf`, `iat`, and `jti` claims.
- Runtime identity is never accepted from JSON, query parameters, or a public
  HTTP header. Caddy requests a client certificate, validates it against the
  Candy Device CA, removes any caller-supplied verified-certificate header, and
  forwards only the certificate it observed on the TLS connection.
- Human registration atomically creates the user, organization, first tenant,
  and `ORGANIZATION_OWNER` membership. Passwords are Argon2id hashes. Access
  tokens expire in at most one hour; refresh credentials are random opaque
  values stored only as SHA-256 digests, rotate once per use, and revoke the
  whole session family on reuse. A disabled user, changed or removed membership,
  or revoked session is denied immediately by both Identity and Cloud API; both
  services validate the active session and current membership against storage.
- Roles are `ORGANIZATION_OWNER`, `TENANT_ADMIN`, `OPERATOR`,
  `BILLING_VIEWER`, and `AUDITOR`. Cloud API derives authorization from the
  signed tenant context; the Web client never supplies a role or tenant scope.
- Human API endpoints are available at `/identity/v1/auth/...`. Registration
  accepts email, an at-least-12-character password, display name, and
  organization name, and returns `202 verification_required`. A verification
  email is dispatched in the same request; delivery failure removes the
  pending account/workspace and returns `503`, so no unusable registration is
  retained. `POST /verify-email` consumes that one-time credential and returns
  the first short-lived access token plus a rotating opaque refresh credential;
  subsequent sessions use login. The `/request-email-verification`,
  `/request-password-reset`, and `/reset-password` endpoints provide the
  recovery path; reset revokes every session. `POST /logout`, `GET /sessions`,
  and `DELETE /sessions/{id}` require a bearer token and perform immediate
  session checks.
- Organization membership is server-authorized. Owners may invite members,
  change non-owner roles, suspend or remove members, and transfer ownership.
  Tenant administrators and auditors may list membership; all other member
  management operations default to denied. Invitation credentials are opaque,
  single-use values stored only as SHA-256 digests. Role, status, removal, and
  ownership changes revoke affected sessions in the same database transaction.
  Accounts can list their organization memberships and switch context by
  rotating into a new session scoped to the selected membership.
- Production requires `CLOUD_IDENTITY_EMAIL_WEBHOOK_URL` using HTTPS. Its
  optional authorization header is supplied by
  `CLOUD_IDENTITY_EMAIL_WEBHOOK_AUTHORIZATION`. The webhook payload contains
  only `purpose`, `recipient`, and an opaque single-use token; neither the
  service nor its logs store that token. The verification link returns to the
  Web root with `?verify_email=<token>`; Web consumes it through the same-origin
  Identity API and removes it from browser history. In a non-production environment,
  delivery remains deliberately unavailable unless an explicit delivery
  implementation is injected for tests.
- Enrollment is intentionally public. The 32-byte node join code owns
  organization and tenant scope. Body-supplied scope is rejected by strict JSON
  decoding.
- Signing private keys, complete Grant envelopes, certificate proofs, Runtime
  configuration bytes, and access tokens must not be logged. Runtime status
  reports may log bounded identifiers, generation, state, and redacted error code.

## Management resources

The same CRUD paths operate on these fixed V1 collections:

```text
nodes sites segments attachments prefixes peers relays path-candidates
egresses service-policies dns-intents
```

The collection and the body `resource.kind` must match. The request body does
not contain metadata; Cloud owns resource id, tenant, revision, and state.

All writes require `Idempotency-Key` with 1-160 bytes. An exact replay within
24 hours returns the original resource and `replayed: true`. Reusing a key with
a different actor, method, path, or document returns `409`.

`PUT` and `DELETE` also require `If-Match` with the current numeric revision,
for example `If-Match: "7"`. Weak ETags are rejected. A stale revision returns
`412`; omitting the precondition returns `428`. The current server accepts this
revision contract but does not yet emit the matching management `ETag` response
header. Until that implementation lands, clients must read
`metadata.revision` and construct the quoted numeric `If-Match` value. This gap
does not apply to Runtime configuration ETags.

Before deletion, clients may call
`GET /api/v1/tenants/{tenant_id}/{collection}/{id}/references`. It returns the
active resources that directly reference the target. If a reference is added
after that check, `DELETE` still fails atomically with
`RESOURCE_REFERENCE_CONFLICT` and returns the current blockers in the same
structured form. Management clients should present those blockers as direct
navigation targets rather than retrying deletion.

Lists use headers rather than query parameters:

```text
X-Page-Size: 1..200, default 50
X-Page-After: non-zero UUID returned in next_cursor
```

## Device enrollment

Management operators create a single-use node join code through
`POST /api/v1/tenants/{tenant_id}/enrollment/activations`. The response contains
the 32-byte URL-safe join code exactly once; Cloud stores only its scoped hash.
The default lifetime is 10 minutes.
`GET` returns status, expiry, reservation, and consumption timestamps without
the secret. `DELETE` revokes an `ACTIVE` or `RESERVED` credential. The Web
console exposes this as **节点加入** and does not claim a node is online until
the device completes the public enrollment exchange below.

To recover an existing node after reinstalling it or losing its local identity,
the management client supplies `replace_node_id` together with the existing
node's exact site, display name, platform, and architecture. Cloud binds the
single-use activation to that control node. Enrollment completion atomically
rotates its device identity, revokes the old certificate and key, preserves all
resource references, and queues new segment projections. A second active or
reserved recovery activation for the same node revokes the previous one.

`DNS_INTENT.site_ids` controls publication inside its `segment_id`: an empty
list publishes to every site attached to the segment, while a non-empty list
publishes only to those attached sites. The legacy optional `site_id` remains
read-compatible, but new clients must write `site_ids` and must not send both.

Runtime creates a root key and operational key locally, then performs:

1. `POST /auth/v1/enrollment/challenges` with the node join code, stable
   request id, installation instance id, device name, public keys, and hashes.
2. Cloud reserves the node join code and returns a challenge id, server
   nonce, organization id, expiry, and replay flag.
3. Runtime signs the exact enrollment transcript with its operational key.
4. `POST /auth/v1/enrollment/complete` with challenge id, stable completion
   request id, and the 64-byte proof.
5. Cloud returns device id, device-key id, DER certificate, PEM chain, expiry,
   and replay flag. Runtime persists key, certificate, chain, device id, and
   key id with strict ownership and atomic replacement.

The fixed binary request fields use base64url without padding. Certificate DER
uses standard base64. Runtime must reuse the same request id after timeout or a
lost response. It must not start a second enrollment with new keys until it has
proved that the original transaction cannot be recovered.

## Grant issuance

`POST /auth/v1/access-grants` is device-mTLS authenticated. Tenant, device, and
device-key scope always come from the verified certificate. The body contains
only request id, node pool, service class, and permission.

The current issuer accepts `service_class: private` and the permissions
`private.connect` and `private.tun.connect`. A TUN Grant is issued only when the
authorization transaction finds exactly one current projection for the same
tenant, device, device key, and Node Pool. Missing, stale, ambiguous, or
cross-scope projections fail closed.

Grant issuance uses the Core-owned `cloud_grant_v1` object contract on wire
line `0.3`. Cloud returns the complete Core-signed Grant only to the caller and
stores only its digest. The response `access_grant` is opaque base64url without
padding. Runtime must not decode it as JSON.

Private-node Grants default to 24 hours. Refresh before expiry using a stable
request id for one authorization generation. An existing unexpired Grant is
verified locally by Candy Server; Cloud outage does not interrupt an already
authorized data-plane session.

## Runtime configuration synchronization

The Runtime delivery endpoints are implemented as part of the V1 contract:

```text
GET  /auth/v1/runtime/capabilities
GET  /auth/v1/runtime/profile
PUT  /auth/v1/runtime/transport-identity
DELETE /auth/v1/runtime/transport-identity
GET  /auth/v1/runtime/configuration
PUT  /auth/v1/runtime/configuration/status
PUT  /auth/v1/runtime/telemetry
```

Runtime may fetch capabilities after enrollment and after a Cloud software
upgrade. The response publishes API and wire version, the complete Core
`site_projection_v1` object name, media type, conditional-request support,
status enum, and the bounded 15/30/300-second polling range with 20% jitter.

Runtime also replaces one latest telemetry row for its authenticated device
identity on every synchronization cycle. The report uses the kernel boot id
and a monotonic sequence to reject stale same-boot updates. Cloud supplies its
own receipt timestamp and considers reports older than 90 seconds stale.
Lifecycle, active Peer count, route-owner readiness, and fail-open state come
from the active Core instance. Performance fields remain null until Core emits
measured RTT, jitter, packet loss, and rates; Cloud never derives them from
configuration state. Management reads this bounded state through
`GET /api/v1/tenants/{tenant_id}/runtime-telemetry`.
Each item also contains a bounded `paths` snapshot. Cloud validates every
reported Peer attachment against the device's current Segment and, when a
candidate identifier is present, against the currently active signed path
candidate. The complete path set is replaced atomically; no unbounded history
is retained.
Newer Runtime clients may also send `local_networks`, capped at 64 canonical
directly connected IPv4 records. Each record contains a stable `network_id`,
interface name, CIDR, address, and `kind=direct_ipv4`. If local network
discovery is temporarily unavailable, Runtime omits this field and Cloud
preserves the last successful inventory; an explicit empty array means
discovery succeeded and found no publishable networks. Older clients may omit
the field.

### Profile and fetch

The Profile response gives Runtime and LuCI the authenticated organization,
tenant and device names. Site, Segment and attachment fields are nullable until
Cloud has completed the network assignment. These display fields never grant
data-plane authority.

The configuration response is a bounded JSON package containing the exact
Core-signed Segment snapshot, local site projection, peer projection catalog,
route verification key, Grant verification trust bundle, and immutable
publication identity from one generation. Its media type is:

```text
application/vnd.candy.runtime-configuration.v1+json
```

Response headers bind the body to one immutable version:

```text
ETag: "sha256-<64 lowercase hex>"
X-Candy-Projection-Publication-Id: <uuid>
X-Candy-Projection-Id: <uuid>
X-Candy-Segment-Id: <uuid>
X-Candy-Attachment-Id: <uuid>
X-Candy-Segment-Generation: <positive integer>
X-Candy-Projection-Generation: <positive integer>
X-Candy-Projection-Content-Hash: <64 lowercase hex>
X-Candy-Refresh-After: 1
```

The ETag is the domain-separated SHA-256 of all length-delimited signed
envelopes plus route and Grant verification trust material, and is a strong
ETag. Any peer projection or verification-key change therefore creates a new
candidate even when the local projection itself did not change.
Runtime sends the last verified candidate in `If-None-Match`; a match returns
`304` with no body. Runtime SHOULD also send `Prefer: wait=20`; Cloud keeps the
conditional request open asynchronously and returns as soon as the ETag changes,
or after the bounded wait expires. Runtime must reject missing or malformed identity headers,
hash mismatch, an invalid Core signature, an unsupported object version, a
generation rollback, or a broken previous-hash chain.

Cloud returns `204` with `Retry-After: 1` when the authenticated device is
active but has no SD-WAN attachment. A missing projection for an active
attachment, identity ambiguity, or invalid stored publication fails closed as
`503`. None of these responses authorizes deleting the locally applied
last-known-good state.

### Transport identity publication

After the Candy QUIC/UDP listener is ready, Runtime publishes one to eight
reachable endpoints with `PUT /auth/v1/runtime/transport-identity`. The request
contains `schema_version: 1`, a bounded idempotency `request_id`, and for each
endpoint its socket address, full DER certificate SHA-256 pin, and Candy
transport preset (`current`, `bbr_v1`, or `aggressive`). Tenant, device, and
device-key identity come only from verified mTLS; they are never accepted in
the body.

Cloud derives a stable lowercase `server_name` from the enrolled device
identity. An accepted PUT atomically activates the supplied set and disables
older endpoints outside that set. Exact replay of the same request id and body
returns the original result with `replayed: true`; reuse with different content
returns `409`. Failed publication leaves the prior active endpoint set intact.

Runtime must not withdraw last-known-good reachability because a refresh or
Cloud call failed. `DELETE /auth/v1/runtime/transport-identity` is the only
explicit withdrawal operation and disables the authenticated device's active
endpoints. Endpoint changes enqueue every dependent Segment for a new coherent
generation; Runtime never invents a Node Pool, TLS identity, peer, route, or
authorization reference locally.

For a transport node, `peer_projection_catalog` contains the signed projections
that reference that node in the same tenant, Segment, and exact generation. It
is bounded, sorted by projection id, duplicate-free, and covered by the ETag.
`grant_verification_keys` contains bounded Ed25519 key id/public key/issuer/
environment tuples and is also covered by the ETag. Runtime verifies these
objects before enabling the full-duplex TUN data plane.

The response also contains a bounded `compatibility_generations` array for
rolling activation. Each entry is an independent object with this shape:

```json
{
  "segment_generation": 41,
  "segment_content_hash": "<64 lowercase hex>",
  "segment_snapshot": "<base64 signed segment envelope>",
  "peer_projection_catalog": [
    {
      "projection_id": "<uuid>",
      "projection_generation": 41,
      "projection_content_hash": "<64 lowercase hex>",
      "site_projection": "<base64 signed projection envelope>"
    }
  ]
}
```

Cloud may include only the exact previous Segment generation, `N-1`, and only
while that publication remains inside both its signed validity and stale
windows. At most one compatibility generation is returned, only to a node that
owns an inbound transport catalog. An expired generation, an empty or duplicate
catalog, a malformed hash, or any generation other than `N-1` fails closed. An
empty array means no prior-generation connection may be accepted.

Runtime must verify the compatibility Segment snapshot and every projection as
a separate catalog. It selects an inbound catalog only by the Grant's exact
`(projection_id, generation, content_hash)` tuple. Compatibility material never
authorizes local routes, local policy, outbound Grant acquisition, or a
generation rollback. The current top-level generation remains the sole source
for those decisions. When Cloud stops returning `N-1`, Runtime removes that
catalog without disturbing current `N` sessions or the last-known-good current
configuration.

### Apply and status report

Runtime writes a fetched candidate to a private staging file, verifies it with
Core, compiles all routes, DNS, peers, paths, and egress policy, and applies the
complete generation transactionally. Only after the local commit succeeds does
it move the candidate to last-known-good and send state `active`.

The status request carries `If-Match` with the exact configuration ETag plus
projection publication id, projection content hash, `state` (`active` or
`rejected`), and a bounded `error_code` only for a rejection. Cloud accepts it
only when identity and all version fields match the exact current projection.
Status replacement is idempotent for identical state; a report for an older or
different projection returns `409`.

Operators read the latest persisted result per device from
`GET /api/v1/tenants/{tenant_id}/runtime-configuration-status`. The management
response is tenant-scoped and contains no signed configuration or Grant bytes.
Its `current` field is true only when the report still names the current Cloud
projection. The node inventory renders `active`, `rejected`, or `pending` when
no current successful or rejected report has been stored yet.

Status-report timeout never rolls back a successful local apply. Runtime
retries the same report with bounded exponential backoff and jitter. A rejected
candidate is retained only as bounded diagnostic evidence; Runtime continues
using the last verified and applied generation.

### Polling and outage behavior

- Poll with a bounded interval and jitter. Use exponential backoff for network,
  `503`, and TLS failures, with a configured maximum delay.
- `304` resets transient failure backoff because Cloud identity and current
  generation were successfully confirmed.
- Do not retry `400`, `401`, or `409` in a tight loop. Record a structured fault
  and wait for identity, software, or Cloud state to change.
- Cloud never instructs Runtime to remove the last-known-good configuration by
  returning an error or an empty response. Withdrawal requires a valid signed
  replacement object that compiles to the intended empty or reduced policy.
- If Candy SD-WAN cannot remain healthy, Runtime removes only Candy-owned TUN,
  routes, rules, nftables objects, and DNS capture. The resulting network state
  must equal the state with Candy not running.

## Signed route publication

`cloud-worker` builds one canonical Segment snapshot and one least-privilege
projection for every active or standby attachment. The repository validates
all bytes and scope, locks the previous head, stores audit and all immutable
objects, advances the Segment once, and commits only after the complete set
succeeds. Partial projection delivery is never authoritative.

Route-signing and Grant-signing keys are distinct. Consumers verify and compile
the matching snapshot/projection before replacing last-known-good state.
Recovery fetches a complete publication, never a partial delta.

For a direct peer, the transport Node must be one of the two endpoint Nodes.
Cloud rejects a publication in which every direct candidate is passive at its
source. The guided two-site workflow uses one stable listener identity for both
directional projections: one side actively dials and the other accepts that
same full-duplex Candy QUIC/UDP connection. This prevents a two-public-node
deployment from becoming listener-only and avoids creating two redundant
connections for a single direct path.

## Error and retry matrix

| Status | Meaning | Runtime action |
| --- | --- | --- |
| `200`/`201` | operation succeeded | verify response and persist atomically |
| `304` | Runtime configuration unchanged | keep current generation; immediately renew the bounded wait after retry backoff |
| `400`/`422` | local request or encoding defect | do not tight-loop; log bounded contract error |
| `401` | activation, proof, JWT, or device identity invalid | stop privileged sync; require identity recovery |
| `403` | authenticated principal is not authorized | preserve local state; require policy/operator change |
| `204` | active device has no SD-WAN attachment | preserve last-known-good; poll after `Retry-After` |
| `404` | management resource absent | preserve state; correct resource reference |
| `409` | idempotency, state, reference, or projection ambiguity | preserve state; refetch or require operator correction |
| `412` | management revision is stale | GET current resource and reconcile |
| `428` | management `If-Match` is missing | resend with the current numeric revision |
| `500` | Grant assembly internal failure | fail closed for new Grant; retry with backoff |
| `503` | dependency unavailable | preserve locally verified state; retry with backoff and jitter |

## Compatibility rules

- Additive optional response fields may appear within V1; strict Runtime
  decoders should ignore unknown response headers, but must validate required
  fields and exact signed object bytes.
- Requests use strict JSON decoding. New required request fields, field meaning
  changes, enum reinterpretation, or security-boundary changes require a new API
  version.
- Core object compatibility is negotiated and verified by Core. HTTP V1 does
  not imply that every Core minor version has identical capabilities.
- The delivered site projection is one capability of the unified Candy Core.
  Cloud does not create a separate Core binary, `cloud-module` product, release,
  or version line.
- Complete Grants and Runtime configuration envelopes are opaque to generic
  API clients and Web UI code.

## Health

- `/health/live`: process event loop is running.
- `/health/ready`: required database, schema, authentication, key, CA, and Core
  module dependencies for that service are available.
- `/health/degraded`: returns `200 not degraded` when the management API's
  authentication and database dependencies are ready, otherwise `503` with
  the failing dependency reason.
