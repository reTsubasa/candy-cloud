# Candy Cloud API Contract

Candy Cloud `0.1.x` exposes versioned control-plane APIs under `/v1`. The Cloud API is not called during a normal Candy data-plane connection; an unexpired Grant is verified locally by Candy Cloud Server.

## Identity boundaries

- Every device belongs to exactly one tenant.
- Every tenant belongs to one organization.
- Every API write carries an authenticated organization and tenant context.
- Customer private node pools use a tenant-specific audience.
- `CANDY_SHARED` node pools use a Candy-operated audience and require an explicit active entitlement.
- Private and shared service permissions are not interchangeable.

## Grant issuance

Grant issuance uses `cloud_grant_v1`, an exact Candy Core `0.3.4` contract on wire line `0.3`. The authorization snapshot contains tenant, device, node pool, subscription, entitlement, policy generation and revocation generation from one database transaction.

Private-node Grants default to 24 hours. Shared-acceleration Grants use a shorter policy-selected lifetime. A request is idempotent on device, authorization generation and request id. The database stores only the signed envelope digest, not the full Grant.

The signing private key is readable only by `cloud-auth`. API responses, errors and logs must never contain the private key, complete Grant envelope, DeviceProof or complete access token.

`private.connect` is the existing non-TUN private permission and has no route
policy reference. `private.tun.connect` is issued only when the same
authorization transaction finds exactly one current projection for the
authenticated tenant, device, device key, and Node Pool. Its Grant must contain
`DATAGRAM | IP_PACKET_TUNNEL_V1` and the exact projection id, generation, and
content hash. Missing, stale, ambiguous, or cross-scope projections fail closed.

## SD-WAN route publication

One publication contains one canonical Segment snapshot plus the complete set
of projections for every ACTIVE or STANDBY DeviceAttachment. `cloud-worker`
derives ownership and reverse routes from the immutable attachment input,
rejects overlaps and inactive owners, verifies every diagnostic Hub
NodeAttachment, and signs all objects with one route-signing key id.

The repository then performs one transaction in this order:

1. Validate all bytes and tenant scope before SQL.
2. Lock the Segment generation and previous hash with `FOR UPDATE`.
3. Insert the audit event, immutable snapshot, every projection, and every
   publication-member row.
4. Advance the Segment generation and content hash exactly once.
5. Commit only after the complete projection set succeeds.

The same publication id replays only when every hash, envelope, identity, and
member byte matches. Divergent replay, generation gaps, missing projections,
or identity conflicts roll back the whole transaction and leave the last good
generation unchanged.

### Shared Hub and Mesh expansion objects

`cloud-worker` uses the same route-signing key to publish
`SharedHubAdmissionPolicyV1` and `MeshMembershipProjectionV1`. Both objects bind
the exact Segment generation and content hash produced by the coherent route
publication. Shared Hub admission additionally binds Node, Node Key, and Node
Pool plus the signed Node/Tenant/Site/Tunnel hierarchy. Mesh membership binds
the local Site/Attachment and a sorted bounded peer set with attachment epoch
floors. Neither builder accepts unsigned route ownership or IPv6 input.

Hub and Edge consumers verify these envelopes against the route trust store and
the applied snapshot/projection before admission. Publication persistence and
delivery must remain atomic with the matching route generation; partial
expansion-object delivery is not authoritative.

## Signing keys and cache operation

The route-signing key is distinct from the Grant-signing key. Rotation first
adds the new public key to Edge and Hub trust stores, then publishes with the
new key id, waits through the maximum object and stale windows, and only then
removes the old public key. Private keys are never written to database rows.

Consumers verify and compile the Segment snapshot and its matching projection
before atomically replacing the last-good pair. Install the verified policy
cache before enabling a tunnel or applying routes. A failed download,
signature, compile, or install keeps the previous pair. Fresh objects authorize
new tunnels through `expires_at`; the exact already-applied generation may be
retained only through `stale_until` and cannot expand routes, MTU, Hub set,
epoch floor, or resource limits.

Rollback disables TUN feature negotiation and TUN Grant issuance, then restores
the prior full signed snapshot/projection pair. Recovery always fetches a full
publication, never a partial projection delta. During a Cloud outage, existing
locally verified Grants and signed policy bytes continue only within their
validity/stale rules; no verifier performs a Cloud API or database lookup in the
tunnel-open or packet path.

## Health

- `/health/live`: process event loop is running.
- `/health/ready`: required database/schema/key dependencies are available.
- `/health/degraded`: process can serve limited reads but cannot safely issue Grants or commit writes.
