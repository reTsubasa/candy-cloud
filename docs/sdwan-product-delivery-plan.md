# Candy SD-WAN Product Delivery Plan

## 1. Delivery objective

Deliver Candy SD-WAN as a production product spanning Candy Cloud, OpenWrt,
Linux Edge, Linux `candy-server`, Candy Core, LuCI, and the signed release
channel.

The product is complete only when at least two enrolled Site nodes can exchange
traffic through a full-duplex Layer-3 TUN, apply Cloud-managed traffic and
egress policy, resolve internal names, expose end-to-end observability, survive
component failures, and upgrade through the normal signed release path.

Supported node combinations are:

- OpenWrt to OpenWrt;
- OpenWrt to Linux;
- Linux to Linux.

A Relay is optional. The default data path is direct Site-to-Site Candy
QUIC/UDP. Every Site retains its existing Candy Internet egress behavior.
Cloud may explicitly assign selected traffic to another Site's existing Candy
egress.

## 2. Fixed product decisions

- This delivery defines the first production SD-WAN V1 contract. Earlier V1
  route, Hub, mesh, and publication structures were never deployed and carry
  no compatibility promise; they must be corrected in place instead of
  creating a V2 or retaining a legacy decoder.
- Candy Core is an internal managed data-plane implementation, delivered as a
  signed shared module or through the product-owned service binaries; it is
  never a user-facing command or standalone service.
- Linux Edge uses the `candy` product command.
- Linux server uses the `candy-server` product command.
- SD-WAN is an additive `candy-server` capability and can run concurrently
  with the existing Candy service.
- Site-to-Site forwarding uses one full-duplex Layer-3 TUN per routing domain,
  not one TUN per direction or one TUN per Peer.
- The TUN carries simultaneous transmit and receive traffic for every allowed
  Site Peer without a global data-plane lock.
- The implementation does not use eBPF. Correctness and performance use
  standard Linux/OpenWrt routing, policy routing, nftables, multi-queue TUN,
  bounded queues, batched I/O, and supported UDP offloads.
- Cloud is never in the customer packet path.
- A business route names its destination Site. Direct and Relay connections
  are path candidates and do not change route ownership.
- Every Site keeps its current Candy DNS and Internet egress logic unless an
  explicit signed Cloud policy selects a remote Site egress.
- DNS, route, Peer, and egress policy for one Site are published and applied as
  one coherent generation.
- A Candy failure must remove all Candy-owned network state and leave the
  network equivalent to Candy not running.
- No automatic congestion-controller fallback from Candy BBR to CUBIC is
  permitted.
- Private keys, node join codes, Grants, and complete traffic payloads
  must never appear in logs or Cloud telemetry.

## 3. Product topology

```text
                         Candy Cloud
              identity / topology / policy / DNS
                    /                       \
                   v                         v
       Site A Candy Edge <============> Site B Candy Edge
       OpenWrt or Linux    direct TUN    OpenWrt or Linux
              |                                 |
          Site A LAN                         Site B LAN
              |                                 |
       Site A Candy egress                Site B Candy egress
                   \                         /
                    \--- optional Relay ----/
```

Default traffic behavior:

```text
Site A private prefix -> full-duplex SD-WAN TUN -> Site B private prefix
Site B private prefix -> full-duplex SD-WAN TUN -> Site A private prefix
Site A Internet       -> existing Site A Candy policy and egress
Site B Internet       -> existing Site B Candy policy and egress
```

Optional Cloud service chain:

```text
selected Site A flow
  -> Site A SD-WAN TUN
  -> Site B
  -> existing Site B Candy egress pipeline
  -> Internet
```

The same service chain is valid from Site B through Site A.

## 4. Product goal checklist

### G1. Unified node lifecycle

- [ ] An OpenWrt or Linux node can be created in Cloud and joined with a
  single-use node join code.
- [ ] Enrollment creates a device identity and operational key locally.
- [ ] Device certificates support renewal, rotation, revocation, and expiry.
- [ ] Replaying an activation or enrollment request is idempotent or rejected.
- [ ] Removing a node revokes new authorization and removes its routes, DNS
  records, Peer permissions, and egress assignments.

### G2. Full-duplex Site TUN

- [ ] A single routing-domain TUN carries simultaneous Site A to Site B and
  Site B to Site A traffic.
- [ ] One TUN can serve multiple Peers and prefixes.
- [ ] Each direction has independent bounded queues and counters.
- [ ] One slow Peer or direction cannot block unrelated Peers.
- [ ] Source Site, Segment, source prefix, destination prefix, TTL, DF, MTU,
  and authorization are validated on ingress.
- [ ] TCP, UDP, ICMP, DNS, fragmentation behavior, and return traffic pass
  through the real Candy QUIC/UDP data plane.

### G3. Cloud-managed dynamic routing

- [ ] Sites advertise connected, configured, or approved learned prefixes.
- [ ] Cloud validates ownership, overlap, tenant scope, Segment membership,
  loops, limits, and route withdrawal.
- [ ] Cloud generates one signed Segment snapshot and one per-node projection.
- [ ] Nodes reject stale generations, broken hash chains, invalid signatures,
  cross-tenant objects, and unauthorized expansion.
- [ ] Routes install atomically and retain the last known good generation on a
  validation or delivery failure.
- [ ] Connected and local routes always outrank remote SD-WAN routes.
- [ ] Optional FRRouting integration imports and exports filtered BGP routes
  without implementing BGP or OSPF inside Candy Core.

### G4. Direct path and optional Relay

- [ ] Cloud publishes authenticated Peer candidates and allowed Relay
  candidates separately from route ownership.
- [ ] Nodes attempt direct IPv4/IPv6 connectivity and coordinated UDP NAT
  traversal.
- [ ] `direct-only`, `direct-preferred`, and policy-selected Relay behavior are
  explicit and observable.
- [ ] A preauthorized healthy path can replace a failed path without waiting
  for a full route publication.
- [ ] Hold-down, hysteresis, and bounded probing prevent path flapping.
- [ ] Relay failure never removes the destination Site route when another
  authorized path remains available.
- [ ] Relay capacity, tenancy, authorization, and traffic accounting are
  enforced.

### G5. Existing Candy service compatibility

- [ ] `candy-server` runs ordinary Candy service and SD-WAN service
  concurrently.
- [ ] Existing ordinary Candy users, configuration, wire behavior, and egress
  continue to work.
- [ ] The standard Candy listener is reused when the protocol trust boundary
  permits capability-based multiplexing.
- [ ] A separate listener is introduced only for a distinct internal trust
  boundary and is documented, health checked, and bounded.
- [ ] `private.connect`, `private.tun.connect`, egress use, and transit use are
  independently authorized.

### G6. Per-Site and cross-Site egress

- [ ] Each Site retains its current Candy Internet routing and DNS behavior.
- [ ] Cloud can assign selected source, destination, domain, application, or
  traffic class to another Site's Candy egress.
- [ ] Remote egress is implemented with policy routing and flow state, not an
  accidental global default route.
- [ ] Return traffic is mapped to the originating Site and session.
- [ ] Cloud rejects recursive egress assignments and route loops.
- [ ] Egress admission enforces tenant, Site, capacity, authorization, and
  policy generation.
- [ ] Loss of the selected remote egress removes Candy-owned steering and
  follows the documented fail-open behavior.

### G7. Unified internal and intelligent DNS

- [ ] The existing Candy DNS decision engine remains the single DNS entry
  point.
- [ ] Cloud manages scoped internal zones, records, services, and optional DHCP
  registration.
- [ ] Internal names are never forwarded to public resolvers.
- [ ] Internal A and AAAA answers correspond to authorized, installed Site
  routes.
- [ ] Public DNS continues to use each Site's current Candy DNS logic.
- [ ] A remote egress policy resolves through the same selected egress and
  creates a bounded per-client DNS route binding.
- [ ] DNS projection, route projection, and egress policy switch atomically.
- [ ] LuCI and Cloud expose a DNS decision trace without leaking query payloads
  beyond the configured audit policy.

### G8. Product observability

- [ ] Cloud displays organizations, Sites, nodes, prefixes, Peers, paths,
  Relays, egresses, policy generations, and health.
- [ ] Per-direction TUN metrics include packets, bytes, effective throughput,
  RTT, loss, queue pressure, FEC, UDP multiplier, fragmentation, and drops.
- [ ] A remote egress flow separates Site-to-Site path metrics from egress
  connection metrics.
- [ ] Route, DNS, enrollment, Grant, path, update, and fail-open events use
  structured severity levels and stable event identifiers.
- [ ] Traffic decision logs contain real flow decisions and never periodic
  placeholder messages.
- [ ] Metrics and logs use bounded retention, rotation, redaction, and disk
  budgets on OpenWrt.

### G9. Fail-open and recovery

- [ ] Every route, rule, nftables object, TUN, mark, table, process, and file
  created by Candy has explicit ownership and generation.
- [ ] Core exit, Runtime exit, failed health check, corrupt policy, or expired
  authorization cannot leave stale steering behind.
- [ ] Cleanup is idempotent and survives restart during cleanup.
- [ ] Cloud outage preserves only still-valid last known good authorization and
  policy.
- [ ] Normal Internet access remains equivalent to Candy not running after
  fail-open cleanup.
- [ ] Recovery never silently selects a different congestion controller.

### G10. Signed delivery and upgrades

- [ ] Cloud images, Linux Runtime, OpenWrt packages, and Core bundles have
  reproducible release metadata and immutable tags.
- [ ] OpenWrt and Linux verify the signed catalog, exact platform, bundle
  manifest, executable hash, Process API, Core API, and wire compatibility.
- [ ] Runtime and Core updates preserve node identity, certificates, Site
  membership, last known good policy, and local configuration.
- [ ] Failed activation restores the prior Core/Runtime and prior network
  behavior.
- [ ] Upgrade tests cover the current stable Runtime `0.4.0-r50` and Core
  `0.3.20` baseline.

## 5. Cross-repository task list

### 5.1 Contracts and ownership

- [ ] Define canonical `Node`, `Site`, `Segment`, `Attachment`, `Peer`,
  `Prefix`, `Relay`, `PathCandidate`, `Egress`, and `ServicePolicy` schemas.
- [ ] Define `DnsProjectionV1` and bind it to the matching route generation.
- [ ] Extend Site projections with Peer candidates, path authorization, egress
  authorization, DNS hash, expiry, and stale limits.
- [ ] Define a stable node status schema shared by Cloud, Core, Runtime, LuCI,
  and Linux CLI.
- [ ] Define monotonic generation, previous-hash, idempotency, replay, rollback,
  and partial-publication rules.
- [ ] Define ownership of routing decisions: Cloud owns authorization and
  candidates; Core owns live path selection; Runtime owns kernel application.
- [ ] Update cross-repository interop vectors before implementing consumers.

### 5.2 `candy-cloud`: management API and console

- [ ] Replace the health-only `cloud-api` surface with authenticated `/v1`
  organization, tenant, user, role, Site, node, Segment, prefix, Relay, egress,
  DNS, and policy APIs.
- [ ] Use OIDC-backed administrator authentication, secure sessions, CSRF
  protection, tenant-scoped RBAC, and explicit audit actors.
- [ ] Add idempotency keys, optimistic concurrency, pagination, stable error
  codes, and request size limits to every mutation API.
- [ ] Implement a TypeScript management console generated from the versioned
  OpenAPI contract.
- [ ] Add topology editing with conflict validation and a complete change
  preview before publication.
- [ ] Add device activation, certificate state, revocation, software version,
  online state, and last policy generation views.
- [ ] Add route, DNS, Relay, egress, and service-policy history with rollback.
- [ ] Add dashboards for health, path quality, traffic, egress use, policy
  errors, and stale nodes.
- [ ] Provide accessible empty, loading, degraded, permission-denied, conflict,
  and destructive-confirmation states.

### 5.3 `candy-cloud`: auth and control delivery

- [ ] Mount the authenticated Grant issuance routes in the production
  `cloud-auth` application behind real device mTLS verification.
- [ ] Complete activation-code issuance, challenge, enrollment, certificate
  renewal, key rotation, and revocation APIs.
- [ ] Issue least-privilege Grants for Peer TUN, Relay, remote egress, and
  ordinary Candy service independently.
- [ ] Add authenticated long polling or streaming for policy notifications;
  retain full-object fetch as the recovery source of truth.
- [ ] Publish route, DNS, Peer, Relay, and egress objects in one database
  transaction per Segment generation.
- [ ] Implement Cloud signing-key and device-CA rotation with overlapping trust
  windows and audited completion.

### 5.4 `candy-cloud`: routing worker

- [ ] Replace the idle worker process with leased, idempotent jobs.
- [ ] Compile and publish a coherent Segment generation after every authorized
  topology change.
- [ ] Validate prefix overlap, ownership, loops, attachment epoch, resource
  limits, Relay eligibility, egress recursion, and DNS/route consistency.
- [ ] Generate a least-privilege projection for every active or standby node.
- [ ] Withdraw routes and authorization on node, Site, Segment, certificate,
  or entitlement revocation.
- [ ] Detect stale publication work and resume without duplicating or skipping
  a generation.
- [ ] Emit bounded audit records and operational metrics for every job.

### 5.5 Core module: full-duplex TUN data plane

- [ ] Implement the currently rejected `client sdwan` Process API command.
- [ ] Open one multi-queue Layer-3 TUN per routing domain and process reads and
  writes concurrently.
- [ ] Map destination prefixes to stable Site/Peer identities with a bounded
  radix or equivalent prefix structure.
- [ ] Use per-Peer and per-direction bounded queues with explicit drop policy.
- [ ] Batch TUN and UDP operations where supported and use UDP GSO/GRO only
  after runtime capability detection.
- [ ] Avoid per-packet heap allocation and global synchronization in the hot
  path.
- [ ] Enforce source-prefix, destination-prefix, tenant, Segment, MTU, TTL, DF,
  replay, and authorization checks.
- [ ] Produce ICMP errors required for MTU, TTL, and unreachable conditions.
- [ ] Preserve Candy BBR, FEC, fragmentation, UDP multiplier, and metrics on
  the real Site-to-Site data path.
- [ ] Expose independent transmit and receive metrics for every Site Peer.

### 5.6 Core module: Peer and path manager

- [ ] Implement mutually authenticated direct Peer connections using signed
  Cloud identity and authorization.
- [ ] Implement endpoint candidate exchange and coordinated UDP NAT traversal.
- [ ] Maintain direct and Relay candidates independently from business routes.
- [ ] Select paths only from the Cloud-authorized candidate set.
- [ ] Add health probing, hold-down, hysteresis, drain, migration, and bounded
  reconnect behavior.
- [ ] Preserve active flows where the transport permits migration; otherwise
  fail affected flows explicitly without corrupting unrelated Peers.
- [ ] Reject stale Peer identity, attachment epoch, and path authorization.

### 5.7 Core module: concurrent Candy server services

- [ ] Remove the current mutual exclusion between ordinary Candy users and
  SD-WAN service blocks.
- [ ] Multiplex ordinary Candy, Site TUN, Relay, and egress capabilities using
  authenticated service permissions.
- [ ] Keep connection, session, UDP flow, queue, and per-tenant limits separate
  by service class.
- [ ] Route SD-WAN ingress either to an authorized Site prefix or to the
  existing Candy egress pipeline according to signed policy.
- [ ] Maintain stateful return mapping for remote Site egress traffic.
- [ ] Prevent source spoofing, cross-tenant forwarding, recursive egress, and
  service-policy bypass.
- [ ] Publish a unified server preflight and health report for all enabled
  services.

### 5.8 `candy-runtime`: OpenWrt node agent

- [ ] Add a Runtime-owned enrollment and Cloud synchronization agent.
- [ ] Generate and store device keys with strict ownership and permissions.
- [ ] Store certificates, Grants, trust roots, and last known good projections
  atomically outside `/tmp`.
- [ ] Generate the Core SD-WAN runtime configuration without copying protocol
  logic into shell or Lua.
- [ ] Create and remove TUN, routes, policy tables, marks, and nftables objects
  through the privileged Runtime boundary.
- [ ] Tag every object with Candy ownership and generation.
- [ ] Reconcile actual kernel state against desired state after restart.
- [ ] Serialize lifecycle, provider, route, policy, and update actions.
- [ ] Implement fail-open cleanup before disabling or restarting failed Core.
- [ ] Preserve the current non-SD-WAN Candy configuration and behavior during
  migration.

### 5.9 `candy-runtime`: Linux Edge and server

- [ ] Ship the user-facing `candy` Linux Edge command and systemd service.
- [ ] Support `candy join`, `candy sdwan status`, `candy sdwan reconnect`, and
  `candy leave` without exposing the internal Core module.
- [ ] Ship one `candy-server` service that can enable ordinary Candy and
  SD-WAN concurrently from one validated configuration.
- [ ] Preserve `--check-config` and `--preflight` on the product command.
- [ ] Add signed Core management, activation health checks, rollback, and
  identity-preserving upgrades for Linux Edge and server.
- [ ] Add standard Linux routing and nftables integration with the same
  ownership and fail-open contract as OpenWrt.
- [ ] Add an optional FRRouting adapter with explicit import/export filters,
  prefix limits, and no direct access to Candy signing material.

### 5.10 `candy-runtime`: unified DNS

- [ ] Extend the current intelligent DNS configuration with signed internal
  zones and service records.
- [ ] Never send an internal-zone miss to a public upstream.
- [ ] Register per-client DNS route bindings for remote egress decisions.
- [ ] Expire bindings on TTL, policy replacement, Site revocation, or route
  withdrawal.
- [ ] Keep public direct/Candy resolution behavior unchanged unless a signed
  remote-egress policy matches.
- [ ] Apply DNS, routes, and egress policy in one recoverable transaction.
- [ ] Preserve a bounded valid cache during Cloud outages and remove Candy DNS
  interception during fail-open.

### 5.11 LuCI SD-WAN page

- [ ] Add one user-facing `SD-WAN` menu page to the existing Candy application.
- [ ] Before enrollment, show Cloud address, activation, validation errors, and
  safe retry.
- [ ] After enrollment, show Site, Segment, Cloud state, certificate state,
  active generation, Peer reachability, effective routes, and internal DNS.
- [ ] Show current path as Direct or Relay and explain why the path is active.
- [ ] Show each Site's normal Candy egress separately from optional remote
  egress assignments.
- [ ] Provide clear join, reconnect, certificate-renew, and leave operations
  with confirmation for destructive actions.
- [ ] Keep IDs, hashes, raw Grants, route generations, and protocol internals
  out of the ordinary view.
- [ ] Put signatures, hashes, authorization, route differences, per-direction
  metrics, queues, MTU, drops, and decision evidence in Diagnostics.
- [ ] Verify desktop and mobile layout on real LuCI themes without overlapping,
  unstable heights, or inaccessible controls.

### 5.12 Cloud and node observability

- [ ] Define stable structured event names and severity for enrollment, auth,
  publication, route, DNS, Peer, path, egress, update, and cleanup operations.
- [ ] Publish per-direction Site traffic and path metrics without raw payloads.
- [ ] Correlate one flow decision across source Site, SD-WAN path, destination
  Site, and optional Candy egress.
- [ ] Add health states for Cloud connectivity, policy freshness, certificate,
  Grant, TUN, Peer, route install, DNS, egress, and cleanup.
- [ ] Add bounded OpenWrt logs and configurable Cloud retention.
- [ ] Add alerts for stale generations, repeated path changes, route conflicts,
  expiring identity, Relay exhaustion, egress failure, and cleanup failure.

### 5.13 Security and abuse resistance

- [ ] Threat-model enrollment, Cloud APIs, signed policy, direct Peers, Relay,
  remote egress, DNS, route injection, replay, and tenant isolation.
- [ ] Fuzz all new wire, projection, DNS, and control-message decoders.
- [ ] Bound every frame, record set, prefix set, queue, connection, flow,
  publication, and API request.
- [ ] Require proof of device identity before disclosing Peer candidates.
- [ ] Prevent a Site from advertising unowned source prefixes.
- [ ] Prevent a Relay or egress node from expanding an authorized route set.
- [ ] Redact secrets, complete Grants, private DNS data, and packet contents.
- [ ] Document trust-root rotation, compromise response, revocation, and
  recovery procedures.

### 5.14 Performance and reliability

- [ ] Establish reproducible Linux and IPQ4000 baselines before enabling
  SD-WAN.
- [ ] Benchmark full-duplex traffic with both directions saturated.
- [ ] Benchmark 64-byte PPS, mixed packet sizes, MTU-sized traffic, TCP, UDP,
  DNS, FEC, UDP multiplier, Direct, Relay, and remote egress.
- [ ] Require IPQ4000 SD-WAN throughput to remain within an explicitly approved
  measured budget of the same current Candy path; publish the actual supported
  profile rather than an unbounded claim.
- [ ] Verify that one impaired Peer cannot consume unbounded memory or starve
  healthy Peers.
- [ ] Verify authorized local path recovery within 3 seconds and fail-open
  cleanup within 3 seconds after a detected fatal failure.
- [ ] Run at least 24-hour loss/jitter stress and 72-hour device soak tests with
  bounded memory, file growth, reconnects, and CPU.
- [ ] Test power loss during enrollment, policy application, update, rollback,
  route cleanup, and identity rotation.

### 5.15 Release and operations

- [ ] Publish all deployable binaries only through GitHub Release Assets and
  the signed stable catalog.
- [ ] Add exact OpenWrt, Linux architecture, Runtime, Core, API, wire, and
  feature compatibility to release metadata.
- [ ] Build Cloud deployment images with pinned dependencies, non-root users,
  read-only filesystems where practical, health checks, backup, restore, and
  key-mount documentation.
- [ ] Add schema migration compatibility and rollback checks for every Cloud
  release.
- [ ] Provide installation, enrollment, Site creation, policy, diagnostics,
  backup, restore, upgrade, rollback, and incident runbooks.
- [ ] Never publish a release while a required real-Core or target-hardware
  gate is skipped.

## 6. Dependency order

The product is one delivery, but implementation follows these hard
dependencies:

1. Freeze shared schemas, Process API additions, signed objects, and status
   contracts.
2. Implement Core full-duplex TUN, Peer identity, route application contract,
   and concurrent server services.
3. Implement Cloud management APIs, routing worker, signed coherent
   publication, and device control delivery.
4. Implement OpenWrt and Linux agents against the frozen contracts.
5. Integrate internal DNS, Direct/Relay path management, and remote egress.
6. Complete Cloud console, LuCI, CLI, observability, operations, and signed
   packaging.
7. Pass the complete cross-platform, failure, security, performance, upgrade,
   and soak acceptance gates before public release.

Work inside one dependency level may run in parallel. A downstream component
must not invent a temporary schema or silently ignore a missing upstream
contract.

## 7. Required acceptance matrix

### 7.1 Node combinations

- [ ] OpenWrt Site A <-> OpenWrt Site B.
- [ ] OpenWrt Site A <-> Linux Site B.
- [ ] Linux Site A <-> Linux Site B.

Each combination must pass simultaneous bidirectional TCP, UDP, ICMP, DNS,
small-packet, MTU-sized, fragmented, sustained throughput, and reconnect tests.

### 7.2 Routing and DNS

- [ ] Two Sites with one prefix each.
- [ ] Multiple prefixes per Site.
- [ ] Three or more Sites sharing one Segment.
- [ ] Prefix add, withdraw, move, conflict, and rejected overlap.
- [ ] Internal forward and reverse lookup in both directions.
- [ ] Cloud outage with valid and expired last known good state.
- [ ] Atomic DNS/route generation replacement.

### 7.3 Paths and egress

- [ ] Direct path without any Relay deployment.
- [ ] Direct path loss with an authorized Relay.
- [ ] Direct-only policy with no silent Relay use.
- [ ] Site A and Site B retain their own existing Candy egresses.
- [ ] Selected Site A traffic uses Site B Candy egress.
- [ ] Selected Site B traffic uses Site A Candy egress.
- [ ] DNS and data use the same selected remote egress.
- [ ] Recursive egress and route loops are rejected.

### 7.4 Failure and lifecycle

- [ ] Core crash, Runtime crash, process kill, and boot interruption.
- [ ] Cloud API, auth, worker, database, and reverse-proxy outage.
- [ ] Peer, Relay, and egress loss.
- [ ] Invalid signature, stale generation, broken hash chain, expired Grant,
  revoked device, and certificate rotation.
- [ ] Runtime and Core upgrade success, rollback, interrupted update, and disk
  pressure.
- [ ] No Candy-owned route, rule, nftables object, process, TUN, or DNS capture
  remains after fail-open.

## 8. Definition of done

Candy SD-WAN is ready for public product delivery only when all of the
following are true:

- [ ] An administrator can deploy Candy Cloud using the documented production
  procedure and pass backup/restore verification.
- [ ] The administrator can create a Segment, Sites, node join codes,
  internal DNS, routes, and optional egress policy from the Cloud console.
- [ ] At least two OpenWrt or Linux nodes can enroll without manual database or
  configuration editing.
- [ ] The nodes establish a direct full-duplex Candy QUIC/UDP TUN without a
  Relay and exchange simultaneous bidirectional Site traffic.
- [ ] An optional Relay can be added and selected without changing route
  ownership or making Relay mandatory.
- [ ] Every Site continues to use its existing Candy Internet egress by
  default.
- [ ] Cloud can explicitly direct selected traffic through another Site's
  existing Candy egress with matching DNS and a correct return path.
- [ ] `candy-server` runs ordinary Candy and SD-WAN services concurrently.
- [ ] Internal DNS, route projection, path authorization, and egress policy are
  signed, coherent, observable, and recoverable.
- [ ] OpenWrt LuCI, Linux CLI, and Cloud present consistent user-facing state
  and professional diagnostics.
- [ ] Failure consequences are bounded to Candy not running, unless a future
  separately approved policy explicitly defines a different failure contract.
- [ ] All target combinations, real hardware tests, security tests, performance
  gates, upgrade tests, and soak tests pass without skipped required gates.
- [ ] The complete release is delivered through immutable source tags, signed
  Core bundles, signed stable catalog entries, and GitHub Release Assets.
