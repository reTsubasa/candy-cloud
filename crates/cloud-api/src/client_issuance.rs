//! Terminal client Grant issuance orchestration.
//!
//! This module owns the *only* path that turns Cloud authorization state into a
//! signed terminal Client Grant. It deliberately lives apart from
//! `client_access`/`client_control`/`client_routing`: those crates read state,
//! while this module decides when Cloud may sign, which generation the envelope
//! claims, and what a replay is allowed to return.
//!
//! Three invariants drive the shape of this code:
//!
//! 1. **Cloud is the only authority.** The node set, the policy generation, and
//!    the traffic mode all come from Cloud reads taken under the caller's session
//!    scope. Nothing here accepts a caller-supplied node, mode, or generation.
//! 2. **A replay returns the exact bytes Cloud signed before.** Re-signing on
//!    replay would silently re-stamp `issued_at`/`expires_at` and let a client
//!    widen its own authorization window by retrying a request.
//! 3. **The signed generation is compare-and-set.** The generation is part of the
//!    signed payload, so it is read before signing and re-checked atomically by
//!    persistence; a lost race re-signs rather than storing a stale claim.

use chrono::{DateTime, Utc};
use cloud_client_grant::{
    format_content_hash, ClientGrantAudience, ClientGrantEnvelopeV1, ClientGrantNodeAssignment,
    ClientGrantPayloadV1, ClientGrantPolicyBinding, ClientGrantSigner, ClientGrantTrafficMode,
    CLIENT_GRANT_MAX_TTL_SECS, CLIENT_GRANT_SCHEMA_VERSION, CLIENT_GRANT_TTL_SECS,
};
use cloud_db::client_access::ClientAccessPolicyRepository;
use cloud_db::client_assignment_lease::{
    assignment_lease_deadline, assignment_lease_state, plan_assignment, AssignedNode,
    AssignmentPlan, PreviousAssignment,
};
use cloud_db::client_control::{
    ClientControlRepository, ClientDeviceRecord, ClientGrantRecord, ClientGrantWrite,
    ClientGrantWriteOutcome,
};
use cloud_db::client_routing::{ClientNodeRepository, MAX_CLIENT_NODE_BACKUPS};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Domain separator for the issuance request fingerprint. Distinct from the
/// registration and policy-publication domains so a hash can never be replayed
/// across idempotency scopes.
const CLIENT_GRANT_REQUEST_DOMAIN: &[u8] = b"candy/terminal-client-grant/v1\0";

/// How long a Cloud-chosen node stays usable inside one Grant.
///
/// This is intentionally far shorter than the Grant lifetime so a node that
/// leaves service is dropped by refresh rather than by revocation alone.
const CLIENT_GRANT_NODE_LEASE_SECS: u64 = 60 * 60;

// Compile-time proof of the two relationships the lease design depends on. These
// are `const` assertions rather than test assertions on purpose: a constant
// comparison written inside a `#[test]` is folded away by the compiler and would
// silently stop protecting anything if someone changed the values.
const _: () = assert!(CLIENT_GRANT_NODE_LEASE_SECS < CLIENT_GRANT_TTL_SECS);
const _: () = assert!(CLIENT_GRANT_TTL_SECS <= CLIENT_GRANT_MAX_TTL_SECS);

/// Bounded compare-and-set retries. A concurrent issuance for the *same* device
/// moves the generation; a small fixed bound keeps a pathological race from
/// turning into an unbounded signing loop.
const MAX_GENERATION_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIssuanceError {
    /// The device exists and is owned by the caller, but Cloud has no active
    /// policy bound to it. The client must stay disconnected and retry later.
    PolicyNotBound,
    /// Cloud has no tenant node it can currently authorize for terminal traffic.
    NoActiveNode,
    /// Cloud could not produce a signed result. Never reported as a client error.
    Unavailable,
    /// The idempotency key was reused for a materially different request.
    IdempotencyConflict,
    /// The signed generation kept losing its compare-and-set race past the retry
    /// bound. Retryable with the same key.
    GenerationConflict,
    /// The session scope does not own the device Cloud was asked to sign for.
    NotOwned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedGrant {
    /// Exactly what Cloud persisted. On a replay this is byte-identical to the
    /// first issuance, because Cloud returns stored bytes instead of re-signing.
    pub record: ClientGrantRecord,
    pub replayed: bool,
}

#[derive(Clone, Copy)]
pub struct ClientIssuance<'a> {
    pub control: &'a ClientControlRepository,
    pub routing: &'a ClientNodeRepository,
    pub access: &'a ClientAccessPolicyRepository,
    pub signer: &'a ClientGrantSigner,
}

impl<'a> ClientIssuance<'a> {
    /// Issues, or byte-identically replays, the Grant for one owned device.
    pub async fn grant_for_device(
        &self,
        device: &ClientDeviceRecord,
        request_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<IssuedGrant, ClientIssuanceError> {
        if request_id.is_nil() {
            return Err(ClientIssuanceError::IdempotencyConflict);
        }
        // A retry of an already-issued request must not re-sign. Checking first
        // keeps replay byte-stable even if the policy or node set moved on, which
        // is exactly the case a re-sign would get wrong.
        if let Some(record) = self
            .control
            .grant_by_request(device.tenant_id, device.record_id, request_id)
            .await
            .map_err(|_| ClientIssuanceError::Unavailable)?
        {
            return Ok(IssuedGrant {
                record: self.verify_binding(device, record)?,
                replayed: true,
            });
        }
        // Gather Cloud's authorization state. The signature covers these values,
        // so reading them once and signing once keeps Grant and policy in step.
        let snapshot = self
            .access
            .authorization_snapshot(
                device.organization_id,
                device.tenant_id,
                device.user_id,
                device.record_id,
            )
            .await
            .map_err(|_| ClientIssuanceError::Unavailable)?
            .ok_or(ClientIssuanceError::PolicyNotBound)?;
        if snapshot.device_key_id != device.device_key_id {
            // The bound key changed since the caller resolved the device, so the
            // Envelope would be addressed to a key the client no longer holds.
            return Err(ClientIssuanceError::IdempotencyConflict);
        }
        let issued_at =
            u64::try_from(now.timestamp()).map_err(|_| ClientIssuanceError::Unavailable)?;
        let expires_at = issued_at
            .checked_add(CLIENT_GRANT_TTL_SECS)
            .ok_or(ClientIssuanceError::Unavailable)?;
        // The node set is chosen against the assignment the device already holds,
        // so a refresh inside a live lease window keeps the same primary and the
        // same failover order. Selection only re-runs once that window is over.
        let nodes = self.select_nodes_for(device, issued_at).await?;
        let lease_until =
            assignment_lease_deadline(issued_at, CLIENT_GRANT_NODE_LEASE_SECS, expires_at)
                .ok_or(ClientIssuanceError::Unavailable)?;
        let lease_until_time = timestamp(lease_until)?;
        let issues_at = timestamp(issued_at)?;
        let expires_at_time = timestamp(expires_at)?;

        for attempt in 0..MAX_GENERATION_ATTEMPTS {
            let generation = self
                .control
                .next_grant_generation(device.tenant_id, device.record_id)
                .await
                .map_err(|_| ClientIssuanceError::Unavailable)?;
            let grant_id = Uuid::now_v7();
            let request_hash = issuance_fingerprint(device, request_id, &snapshot, &nodes);
            let payload = ClientGrantPayloadV1 {
                schema_version: CLIENT_GRANT_SCHEMA_VERSION,
                grant_id,
                tenant_id: device.tenant_id,
                user_id: device.user_id,
                device_id: device.device_id,
                device_key_id: device.device_key_id,
                device_public_key: cloud_client_grant::format_device_public_key(
                    &snapshot.public_key,
                ),
                audience: ClientGrantAudience {
                    tenant_id: device.tenant_id,
                    user_id: device.user_id,
                    device_id: device.device_id,
                    device_key_id: device.device_key_id,
                },
                device_generation: device.generation,
                generation,
                issued_at,
                not_before: issued_at,
                expires_at,
                mode_capabilities: snapshot
                    .policy
                    .mode_capabilities
                    .iter()
                    .map(|mode| traffic_mode(*mode))
                    .collect(),
                policy: ClientGrantPolicyBinding {
                    policy_id: snapshot.policy.policy_id,
                    generation: snapshot.policy.generation,
                    content_hash: format_content_hash(&snapshot.policy_content_hash),
                },
                nodes: nodes
                    .iter()
                    .enumerate()
                    .map(|(index, node)| ClientGrantNodeAssignment {
                        node_id: node.node_id,
                        endpoint: node.endpoint.clone(),
                        priority: u8::try_from(index + 1).unwrap_or(u8::MAX),
                        node_key_id: node.node_key_id,
                        transport: "quic".to_owned(),
                        server_name: node.server_name.clone(),
                        server_cert_sha256: cloud_client_grant::format_cert_pin(
                            &node.server_cert_sha256,
                        ),
                        assignment_lease_until: lease_until,
                    })
                    .collect(),
                signing_key_id: String::new(),
            };
            let envelope = self
                .signer
                .issue(payload)
                .map_err(|_| ClientIssuanceError::Unavailable)?;
            let envelope_bytes = envelope
                .to_envelope_bytes()
                .map_err(|_| ClientIssuanceError::Unavailable)?;
            let write = ClientGrantWrite {
                grant_id,
                organization_id: device.organization_id,
                tenant_id: device.tenant_id,
                user_id: device.user_id,
                client_device_id: device.record_id,
                device_key_id: device.device_key_id,
                generation,
                request_id,
                request_hash,
                signing_key_id: self.signer.key_id().to_owned(),
                grant_envelope: envelope_bytes,
                issued_at: issues_at,
                expires_at: expires_at_time,
                assignment_lease_until: lease_until_time,
            };
            match self.control.write_grant(&write).await {
                Ok(ClientGrantWriteOutcome::Issued { replayed, .. }) => {
                    let stored = self
                        .control
                        .grant_by_request(device.tenant_id, device.record_id, request_id)
                        .await
                        .map_err(|_| ClientIssuanceError::Unavailable)?
                        .ok_or(ClientIssuanceError::Unavailable)?;
                    return Ok(IssuedGrant {
                        record: self.verify_binding(device, stored)?,
                        replayed,
                    });
                }
                // The generation moved between the read and the insert. Re-read and
                // re-sign so the stored envelope claims the generation it actually
                // received instead of a stale one.
                Err(cloud_db::client_control::ClientControlError::GenerationConflict)
                    if attempt + 1 < MAX_GENERATION_ATTEMPTS =>
                {
                    continue;
                }
                Err(cloud_db::client_control::ClientControlError::BindingConflict) => {
                    // Same idempotency key, different request fingerprint: the caller
                    // reused a key for a materially different authorization request.
                    return Err(ClientIssuanceError::IdempotencyConflict);
                }
                Err(cloud_db::client_control::ClientControlError::GenerationConflict) => {
                    return Err(ClientIssuanceError::GenerationConflict);
                }
                Err(_) => return Err(ClientIssuanceError::Unavailable),
            }
        }
        Err(ClientIssuanceError::GenerationConflict)
    }

    /// Reads back what Cloud actually persisted. On replay this is the only
    /// acceptable answer, because it is byte-identical to the first issuance.
    fn verify_binding(
        &self,
        device: &ClientDeviceRecord,
        stored: ClientGrantRecord,
    ) -> Result<ClientGrantRecord, ClientIssuanceError> {
        if stored.device_key_id != device.device_key_id
            || stored.client_device_id != device.record_id
            || stored.user_id != device.user_id
            || stored.tenant_id != device.tenant_id
            || stored.organization_id != device.organization_id
        {
            return Err(ClientIssuanceError::NotOwned);
        }
        Ok(stored)
    }

    /// Chooses the node set for a Grant that is about to be signed.
    ///
    /// The device's previous assignment is consulted first. While its lease is
    /// still live the same nodes are reused in the same failover order, so a
    /// refresh does not silently move a working device onto a different edge. The
    /// reuse is *not* blind: every reused node must still be an active candidate
    /// right now, so a node that left service still forces fresh selection.
    ///
    /// Re-selection is the fallback for every case the lease cannot answer -- no
    /// previous assignment, a lease with no recorded deadline (a row written
    /// before migration `0047`), an elapsed window, or a node that is no longer
    /// offered.
    async fn select_nodes_for(
        &self,
        device: &ClientDeviceRecord,
        issued_at: u64,
    ) -> Result<Vec<cloud_db::client_routing::ClientNodeCandidate>, ClientIssuanceError> {
        let candidates = self
            .routing
            .active_candidates(device.tenant_id)
            .await
            .map_err(|_| ClientIssuanceError::Unavailable)?;
        if candidates.is_empty() {
            return Err(ClientIssuanceError::NoActiveNode);
        }
        let previous = self.previous_assignment(device, issued_at).await?;
        if let AssignmentPlan::Reuse { nodes } =
            plan_assignment(issued_at, previous.as_ref(), &candidates)
        {
            // A reused assignment still has to fit the frozen node ceiling. It
            // cannot fail for an assignment Cloud itself signed, but a stored blob
            // is not evidence of its own validity, so a mismatch falls back to
            // selection instead of producing an envelope the validator rejects.
            if !nodes.is_empty() && nodes.len() <= MAX_CLIENT_NODE_BACKUPS + 1 {
                // Reuse keeps the stored *identity and order*, but the values come
                // from the freshly resolved candidates, so a repaired endpoint or a
                // rotated node key is carried into the new Grant instead of the
                // values frozen into the old envelope.
                return Ok(nodes);
            }
        }
        self.select_fresh_nodes(candidates)
    }

    /// Fresh selection when no live lease can be reused.
    ///
    /// Asks for as many backups as Cloud actually has: requesting a fixed two
    /// would turn a healthy single-node tenant into a permanent "no node" error,
    /// which is worse than a shorter failover list.
    fn select_fresh_nodes(
        &self,
        candidates: Vec<cloud_db::client_routing::ClientNodeCandidate>,
    ) -> Result<Vec<cloud_db::client_routing::ClientNodeCandidate>, ClientIssuanceError> {
        let backup_count = candidates
            .len()
            .saturating_sub(1)
            .min(MAX_CLIENT_NODE_BACKUPS);
        let selection = cloud_db::client_routing::select_nodes(candidates, None, backup_count)
            .map_err(|error| match error {
                cloud_db::client_routing::ClientRoutingError::NoActiveNode => {
                    ClientIssuanceError::NoActiveNode
                }
                cloud_db::client_routing::ClientRoutingError::InvalidScope => {
                    ClientIssuanceError::NotOwned
                }
                _ => ClientIssuanceError::Unavailable,
            })?;
        let mut nodes = Vec::with_capacity(selection.backups.len() + 1);
        nodes.push(selection.primary);
        nodes.extend(selection.backups);
        Ok(nodes)
    }

    /// The assignment the device's newest active Grant already holds.
    ///
    /// The recorded deadline answers "is this still live?" *before* the envelope
    /// is decoded, which is what migration `0047` is for: an elapsed window needs
    /// no parse at all. When the window is live the envelope is decoded to learn
    /// which nodes were assigned, and its signed deadline is then compared against
    /// the recorded one. A disagreement means the derived column is stale or was
    /// written by something other than this path, so Cloud refuses to reuse and
    /// re-selects rather than trusting either value.
    async fn previous_assignment(
        &self,
        device: &ClientDeviceRecord,
        now: u64,
    ) -> Result<Option<PreviousAssignment>, ClientIssuanceError> {
        let at = timestamp(now)?;
        let Some(record) = self
            .control
            .active_grant(device.tenant_id, device.record_id, device.device_key_id, at)
            .await
            .map_err(|_| ClientIssuanceError::Unavailable)?
        else {
            return Ok(None);
        };
        // No recorded deadline is "no evidence", not "no lease": rows written
        // before `0047` must re-select rather than have Cloud invent a window.
        let Some(recorded_until) = record.assignment_lease_until else {
            return Ok(None);
        };
        let recorded_until = u64::try_from(recorded_until.timestamp())
            .map_err(|_| ClientIssuanceError::Unavailable)?;
        if !assignment_lease_state(now, recorded_until).is_reusable() {
            return Ok(None);
        }
        let envelope = ClientGrantEnvelopeV1::from_envelope_bytes(&record.grant_envelope)
            .map_err(|_| ClientIssuanceError::Unavailable)?;
        let Some(first) = envelope.payload.nodes.first() else {
            return Ok(None);
        };
        // Every node in one Grant carries the same lease instant; a Grant whose
        // nodes disagree was not produced by this path, so it is not reusable.
        let signed_until = first.assignment_lease_until;
        if envelope
            .payload
            .nodes
            .iter()
            .any(|node| node.assignment_lease_until != signed_until)
            || signed_until != recorded_until
        {
            tracing::warn!(
                event = "client_grant_assignment_lease_mismatch",
                tenant_id = %device.tenant_id,
                client_device_id = %device.record_id,
                grant_id = %record.grant_id,
                recorded_assignment_lease_until = recorded_until,
                signed_assignment_lease_until = signed_until,
                "recorded assignment lease disagrees with the signed envelope; re-selecting"
            );
            return Ok(None);
        }
        // The envelope is decoded into the minimal identity pair, so the planner
        // never handles the wire type and cannot accidentally re-interpret it.
        let nodes: Vec<AssignedNode> = envelope
            .payload
            .nodes
            .iter()
            .map(|node| AssignedNode {
                node_id: node.node_id,
                node_key_id: node.node_key_id,
            })
            .collect();
        Ok(Some(PreviousAssignment {
            lease_until: signed_until,
            nodes,
        }))
    }
}

fn traffic_mode(mode: cloud_db::client_access::ClientTrafficMode) -> ClientGrantTrafficMode {
    match mode {
        cloud_db::client_access::ClientTrafficMode::Policy => ClientGrantTrafficMode::Policy,
        cloud_db::client_access::ClientTrafficMode::Global => ClientGrantTrafficMode::Global,
    }
}

fn timestamp(seconds: u64) -> Result<DateTime<Utc>, ClientIssuanceError> {
    let seconds = i64::try_from(seconds).map_err(|_| ClientIssuanceError::Unavailable)?;
    DateTime::from_timestamp(seconds, 0).ok_or(ClientIssuanceError::Unavailable)
}

/// Fingerprint of a *materially identical* issuance request.
///
/// Deliberately excludes `grant_id`, `generation`, `issued_at`, and `expires_at`:
/// those change on every attempt, and including them would make a legitimate
/// retry look like key reuse. What remains is exactly the authorization decision
/// Cloud is being asked to make again, so reusing one idempotency key against a
/// changed policy, key, or node set is a conflict rather than a silent hand-back
/// of an older authorization.
fn issuance_fingerprint(
    device: &ClientDeviceRecord,
    request_id: Uuid,
    snapshot: &cloud_db::client_access::ClientAuthorizationSnapshot,
    nodes: &[cloud_db::client_routing::ClientNodeCandidate],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CLIENT_GRANT_REQUEST_DOMAIN);
    for value in [
        request_id.as_bytes().as_slice(),
        device.organization_id.as_bytes().as_slice(),
        device.tenant_id.as_bytes().as_slice(),
        device.user_id.as_bytes().as_slice(),
        device.record_id.as_bytes().as_slice(),
        device.device_id.as_bytes().as_slice(),
        device.device_key_id.as_bytes().as_slice(),
        device.generation.to_be_bytes().as_slice(),
        snapshot.policy.policy_id.as_bytes().as_slice(),
        snapshot.policy.generation.to_be_bytes().as_slice(),
        snapshot.policy_content_hash.as_slice(),
    ] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    for mode in &snapshot.policy.mode_capabilities {
        let value = match mode {
            cloud_db::client_access::ClientTrafficMode::Policy => b"policy".as_slice(),
            cloud_db::client_access::ClientTrafficMode::Global => b"global".as_slice(),
        };
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    for node in nodes {
        for value in [
            node.node_id.as_bytes().as_slice(),
            node.node_key_id.as_bytes().as_slice(),
            node.endpoint_id.as_bytes().as_slice(),
            node.endpoint.as_bytes(),
        ] {
            hash.update((value.len() as u32).to_be_bytes());
            hash.update(value);
        }
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloud_db::client_control::ClientPlatform;
    use cloud_db::client_routing::ClientNodeCandidate;

    fn device() -> ClientDeviceRecord {
        ClientDeviceRecord {
            record_id: Uuid::from_u128(1),
            organization_id: Uuid::from_u128(2),
            tenant_id: Uuid::from_u128(3),
            user_id: Uuid::from_u128(4),
            device_id: Uuid::from_u128(5),
            device_key_id: Uuid::from_u128(6),
            platform: ClientPlatform::Macos,
            generation: 7,
            traffic_mode: cloud_db::client_access::ClientTrafficMode::Policy,
        }
    }

    fn node(node_id: u128, endpoint: &str) -> ClientNodeCandidate {
        ClientNodeCandidate {
            node_id: Uuid::from_u128(node_id),
            node_key_id: Uuid::from_u128(node_id + 1),
            endpoint_id: Uuid::from_u128(node_id + 2),
            endpoint: endpoint.to_owned(),
            region: "cn-east".to_owned(),
            server_name: "edge.example.test".to_owned(),
            server_cert_sha256: [3; 32],
        }
    }

    #[test]
    fn issuance_fingerprint_is_stable_across_retries_and_volatile_fields() {
        let device = device();
        let request_id = Uuid::from_u128(9);
        let snapshot = snapshot();
        let nodes = vec![node(10, "edge-a.example.test:443")];
        let first = issuance_fingerprint(&device, request_id, &snapshot, &nodes);
        let second = issuance_fingerprint(&device, request_id, &snapshot, &nodes);
        assert_eq!(first, second);
        assert_ne!(first, [0; 32]);
    }

    #[test]
    fn issuance_fingerprint_changes_when_the_authorization_decision_changes() {
        let device = device();
        let request_id = Uuid::from_u128(9);
        let base = issuance_fingerprint(
            &device,
            request_id,
            &snapshot(),
            &[node(10, "edge-a.example.test:443")],
        );

        let other_key = ClientDeviceRecord {
            device_key_id: Uuid::from_u128(66),
            ..device
        };
        assert_ne!(
            base,
            issuance_fingerprint(
                &other_key,
                request_id,
                &snapshot(),
                &[node(10, "edge-a.example.test:443")]
            )
        );

        let mut published = snapshot();
        published.policy.generation = 8;
        assert_ne!(
            base,
            issuance_fingerprint(
                &device,
                request_id,
                &published,
                &[node(10, "edge-a.example.test:443")]
            )
        );

        assert_ne!(
            base,
            issuance_fingerprint(
                &device,
                request_id,
                &snapshot(),
                &[node(11, "edge-b.example.test:443")]
            )
        );
    }

    #[test]
    fn node_lease_never_exceeds_the_grant_lifetime() {
        let issued_at = 1_900_000_000_u64;
        let expires_at = issued_at + CLIENT_GRANT_TTL_SECS;
        // The deadline comes from the same pure planner the issuance path uses,
        // so this test fails if the two ever disagree about the window shape.
        let lease = assignment_lease_deadline(issued_at, CLIENT_GRANT_NODE_LEASE_SECS, expires_at)
            .expect("the default lease window is signable");
        assert!(lease > issued_at && lease <= expires_at);
        // The lease is intentionally well inside the Grant window so a node that
        // leaves service is dropped by refresh instead of lingering until expiry.
        assert_eq!(lease, issued_at + CLIENT_GRANT_NODE_LEASE_SECS);

        // A lease longer than the Grant is clamped rather than refused, because
        // running out of Grant would otherwise make issuance fail outright.
        assert_eq!(
            assignment_lease_deadline(issued_at, CLIENT_GRANT_TTL_SECS * 2, expires_at),
            Some(expires_at)
        );
    }

    fn snapshot() -> cloud_db::client_access::ClientAuthorizationSnapshot {
        use cloud_db::client_access::{ClientAccessPolicy, ClientTrafficMode};
        let device = device();
        cloud_db::client_access::ClientAuthorizationSnapshot {
            organization_id: device.organization_id,
            tenant_id: device.tenant_id,
            user_id: device.user_id,
            client_device_id: device.record_id,
            device_key_id: device.device_key_id,
            platform: device.platform,
            device_generation: device.generation,
            public_key: [5; 32],
            policy: ClientAccessPolicy {
                schema_version: 1,
                policy_id: Uuid::from_u128(20),
                tenant_id: device.tenant_id,
                generation: 7,
                mode_capabilities: vec![ClientTrafficMode::Policy],
                global_egress_enabled: false,
                allowed_resources: Vec::new(),
            },
            policy_content_hash: [6; 32],
        }
    }
}
