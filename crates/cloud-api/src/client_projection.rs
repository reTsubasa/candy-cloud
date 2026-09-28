//! Terminal PolicyProjection issuance orchestration.
//!
//! This is the Projection counterpart to `client_issuance`: the only path that
//! turns Cloud authorization state into a signed Projection, and the only place
//! that decides when a stored Projection may be answered instead of re-signed.
//!
//! The Grant path and this path are deliberately separate objects with separate
//! signing domains and separate keys. A Grant authorizes a tunnel and names the
//! nodes; a Projection describes what may cross it. Neither can be replayed as
//! the other.
//!
//! Four invariants shape this code:
//!
//! 1. **Cloud is the only authority.** The traffic mode comes from the device
//!    row, the resources from the bound policy, the DNS/underlay/degraded
//!    behaviour from the published settings document, and the nodes from the
//!    Grant Cloud already signed. Nothing is taken from the request body.
//! 2. **No invented values.** With no bound policy, no published settings, or no
//!    active Grant, Cloud refuses to sign. A Projection is fail-closed, so the
//!    alternative -- filling in a default underlay exclusion or DNS server --
//!    would be a routing decision nobody reviewed.
//! 3. **A replay returns the exact bytes Cloud signed before.** Re-signing would
//!    re-stamp `issued_at`/`stale_until` and let a device widen its own window by
//!    polling.
//! 4. **A poll is idempotent when nothing changed.** `inputs_hash` is recomputed
//!    on every read; if it matches the stored document and the window is still
//!    valid, the stored bytes are returned rather than a new generation being
//!    burned on a document that did not change.

use chrono::{DateTime, Utc};
use cloud_client_grant::ClientGrantEnvelopeV1;
use cloud_client_projection::{
    format_content_hash, PolicyProjectionAudience, PolicyProjectionDegradedBehavior,
    PolicyProjectionDns, PolicyProjectionDnsEgress, PolicyProjectionDnsMode,
    PolicyProjectionGlobalEgress, PolicyProjectionNodeAssignment, PolicyProjectionResource,
    PolicyProjectionSigner, PolicyProjectionTrafficMode, PolicyProjectionV1,
    POLICY_PROJECTION_SCHEMA_VERSION, POLICY_PROJECTION_TYPE,
};
use cloud_db::client_access::ClientAccessPolicyRepository;
use cloud_db::client_control::{ClientControlRepository, ClientDeviceRecord, ClientGrantRecord};
use cloud_db::client_projection::{
    projection_inputs_fingerprint, ClientProjectionRecord, ClientProjectionRepository,
    ClientProjectionWrite, ClientProjectionWriteOutcome,
};
use cloud_db::client_settings::{ClientProjectionSettings, ClientProjectionSettingsRepository};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// How long one signed Projection stays usable. Kept shorter than the Grant so a
/// resource or settings change is picked up by refresh rather than by revocation
/// alone, and clamped to the Grant's expiry because a Projection may never
/// outlive the tunnel authorization it depends on.
const CLIENT_PROJECTION_TTL_SECS: u64 = 6 * 60 * 60;

/// A stored Projection is only reused while it still has at least this much life
/// left. Without it a client that polls just before `stale_until` would be handed
/// a document that expires on arrival and would have to poll again immediately,
/// which turns a healthy refresh into a tight loop.
const CLIENT_PROJECTION_REFRESH_MARGIN_SECS: u64 = 30 * 60;

// Compile-time proof of the relationship the refresh design depends on: a margin
// at or above the lifetime would make every Projection look due for refresh and
// burn a new generation on every poll. This is a `const` assertion rather than a
// test assertion because a constant comparison inside `#[test]` is folded away.
const _: () = assert!(CLIENT_PROJECTION_REFRESH_MARGIN_SECS < CLIENT_PROJECTION_TTL_SECS);

/// Bounded compare-and-set retries, mirroring the Grant path. A concurrent
/// issuance for the same device moves the generation; a small fixed bound keeps a
/// pathological race from turning into an unbounded signing loop.
const MAX_GENERATION_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProjectionError {
    /// The device exists and is owned by the caller, but Cloud has no active
    /// policy bound to it. The client stays disconnected and retries later.
    PolicyNotBound,
    /// Cloud has no published projection settings for the tenant. Signing would
    /// require inventing DNS, underlay, or degraded behaviour, so Cloud refuses.
    SettingsNotPublished,
    /// The device has no active Grant. A Projection is always anchored to one.
    GrantNotIssued,
    /// The active Grant was signed against a different policy generation or
    /// content hash than the one now bound to the device. Signing a Projection
    /// here would describe resources the Grant does not authorize, so Cloud
    /// refuses and the client refreshes its Grant first.
    GrantStale,
    /// The active Grant's node leases have expired. A Projection may not name a
    /// node whose lease Cloud already considers over, so the client must refresh
    /// its Grant to obtain fresh leases before a Projection can be signed.
    NodeLeaseExpired,
    /// Cloud has no tenant node it can currently authorize for terminal traffic.
    NoActiveNode,
    /// The device is in a mode its bound policy does not permit. This can only
    /// happen if the policy changed after the mode was recorded, and it must be
    /// surfaced rather than silently downgrading the device.
    TrafficModeNotPermitted,
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
pub struct IssuedProjection {
    /// Exactly what Cloud persisted. On a replay this is byte-identical to the
    /// first issuance, because Cloud returns stored bytes instead of re-signing.
    pub record: ClientProjectionRecord,
    pub replayed: bool,
}

#[derive(Clone, Copy)]
pub struct ClientProjectionService<'a> {
    pub control: &'a ClientControlRepository,
    pub projections: &'a ClientProjectionRepository,
    pub access: &'a ClientAccessPolicyRepository,
    pub settings: &'a ClientProjectionSettingsRepository,
    pub signer: &'a PolicyProjectionSigner,
}

/// Everything the signed document depends on, read once so the signature and the
/// stored `inputs_hash` describe the same Cloud state.
struct ProjectionInputs {
    settings: ClientProjectionSettings,
    settings_content_hash: [u8; 32],
    policy_generation: u64,
    policy_content_hash: [u8; 32],
    mode_capabilities: Vec<PolicyProjectionTrafficMode>,
    traffic_mode: PolicyProjectionTrafficMode,
    resources: Vec<PolicyProjectionResource>,
    grant: ClientGrantRecord,
    nodes: Vec<PolicyProjectionNodeAssignment>,
}

impl<'a> ClientProjectionService<'a> {
    /// Issues, replays by request id, or answers with the unchanged current
    /// Projection for one owned device.
    pub async fn projection_for_device(
        &self,
        device: &ClientDeviceRecord,
        request_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<IssuedProjection, ClientProjectionError> {
        if request_id.is_nil() {
            return Err(ClientProjectionError::IdempotencyConflict);
        }
        // A retry of an already-issued request must not re-sign, even if the
        // policy or node set moved on since -- that is exactly the case a re-sign
        // would get wrong.
        if let Some(record) = self
            .projections
            .projection_by_request(device.tenant_id, device.record_id, request_id)
            .await
            .map_err(|_| ClientProjectionError::Unavailable)?
        {
            return Ok(IssuedProjection {
                record: self.verify_binding(device, record)?,
                replayed: true,
            });
        }
        let issued_at =
            u64::try_from(now.timestamp()).map_err(|_| ClientProjectionError::Unavailable)?;

        for attempt in 0..MAX_GENERATION_ATTEMPTS {
            let inputs = self.gather_inputs(device, issued_at).await?;
            let inputs_hash = projection_inputs_fingerprint(
                inputs.policy_generation,
                &inputs.policy_content_hash,
                inputs.settings.generation,
                &inputs.settings_content_hash,
                device.traffic_mode,
                inputs.grant.grant_id,
                &inputs
                    .nodes
                    .iter()
                    .map(|node| node.node_id)
                    .collect::<Vec<_>>(),
            );
            // Only the *first* attempt may answer from storage. A later attempt is
            // already re-signing because a generation or input changed, so treating
            // a leftover row as current would loop.
            if attempt == 0 {
                if let Some(current) = self
                    .projections
                    .current_projection(
                        device.tenant_id,
                        device.record_id,
                        device.device_key_id,
                        now,
                    )
                    .await
                    .map_err(|_| ClientProjectionError::Unavailable)?
                {
                    if current.inputs_hash == inputs_hash {
                        let remaining = current
                            .stale_until
                            .timestamp()
                            .saturating_sub(now.timestamp());
                        if remaining
                            >= i64::try_from(CLIENT_PROJECTION_REFRESH_MARGIN_SECS)
                                .unwrap_or(i64::MAX)
                        {
                            return Ok(IssuedProjection {
                                record: self.verify_binding(device, current)?,
                                replayed: true,
                            });
                        }
                    }
                }
            }
            let generation = self
                .projections
                .next_projection_generation(device.tenant_id, device.record_id)
                .await
                .map_err(|_| ClientProjectionError::Unavailable)?;
            let projection_id = Uuid::now_v7();
            let request_hash = request_fingerprint(
                device,
                request_id,
                inputs.policy_generation,
                &inputs.policy_content_hash,
                &inputs.settings,
                &inputs.grant,
                &inputs.nodes,
            );
            let projection =
                self.assemble(device, &inputs, projection_id, generation, issued_at)?;
            let signed = self
                .signer
                .sign(projection)
                .map_err(|_| ClientProjectionError::Unavailable)?;
            let content_hash: [u8; 32] = signed
                .content_hash()
                .map_err(|_| ClientProjectionError::Unavailable)?;
            let envelope_bytes = signed
                .to_envelope_bytes()
                .map_err(|_| ClientProjectionError::Unavailable)?;
            let stale_until = signed.stale_until;
            let write = ClientProjectionWrite {
                projection_id,
                organization_id: device.organization_id,
                tenant_id: device.tenant_id,
                user_id: device.user_id,
                client_device_id: device.record_id,
                device_key_id: device.device_key_id,
                grant_id: inputs.grant.grant_id,
                policy_generation: inputs.policy_generation,
                settings_generation: inputs.settings.generation,
                device_traffic_mode: device.traffic_mode,
                generation,
                request_id,
                request_hash,
                content_hash,
                inputs_hash,
                signing_key_id: self.signer.key_id().to_owned(),
                projection_envelope: envelope_bytes,
                issued_at: timestamp(issued_at)?,
                stale_until: timestamp(stale_until)?,
            };
            match self.projections.write_projection(&write).await {
                Ok(ClientProjectionWriteOutcome::Published { replayed, .. }) => {
                    let stored = self
                        .projections
                        .projection_by_request(device.tenant_id, device.record_id, request_id)
                        .await
                        .map_err(|_| ClientProjectionError::Unavailable)?
                        .ok_or(ClientProjectionError::Unavailable)?;
                    return Ok(IssuedProjection {
                        record: self.verify_binding(device, stored)?,
                        replayed,
                    });
                }
                // The generation moved between the read and the insert. Re-read and
                // re-sign so the stored envelope claims the generation it actually
                // received instead of a stale one.
                Err(cloud_db::client_projection::ClientProjectionError::GenerationConflict)
                    if attempt + 1 < MAX_GENERATION_ATTEMPTS =>
                {
                    continue;
                }
                Err(cloud_db::client_projection::ClientProjectionError::BindingConflict) => {
                    return Err(ClientProjectionError::IdempotencyConflict);
                }
                Err(cloud_db::client_projection::ClientProjectionError::GenerationConflict) => {
                    return Err(ClientProjectionError::GenerationConflict);
                }
                Err(_) => return Err(ClientProjectionError::Unavailable),
            }
        }
        Err(ClientProjectionError::GenerationConflict)
    }

    /// Reads every Cloud-side input the signature covers.
    async fn gather_inputs(
        &self,
        device: &ClientDeviceRecord,
        issued_at: u64,
    ) -> Result<ProjectionInputs, ClientProjectionError> {
        let snapshot = self
            .access
            .authorization_snapshot(
                device.organization_id,
                device.tenant_id,
                device.user_id,
                device.record_id,
            )
            .await
            .map_err(|_| ClientProjectionError::Unavailable)?
            .ok_or(ClientProjectionError::PolicyNotBound)?;
        if snapshot.device_key_id != device.device_key_id {
            // The bound key changed since the caller resolved the device, so the
            // Projection would be addressed to a key the client no longer holds.
            return Err(ClientProjectionError::IdempotencyConflict);
        }
        let settings = self
            .settings
            .current(device.tenant_id)
            .await
            .map_err(|_| ClientProjectionError::Unavailable)?
            .ok_or(ClientProjectionError::SettingsNotPublished)?;
        let settings_content_hash = settings
            .content_hash()
            .map_err(|_| ClientProjectionError::Unavailable)?;
        let mode_capabilities: Vec<PolicyProjectionTrafficMode> = snapshot
            .policy
            .mode_capabilities
            .iter()
            .map(|mode| traffic_mode(*mode))
            .collect();
        let traffic_mode = traffic_mode(device.traffic_mode);
        if !mode_capabilities.contains(&traffic_mode) {
            return Err(ClientProjectionError::TrafficModeNotPermitted);
        }
        let grant = self
            .control
            .active_grant(
                device.tenant_id,
                device.record_id,
                device.device_key_id,
                timestamp(issued_at)?,
            )
            .await
            .map_err(|_| ClientProjectionError::Unavailable)?
            .ok_or(ClientProjectionError::GrantNotIssued)?;
        // The node set is read out of the Grant Cloud already signed rather than
        // re-selected. Re-running selection could name a node outside the Grant,
        // and the Client's frozen validator would then reject the whole document
        // because `global_egress.node_id` must be one of the assigned nodes.
        let nodes = grant_nodes(&grant)?;
        // The Projection describes the resources of a policy generation, so it may
        // only be signed against a Grant that authorizes that same generation.
        if grant_policy_binding(&grant)?
            != (
                snapshot.policy.policy_id,
                snapshot.policy.generation,
                snapshot.policy_content_hash,
            )
        {
            return Err(ClientProjectionError::GrantStale);
        }
        let resources = snapshot
            .policy
            .allowed_resources
            .iter()
            .map(|resource| PolicyProjectionResource {
                name: resource.name.clone(),
                domains: resource.domains.clone(),
                cidrs: resource.cidrs.clone(),
                ports: resource.ports.clone(),
            })
            .collect();
        Ok(ProjectionInputs {
            settings,
            settings_content_hash,
            policy_generation: snapshot.policy.generation,
            policy_content_hash: snapshot.policy_content_hash,
            mode_capabilities,
            traffic_mode,
            resources,
            grant,
            nodes,
        })
    }

    fn assemble(
        &self,
        device: &ClientDeviceRecord,
        inputs: &ProjectionInputs,
        projection_id: Uuid,
        generation: u64,
        issued_at: u64,
    ) -> Result<PolicyProjectionV1, ClientProjectionError> {
        let grant_expires_at = u64::try_from(inputs.grant.expires_at.timestamp())
            .map_err(|_| ClientProjectionError::Unavailable)?;
        // A Projection may never outlive the Grant, and neither may a node lease:
        // the lease is clamped to `stale_until` so the Client's frozen validator
        // never sees a node that stays usable after the document expired.
        let stale_until = issued_at
            .checked_add(CLIENT_PROJECTION_TTL_SECS)
            .ok_or(ClientProjectionError::Unavailable)?
            .min(grant_expires_at);
        if stale_until <= issued_at {
            return Err(ClientProjectionError::GrantNotIssued);
        }
        let mut nodes = inputs.nodes.clone();
        for node in &mut nodes {
            node.assignment_lease_until = node.assignment_lease_until.min(stale_until);
            if node.assignment_lease_until <= issued_at {
                return Err(ClientProjectionError::NodeLeaseExpired);
            }
        }
        let selected_node = nodes
            .first()
            .cloned()
            .ok_or(ClientProjectionError::NoActiveNode)?;
        let egress_node_id = selected_node.node_id;
        let standby_nodes = nodes[1..].to_vec();
        let global = inputs.traffic_mode == PolicyProjectionTrafficMode::Global;
        let (dns_mode, dns_egress) = if global {
            (
                PolicyProjectionDnsMode::CloudGlobal,
                PolicyProjectionDnsEgress::SelectedNode,
            )
        } else {
            (
                PolicyProjectionDnsMode::CloudSplit,
                PolicyProjectionDnsEgress::None,
            )
        };
        Ok(PolicyProjectionV1 {
            schema_version: POLICY_PROJECTION_SCHEMA_VERSION,
            projection_id,
            projection_type: POLICY_PROJECTION_TYPE.to_owned(),
            tenant_id: device.tenant_id,
            user_id: device.user_id,
            device_id: device.device_id,
            device_key_id: device.device_key_id,
            audience: PolicyProjectionAudience {
                tenant_id: device.tenant_id,
                user_id: device.user_id,
                device_id: device.device_id,
                device_key_id: device.device_key_id,
            },
            grant_id: inputs.grant.grant_id,
            grant_expires_at,
            generation,
            content_hash: String::new(),
            not_before: issued_at,
            stale_until,
            issued_at,
            traffic_mode: inputs.traffic_mode,
            mode_capabilities: inputs.mode_capabilities.clone(),
            selected_node,
            standby_nodes,
            allowed_resources: inputs.resources.clone(),
            dns_projection: PolicyProjectionDns {
                mode: dns_mode,
                servers: inputs.settings.dns_servers.clone(),
                // An absent search-domain list and an empty one mean the same
                // thing to the Client; omitting it keeps the document minimal.
                search_domains: if inputs.settings.search_domains.is_empty() {
                    None
                } else {
                    Some(inputs.settings.search_domains.clone())
                },
                leak_protection: true,
            },
            underlay_exclusions: inputs.settings.underlay_exclusions.clone(),
            degraded_behavior: degraded_behavior(inputs.settings.degraded_behavior),
            // Policy mode must carry no latent default-route permission, so the
            // node is only named; `enabled` stays false exactly as the frozen
            // Client validation requires.
            global_egress: PolicyProjectionGlobalEgress {
                enabled: global,
                node_id: egress_node_id,
                dns_egress,
            },
            signing_key_id: String::new(),
            signature: String::new(),
        })
    }

    /// Reads back what Cloud actually persisted and re-checks the binding.
    fn verify_binding(
        &self,
        device: &ClientDeviceRecord,
        stored: ClientProjectionRecord,
    ) -> Result<ClientProjectionRecord, ClientProjectionError> {
        if stored.device_key_id != device.device_key_id
            || stored.client_device_id != device.record_id
            || stored.user_id != device.user_id
            || stored.tenant_id != device.tenant_id
            || stored.organization_id != device.organization_id
        {
            return Err(ClientProjectionError::NotOwned);
        }
        Ok(stored)
    }
}

/// Reads the node assignments out of a stored Grant envelope.
///
/// The envelope bytes were signed and persisted by the Grant path, so this only
/// parses them; it must never re-select or re-sign. A parse failure is an
/// internal error, not a client error: Cloud stored the envelope itself.
fn grant_nodes(
    grant: &ClientGrantRecord,
) -> Result<Vec<PolicyProjectionNodeAssignment>, ClientProjectionError> {
    let envelope = ClientGrantEnvelopeV1::from_envelope_bytes(&grant.grant_envelope)
        .map_err(|_| ClientProjectionError::Unavailable)?;
    let nodes: Vec<PolicyProjectionNodeAssignment> = envelope
        .payload
        .nodes
        .iter()
        .map(|node| PolicyProjectionNodeAssignment {
            node_id: node.node_id,
            endpoint: node.endpoint.clone(),
            priority: node.priority,
            node_key_id: node.node_key_id,
            transport: node.transport.clone(),
            assignment_lease_until: node.assignment_lease_until,
        })
        .collect();
    if nodes.is_empty() {
        return Err(ClientProjectionError::NoActiveNode);
    }
    Ok(nodes)
}

/// The `(policy_id, generation, content_hash)` the Grant was signed against.
fn grant_policy_binding(
    grant: &ClientGrantRecord,
) -> Result<(Uuid, u64, [u8; 32]), ClientProjectionError> {
    let envelope = ClientGrantEnvelopeV1::from_envelope_bytes(&grant.grant_envelope)
        .map_err(|_| ClientProjectionError::Unavailable)?;
    let binding = envelope.payload.policy;
    let hash =
        parse_content_hash(&binding.content_hash).ok_or(ClientProjectionError::Unavailable)?;
    Ok((binding.policy_id, binding.generation, hash))
}

/// Parses the `sha256:<hex>` form back to bytes, so two hashes can be compared as
/// bytes instead of as text.
///
/// This is the single parser for the wire form on the terminal plane. It accepts
/// exactly the frozen Client pattern `^sha256:[0-9a-f]{64}$`, which is also the
/// only spelling `format_content_hash` emits: a second spelling of a value the
/// contract defines one way would let a Client pass here and fail against a
/// stricter peer.
pub(crate) fn parse_content_hash(value: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix("sha256:")?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut hash = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        hash[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(hash)
}

fn traffic_mode(mode: cloud_db::client_access::ClientTrafficMode) -> PolicyProjectionTrafficMode {
    match mode {
        cloud_db::client_access::ClientTrafficMode::Policy => PolicyProjectionTrafficMode::Policy,
        cloud_db::client_access::ClientTrafficMode::Global => PolicyProjectionTrafficMode::Global,
    }
}

fn degraded_behavior(
    behavior: cloud_db::client_settings::ClientDegradedBehavior,
) -> PolicyProjectionDegradedBehavior {
    match behavior {
        cloud_db::client_settings::ClientDegradedBehavior::ProtectedFailClosed => {
            PolicyProjectionDegradedBehavior::ProtectedFailClosed
        }
        cloud_db::client_settings::ClientDegradedBehavior::ProtectedFailClosedDirectNonprotected => {
            PolicyProjectionDegradedBehavior::ProtectedFailClosedDirectNonprotected
        }
        cloud_db::client_settings::ClientDegradedBehavior::StopAll => {
            PolicyProjectionDegradedBehavior::StopAll
        }
    }
}

fn timestamp(seconds: u64) -> Result<DateTime<Utc>, ClientProjectionError> {
    let seconds = i64::try_from(seconds).map_err(|_| ClientProjectionError::Unavailable)?;
    DateTime::from_timestamp(seconds, 0).ok_or(ClientProjectionError::Unavailable)
}

/// Fingerprint of the issuance request, excluding the fields that change on
/// every signing attempt (`projection_id`, `generation`, `issued_at`,
/// `stale_until`) so a legitimate retry replays while a materially different
/// request under the same key conflicts.
fn request_fingerprint(
    device: &ClientDeviceRecord,
    request_id: Uuid,
    policy_generation: u64,
    policy_content_hash: &[u8; 32],
    settings: &ClientProjectionSettings,
    grant: &ClientGrantRecord,
    nodes: &[PolicyProjectionNodeAssignment],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(cloud_db::client_projection::CLIENT_PROJECTION_REQUEST_DOMAIN);
    hash.update(device.organization_id.as_bytes());
    hash.update(device.tenant_id.as_bytes());
    hash.update(device.user_id.as_bytes());
    hash.update(device.record_id.as_bytes());
    hash.update(device.device_key_id.as_bytes());
    hash.update(device.traffic_mode.to_database_value().as_bytes());
    hash.update(request_id.as_bytes());
    hash.update(grant.grant_id.as_bytes());
    hash.update(policy_generation.to_be_bytes());
    hash.update(policy_content_hash);
    hash.update(settings.generation.to_be_bytes());
    if let Ok(document) = serde_json::to_vec(settings) {
        hash.update((document.len() as u32).to_be_bytes());
        hash.update(&document);
    }
    hash.update((nodes.len() as u32).to_be_bytes());
    for node in nodes {
        hash.update(node.node_id.as_bytes());
        hash.update((node.endpoint.len() as u32).to_be_bytes());
        hash.update(node.endpoint.as_bytes());
        hash.update(node.node_key_id.as_bytes());
        hash.update(node.assignment_lease_until.to_be_bytes());
    }
    hash.finalize().into()
}

/// Re-exported so the HTTP layer can compare an `If-None-Match` header against a
/// stored record without duplicating the wire format.
pub fn content_hash_text(hash: &[u8; 32]) -> String {
    format_content_hash(hash)
}
