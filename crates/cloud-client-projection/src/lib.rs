//! Terminal `policy-projection-v1`: the signed, device-specific description of
//! what a SD-WAN Client may send over the tunnel, and how.
//!
//! A Projection is **not** the terminal Client Grant, and not the node/site
//! `runtime_configuration_v1` document either. The Grant answers "may this device
//! open a tunnel at all, to which nodes"; the Projection answers "once connected,
//! which resources, in which mode, over which DNS and underlay behaviour". They
//! are separate objects with separate signing domains and separate keys so that
//! neither can be replayed in place of the other.
//!
//! Wire contract (frozen in the Client repository as
//! `contracts/policy_projection.schema.json`):
//!
//! ```text
//! signed_payload  = every projection field except `signature` and `content_hash`
//! canonical_bytes = RFC 8785 JCS(signed_payload)
//! content_hash    = SHA-256(canonical_bytes)
//! signature       = Ed25519.Sign(key, "candy/sdwan/policy-projection/v1" || content_hash)
//! ```
//!
//! Two details are load-bearing and easy to get wrong:
//!
//! * `signing_key_id` **stays inside** the hashed payload. Only `signature` and
//!   `content_hash` are removed. Dropping `signing_key_id` too would still produce
//!   a self-consistent signature, but a different one, and every Client that
//!   verifies against the frozen contract would reject it.
//! * the signature is **standard** base64 (padded, `+`/`/`), matching the frozen
//!   `signature_vector.json`, not the URL-safe alphabet the Grant token uses.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub mod keyring;

pub const POLICY_PROJECTION_SCHEMA_VERSION: u16 = 1;
pub const POLICY_PROJECTION_TYPE: &str = "device_client";
pub const POLICY_PROJECTION_DOMAIN: &[u8] = b"candy/sdwan/policy-projection/v1";
pub const MAX_POLICY_PROJECTION_SIGNING_KEY_ID_LEN: usize = 128;
pub const MAX_POLICY_PROJECTION_STANDBY_NODES: usize = 8;
pub const MAX_POLICY_PROJECTION_RESOURCES: usize = 4096;
pub const MAX_POLICY_PROJECTION_DNS_SERVERS: usize = 8;
pub const MAX_POLICY_PROJECTION_SEARCH_DOMAINS: usize = 32;
pub const MAX_POLICY_PROJECTION_UNDERLAY_EXCLUSIONS: usize = 256;
/// Bounded like the Grant envelope so a corrupt or hostile row cannot make Cloud
/// allocate an unbounded buffer while reading a stored Projection back.
pub const MAX_POLICY_PROJECTION_BYTES: usize = 1024 * 1024;

const MAX_RESOURCE_NAME_LEN: usize = 128;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_CIDR_LEN: usize = 64;
const MAX_ENDPOINT_LEN: usize = 255;
const MAX_DNS_SERVER_LEN: usize = 128;
const MAX_SEARCH_DOMAIN_LEN: usize = 253;
const MAX_UNDERLAY_EXCLUSION_LEN: usize = 128;
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyProjectionTrafficMode {
    Policy,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProjectionDnsMode {
    CloudSplit,
    CloudGlobal,
    System,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProjectionDnsEgress {
    SelectedNode,
    CloudResolver,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProjectionDegradedBehavior {
    ProtectedFailClosed,
    ProtectedFailClosedDirectNonprotected,
    StopAll,
}

/// Audience is explicit so a Projection cannot be replayed against another
/// device, user, or key even inside the same tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProjectionAudience {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
}

/// One Cloud-selected transport node. The Client may only ever connect to nodes
/// that appear here, and only inside the lease window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProjectionNodeAssignment {
    pub node_id: Uuid,
    pub endpoint: String,
    pub priority: u8,
    pub node_key_id: Uuid,
    pub transport: String,
    pub assignment_lease_until: u64,
}

/// One authorized resource. `anyOf` in the frozen schema means a resource that
/// names neither a domain nor a CIDR authorizes nothing, so it is rejected here
/// rather than shipped as an entry the Client would have to interpret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProjectionResource {
    pub name: String,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProjectionDns {
    pub mode: PolicyProjectionDnsMode,
    pub servers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_domains: Option<Vec<String>>,
    pub leak_protection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProjectionGlobalEgress {
    pub enabled: bool,
    pub node_id: Uuid,
    pub dns_egress: PolicyProjectionDnsEgress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProjectionV1 {
    pub schema_version: u16,
    pub projection_id: Uuid,
    pub projection_type: String,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub audience: PolicyProjectionAudience,
    pub grant_id: Uuid,
    pub grant_expires_at: u64,
    pub generation: u64,
    pub content_hash: String,
    pub not_before: u64,
    pub stale_until: u64,
    pub issued_at: u64,
    pub traffic_mode: PolicyProjectionTrafficMode,
    pub mode_capabilities: Vec<PolicyProjectionTrafficMode>,
    pub selected_node: PolicyProjectionNodeAssignment,
    pub standby_nodes: Vec<PolicyProjectionNodeAssignment>,
    pub allowed_resources: Vec<PolicyProjectionResource>,
    pub dns_projection: PolicyProjectionDns,
    pub underlay_exclusions: Vec<String>,
    pub degraded_behavior: PolicyProjectionDegradedBehavior,
    pub global_egress: PolicyProjectionGlobalEgress,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyProjectionError {
    #[error("policy projection does not satisfy the v1 contract")]
    InvalidProjection,
    #[error("policy projection audience does not match the bound device")]
    AudienceMismatch,
    #[error("policy projection content hash does not match the signed payload")]
    ContentHashMismatch,
    #[error("policy projection signature is invalid")]
    InvalidSignature,
    #[error("policy projection canonicalization failed")]
    Canonicalization,
}

impl PolicyProjectionV1 {
    /// Full v1 validation, including every semantic constraint the Client's
    /// `checkProjectionSemantics` enforces. Cloud must never emit a Projection
    /// this rejects: the Client treats a violation as a hard verification failure
    /// and stays disconnected, so shipping one is an outage, not a warning.
    pub fn validate(&self) -> Result<(), PolicyProjectionError> {
        if self.schema_version != POLICY_PROJECTION_SCHEMA_VERSION
            || self.projection_type != POLICY_PROJECTION_TYPE
            || self.projection_id.is_nil()
            || self.grant_id.is_nil()
            || self.generation == 0
            || self.grant_expires_at == 0
            || self.not_before == 0
            || self.issued_at == 0
            || self.stale_until == 0
        {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        let audience = &self.audience;
        if [
            audience.tenant_id,
            audience.user_id,
            audience.device_id,
            audience.device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
        {
            return Err(PolicyProjectionError::AudienceMismatch);
        }
        if audience.tenant_id != self.tenant_id
            || audience.user_id != self.user_id
            || audience.device_id != self.device_id
            || audience.device_key_id != self.device_key_id
        {
            return Err(PolicyProjectionError::AudienceMismatch);
        }
        // A Projection may never outlive the Grant that authorizes the tunnel, so
        // the whole window is anchored to `grant_expires_at` rather than to a
        // second, independently drifting lifetime.
        if self.not_before > self.issued_at
            || self.issued_at > self.stale_until
            || self.stale_until > self.grant_expires_at
        {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        if self.mode_capabilities.is_empty()
            || self.mode_capabilities.len() > 2
            || has_duplicates(&self.mode_capabilities)
            || !self.mode_capabilities.contains(&self.traffic_mode)
        {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        let mut seen_nodes = std::collections::HashSet::new();
        if self.standby_nodes.len() > MAX_POLICY_PROJECTION_STANDBY_NODES {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        for node in std::iter::once(&self.selected_node).chain(self.standby_nodes.iter()) {
            validate_node(node, self.stale_until)?;
            if !seen_nodes.insert(node.node_id) {
                return Err(PolicyProjectionError::InvalidProjection);
            }
        }
        if self.allowed_resources.len() > MAX_POLICY_PROJECTION_RESOURCES {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        for resource in &self.allowed_resources {
            validate_resource(resource)?;
        }
        validate_dns(&self.dns_projection)?;
        if self.underlay_exclusions.is_empty()
            || self.underlay_exclusions.len() > MAX_POLICY_PROJECTION_UNDERLAY_EXCLUSIONS
            || has_duplicates(&self.underlay_exclusions)
        {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        for exclusion in &self.underlay_exclusions {
            if exclusion.is_empty()
                || exclusion.len() > MAX_UNDERLAY_EXCLUSION_LEN
                || exclusion.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(PolicyProjectionError::InvalidProjection);
            }
        }
        // The global egress node must be one Cloud actually assigned, otherwise a
        // client in global mode would be told to exit through a node its Grant
        // does not cover.
        if self.global_egress.node_id.is_nil() || !seen_nodes.contains(&self.global_egress.node_id)
        {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        match self.traffic_mode {
            PolicyProjectionTrafficMode::Global => {
                if !self.global_egress.enabled
                    || self.global_egress.dns_egress == PolicyProjectionDnsEgress::None
                {
                    return Err(PolicyProjectionError::InvalidProjection);
                }
            }
            // Policy mode must not carry a latent default-route permission: the
            // Client reads these fields, so an "off but enabled" combination would
            // be exactly the local `global=true` bypass the design forbids.
            PolicyProjectionTrafficMode::Policy => {
                if self.global_egress.enabled
                    || self.global_egress.dns_egress != PolicyProjectionDnsEgress::None
                {
                    return Err(PolicyProjectionError::InvalidProjection);
                }
            }
        }
        if self.signing_key_id.is_empty()
            || self.signing_key_id.len() > MAX_POLICY_PROJECTION_SIGNING_KEY_ID_LEN
            || !self
                .signing_key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
        {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        Ok(())
    }

    /// RFC 8785 JCS over the signed payload, i.e. every field except `signature`
    /// and `content_hash`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyProjectionError> {
        let mut value =
            serde_json::to_value(self).map_err(|_| PolicyProjectionError::Canonicalization)?;
        let object = value
            .as_object_mut()
            .ok_or(PolicyProjectionError::Canonicalization)?;
        // Only these two are unsigned. `signing_key_id` intentionally remains in
        // the hashed view so the key identity itself cannot be swapped.
        object.remove("signature");
        object.remove("content_hash");
        serde_json_canonicalizer::to_vec(&value)
            .map_err(|_| PolicyProjectionError::Canonicalization)
    }

    pub fn content_hash(&self) -> Result<[u8; 32], PolicyProjectionError> {
        self.validate()?;
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Storage and wire form: canonical JSON of the complete signed object.
    ///
    /// Storing canonical bytes (rather than Cloud's insertion order) means a
    /// replay can hand back byte-identical content and a reader never has to
    /// re-serialize, so the signature cannot drift across restarts.
    pub fn to_envelope_bytes(&self) -> Result<Vec<u8>, PolicyProjectionError> {
        serde_json_canonicalizer::to_vec(self).map_err(|_| PolicyProjectionError::Canonicalization)
    }

    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, PolicyProjectionError> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_PROJECTION_BYTES {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        serde_json::from_slice(bytes).map_err(|_| PolicyProjectionError::InvalidProjection)
    }

    /// Verifies hash, signing key id, and signature exactly as a Client/Core
    /// verifier must.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), PolicyProjectionError> {
        self.validate()?;
        let expected_hash = self.content_hash()?;
        if parse_content_hash(&self.content_hash)? != expected_hash {
            return Err(PolicyProjectionError::ContentHashMismatch);
        }
        let signature_bytes = BASE64_STANDARD
            .decode(&self.signature)
            .map_err(|_| PolicyProjectionError::InvalidSignature)?;
        if signature_bytes.len() != ED25519_SIGNATURE_LEN {
            return Err(PolicyProjectionError::InvalidSignature);
        }
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| PolicyProjectionError::InvalidSignature)?;
        verifying_key
            .verify(&signing_message(&expected_hash), &signature)
            .map_err(|_| PolicyProjectionError::InvalidSignature)
    }
}

/// Cloud-side signing capability. The Projection key never leaves Cloud; the
/// Client and Node/Core only ever receive the matching verifying key.
#[derive(Clone)]
pub struct PolicyProjectionSigner {
    signing_key: SigningKey,
    key_id: String,
}

impl PolicyProjectionSigner {
    pub fn new(
        key_id: impl Into<String>,
        signing_key: SigningKey,
    ) -> Result<Self, PolicyProjectionError> {
        let key_id = key_id.into();
        if key_id.is_empty()
            || key_id.len() > MAX_POLICY_PROJECTION_SIGNING_KEY_ID_LEN
            || !key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
        {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        Ok(Self {
            signing_key,
            key_id,
        })
    }

    /// Loads the Projection signing key from a deployment-private file.
    pub fn from_key_file(
        path: &std::path::Path,
        key_id: impl Into<String>,
    ) -> std::io::Result<Self> {
        let seed = keyring::load_signing_seed(path)?;
        Self::new(key_id, SigningKey::from_bytes(&seed)).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Signs one projection, overwriting `signing_key_id` and `content_hash` so a
    /// caller cannot assemble a document whose claimed key or hash disagrees with
    /// the bytes Cloud actually signs.
    pub fn sign(
        &self,
        mut projection: PolicyProjectionV1,
    ) -> Result<PolicyProjectionV1, PolicyProjectionError> {
        projection.signing_key_id = self.key_id.clone();
        projection.content_hash = String::new();
        projection.signature = String::new();
        let content_hash = projection.content_hash()?;
        let signature = self.signing_key.sign(&signing_message(&content_hash));
        let mut signed = projection;
        signed.content_hash = format_content_hash(&content_hash);
        signed.signature = BASE64_STANDARD.encode(signature.to_bytes());
        // Self-verify before returning: Cloud must never hand out a Projection it
        // cannot itself validate against the Client's frozen rules.
        signed.verify(&self.verifying_key())?;
        Ok(signed)
    }
}

fn validate_node(
    node: &PolicyProjectionNodeAssignment,
    stale_until: u64,
) -> Result<(), PolicyProjectionError> {
    if node.node_id.is_nil()
        || node.node_key_id.is_nil()
        || node.endpoint.is_empty()
        || node.endpoint.len() > MAX_ENDPOINT_LEN
        || node.endpoint.bytes().any(|byte| byte.is_ascii_control())
        || node.priority == 0
        || (node.transport != "quic" && node.transport != "tls_tcp")
        || node.assignment_lease_until == 0
        // A lease beyond `stale_until` would keep a node usable after the
        // projection itself stopped being trustworthy.
        || node.assignment_lease_until > stale_until
    {
        return Err(PolicyProjectionError::InvalidProjection);
    }
    Ok(())
}

fn validate_resource(resource: &PolicyProjectionResource) -> Result<(), PolicyProjectionError> {
    if resource.name.is_empty()
        || resource.name.len() > MAX_RESOURCE_NAME_LEN
        || !resource
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
        || (resource.domains.is_empty() && resource.cidrs.is_empty())
        || resource.domains.len() > 1024
        || resource.cidrs.len() > 1024
        || resource.ports.len() > 128
        || has_duplicates(&resource.domains)
        || has_duplicates(&resource.cidrs)
        || has_duplicates(&resource.ports)
    {
        return Err(PolicyProjectionError::InvalidProjection);
    }
    if resource.domains.iter().any(|domain| {
        domain.is_empty()
            || domain.len() > MAX_DOMAIN_LEN
            || domain.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(PolicyProjectionError::InvalidProjection);
    }
    if resource.cidrs.iter().any(|cidr| {
        cidr.is_empty()
            || cidr.len() > MAX_CIDR_LEN
            || cidr.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(PolicyProjectionError::InvalidProjection);
    }
    // Port 0 is not a usable destination and the frozen schema starts at 1.
    if resource.ports.contains(&0) {
        return Err(PolicyProjectionError::InvalidProjection);
    }
    Ok(())
}

fn validate_dns(dns: &PolicyProjectionDns) -> Result<(), PolicyProjectionError> {
    if dns.servers.len() > MAX_POLICY_PROJECTION_DNS_SERVERS {
        return Err(PolicyProjectionError::InvalidProjection);
    }
    if dns.servers.iter().any(|server| {
        server.is_empty()
            || server.len() > MAX_DNS_SERVER_LEN
            || server.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(PolicyProjectionError::InvalidProjection);
    }
    if let Some(search_domains) = &dns.search_domains {
        if search_domains.len() > MAX_POLICY_PROJECTION_SEARCH_DOMAINS {
            return Err(PolicyProjectionError::InvalidProjection);
        }
        if search_domains.iter().any(|domain| {
            domain.is_empty()
                || domain.len() > MAX_SEARCH_DOMAIN_LEN
                || domain.bytes().any(|byte| byte.is_ascii_control())
        }) {
            return Err(PolicyProjectionError::InvalidProjection);
        }
    }
    Ok(())
}

fn signing_message(content_hash: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(POLICY_PROJECTION_DOMAIN.len() + content_hash.len());
    message.extend_from_slice(POLICY_PROJECTION_DOMAIN);
    message.extend_from_slice(content_hash);
    message
}

pub fn format_content_hash(hash: &[u8; 32]) -> String {
    let mut output = String::with_capacity(7 + 64);
    output.push_str("sha256:");
    for byte in hash {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn parse_content_hash(value: &str) -> Result<[u8; 32], PolicyProjectionError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(PolicyProjectionError::InvalidProjection)?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PolicyProjectionError::InvalidProjection);
    }
    let mut hash = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let text =
            std::str::from_utf8(chunk).map_err(|_| PolicyProjectionError::InvalidProjection)?;
        hash[index] =
            u8::from_str_radix(text, 16).map_err(|_| PolicyProjectionError::InvalidProjection)?;
    }
    Ok(hash)
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}
