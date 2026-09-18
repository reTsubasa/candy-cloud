//! Terminal `client-grant-v1`: the signed authorization a SD-WAN Client device
//! presents to Node/Core before any business traffic is allowed.
//!
//! This is deliberately **not** the existing node `AccessGrantPayloadV1`. A node
//! Grant binds `devices`/`device_keys`, a Node Pool entitlement, and Site/Segment
//! projection. A terminal Client Grant binds a Cloud human-owned `client_device`,
//! the terminal policy generation, and the Cloud-selected node lease set. Nodes and
//! Core must verify this object through its own object type, never by reusing the
//! node Grant path.
//!
//! Wire contract:
//!
//! ```text
//! signed_payload  = payload 字段全集
//! canonical_bytes = RFC 8785 JCS(signed_payload)
//! content_hash    = SHA-256(canonical_bytes)
//! signature       = Ed25519.Sign(key, "candy/sdwan/client-grant/v1" || content_hash)
//! grant_token     = base64url(JCS(envelope))
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub mod keyring;

pub const CLIENT_GRANT_SCHEMA_VERSION: u16 = 1;
pub const CLIENT_GRANT_DOMAIN: &[u8] = b"candy/sdwan/client-grant/v1";
pub const CLIENT_GRANT_TTL_SECS: u64 = 24 * 60 * 60;
pub const CLIENT_GRANT_MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;
pub const MAX_CLIENT_GRANT_SIGNING_KEY_ID_LEN: usize = 128;
pub const MAX_CLIENT_GRANT_NODES: usize = 3;
pub const MAX_CLIENT_GRANT_TOKEN_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientGrantTrafficMode {
    Policy,
    Global,
}

/// One Cloud-selected transport node. Mirrors the `node_assignment` shape frozen
/// in the Client `policy-projection-v1` contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantNodeAssignment {
    pub node_id: Uuid,
    pub endpoint: String,
    pub priority: u8,
    pub node_key_id: Uuid,
    pub transport: String,
    pub assignment_lease_until: u64,
}

/// The terminal policy generation this Grant is allowed to enforce. The Grant does
/// not carry the resource list itself; the signed Projection does. Binding the
/// generation and content hash stops a device from applying resources Cloud never
/// authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantPolicyBinding {
    pub policy_id: Uuid,
    pub generation: u64,
    pub content_hash: String,
}

/// Audience is explicit so a Grant cannot be replayed against another device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantAudience {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantPayloadV1 {
    pub schema_version: u16,
    pub grant_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub audience: ClientGrantAudience,
    pub device_generation: u64,
    pub generation: u64,
    pub issued_at: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub mode_capabilities: Vec<ClientGrantTrafficMode>,
    pub policy: ClientGrantPolicyBinding,
    pub nodes: Vec<ClientGrantNodeAssignment>,
    pub signing_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantEnvelopeV1 {
    pub schema_version: u16,
    pub payload: ClientGrantPayloadV1,
    pub content_hash: String,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientGrantError {
    #[error("client grant payload does not satisfy the v1 contract")]
    InvalidPayload,
    #[error("client grant envelope does not satisfy the v1 contract")]
    InvalidEnvelope,
    #[error("client grant content hash does not match the signed payload")]
    ContentHashMismatch,
    #[error("client grant audience does not match the bound device")]
    AudienceMismatch,
    #[error("client grant signature is invalid")]
    InvalidSignature,
    #[error("client grant canonicalization failed")]
    Canonicalization,
    #[error("client grant token encoding is invalid")]
    InvalidToken,
}

impl ClientGrantPayloadV1 {
    /// Full v1 validation. Every rejection here must also fail closed on the
    /// Node/Core side; Cloud must never emit an envelope this rejects.
    pub fn validate(&self) -> Result<(), ClientGrantError> {
        if self.schema_version != CLIENT_GRANT_SCHEMA_VERSION
            || self.grant_id.is_nil()
            || self.device_generation == 0
            || self.generation == 0
            || self.signing_key_id.is_empty()
            || self.signing_key_id.len() > MAX_CLIENT_GRANT_SIGNING_KEY_ID_LEN
        {
            return Err(ClientGrantError::InvalidPayload);
        }
        let audience = &self.audience;
        if [audience.tenant_id, audience.user_id, audience.device_id, audience.device_key_id]
            .into_iter()
            .any(|id| id.is_nil())
            || audience.tenant_id != self.tenant_id
            || audience.user_id != self.user_id
            || audience.device_id != self.device_id
            || audience.device_key_id != self.device_key_id
        {
            return Err(ClientGrantError::AudienceMismatch);
        }
        if self.not_before > self.issued_at
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > CLIENT_GRANT_MAX_TTL_SECS
        {
            return Err(ClientGrantError::InvalidPayload);
        }
        if self.mode_capabilities.is_empty()
            || self.mode_capabilities.len() > 2
            || has_duplicates(&self.mode_capabilities)
        {
            return Err(ClientGrantError::InvalidPayload);
        }
        if self.policy.policy_id.is_nil()
            || self.policy.generation == 0
            || !is_content_hash(&self.policy.content_hash)
        {
            return Err(ClientGrantError::InvalidPayload);
        }
        if self.nodes.is_empty() || self.nodes.len() > MAX_CLIENT_GRANT_NODES {
            return Err(ClientGrantError::InvalidPayload);
        }
        let mut seen_nodes = std::collections::HashSet::new();
        for (index, node) in self.nodes.iter().enumerate() {
            if node.node_id.is_nil()
                || node.node_key_id.is_nil()
                || node.endpoint.trim().is_empty()
                || node.endpoint.len() > 255
                || node.endpoint.bytes().any(|byte| byte.is_ascii_control())
                || node.transport != "quic"
                || node.assignment_lease_until <= self.issued_at
                || node.assignment_lease_until > self.expires_at
                || !seen_nodes.insert(node.node_id)
            {
                return Err(ClientGrantError::InvalidPayload);
            }
            // Priority is 1-based and dense so failover order is unambiguous.
            if node.priority as usize != index + 1 {
                return Err(ClientGrantError::InvalidPayload);
            }
        }
        Ok(())
    }

    pub fn content_hash(&self) -> Result<[u8; 32], ClientGrantError> {
        self.validate()?;
        let canonical = self.canonical_bytes()?;
        Ok(Sha256::digest(canonical).into())
    }

    /// RFC 8785 JCS over every payload field. Shared with Core so both sides hash
    /// identical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ClientGrantError> {
        serde_json_canonicalizer::to_vec(self).map_err(|_| ClientGrantError::Canonicalization)
    }
}

impl ClientGrantEnvelopeV1 {
    pub fn content_hash_bytes(&self) -> Result<[u8; 32], ClientGrantError> {
        parse_content_hash(&self.content_hash)
    }

    /// Verifies hash, signing key id, and signature over the payload exactly as a
    /// Node/Core verifier must.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), ClientGrantError> {
        self.payload.validate()?;
        if self.schema_version != CLIENT_GRANT_SCHEMA_VERSION
            || self.signing_key_id != self.payload.signing_key_id
        {
            return Err(ClientGrantError::InvalidEnvelope);
        }
        let expected_hash = self.payload.content_hash()?;
        if expected_hash != self.content_hash_bytes()? {
            return Err(ClientGrantError::ContentHashMismatch);
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ClientGrantError::InvalidSignature)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| ClientGrantError::InvalidSignature)?;
        verifying_key
            .verify(&signing_message(&expected_hash), &signature)
            .map_err(|_| ClientGrantError::InvalidSignature)
    }

    /// Deterministic wire bytes for `grant_token`.
    pub fn to_token(&self) -> Result<String, ClientGrantError> {
        Ok(URL_SAFE_NO_PAD.encode(self.to_envelope_bytes()?))
    }

    pub fn from_token(token: &str) -> Result<Self, ClientGrantError> {
        if token.is_empty() || token.len() > MAX_CLIENT_GRANT_TOKEN_LEN {
            return Err(ClientGrantError::InvalidToken);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| ClientGrantError::InvalidToken)?;
        Self::from_envelope_bytes(&raw)
    }

    /// Storage form used by Cloud persistence. This is exactly the byte string
    /// `grant_token` encodes, so a replayed Grant is byte-identical to the first
    /// issuance and cannot be re-signed with a different timestamp.
    pub fn to_envelope_bytes(&self) -> Result<Vec<u8>, ClientGrantError> {
        serde_json_canonicalizer::to_vec(self).map_err(|_| ClientGrantError::Canonicalization)
    }

    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, ClientGrantError> {
        if bytes.is_empty() || bytes.len() > MAX_CLIENT_GRANT_TOKEN_LEN {
            return Err(ClientGrantError::InvalidEnvelope);
        }
        serde_json::from_slice(bytes).map_err(|_| ClientGrantError::InvalidEnvelope)
    }
}

/// Cloud-side signing capability. The private key never leaves Cloud; Node/Core
/// only ever receives the matching verifying key.
#[derive(Clone)]
pub struct ClientGrantSigner {
    signing_key: SigningKey,
    key_id: String,
}

impl ClientGrantSigner {
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Result<Self, ClientGrantError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > MAX_CLIENT_GRANT_SIGNING_KEY_ID_LEN {
            return Err(ClientGrantError::InvalidEnvelope);
        }
        Ok(Self {
            signing_key,
            key_id,
        })
    }

    /// Loads the terminal Client Grant signing key from a deployment-private file.
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

    pub fn issue(
        &self,
        mut payload: ClientGrantPayloadV1,
    ) -> Result<ClientGrantEnvelopeV1, ClientGrantError> {
        payload.signing_key_id = self.key_id.clone();
        payload.validate()?;
        let content_hash = payload.content_hash()?;
        let signature = self.signing_key.sign(&signing_message(&content_hash));
        let envelope = ClientGrantEnvelopeV1 {
            schema_version: CLIENT_GRANT_SCHEMA_VERSION,
            payload,
            content_hash: format_content_hash(&content_hash),
            signing_key_id: self.key_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        envelope.verify(&self.verifying_key())?;
        Ok(envelope)
    }
}

fn signing_message(content_hash: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(CLIENT_GRANT_DOMAIN.len() + content_hash.len());
    message.extend_from_slice(CLIENT_GRANT_DOMAIN);
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

fn parse_content_hash(value: &str) -> Result<[u8; 32], ClientGrantError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(ClientGrantError::InvalidEnvelope)?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ClientGrantError::InvalidEnvelope);
    }
    let mut hash = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| ClientGrantError::InvalidEnvelope)?;
        hash[index] = u8::from_str_radix(text, 16).map_err(|_| ClientGrantError::InvalidEnvelope)?;
    }
    Ok(hash)
}

fn is_content_hash(value: &str) -> bool {
    parse_content_hash(value).is_ok()
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}
