//! Storage for the signed terminal PolicyProjection, its receipts, and the
//! device revocation that removes both from service.
//!
//! This mirrors `client_control`'s Grant persistence on purpose: a Projection is
//! state, not an event. The stored envelope is the only thing a replay is
//! allowed to return, because re-serializing a signed document would re-stamp
//! `issued_at`/`stale_until` and let a device extend its own authorization
//! window by polling.
//!
//! What is new here relative to Grants is `inputs_hash`. A Projection is a pure
//! function of Cloud state (policy, settings, traffic mode, node set) plus a time
//! window, so Cloud can recompute the inputs and tell "this is still the
//! document I would sign" from "Cloud changed something" without re-signing.
//! Only the former may be answered from storage, which is what keeps `GET
//! .../projection` idempotent for a polling client.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::client_access::ClientTrafficMode;
use crate::DbPool;

/// Upper bound for Cloud-allocated Projection generations. Mirrors the Grant
/// bound: the column is `BIGINT UNSIGNED`, so refusing to allocate past this
/// keeps the value representable everywhere instead of silently wrapping.
const MAX_PROJECTION_GENERATION: u64 = i64::MAX as u64;
/// Bounded like the Grant envelope so a corrupt or hostile row cannot make Cloud
/// allocate an unbounded buffer while reading a stored Projection back.
const MAX_PROJECTION_ENVELOPE_LEN: usize = 1024 * 1024;
const MAX_ERROR_CODE_LEN: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientProjectionError {
    #[error("invalid terminal client scope")]
    InvalidScope,
    #[error("terminal client projection binding conflict")]
    BindingConflict,
    #[error("terminal client projection generation changed concurrently")]
    GenerationConflict,
    #[error("terminal client database record is invalid")]
    InvalidRecord,
    #[error("terminal client projection receipt is invalid")]
    InvalidReceipt,
}

/// The lifecycle state a device reports for one Projection generation.
///
/// `Rejected` is terminal for its generation: a device that rejected a
/// Projection will not later commit the same one, so Cloud must not accept the
/// transition. Every other state moves strictly forward, which stops a stale or
/// duplicated report from rolling a committed Projection back to `staged`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientProjectionReceiptState {
    Received,
    Verified,
    Staged,
    Committed,
    Rejected,
}

impl ClientProjectionReceiptState {
    pub fn from_wire_value(value: &str) -> Option<Self> {
        match value {
            "received" => Some(Self::Received),
            "verified" => Some(Self::Verified),
            "staged" => Some(Self::Staged),
            "committed" => Some(Self::Committed),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }

    pub fn to_database_value(self) -> &'static str {
        match self {
            Self::Received => "RECEIVED",
            Self::Verified => "VERIFIED",
            Self::Staged => "STAGED",
            Self::Committed => "COMMITTED",
            Self::Rejected => "REJECTED",
        }
    }

    /// The lowercase wire value the Client contract uses for a receipt state.
    pub fn to_wire_value(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Verified => "verified",
            Self::Staged => "staged",
            Self::Committed => "committed",
            Self::Rejected => "rejected",
        }
    }

    fn from_database_value(value: &str) -> Option<Self> {
        match value {
            "RECEIVED" => Some(Self::Received),
            "VERIFIED" => Some(Self::Verified),
            "STAGED" => Some(Self::Staged),
            "COMMITTED" => Some(Self::Committed),
            "REJECTED" => Some(Self::Rejected),
            _ => None,
        }
    }

    /// Whether `next` may follow `self` for the same Projection generation.
    ///
    /// The progression is `received -> verified -> staged -> committed`, with any
    /// state allowed to jump to `rejected`. Re-reporting the *same* state is
    /// allowed so a retried receipt after a dropped response still succeeds.
    pub fn permits(self, next: Self) -> bool {
        if next == Self::Rejected {
            return self != Self::Rejected;
        }
        self == next || self.next() == Some(next)
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::Received => Some(Self::Verified),
            Self::Verified => Some(Self::Staged),
            Self::Staged => Some(Self::Committed),
            Self::Committed | Self::Rejected => None,
        }
    }
}

/// A Projection about to be persisted. `inputs_hash` and `content_hash` are
/// computed by the caller from the signed document so storage never re-derives
/// either: the signed bytes are the source of truth for the hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProjectionWrite {
    pub projection_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    pub grant_id: Uuid,
    pub policy_generation: u64,
    pub settings_generation: u64,
    pub device_traffic_mode: ClientTrafficMode,
    /// Generation the signed envelope claims. Read before signing because the
    /// generation is inside the signed payload; `write_projection` re-checks it
    /// atomically so a concurrent issuance cannot store a stale claim.
    pub generation: u64,
    pub request_id: Uuid,
    pub request_hash: [u8; 32],
    pub content_hash: [u8; 32],
    pub inputs_hash: [u8; 32],
    pub signing_key_id: String,
    pub projection_envelope: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub stale_until: DateTime<Utc>,
}

impl ClientProjectionWrite {
    /// Public so the invariants `write_projection` refuses *before* opening a
    /// transaction can be pinned without a live database, exactly like
    /// `ClientGrantWrite::validate`.
    pub fn validate(&self) -> Result<(), ClientProjectionError> {
        if [
            self.projection_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
            self.grant_id,
            self.request_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
            || self.generation > MAX_PROJECTION_GENERATION
            || self.policy_generation == 0
            || self.settings_generation == 0
            || self.request_hash == [0; 32]
            || self.content_hash == [0; 32]
            || self.inputs_hash == [0; 32]
            || self.signing_key_id.is_empty()
            || self.signing_key_id.len() > 128
            || self.projection_envelope.is_empty()
            || self.projection_envelope.len() > MAX_PROJECTION_ENVELOPE_LEN
            || self.stale_until <= self.issued_at
        {
            return Err(ClientProjectionError::InvalidRecord);
        }
        Ok(())
    }
}

/// A Projection read back from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProjectionRecord {
    pub projection_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    pub grant_id: Uuid,
    pub policy_generation: u64,
    pub settings_generation: u64,
    pub device_traffic_mode: ClientTrafficMode,
    pub generation: u64,
    pub request_hash: [u8; 32],
    pub content_hash: [u8; 32],
    pub inputs_hash: [u8; 32],
    pub signing_key_id: String,
    pub projection_envelope: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub stale_until: DateTime<Utc>,
}

impl ClientProjectionRecord {
    /// The content hash as it appears on the wire and in `If-None-Match`.
    pub fn content_hash_text(&self) -> String {
        format!("sha256:{}", hex(&self.content_hash))
    }

    pub fn validate(&self) -> Result<(), ClientProjectionError> {
        if [
            self.projection_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
            self.grant_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
            || self.generation > MAX_PROJECTION_GENERATION
            || self.policy_generation == 0
            || self.settings_generation == 0
            || self.request_hash == [0; 32]
            || self.content_hash == [0; 32]
            || self.inputs_hash == [0; 32]
            || self.signing_key_id.is_empty()
            || self.signing_key_id.len() > 128
            || self.projection_envelope.is_empty()
            || self.projection_envelope.len() > MAX_PROJECTION_ENVELOPE_LEN
            || self.stale_until <= self.issued_at
        {
            return Err(ClientProjectionError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProjectionWriteOutcome {
    Published {
        projection_id: Uuid,
        generation: u64,
        replayed: bool,
    },
}

/// The outcome of recording one receipt. `recorded = false` means the state was
/// already at or past the reported one, so the call was a no-op replay rather
/// than a state change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientReceiptOutcome {
    pub state: ClientProjectionReceiptState,
    pub replayed: bool,
}

/// A receipt as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProjectionReceiptRecord {
    pub receipt_id: Uuid,
    pub projection_id: Uuid,
    pub generation: u64,
    pub content_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub state: ClientProjectionReceiptState,
    pub error_code: Option<String>,
    pub reported_at: DateTime<Utc>,
}

/// Everything the receipt endpoint needs to accept or refuse one report. The
/// device-identifying fields are separate from the state so the caller can
/// compare them against the session-owned device before anything is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProjectionReceiptWrite {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    pub projection_id: Uuid,
    pub generation: u64,
    pub content_hash: [u8; 32],
    pub request_id: Uuid,
    pub request_hash: [u8; 32],
    pub state: ClientProjectionReceiptState,
    pub error_code: Option<String>,
}

impl ClientProjectionReceiptWrite {
    /// Fingerprint of everything a receipt reports, so a retried idempotency key
    /// with a *different* report conflicts instead of silently replaying the
    /// first one.
    ///
    /// Deliberately excludes `reported_at`: a retry minutes later must still
    /// match. Also excludes `request_id` (it *is* the idempotency key, so it can
    /// never differ between two rows that collide) and `request_hash` itself,
    /// which this value is about to fill in. The state and error code are
    /// included, because a device that first reported `received` and then
    /// reports `committed` under the same key has made a programming error that
    /// Cloud must surface rather than absorb.
    ///
    /// Callers build the write with `request_hash: [0; 32]`, call this, and
    /// assign the result, so the fingerprint can never be computed over a
    /// partially filled struct.
    pub fn request_fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(CLIENT_PROJECTION_RECEIPT_DOMAIN);
        for value in [
            self.organization_id.as_bytes().as_slice(),
            self.tenant_id.as_bytes().as_slice(),
            self.user_id.as_bytes().as_slice(),
            self.client_device_id.as_bytes().as_slice(),
            self.device_key_id.as_bytes().as_slice(),
            self.projection_id.as_bytes().as_slice(),
        ] {
            hash.update(value);
        }
        hash.update(self.generation.to_be_bytes());
        hash.update(self.content_hash);
        hash.update(self.state.to_database_value().as_bytes());
        hash.update((self.error_code.as_deref().map_or(0, str::len) as u32).to_be_bytes());
        if let Some(error_code) = self.error_code.as_deref() {
            hash.update(error_code.as_bytes());
        }
        hash.finalize().into()
    }

    pub fn validate(&self) -> Result<(), ClientProjectionError> {
        if [
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
            self.projection_id,
            self.request_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
            || self.generation > MAX_PROJECTION_GENERATION
            || self.content_hash == [0; 32]
            || self.request_hash == [0; 32]
        {
            return Err(ClientProjectionError::InvalidReceipt);
        }
        if let Some(error_code) = &self.error_code {
            // Mirrors the frozen `^[a-z][a-z0-9_.-]{2,79}$` wire pattern so Cloud
            // never stores a code the Client contract would not accept.
            if error_code.len() < 3
                || error_code.len() > MAX_ERROR_CODE_LEN
                || !error_code.as_bytes()[0].is_ascii_lowercase()
                || !error_code.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
                })
            {
                return Err(ClientProjectionError::InvalidReceipt);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ClientProjectionRepository {
    pool: DbPool,
}

impl ClientProjectionRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Reads the generation Cloud must sign next for this device.
    ///
    /// A hint until `write_projection` confirms it: signing needs the generation
    /// inside the envelope, so it must be read before the signature exists. A
    /// lost race surfaces as `GenerationConflict` and the caller re-signs with the
    /// newly read value instead of storing a stale claim.
    pub async fn next_projection_generation(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
    ) -> Result<u64, ClientProjectionError> {
        if [tenant_id, client_device_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientProjectionError::InvalidScope);
        }
        let current: Option<u64> = sqlx::query_scalar(
            "SELECT MAX(generation) FROM client_projections WHERE tenant_id = ? AND client_device_id = ?",
        )
        .bind(tenant_id)
        .bind(client_device_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        let next = current.unwrap_or(0).saturating_add(1);
        if next == 0 || next > MAX_PROJECTION_GENERATION {
            return Err(ClientProjectionError::InvalidRecord);
        }
        Ok(next)
    }

    /// Persists a signed Projection with a compare-and-set on its generation.
    ///
    /// The write supersedes the device's previous Projection inside the same
    /// transaction, so a device never has two `PUBLISHED` documents to choose
    /// from. A replay of the same `request_id` returns the stored row instead of
    /// inserting a second generation.
    pub async fn write_projection(
        &self,
        projection: &ClientProjectionWrite,
    ) -> Result<ClientProjectionWriteOutcome, ClientProjectionError> {
        projection.validate()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientProjectionError::InvalidRecord)?;
        let grant_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_grants WHERE id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND client_device_id = ? AND device_key_id = ? AND status = 'ACTIVE')",
        )
        .bind(projection.grant_id)
        .bind(projection.organization_id)
        .bind(projection.tenant_id)
        .bind(projection.user_id)
        .bind(projection.client_device_id)
        .bind(projection.device_key_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        if !grant_exists {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return Err(ClientProjectionError::BindingConflict);
        }
        // The device must still be active and still pointed at the key and mode
        // Cloud signed for. A device revoked or flipped to another key between
        // signing and writing must not receive a Projection it can no longer use.
        let device_mode: Option<String> = sqlx::query_scalar(
            "SELECT traffic_mode FROM client_devices WHERE id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND status = 'ACTIVE' FOR UPDATE",
        )
        .bind(projection.client_device_id)
        .bind(projection.organization_id)
        .bind(projection.tenant_id)
        .bind(projection.user_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        let Some(device_mode) = device_mode else {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return Err(ClientProjectionError::BindingConflict);
        };
        if ClientTrafficMode::from_database_value(&device_mode)
            != Some(projection.device_traffic_mode)
        {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return Err(ClientProjectionError::BindingConflict);
        }
        let existing = sqlx::query(
            "SELECT id, request_hash, generation FROM client_projections WHERE tenant_id = ? AND client_device_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(projection.tenant_id)
        .bind(projection.client_device_id)
        .bind(projection.request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        if let Some(row) = existing {
            let stored_hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            let stored_id: Uuid = row
                .try_get("id")
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            let stored_generation: u64 = row
                .try_get("generation")
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return if stored_hash.as_slice() == projection.request_hash {
                Ok(ClientProjectionWriteOutcome::Published {
                    projection_id: stored_id,
                    generation: stored_generation,
                    replayed: true,
                })
            } else {
                Err(ClientProjectionError::BindingConflict)
            };
        }
        let current_generation: Option<u64> = sqlx::query_scalar(
            "SELECT MAX(generation) FROM client_projections WHERE tenant_id = ? AND client_device_id = ? FOR UPDATE",
        )
        .bind(projection.tenant_id)
        .bind(projection.client_device_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        let expected_generation = current_generation.unwrap_or(0).saturating_add(1);
        if projection.generation != expected_generation
            || expected_generation == 0
            || expected_generation > MAX_PROJECTION_GENERATION
        {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return Err(ClientProjectionError::GenerationConflict);
        }
        sqlx::query(
            "UPDATE client_projections SET status = 'SUPERSEDED' WHERE tenant_id = ? AND client_device_id = ? AND status = 'PUBLISHED'",
        )
        .bind(projection.tenant_id)
        .bind(projection.client_device_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO client_projections (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, grant_id, policy_generation, settings_generation, device_traffic_mode, generation, request_id, request_hash, content_hash, inputs_hash, projection_envelope, issued_at, stale_until, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PUBLISHED')",
        )
        .bind(projection.projection_id)
        .bind(projection.organization_id)
        .bind(projection.tenant_id)
        .bind(projection.user_id)
        .bind(projection.client_device_id)
        .bind(projection.device_key_id)
        .bind(projection.grant_id)
        .bind(projection.policy_generation)
        .bind(projection.settings_generation)
        .bind(projection.device_traffic_mode.to_database_value())
        .bind(projection.generation)
        .bind(projection.request_id)
        .bind(projection.request_hash.as_slice())
        .bind(projection.content_hash.as_slice())
        .bind(projection.inputs_hash.as_slice())
        .bind(&projection.projection_envelope)
        .bind(projection.issued_at)
        .bind(projection.stale_until)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientProjectionError::InvalidRecord)?;
        Ok(ClientProjectionWriteOutcome::Published {
            projection_id: projection.projection_id,
            generation: projection.generation,
            replayed: false,
        })
    }

    /// Reads back the Projection stored for one idempotent request, so a replay
    /// can return byte-identical envelopes instead of re-signing.
    pub async fn projection_by_request(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
        request_id: Uuid,
    ) -> Result<Option<ClientProjectionRecord>, ClientProjectionError> {
        if [tenant_id, client_device_id, request_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientProjectionError::InvalidScope);
        }
        let row = sqlx::query(&format!(
            "{SELECT_PROJECTION} WHERE tenant_id = ? AND client_device_id = ? AND request_id = ?"
        ))
        .bind(tenant_id)
        .bind(client_device_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        row.map(projection_record_from_row).transpose()
    }

    /// The newest still-valid Projection for a device key, if any.
    ///
    /// `PUBLISHED` only: a superseded or revoked row is history. The read is a
    /// convenience for the poll path, which still re-checks `inputs_hash` before
    /// answering from it.
    pub async fn current_projection(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
        device_key_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<ClientProjectionRecord>, ClientProjectionError> {
        if [tenant_id, client_device_id, device_key_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientProjectionError::InvalidScope);
        }
        let row = sqlx::query(&format!(
            "{SELECT_PROJECTION} WHERE tenant_id = ? AND client_device_id = ? AND device_key_id = ? AND status = 'PUBLISHED' AND stale_until > ? ORDER BY generation DESC LIMIT 1"
        ))
        .bind(tenant_id)
        .bind(client_device_id)
        .bind(device_key_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        row.map(projection_record_from_row).transpose()
    }

    /// Records one device receipt, refusing transitions that would move a
    /// Projection's state backwards.
    pub async fn record_receipt(
        &self,
        receipt: &ClientProjectionReceiptWrite,
    ) -> Result<ClientReceiptOutcome, ClientProjectionError> {
        receipt.validate()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientProjectionError::InvalidRecord)?;
        // The receipt must name a Projection Cloud actually published for this
        // exact device, key, and generation. Accepting a receipt for a generation
        // Cloud never signed would let a device claim it committed something that
        // does not exist.
        let projection = sqlx::query(
            "SELECT id, content_hash, generation FROM client_projections WHERE id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND client_device_id = ? AND device_key_id = ? FOR UPDATE",
        )
        .bind(receipt.projection_id)
        .bind(receipt.organization_id)
        .bind(receipt.tenant_id)
        .bind(receipt.user_id)
        .bind(receipt.client_device_id)
        .bind(receipt.device_key_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        let Some(projection) = projection else {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return Err(ClientProjectionError::BindingConflict);
        };
        let stored_generation: u64 = projection
            .try_get("generation")
            .map_err(|_| ClientProjectionError::InvalidRecord)?;
        let stored_hash: Vec<u8> = projection
            .try_get("content_hash")
            .map_err(|_| ClientProjectionError::InvalidRecord)?;
        if stored_generation != receipt.generation
            || stored_hash.as_slice() != receipt.content_hash.as_slice()
        {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return Err(ClientProjectionError::BindingConflict);
        }
        let existing = sqlx::query(
            "SELECT request_hash, state FROM client_projection_receipts WHERE tenant_id = ? AND client_device_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(receipt.tenant_id)
        .bind(receipt.client_device_id)
        .bind(receipt.request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        if let Some(row) = existing {
            let stored_request: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            let state = ClientProjectionReceiptState::from_database_value(
                &row.try_get::<String, _>("state")
                    .map_err(|_| ClientProjectionError::InvalidRecord)?,
            )
            .ok_or(ClientProjectionError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return if stored_request.as_slice() == receipt.request_hash {
                Ok(ClientReceiptOutcome {
                    state,
                    replayed: true,
                })
            } else {
                Err(ClientProjectionError::BindingConflict)
            };
        }
        let latest: Option<String> = sqlx::query_scalar(
            "SELECT state FROM client_projection_receipts WHERE tenant_id = ? AND client_device_id = ? AND projection_id = ? ORDER BY reported_at DESC, id DESC LIMIT 1 FOR UPDATE",
        )
        .bind(receipt.tenant_id)
        .bind(receipt.client_device_id)
        .bind(receipt.projection_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        if let Some(latest) = latest {
            let latest = ClientProjectionReceiptState::from_database_value(&latest)
                .ok_or(ClientProjectionError::InvalidRecord)?;
            if !latest.permits(receipt.state) {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| ClientProjectionError::InvalidRecord)?;
                return Err(ClientProjectionError::InvalidReceipt);
            }
        } else if receipt.state != ClientProjectionReceiptState::Received {
            // The first receipt for a generation must open the progression. A
            // device cannot open with `committed` and skip the states Cloud uses
            // to detect a document that was installed but never verified.
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionError::InvalidRecord)?;
            return Err(ClientProjectionError::InvalidReceipt);
        }
        sqlx::query(
            "INSERT INTO client_projection_receipts (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, projection_id, generation, content_hash, request_id, request_hash, state, error_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::now_v7())
        .bind(receipt.organization_id)
        .bind(receipt.tenant_id)
        .bind(receipt.user_id)
        .bind(receipt.client_device_id)
        .bind(receipt.device_key_id)
        .bind(receipt.projection_id)
        .bind(receipt.generation)
        .bind(receipt.content_hash.as_slice())
        .bind(receipt.request_id)
        .bind(receipt.request_hash.as_slice())
        .bind(receipt.state.to_database_value())
        .bind(&receipt.error_code)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientProjectionError::InvalidRecord)?;
        Ok(ClientReceiptOutcome {
            state: receipt.state,
            replayed: false,
        })
    }

    /// Marks every live Projection for a device revoked and returns how many
    /// rows changed.
    ///
    /// Revocation is deliberately idempotent: revoking an already-revoked device
    /// returns `0` instead of an error, so a retried revoke is safe.
    pub async fn revoke_projections(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        client_device_id: Uuid,
        device_key_id: Uuid,
    ) -> Result<u64, ClientProjectionError> {
        if [
            organization_id,
            tenant_id,
            user_id,
            client_device_id,
            device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
        {
            return Err(ClientProjectionError::InvalidScope);
        }
        let result = sqlx::query(
            "UPDATE client_projections SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP(6) WHERE organization_id = ? AND tenant_id = ? AND user_id = ? AND client_device_id = ? AND device_key_id = ? AND status = 'PUBLISHED'",
        )
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(client_device_id)
        .bind(device_key_id)
        .execute(&self.pool)
        .await
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
        Ok(result.rows_affected())
    }
}

/// The explicit column list, shared by every projection read so a new column
/// cannot silently shift a positional decode.
const SELECT_PROJECTION: &str = "SELECT id, organization_id, tenant_id, user_id, client_device_id, device_key_id, grant_id, policy_generation, settings_generation, device_traffic_mode, generation, request_hash, content_hash, inputs_hash, signing_key_id, projection_envelope, issued_at, stale_until FROM client_projections";

fn projection_record_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<ClientProjectionRecord, ClientProjectionError> {
    let record = ClientProjectionRecord {
        projection_id: row
            .try_get("id")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        user_id: row
            .try_get("user_id")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        client_device_id: row
            .try_get("client_device_id")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        device_key_id: row
            .try_get("device_key_id")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        grant_id: row
            .try_get("grant_id")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        policy_generation: row
            .try_get("policy_generation")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        settings_generation: row
            .try_get("settings_generation")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        device_traffic_mode: ClientTrafficMode::from_database_value(
            &row.try_get::<String, _>("device_traffic_mode")
                .map_err(|_| ClientProjectionError::InvalidRecord)?,
        )
        .ok_or(ClientProjectionError::InvalidRecord)?,
        generation: row
            .try_get("generation")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        request_hash: bytes32(&row, "request_hash")?,
        content_hash: bytes32(&row, "content_hash")?,
        inputs_hash: bytes32(&row, "inputs_hash")?,
        signing_key_id: row
            .try_get("signing_key_id")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        projection_envelope: row
            .try_get("projection_envelope")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        issued_at: row
            .try_get("issued_at")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
        stale_until: row
            .try_get("stale_until")
            .map_err(|_| ClientProjectionError::InvalidRecord)?,
    };
    record.validate()?;
    Ok(record)
}

fn bytes32(row: &sqlx::mysql::MySqlRow, column: &str) -> Result<[u8; 32], ClientProjectionError> {
    let stored: Vec<u8> = row
        .try_get(column)
        .map_err(|_| ClientProjectionError::InvalidRecord)?;
    stored
        .as_slice()
        .try_into()
        .map_err(|_| ClientProjectionError::InvalidRecord)
}

/// Lowercase hex without a prefix, matching the index used by the Client's
/// `If-None-Match` comparison.
fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// The fingerprint of everything a Projection's signature depends on except the
/// time window and the generation.
///
/// This is what makes a poll idempotent. Fields that change on every signing
/// attempt are excluded; the policy, settings, mode, node set, and hash of the
/// assembled document are included, so any input Cloud would sign differently
/// produces a different fingerprint and forces a re-sign.
pub fn projection_inputs_fingerprint(
    policy_generation: u64,
    policy_content_hash: &[u8; 32],
    settings_generation: u64,
    settings_content_hash: &[u8; 32],
    device_traffic_mode: ClientTrafficMode,
    grant_id: Uuid,
    nodes: &[Uuid],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/terminal-client-projection-inputs/v1\0");
    hash.update(policy_generation.to_be_bytes());
    hash.update(policy_content_hash);
    hash.update(settings_generation.to_be_bytes());
    hash.update(settings_content_hash);
    hash.update(device_traffic_mode.to_database_value().as_bytes());
    hash.update(grant_id.as_bytes());
    hash.update((nodes.len() as u32).to_be_bytes());
    for node in nodes {
        hash.update(node.as_bytes());
    }
    hash.finalize().into()
}

/// Domain separator for the projection request fingerprint. Distinct from the
/// Grant and settings domains so a hash can never be replayed across scopes.
pub const CLIENT_PROJECTION_REQUEST_DOMAIN: &[u8] = b"candy/terminal-client-projection/v1\0";

/// Domain separator for the receipt request fingerprint. Kept distinct from the
/// Projection issuance domain so a receipt key can never be reused as an issuance
/// key (or the reverse) without the mismatch being detected.
pub const CLIENT_PROJECTION_RECEIPT_DOMAIN: &[u8] =
    b"candy/terminal-client-projection-receipt/v1\0";
