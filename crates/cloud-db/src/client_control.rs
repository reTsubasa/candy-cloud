use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::client_access::ClientTrafficMode;
use crate::DbPool;

const MAX_DISPLAY_NAME_LEN: usize = 200;
const MAX_INSTALL_ID_LEN: usize = 128;
const MAX_CLIENT_VERSION_LEN: usize = 64;
const MAX_GRANT_ENVELOPE_LEN: usize = 1024 * 1024;
/// Bounds for a terminal device public key. These mirror the
/// `client_device_keys_public_key_bounded` CHECK in
/// `0038_terminal_client_control.sql`, so Cloud refuses a key the schema would
/// reject anyway instead of letting a duplicate-key error surface as a 503.
const MIN_DEVICE_PUBLIC_KEY_LEN: usize = 32;
const MAX_DEVICE_PUBLIC_KEY_LEN: usize = 64;
/// Upper bound for Cloud-allocated Grant generations. The column is
/// `BIGINT UNSIGNED`; refusing to allocate past this keeps the value safely
/// inside every downstream representation instead of silently wrapping.
const MAX_GRANT_GENERATION: u64 = i64::MAX as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPlatform {
    Windows,
    Macos,
    Android,
}

impl ClientPlatform {
    pub const fn database_value(self) -> &'static str {
        match self {
            Self::Windows => "WINDOWS",
            Self::Macos => "MACOS",
            Self::Android => "ANDROID",
        }
    }

    pub fn from_database_value(value: &str) -> Option<Self> {
        match value {
            "WINDOWS" => Some(Self::Windows),
            "MACOS" => Some(Self::Macos),
            "ANDROID" => Some(Self::Android),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDeviceRegistration {
    pub record_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub platform: ClientPlatform,
    pub display_name: String,
    pub install_id: String,
    pub client_version: Option<String>,
    pub public_key: [u8; 32],
    pub request_id: Uuid,
    pub actor_id: Uuid,
}

impl ClientDeviceRegistration {
    pub fn validate(&self) -> Result<(), ClientControlError> {
        for id in [
            self.record_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.device_id,
            self.device_key_id,
            self.request_id,
            self.actor_id,
        ] {
            if id.is_nil() {
                return Err(ClientControlError::InvalidScope);
            }
        }
        if self.display_name.trim().is_empty() || self.display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(ClientControlError::InvalidDisplayName);
        }
        if self.actor_id != self.user_id {
            return Err(ClientControlError::InvalidScope);
        }
        if self.install_id.len() < 8
            || self.install_id.len() > MAX_INSTALL_ID_LEN
            || !self
                .install_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(ClientControlError::InvalidInstallId);
        }
        if self
            .client_version
            .as_ref()
            .is_some_and(|version| version.is_empty() || version.len() > MAX_CLIENT_VERSION_LEN)
        {
            return Err(ClientControlError::InvalidClientVersion);
        }
        if self.public_key == [0; 32] {
            return Err(ClientControlError::InvalidPublicKey);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientControlError {
    #[error("invalid terminal client scope")]
    InvalidScope,
    #[error("invalid terminal client display name")]
    InvalidDisplayName,
    #[error("invalid terminal client install id")]
    InvalidInstallId,
    #[error("invalid terminal client version")]
    InvalidClientVersion,
    #[error("invalid terminal client public key")]
    InvalidPublicKey,
    #[error("terminal client binding conflict")]
    BindingConflict,
    #[error("terminal client grant generation changed concurrently")]
    GenerationConflict,
    /// A lifecycle change Cloud refuses to make. Revocation is terminal, so any
    /// transition that would leave or re-enter `REVOKED` is an error rather than
    /// a silent success: an operator who asked for the wrong thing must be told,
    /// not handed a `200` that describes a state the device is not in.
    #[error("terminal client status transition is not allowed")]
    InvalidTransition,
    /// The scope named a device Cloud has no record of. Kept separate from
    /// `InvalidScope`, which means "this caller may not act here": reporting a
    /// missing device as an authorization failure would be a lie, and reporting
    /// it as a state conflict would be a different one.
    #[error("terminal client device not found")]
    NotFound,
    #[error("terminal client database record is invalid")]
    InvalidRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceRegistrationOutcome {
    /// First registration of this device key, or an idempotent replay of it.
    Registered { device_id: Uuid, replayed: bool },
    /// The device was already revoked. A revoked device is never silently
    /// re-registered: Cloud requires an explicit re-enrollment decision.
    Revoked {
        device_id: Uuid,
        device_key_id: Uuid,
    },
}

/// Lifecycle state of a registered terminal device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceStatus {
    Active,
    Suspended,
    Revoked,
}

impl ClientDeviceStatus {
    /// The `client_devices.status` column value. Kept separate from the wire
    /// form for the same reason `ClientTrafficMode` keeps them separate: the
    /// frozen Client contract spells this lower case, and a handler that
    /// answered in the storage spelling would be rejected by every client.
    pub fn from_database_value(value: &str) -> Option<Self> {
        match value {
            "ACTIVE" => Some(Self::Active),
            "SUSPENDED" => Some(Self::Suspended),
            "REVOKED" => Some(Self::Revoked),
            _ => None,
        }
    }

    pub fn to_database_value(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Suspended => "SUSPENDED",
            Self::Revoked => "REVOKED",
        }
    }

    /// The lowercase spelling the management contract accepts and answers in.
    pub fn to_wire_value(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }

    /// Wire parsing is deliberately strict and case-sensitive: a caller that
    /// sends `ACTIVE` is refused rather than guessed at, so the two spellings
    /// can never be confused for one another by accident.
    pub fn from_wire_value(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }

    /// Revocation is a terminal lifecycle state. Everything that mutates a
    /// device has to agree on that, so the predicate lives with the enum.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

/// Decides what a management-plane status request should actually do.
///
/// Extracted from `set_device_status` so the lifecycle rules are a pure function
/// that can be pinned without a database, the same way `validate` pins the
/// structural invariants.
///
/// * `Ok(None)` means the device is already in the requested state and the call
///   is an idempotent replay: nothing is written, no audit event is emitted.
/// * `Ok(Some(status))` is the state Cloud should write.
/// * `Err(InvalidTransition)` covers every request that involves `REVOKED`,
///   in either direction, because a revoked device is never resurrected and
///   revocation is performed by the dedicated revoke path, not here.
pub fn plan_device_status_change(
    current: ClientDeviceStatus,
    requested: ClientDeviceStatus,
) -> Result<Option<ClientDeviceStatus>, ClientControlError> {
    if current.is_terminal() || requested.is_terminal() {
        return Err(ClientControlError::InvalidTransition);
    }
    if current == requested {
        return Ok(None);
    }
    Ok(Some(requested))
}

/// Result of a management-plane suspend/activate request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceStatusOutcome {
    Suspended { device_id: Uuid, replayed: bool },
    Activated { device_id: Uuid, replayed: bool },
}

impl ClientDeviceStatusOutcome {
    pub fn device_id(self) -> Uuid {
        match self {
            Self::Suspended { device_id, .. } | Self::Activated { device_id, .. } => device_id,
        }
    }

    pub fn status(self) -> ClientDeviceStatus {
        match self {
            Self::Suspended { .. } => ClientDeviceStatus::Suspended,
            Self::Activated { .. } => ClientDeviceStatus::Active,
        }
    }

    /// `true` when the device was already in the requested state and Cloud wrote
    /// nothing, so an HTTP caller can distinguish "applied" from "already true".
    pub fn replayed(self) -> bool {
        match self {
            Self::Suspended { replayed, .. } | Self::Activated { replayed, .. } => replayed,
        }
    }
}

/// One management-plane key rotation request.
///
/// Kept as a value rather than five positional arguments so the validation rules
/// that must hold *before* Cloud opens a transaction are in one place, and so the
/// repository method reads as an auditable unit the way
/// `ClientDeviceRegistration` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDeviceKeyRotation {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    /// The key identity the *client* mints for its new key. Cloud never picks it,
    /// because the client is the only party that holds the matching secret.
    pub device_key_id: Uuid,
    pub public_key: Vec<u8>,
}

impl ClientDeviceKeyRotation {
    /// Public so the boundary rules can be pinned without a database, exactly
    /// like `ClientDeviceRegistration::validate`.
    pub fn validate(&self) -> Result<(), ClientControlError> {
        if [
            self.organization_id,
            self.tenant_id,
            self.device_id,
            self.device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        // The length window is the same one the `client_device_keys` CHECK
        // enforces, so a key the schema would reject is a `400` here instead of a
        // duplicate-key storage fault surfacing as a `503`.
        //
        // An all-zero key is refused for the same reason registration refuses
        // one: it is not a public key any client can prove possession of, so
        // storing it would silently brick the device.
        if self.public_key.len() < MIN_DEVICE_PUBLIC_KEY_LEN
            || self.public_key.len() > MAX_DEVICE_PUBLIC_KEY_LEN
            || self.public_key.iter().all(|byte| *byte == 0)
        {
            return Err(ClientControlError::InvalidPublicKey);
        }
        Ok(())
    }
}

/// Pure preconditions of a key rotation, extracted so the rules an operator can
/// trip are testable without MySQL.
///
/// * `Err(InvalidTransition)` when the device is not `ACTIVE`. A suspended device
///   must be activated first, and a revoked one is never rotated back into
///   service; both are operator-visible state conflicts rather than silent
///   successes.
/// * `Err(BindingConflict)` when the requested `device_key_id` is already in use
///   in this tenant. Reusing a key identity would make two different public keys
///   claim the same audience, so it is refused even when the caller believes it
///   is retrying: rotation is never replayed.
pub fn plan_device_key_rotation(
    current: ClientDeviceStatus,
    device_key_id_exists: bool,
) -> Result<(), ClientControlError> {
    if current != ClientDeviceStatus::Active {
        return Err(ClientControlError::InvalidTransition);
    }
    if device_key_id_exists {
        return Err(ClientControlError::BindingConflict);
    }
    Ok(())
}

/// Result of a management-plane key rotation.
///
/// `replayed` is always `false`: a rotation that produced a new key is by
/// definition new work, and a retry of an already-applied rotation is refused as
/// a conflict rather than answered as a replay. The field exists so the wire
/// response has the same shape as every other terminal-client mutation, and so a
/// future idempotent rotation cannot silently change the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceKeyRotationOutcome {
    Rotated {
        device_id: Uuid,
        /// The key that was `ACTIVE` before this call and is now `RETIRED`.
        previous_device_key_id: Uuid,
        device_key_id: Uuid,
        revoked_grants: u64,
        revoked_projections: u64,
        replayed: bool,
    },
}

impl ClientDeviceKeyRotationOutcome {
    pub fn replayed(self) -> bool {
        match self {
            Self::Rotated { replayed, .. } => replayed,
        }
    }
}

/// Scope of one management-plane status change.
///
/// Note the scope is `(organization_id, tenant_id, device_id)` with no
/// `user_id`. The client plane is session-scoped, so every one of its queries
/// carries a user; the management plane acts on a device *as an operator*, and
/// the human who asked is recorded in the audit event's `actor_id` rather than
/// being folded into the row scope. Requiring a user id here would force the
/// handler to invent one and would make a device invisible to management whenever
/// its owning user moved on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetDeviceStatus {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub new_status: ClientDeviceStatus,
}

impl SetDeviceStatus {
    pub fn validate(&self) -> Result<(), ClientControlError> {
        if [self.organization_id, self.tenant_id, self.device_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        Ok(())
    }
}

/// Internal binding for one registered terminal device.
///
/// The wire contract uses the client-chosen `device_id` while Cloud persistence
/// uses an internal `record_id`. Every Grant and Projection path must translate
/// through this lookup so a handler can never accept a caller-supplied internal
/// identifier, and so the *active* device key is Cloud-chosen rather than
/// caller-chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDeviceRecord {
    pub record_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub platform: ClientPlatform,
    pub generation: u64,
    /// The device's effective traffic mode. Cloud owns this value: it is written
    /// by the traffic-mode endpoint, never read from a Projection request body.
    pub traffic_mode: ClientTrafficMode,
}

/// Result of resolving a wire `device_id` with the caller's session scope.
///
/// Suspended and revoked are distinct outcomes rather than one "not found",
/// because Cloud must tell a client that its credential was revoked (`410`)
/// instead of letting it retry forever against a device that no longer exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceLookup {
    Active(ClientDeviceRecord),
    /// The device row exists but Cloud has no active key for it, so it is not an
    /// issuable target. Reported separately from `Revoked` because it is
    /// recoverable: re-registering the device key restores service.
    Suspended {
        record_id: Uuid,
        device_id: Uuid,
    },
    Revoked {
        record_id: Uuid,
        device_id: Uuid,
    },
}

impl ClientDeviceRecord {
    /// Public so the "a row read back from storage is still a valid binding"
    /// invariant can be tested without a database.
    pub fn validate(&self) -> Result<(), ClientControlError> {
        if [
            self.record_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.device_id,
            self.device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
        {
            return Err(ClientControlError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrantWrite {
    pub grant_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    /// Generation the signed envelope claims. Cloud reads the next free value
    /// with `next_grant_generation` *before* signing, because the generation is
    /// part of the signed payload, and `write_grant` re-checks it atomically so a
    /// concurrent issuance can never store an envelope whose claim is stale.
    pub generation: u64,
    pub request_id: Uuid,
    pub request_hash: [u8; 32],
    pub signing_key_id: String,
    pub grant_envelope: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The instant the node assignment inside `grant_envelope` stops being valid.
    ///
    /// Redundant with the signed payload on purpose: it is recorded here so the
    /// next issuance can ask "does this device still hold a live assignment?"
    /// without decoding a blob. The envelope stays the authority -- this column is
    /// only how the question is answered cheaply (see migration `0047`).
    pub assignment_lease_until: DateTime<Utc>,
}

impl ClientGrantWrite {
    /// Public so the invariants that `write_grant` refuses *before* opening a
    /// transaction can be pinned by tests without a database, the same way
    /// `ClientDeviceRegistration::validate` is.
    pub fn validate(&self) -> Result<(), ClientControlError> {
        if [
            self.grant_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
            self.request_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
            || self.generation > MAX_GRANT_GENERATION
            || self.request_hash == [0; 32]
            || self.grant_envelope.is_empty()
            || self.grant_envelope.len() > MAX_GRANT_ENVELOPE_LEN
            || self.signing_key_id.is_empty()
            || self.signing_key_id.len() > 128
            || self.expires_at <= self.issued_at
            // The lease window must be exactly the shape the signed envelope
            // validator accepts: strictly after `issued_at` (otherwise the client
            // is handed a Grant it must reject) and never past `expires_at`.
            || self.assignment_lease_until <= self.issued_at
            || self.assignment_lease_until > self.expires_at
        {
            return Err(ClientControlError::InvalidRecord);
        }
        Ok(())
    }
}

/// Grant generation is allocated by Cloud, never by the caller: a client that
/// could choose its own generation could present an older Grant as the newest
/// one. `write_grant` re-validates the claimed generation against the device's
/// current maximum inside the inserting transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientGrantWriteOutcome {
    Issued {
        grant_id: Uuid,
        generation: u64,
        replayed: bool,
    },
}

/// A persisted terminal Client Grant envelope.
///
/// Replay must return the exact bytes Cloud signed the first time. Re-signing on
/// replay would silently re-stamp `issued_at`/`expires_at` and let a client widen
/// its own authorization window by retrying a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrantRecord {
    pub grant_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    pub generation: u64,
    /// Fingerprint of the issuance request that produced this envelope. A replay
    /// compares its own fingerprint against this value, so reusing one idempotency
    /// key for a materially different request is a conflict instead of a silent
    /// hand-back of the old authorization.
    pub request_hash: [u8; 32],
    pub signing_key_id: String,
    pub grant_envelope: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Derived copy of the `assignment_lease_until` signed into `grant_envelope`.
    ///
    /// `None` for rows written before migration `0047`, and that absence is
    /// meaningful: Cloud has no evidence about the assignment, so it re-selects
    /// rather than assuming the old lease still holds.
    pub assignment_lease_until: Option<DateTime<Utc>>,
}

impl ClientGrantRecord {
    /// Public for the same reason as `ClientGrantWrite::validate`: a Grant read
    /// back from storage must satisfy exactly the same invariants Cloud enforced
    /// when it wrote it, and that has to be checkable without a live database.
    pub fn validate(&self) -> Result<(), ClientControlError> {
        if [
            self.grant_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
            || self.generation > MAX_GRANT_GENERATION
            || self.request_hash == [0; 32]
            || self.signing_key_id.is_empty()
            || self.signing_key_id.len() > 128
            || self.grant_envelope.is_empty()
            || self.grant_envelope.len() > MAX_GRANT_ENVELOPE_LEN
            || self.expires_at <= self.issued_at
        {
            return Err(ClientControlError::InvalidRecord);
        }
        // The column is nullable because rows written before `0047` have no
        // recorded lease, and absence must stay readable. When it *is* present it
        // has to describe the same window the signed payload accepts, so a record
        // that drifted out of range is refused exactly like the write was.
        if let Some(lease_until) = self.assignment_lease_until {
            if lease_until <= self.issued_at || lease_until > self.expires_at {
                return Err(ClientControlError::InvalidRecord);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ClientControlRepository {
    pool: DbPool,
}

impl ClientControlRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Registers a terminal public key under the already-authenticated human session scope.
    /// The transaction deliberately does not touch node enrollment tables.
    pub async fn register_device(
        &self,
        request: &ClientDeviceRegistration,
    ) -> Result<ClientDeviceRegistrationOutcome, ClientControlError> {
        request.validate()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let organization: Uuid = sqlx::query_scalar(
            "SELECT tenant.organization_id FROM tenants tenant JOIN organizations organization ON organization.id = tenant.organization_id AND organization.status = 'ACTIVE' JOIN human_users user ON user.id = ? AND user.status = 'ACTIVE' JOIN organization_memberships membership ON membership.organization_id = tenant.organization_id AND membership.user_id = user.id AND membership.status = 'ACTIVE' WHERE tenant.id = ? AND tenant.status = 'ACTIVE' FOR SHARE",
        )
                .bind(request.user_id)
                .bind(request.tenant_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?
                .ok_or(ClientControlError::InvalidScope)?;
        if organization != request.organization_id {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::InvalidScope);
        }

        let request_hash = request_fingerprint(request);
        let request_replay = sqlx::query(
            "SELECT device_id, request_hash FROM client_devices WHERE tenant_id = ? AND user_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(request.user_id)
        .bind(request.request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if let Some(row) = request_replay {
            let stored_hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            let stored_device: Uuid = row
                .try_get("device_id")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return if stored_hash.as_slice() == request_hash && stored_device == request.device_id {
                Ok(ClientDeviceRegistrationOutcome::Registered {
                    device_id: request.device_id,
                    replayed: true,
                })
            } else {
                Err(ClientControlError::BindingConflict)
            };
        }

        let existing = sqlx::query(
            "SELECT id, status, install_id, (SELECT device_key.device_key_id FROM client_device_keys device_key WHERE device_key.client_device_id = client_devices.id ORDER BY device_key.created_at DESC, device_key.device_key_id DESC LIMIT 1) AS device_key_id FROM client_devices WHERE tenant_id = ? AND device_id = ? FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(request.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if let Some(row) = existing {
            let status: String = row
                .try_get("status")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            let status = ClientDeviceStatus::from_database_value(&status)
                .ok_or(ClientControlError::InvalidRecord)?;
            let stored_key: Option<Uuid> = row
                .try_get("device_key_id")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return match status {
                ClientDeviceStatus::Revoked => Ok(ClientDeviceRegistrationOutcome::Revoked {
                    device_id: request.device_id,
                    device_key_id: stored_key.unwrap_or(request.device_key_id),
                }),
                // Re-registering the same device with a *new* key is key rotation,
                // which needs its own Cloud decision. Treating it as a plain
                // conflict keeps a client from swapping its own key silently.
                ClientDeviceStatus::Active | ClientDeviceStatus::Suspended => {
                    Err(ClientControlError::BindingConflict)
                }
            };
        }

        // `install_id` is unique per tenant. A different device claiming an
        // install identity that already exists is a caller error, not a storage
        // fault, so it must surface as a conflict rather than a 503.
        let install_taken: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_devices WHERE tenant_id = ? AND install_id = ?)",
        )
        .bind(request.tenant_id)
        .bind(&request.install_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if install_taken {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::BindingConflict);
        }

        sqlx::query(
            "INSERT INTO client_devices (id, organization_id, tenant_id, user_id, device_id, platform, display_name, install_id, request_id, request_hash, client_version, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(request.record_id)
        .bind(request.organization_id)
        .bind(request.tenant_id)
        .bind(request.user_id)
        .bind(request.device_id)
        .bind(request.platform.database_value())
        .bind(&request.display_name)
        .bind(&request.install_id)
        .bind(request.request_id)
        .bind(request_hash.as_slice())
        .bind(&request.client_version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO client_device_keys (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, public_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(Uuid::now_v7())
        .bind(request.organization_id)
        .bind(request.tenant_id)
        .bind(request.user_id)
        .bind(request.record_id)
        .bind(request.device_key_id)
        .bind(request.public_key.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'HUMAN', ?, 'CLIENT_DEVICE_REGISTERED', 'CLIENT_DEVICE', ?, JSON_OBJECT('device_key_id', ?))",
        )
        .bind(Uuid::now_v7())
        .bind(request.organization_id)
        .bind(request.tenant_id)
        .bind(request.actor_id.to_string())
        .bind(request.device_id.to_string())
        .bind(request.device_key_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(ClientDeviceRegistrationOutcome::Registered {
            device_id: request.device_id,
            replayed: false,
        })
    }

    /// Resolves the client-supplied `device_id` to Cloud's internal binding while
    /// requiring the caller's session scope.
    ///
    /// Returns `Ok(None)` only when the device is unknown or belongs to another
    /// user/tenant. A revoked device is reported as `Revoked` so callers can answer
    /// `410` instead of a misleading `404`, and a device with no active key is
    /// reported as `Suspended` rather than silently appearing authorized.
    pub async fn device_by_wire_id(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<ClientDeviceLookup>, ClientControlError> {
        if [organization_id, tenant_id, user_id, device_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT device.id AS record_id, device.organization_id, device.tenant_id, device.user_id, device.device_id, device.platform, device.status AS device_status, device.generation AS device_generation, device.traffic_mode AS traffic_mode, device_key.device_key_id FROM client_devices device LEFT JOIN client_device_keys device_key ON device_key.client_device_id = device.id AND device_key.organization_id = device.organization_id AND device_key.tenant_id = device.tenant_id AND device_key.user_id = device.user_id AND device_key.status = 'ACTIVE' WHERE device.organization_id = ? AND device.tenant_id = ? AND device.user_id = ? AND device.device_id = ?",
        )
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let status: String = row
            .try_get("device_status")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let status = ClientDeviceStatus::from_database_value(&status)
            .ok_or(ClientControlError::InvalidRecord)?;
        if status == ClientDeviceStatus::Revoked {
            return Ok(Some(revoked_lookup(&row)?));
        }
        let platform: String = row
            .try_get("platform")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let active_key: Option<Uuid> = row
            .try_get("device_key_id")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        // A device whose key was retired or revoked has no Cloud-authorized key,
        // so it cannot be treated as an issuable target even though the device row
        // is still ACTIVE.
        let Some(device_key_id) = active_key else {
            return Ok(Some(ClientDeviceLookup::Suspended {
                record_id: row
                    .try_get("record_id")
                    .map_err(|_| ClientControlError::InvalidRecord)?,
                device_id: row
                    .try_get("device_id")
                    .map_err(|_| ClientControlError::InvalidRecord)?,
            }));
        };
        let record = ClientDeviceRecord {
            record_id: row
                .try_get("record_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            organization_id: row
                .try_get("organization_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            tenant_id: row
                .try_get("tenant_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            user_id: row
                .try_get("user_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            device_id: row
                .try_get("device_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            device_key_id,
            platform: ClientPlatform::from_database_value(&platform)
                .ok_or(ClientControlError::InvalidRecord)?,
            generation: row
                .try_get("device_generation")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            traffic_mode: ClientTrafficMode::from_database_value(
                &row.try_get::<String, _>("traffic_mode")
                    .map_err(|_| ClientControlError::InvalidRecord)?,
            )
            .ok_or(ClientControlError::InvalidRecord)?,
        };
        record.validate()?;
        Ok(Some(match status {
            ClientDeviceStatus::Active => ClientDeviceLookup::Active(record),
            ClientDeviceStatus::Suspended => ClientDeviceLookup::Suspended {
                record_id: record.record_id,
                device_id: record.device_id,
            },
            ClientDeviceStatus::Revoked => unreachable!("revoked devices return above"),
        }))
    }

    pub async fn touch_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
        device_key_id: Uuid,
    ) -> Result<bool, ClientControlError> {
        if [tenant_id, user_id, device_id, device_key_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let result = sqlx::query(
            "UPDATE client_devices d JOIN client_device_keys k ON k.client_device_id = d.id AND k.tenant_id = d.tenant_id SET d.last_seen_at = ? WHERE d.tenant_id = ? AND d.user_id = ? AND d.device_id = ? AND k.device_key_id = ? AND d.status = 'ACTIVE' AND k.status = 'ACTIVE'",
        )
        .bind(Utc::now())
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .bind(device_key_id)
        .execute(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(result.rows_affected() == 1)
    }

    /// Retires one device and everything Cloud issued to it, on the device's own
    /// request.
    ///
    /// Revocation is the one lifecycle change a client is allowed to make about
    /// itself, and only ever downward: the device row, its keys, and its Grants
    /// are all moved out of `ACTIVE` in a single transaction so no ordering can
    /// leave a live key or a usable Grant behind. A projection is revoked by the
    /// caller because its repository is a separate object.
    ///
    /// Idempotent: a device that is already revoked, or whose scope does not
    /// match the session, affects zero rows and is reported as such rather than
    /// as an error. That keeps a retry after a dropped response from failing, and
    /// keeps a caller from learning whether some other user's device exists.
    pub async fn revoke_device(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
        device_key_id: Uuid,
    ) -> Result<u64, ClientControlError> {
        if [
            organization_id,
            tenant_id,
            user_id,
            device_id,
            device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let record_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM client_devices WHERE organization_id = ? AND tenant_id = ? AND user_id = ? AND device_id = ? AND status = 'ACTIVE' FOR UPDATE",
        )
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let Some(record_id) = record_id else {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Ok(0);
        };
        // The key must be the one Cloud currently authorizes for this device, so
        // a stale key held by someone else cannot switch off a device it no
        // longer owns.
        let key_matches: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_device_keys WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND device_key_id = ? AND status = 'ACTIVE')",
        )
        .bind(record_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_key_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if !key_matches {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Ok(0);
        }
        sqlx::query(
            "UPDATE client_devices SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ?",
        )
        .bind(record_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        sqlx::query(
            "UPDATE client_device_keys SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP(6) WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND status IN ('ACTIVE','RETIRED')",
        )
        .bind(record_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        // The Grant row goes first so a concurrent Projection read cannot see a
        // still-active Grant while the device is already revoked.
        sqlx::query(
            "UPDATE client_grants SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP(6) WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND status = 'ACTIVE'",
        )
        .bind(record_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'HUMAN', ?, 'CLIENT_DEVICE_REVOKED', 'CLIENT_DEVICE', ?, JSON_OBJECT('device_key_id', ?))",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id.to_string())
        .bind(device_id.to_string())
        .bind(device_key_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(1)
    }

    /// Suspends or re-activates one device, on an operator's instruction.
    ///
    /// This is the management-plane half of the lifecycle and it is deliberately
    /// *not* reachable from a client session: a device can revoke itself, but it
    /// can never switch itself back on. The two directions are not symmetric:
    ///
    /// * `SUSPENDED` makes the device unsafe immediately. The device row moves
    ///   out of `ACTIVE`, and every Grant and Projection Cloud issued to it is
    ///   revoked in the same transaction, because a device that keeps enforcing a
    ///   policy Cloud no longer authorizes is exactly the state an operator
    ///   suspends a device to prevent. The *key rows* are left `ACTIVE` on
    ///   purpose: suspension is expected to be temporary and a client that keeps
    ///   its key does not have to re-register to come back.
    /// * `ACTIVE` restores the device row only. There is no implicit key change:
    ///   a `RETIRED` key stays retired, because bringing a key back to life is a
    ///   *key* decision that belongs to `rotate_device_key`, not to a status
    ///   change. A device suspended after a rotation therefore comes back with
    ///   its current `ACTIVE` key and re-issues Grants and Projections normally.
    ///
    /// Idempotent by state, not by request: asking for the state a device is
    /// already in returns `replayed: true` and writes no audit event, so a
    /// retried operator action does not fill the audit log with duplicates. The
    /// caller's request identity is not recorded because the requested state *is*
    /// the whole request, the same way it is for the traffic-mode switch.
    ///
    /// Revocation is terminal in both directions. Any request involving
    /// `REVOKED` -- including one that asks for it -- is refused rather than
    /// applied, so a revoked device can never be quietly brought back into
    /// service by a status call; re-enrollment is a separate, deliberate act.
    pub async fn set_device_status(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        device_id: Uuid,
        new_status: ClientDeviceStatus,
    ) -> Result<ClientDeviceStatusOutcome, ClientControlError> {
        let scope = SetDeviceStatus {
            organization_id,
            tenant_id,
            device_id,
            new_status,
        };
        self.set_device_status_inner(&scope).await
    }

    async fn set_device_status_inner(
        &self,
        scope: &SetDeviceStatus,
    ) -> Result<ClientDeviceStatusOutcome, ClientControlError> {
        scope.validate()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        // `FOR UPDATE` on the device row is what makes the read-decide-write
        // sequence safe: two concurrent operator actions serialize here instead of
        // both reading `ACTIVE` and both writing an audit event.
        let row = sqlx::query(
            "SELECT id, user_id, status, (SELECT device_key.device_key_id FROM client_device_keys device_key WHERE device_key.client_device_id = client_devices.id AND device_key.status = 'ACTIVE' ORDER BY device_key.created_at DESC, device_key.device_key_id DESC LIMIT 1) AS device_key_id FROM client_devices WHERE organization_id = ? AND tenant_id = ? AND device_id = ? FOR UPDATE",
        )
        .bind(scope.organization_id)
        .bind(scope.tenant_id)
        .bind(scope.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let Some(row) = row else {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::NotFound);
        };
        let record_id: Uuid = row
            .try_get("id")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let user_id: Uuid = row
            .try_get("user_id")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let stored: String = row
            .try_get("status")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let current = ClientDeviceStatus::from_database_value(&stored)
            .ok_or(ClientControlError::InvalidRecord)?;
        let active_key: Option<Uuid> = row
            .try_get("device_key_id")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        // Deciding here, inside the lock, is what keeps "already suspended" from
        // racing with another operator's suspension: the second caller sees the
        // committed state and correctly reports a replay.
        let planned = match plan_device_status_change(current, scope.new_status) {
            Ok(planned) => planned,
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| ClientControlError::InvalidRecord)?;
                return Err(error);
            }
        };
        let Some(planned) = planned else {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Ok(match scope.new_status {
                ClientDeviceStatus::Suspended => ClientDeviceStatusOutcome::Suspended {
                    device_id: scope.device_id,
                    replayed: true,
                },
                _ => ClientDeviceStatusOutcome::Activated {
                    device_id: scope.device_id,
                    replayed: true,
                },
            });
        };
        sqlx::query(
            "UPDATE client_devices SET status = ? WHERE id = ? AND organization_id = ? AND tenant_id = ?",
        )
        .bind(planned.to_database_value())
        .bind(record_id)
        .bind(scope.organization_id)
        .bind(scope.tenant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if planned == ClientDeviceStatus::Suspended {
            // Grant first, then Projection, in that order. A Projection is derived
            // from a Grant, so an observer that sees a revoked Grant while a
            // Projection is briefly still PUBLISHED can never be looking at the
            // reverse, and the window in which a client could still fetch a
            // Projection backing a dead Grant is the shorter one.
            sqlx::query(
                "UPDATE client_grants SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP(6) WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND status = 'ACTIVE'",
            )
            .bind(record_id)
            .bind(scope.organization_id)
            .bind(scope.tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
            // Deliberately *not* filtered by `device_key_id`: suspension is about
            // the device, so every Projection it holds has to go, including any
            // still-PUBLISHED row under a key that was retired by an earlier
            // rotation.
            sqlx::query(
                "UPDATE client_projections SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP(6) WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND status = 'PUBLISHED'",
            )
            .bind(record_id)
            .bind(scope.organization_id)
            .bind(scope.tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        }
        let action = match planned {
            ClientDeviceStatus::Suspended => "CLIENT_DEVICE_SUSPENDED",
            _ => "CLIENT_DEVICE_ACTIVATED",
        };
        // The actor is the management-plane human, never the device: this path is
        // unreachable from a client session, and an audit trail that named the
        // device as its own suspender would be misleading.
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'HUMAN', ?, ?, 'CLIENT_DEVICE', ?, JSON_OBJECT('device_key_id', ?, 'status', ?))",
        )
        .bind(Uuid::now_v7())
        .bind(scope.organization_id)
        .bind(scope.tenant_id)
        .bind(user_id.to_string())
        .bind(action)
        .bind(scope.device_id.to_string())
        .bind(
            active_key
                .map(|key| key.to_string())
                .unwrap_or_default(),
        )
        .bind(planned.to_wire_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(match planned {
            ClientDeviceStatus::Suspended => ClientDeviceStatusOutcome::Suspended {
                device_id: scope.device_id,
                replayed: false,
            },
            _ => ClientDeviceStatusOutcome::Activated {
                device_id: scope.device_id,
                replayed: false,
            },
        })
    }

    /// Rotates one device's key and retires everything that was bound to the old
    /// one.
    ///
    /// Rotation is not just a new key row. A terminal Grant and Projection are
    /// bound to the *old* `device_key_id` -- the audience is part of what Cloud
    /// signed -- so a rotation that only inserted a new key would leave the old
    /// Grant verifiable and the old Projection enforceable, which would make the
    /// rotation cosmetic. Everything the old key authorized is therefore retired
    /// in the same transaction, in this order:
    ///
    /// 1. the old key row becomes `RETIRED` (never `REVOKED`: retired means
    ///    "superseded", and keeping the distinction lets an operator read the
    ///    history of a device that rotated cleanly apart from one that was
    ///    revoked;
    /// 2. the new key row is inserted `ACTIVE`;
    /// 3. `ACTIVE` Grants for the device are revoked;
    /// 4. `PUBLISHED` Projections for the device are revoked.
    ///
    /// The device's `generation` is left monotonic and *untouched* here. It is the
    /// device's own identity generation, allocated by registration, not a
    /// rotation counter: bumping it inside this transaction would both re-sign
    /// nothing and risk colliding with the generation-serialized Grant and
    /// Projection allocators. Grant and Projection generations restart from the
    /// stored maximum, so the next issuance is strictly newer than anything the
    /// old key ever held.
    ///
    /// Not idempotent, by design. A retried rotation is refused as a conflict
    /// rather than replayed: replaying would mean answering `rotated` for a key
    /// Cloud did not just create, and the caller could no longer tell whether its
    /// new key is actually in service. The counts returned let an operator verify
    /// that the old authorization really was retired.
    pub async fn rotate_device_key(
        &self,
        rotation: &ClientDeviceKeyRotation,
    ) -> Result<ClientDeviceKeyRotationOutcome, ClientControlError> {
        rotation.validate()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let row = sqlx::query(
            "SELECT id, user_id, status FROM client_devices WHERE organization_id = ? AND tenant_id = ? AND device_id = ? FOR UPDATE",
        )
        .bind(rotation.organization_id)
        .bind(rotation.tenant_id)
        .bind(rotation.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let Some(row) = row else {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::NotFound);
        };
        let record_id: Uuid = row
            .try_get("id")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let user_id: Uuid = row
            .try_get("user_id")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let stored: String = row
            .try_get("status")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let current = ClientDeviceStatus::from_database_value(&stored)
            .ok_or(ClientControlError::InvalidRecord)?;
        // The key identity is unique per tenant rather than per device, because a
        // `device_key_id` is what a Projection audience names. Reusing one would
        // make two keys indistinguishable to every audience check, so it is
        // refused here rather than left to a duplicate-key constraint.
        let key_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_device_keys WHERE tenant_id = ? AND device_key_id = ?)",
        )
        .bind(rotation.tenant_id)
        .bind(rotation.device_key_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if let Err(error) = plan_device_key_rotation(current, key_exists) {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(error);
        }
        let previous_key: Option<Uuid> = sqlx::query_scalar(
            "SELECT device_key_id FROM client_device_keys WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND status = 'ACTIVE' ORDER BY created_at DESC, device_key_id DESC LIMIT 1 FOR UPDATE",
        )
        .bind(record_id)
        .bind(rotation.organization_id)
        .bind(rotation.tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let Some(previous_key) = previous_key else {
            // An `ACTIVE` device with no `ACTIVE` key is an inconsistent row, not
            // a caller error: Cloud cannot say which key was replaced, so it must
            // not claim a rotation happened.
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::InvalidRecord);
        };
        sqlx::query(
            "UPDATE client_device_keys SET status = 'RETIRED' WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND device_key_id = ? AND status = 'ACTIVE'",
        )
        .bind(record_id)
        .bind(rotation.organization_id)
        .bind(rotation.tenant_id)
        .bind(previous_key)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO client_device_keys (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, public_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(Uuid::now_v7())
        .bind(rotation.organization_id)
        .bind(rotation.tenant_id)
        .bind(user_id)
        .bind(record_id)
        .bind(rotation.device_key_id)
        .bind(rotation.public_key.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let revoked_grants = sqlx::query(
            "UPDATE client_grants SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP(6) WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND status = 'ACTIVE'",
        )
        .bind(record_id)
        .bind(rotation.organization_id)
        .bind(rotation.tenant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?
        .rows_affected();
        let revoked_projections = sqlx::query(
            "UPDATE client_projections SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP(6) WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND status = 'PUBLISHED'",
        )
        .bind(record_id)
        .bind(rotation.organization_id)
        .bind(rotation.tenant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?
        .rows_affected();
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'HUMAN', ?, 'CLIENT_DEVICE_KEY_ROTATED', 'CLIENT_DEVICE', ?, JSON_OBJECT('previous_device_key_id', ?, 'device_key_id', ?, 'revoked_grants', ?, 'revoked_projections', ?))",
        )
        .bind(Uuid::now_v7())
        .bind(rotation.organization_id)
        .bind(rotation.tenant_id)
        .bind(user_id.to_string())
        .bind(rotation.device_id.to_string())
        .bind(previous_key.to_string())
        .bind(rotation.device_key_id.to_string())
        .bind(revoked_grants)
        .bind(revoked_projections)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(ClientDeviceKeyRotationOutcome::Rotated {
            device_id: rotation.device_id,
            previous_device_key_id: previous_key,
            device_key_id: rotation.device_key_id,
            revoked_grants,
            revoked_projections,
            replayed: false,
        })
    }

    pub async fn write_grant(
        &self,
        grant: &ClientGrantWrite,
    ) -> Result<ClientGrantWriteOutcome, ClientControlError> {
        grant.validate()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let device_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_devices WHERE id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND status = 'ACTIVE')",
        )
        .bind(grant.client_device_id)
        .bind(grant.organization_id)
        .bind(grant.tenant_id)
        .bind(grant.user_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if !device_exists {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::BindingConflict);
        }
        let key_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_device_keys WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND device_key_id = ? AND status = 'ACTIVE')",
        )
        .bind(grant.client_device_id)
        .bind(grant.organization_id)
        .bind(grant.tenant_id)
        .bind(grant.user_id)
        .bind(grant.device_key_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if !key_exists {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::BindingConflict);
        }

        let existing = sqlx::query(
            "SELECT id, request_hash, generation FROM client_grants WHERE tenant_id = ? AND client_device_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(grant.tenant_id)
        .bind(grant.client_device_id)
        .bind(grant.request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if let Some(row) = existing {
            let stored_hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            let stored_id: Uuid = row
                .try_get("id")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            let stored_generation: u64 = row
                .try_get("generation")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return if stored_hash.as_slice() == grant.request_hash {
                Ok(ClientGrantWriteOutcome::Issued {
                    grant_id: stored_id,
                    generation: stored_generation,
                    replayed: true,
                })
            } else {
                Err(ClientControlError::BindingConflict)
            };
        }

        // The signed envelope already claims a generation, so this is a
        // compare-and-set rather than an allocation: the row is accepted only if
        // it is exactly the next free generation for this device. A concurrent
        // issuance that signed the same claim loses here and the caller re-signs.
        // The `FOR UPDATE` read also serializes concurrent issuances.
        let current_generation: Option<u64> = sqlx::query_scalar(
            "SELECT MAX(generation) FROM client_grants WHERE tenant_id = ? AND client_device_id = ? FOR UPDATE",
        )
        .bind(grant.tenant_id)
        .bind(grant.client_device_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let expected_generation = current_generation.unwrap_or(0).saturating_add(1);
        if grant.generation != expected_generation
            || expected_generation == 0
            || expected_generation > MAX_GRANT_GENERATION
        {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::GenerationConflict);
        }
        let next_generation = expected_generation;

        let digest: [u8; 32] = Sha256::digest(&grant.grant_envelope).into();
        sqlx::query(
            "INSERT INTO client_grants (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, generation, request_id, request_hash, signing_key_id, grant_digest, grant_envelope, issued_at, expires_at, assignment_lease_until, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(grant.grant_id)
        .bind(grant.organization_id)
        .bind(grant.tenant_id)
        .bind(grant.user_id)
        .bind(grant.client_device_id)
        .bind(grant.device_key_id)
        .bind(next_generation)
        .bind(grant.request_id)
        .bind(grant.request_hash.as_slice())
        .bind(&grant.signing_key_id)
        .bind(digest.as_slice())
        .bind(&grant.grant_envelope)
        .bind(grant.issued_at)
        .bind(grant.expires_at)
        .bind(grant.assignment_lease_until)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(ClientGrantWriteOutcome::Issued {
            grant_id: grant.grant_id,
            generation: next_generation,
            replayed: false,
        })
    }

    /// Reads back the Grant stored for one idempotent issuance request. Used to
    /// return byte-identical envelopes on replay.
    pub async fn grant_by_request(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
        request_id: Uuid,
    ) -> Result<Option<ClientGrantRecord>, ClientControlError> {
        if [tenant_id, client_device_id, request_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT id, organization_id, tenant_id, user_id, client_device_id, device_key_id, generation, request_hash, signing_key_id, grant_envelope, issued_at, expires_at, assignment_lease_until FROM client_grants WHERE tenant_id = ? AND client_device_id = ? AND request_id = ?",
        )
        .bind(tenant_id)
        .bind(client_device_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        row.map(grant_record_from_row).transpose()
    }

    /// Reads the generation Cloud must sign next for this device.
    ///
    /// The value is a hint until `write_grant` confirms it: signing needs the
    /// generation inside the envelope, so it must be read before the signature
    /// exists. A lost race surfaces as `GenerationConflict` and the caller re-signs
    /// with the newly read value rather than storing a stale claim.
    pub async fn next_grant_generation(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
    ) -> Result<u64, ClientControlError> {
        if [tenant_id, client_device_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let current: Option<u64> = sqlx::query_scalar(
            "SELECT MAX(generation) FROM client_grants WHERE tenant_id = ? AND client_device_id = ?",
        )
        .bind(tenant_id)
        .bind(client_device_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let next = current.unwrap_or(0).saturating_add(1);
        if next == 0 || next > MAX_GRANT_GENERATION {
            return Err(ClientControlError::InvalidRecord);
        }
        Ok(next)
    }

    /// Returns the newest unexpired Grant for a device key, if any.
    ///
    /// Device registration replays this so a client that lost its local Grant can
    /// recover the Cloud-issued one without triggering a new signature and without
    /// being handed an expired credential.
    ///
    /// This is a convenience read only. Issuance must not rely on it to decide
    /// whether a Grant may be written, because the row can change between the
    /// read and the insert; `write_grant` owns that decision.
    pub async fn active_grant(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
        device_key_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<ClientGrantRecord>, ClientControlError> {
        if [tenant_id, client_device_id, device_key_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT id, organization_id, tenant_id, user_id, client_device_id, device_key_id, generation, request_hash, signing_key_id, grant_envelope, issued_at, expires_at, assignment_lease_until FROM client_grants WHERE tenant_id = ? AND client_device_id = ? AND device_key_id = ? AND status = 'ACTIVE' AND expires_at > ? ORDER BY generation DESC, issued_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(client_device_id)
        .bind(device_key_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        row.map(grant_record_from_row).transpose()
    }
}

fn revoked_lookup(row: &sqlx::mysql::MySqlRow) -> Result<ClientDeviceLookup, ClientControlError> {
    Ok(ClientDeviceLookup::Revoked {
        record_id: row
            .try_get("record_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        device_id: row
            .try_get("device_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
    })
}

fn grant_record_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<ClientGrantRecord, ClientControlError> {
    let record = ClientGrantRecord {
        grant_id: row
            .try_get("id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        user_id: row
            .try_get("user_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        client_device_id: row
            .try_get("client_device_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        device_key_id: row
            .try_get("device_key_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        generation: row
            .try_get("generation")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        request_hash: {
            let stored: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            stored
                .as_slice()
                .try_into()
                .map_err(|_| ClientControlError::InvalidRecord)?
        },
        signing_key_id: row
            .try_get("signing_key_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        grant_envelope: row
            .try_get("grant_envelope")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        issued_at: row
            .try_get("issued_at")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        assignment_lease_until: row
            .try_get("assignment_lease_until")
            .map_err(|_| ClientControlError::InvalidRecord)?,
    };
    record.validate()?;
    Ok(record)
}

fn request_fingerprint(request: &ClientDeviceRegistration) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/terminal-client-registration/v1\0");
    for value in [
        request.organization_id.as_bytes().as_slice(),
        request.tenant_id.as_bytes().as_slice(),
        request.user_id.as_bytes().as_slice(),
        request.device_id.as_bytes().as_slice(),
        request.device_key_id.as_bytes().as_slice(),
        request.platform.database_value().as_bytes(),
        request.display_name.as_bytes(),
        request.install_id.as_bytes(),
        request.public_key.as_slice(),
    ] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    if let Some(version) = &request.client_version {
        hash.update((version.len() as u32).to_be_bytes());
        hash.update(version.as_bytes());
    } else {
        hash.update(0_u32.to_be_bytes());
    }
    hash.finalize().into()
}
