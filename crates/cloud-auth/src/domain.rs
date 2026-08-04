use std::fmt;

use uuid::Uuid;

pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const MAX_DEVICE_DISPLAY_NAME_LEN: usize = 200;
pub const MAX_KEY_ID_LEN: usize = 80;
pub const MAX_REQUEST_ID_LEN: usize = 120;
pub const MAX_SERVICE_PERMISSION_LEN: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    InvalidDeviceIdentity,
    InvalidDisplayName,
    InvalidKeyId,
    InvalidOperationalPublicKey,
    OperationalKeyMismatch,
    InactiveDevice,
    InactiveSubscription,
    InactiveEntitlement,
    EntitlementMismatch,
    InvalidRequestId,
    InvalidExpiration,
    IdempotencyConflict,
}

impl DomainError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidDeviceIdentity => "invalid_device_identity",
            Self::InvalidDisplayName => "invalid_display_name",
            Self::InvalidKeyId => "invalid_key_id",
            Self::InvalidOperationalPublicKey => "invalid_operational_public_key",
            Self::OperationalKeyMismatch => "operational_key_mismatch",
            Self::InactiveDevice => "inactive_device",
            Self::InactiveSubscription => "inactive_subscription",
            Self::InactiveEntitlement => "inactive_entitlement",
            Self::EntitlementMismatch => "entitlement_mismatch",
            Self::InvalidRequestId => "invalid_request_id",
            Self::InvalidExpiration => "invalid_expiration",
            Self::IdempotencyConflict => "idempotency_conflict",
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DomainError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollmentRequest {
    pub tenant_id: Uuid,
    /// The device-provided UUID. It must use canonical lowercase hyphenated form.
    pub device_identity: String,
    pub display_name: String,
    pub key_id: String,
    pub operational_public_key: Vec<u8>,
}

impl DeviceEnrollmentRequest {
    pub fn complete(self, record_id: Uuid) -> Result<DeviceEnrollment, DomainError> {
        let identity = canonical_uuid(&self.device_identity)?;
        validate_non_empty_bounded(&self.display_name, MAX_DEVICE_DISPLAY_NAME_LEN)
            .then_some(())
            .ok_or(DomainError::InvalidDisplayName)?;
        validate_non_empty_bounded(&self.key_id, MAX_KEY_ID_LEN)
            .then_some(())
            .ok_or(DomainError::InvalidKeyId)?;
        let public_key: [u8; ED25519_PUBLIC_KEY_LEN] = self
            .operational_public_key
            .try_into()
            .map_err(|_| DomainError::InvalidOperationalPublicKey)?;

        Ok(DeviceEnrollment {
            device: EnrolledDevice {
                id: record_id,
                tenant_id: self.tenant_id,
                identity,
                display_name: self.display_name,
                status: DeviceStatus::Pending,
            },
            operational_key: OperationalKey {
                id: Uuid::new_v4(),
                tenant_id: self.tenant_id,
                key_id: self.key_id,
                public_key,
                status: OperationalKeyStatus::Active,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollment {
    pub device: EnrolledDevice,
    pub operational_key: OperationalKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledDevice {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub identity: Uuid,
    pub display_name: String,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalKeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub key_id: String,
    pub public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    pub status: OperationalKeyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceClass {
    Private,
    CandyShared,
    CandyDedicated,
    Partner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotStatus {
    Trial,
    Active,
    Grace,
    Suspended,
    Revoked,
    Expired,
}

impl SnapshotStatus {
    const fn permits_new_grants(self) -> bool {
        matches!(self, Self::Trial | Self::Active | Self::Grace)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDevice {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementSnapshot {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub node_pool_id: Uuid,
    pub service_class: ServiceClass,
    pub service_permission: String,
    pub status: SnapshotStatus,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationSnapshot {
    pub tenant_id: Uuid,
    /// Monotonic aggregate version captured in one authorization read transaction.
    pub authorization_generation: u64,
    pub device: SnapshotDevice,
    pub subscription_status: SnapshotStatus,
    pub entitlement: EntitlementSnapshot,
    pub policy_generation: u64,
    pub revocation_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub node_pool_id: Uuid,
    pub service_class: ServiceClass,
    pub service_permission: String,
}

impl AuthorizationSnapshot {
    /// Validates that a request uses only the permissions captured in this snapshot.
    pub fn authorize(&self, request: &GrantRequest) -> Result<(), DomainError> {
        if self.device.status != DeviceStatus::Active
            || self.device.id != request.device_id
            || self.device.tenant_id != self.tenant_id
            || request.tenant_id != self.tenant_id
        {
            return Err(DomainError::InactiveDevice);
        }
        if !self.subscription_status.permits_new_grants() {
            return Err(DomainError::InactiveSubscription);
        }
        if !self.entitlement.status.permits_new_grants() {
            return Err(DomainError::InactiveEntitlement);
        }
        if self.entitlement.tenant_id != self.tenant_id
            || self.entitlement.node_pool_id != request.node_pool_id
            || self.entitlement.service_class != request.service_class
            || self.entitlement.service_permission != request.service_permission
            || !validate_non_empty_bounded(&request.service_permission, MAX_SERVICE_PERMISSION_LEN)
        {
            return Err(DomainError::EntitlementMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantIssuanceKey {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub authorization_generation: u64,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantIssuanceCandidate {
    pub key: GrantIssuanceKey,
    /// SHA-256 of the canonical request fields, never the Grant envelope.
    pub request_fingerprint: [u8; 32],
    pub signing_key_id: String,
    /// SHA-256 of the signed Grant envelope; the envelope itself is not persisted here.
    pub grant_digest: [u8; 32],
    pub expires_at_unix: i64,
}

impl GrantIssuanceCandidate {
    pub fn resolve(
        &self,
        existing: Option<&GrantIssuanceRecord>,
    ) -> Result<GrantIssuanceResolution, DomainError> {
        self.validate()?;
        match existing {
            None => Ok(GrantIssuanceResolution::Issue),
            Some(record)
                if record.key == self.key
                    && record.request_fingerprint == self.request_fingerprint =>
            {
                Ok(GrantIssuanceResolution::Replay(record.clone()))
            }
            Some(_) => Err(DomainError::IdempotencyConflict),
        }
    }

    fn validate(&self) -> Result<(), DomainError> {
        validate_non_empty_bounded(&self.key.request_id, MAX_REQUEST_ID_LEN)
            .then_some(())
            .ok_or(DomainError::InvalidRequestId)?;
        validate_non_empty_bounded(&self.signing_key_id, MAX_KEY_ID_LEN)
            .then_some(())
            .ok_or(DomainError::InvalidKeyId)?;
        (self.expires_at_unix > 0)
            .then_some(())
            .ok_or(DomainError::InvalidExpiration)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantIssuanceRecord {
    pub id: Uuid,
    pub key: GrantIssuanceKey,
    pub request_fingerprint: [u8; 32],
    pub signing_key_id: String,
    pub grant_digest: [u8; 32],
    pub expires_at_unix: i64,
    pub created_at_unix: i64,
}

impl GrantIssuanceRecord {
    pub fn from_candidate(
        id: Uuid,
        candidate: GrantIssuanceCandidate,
        created_at_unix: i64,
    ) -> Result<Self, DomainError> {
        candidate.validate()?;
        (created_at_unix > 0 && candidate.expires_at_unix > created_at_unix)
            .then_some(())
            .ok_or(DomainError::InvalidExpiration)?;
        Ok(Self {
            id,
            key: candidate.key,
            request_fingerprint: candidate.request_fingerprint,
            signing_key_id: candidate.signing_key_id,
            grant_digest: candidate.grant_digest,
            expires_at_unix: candidate.expires_at_unix,
            created_at_unix,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantIssuanceResolution {
    Issue,
    Replay(GrantIssuanceRecord),
}

/// Persistence adapters must implement this as one transaction. A duplicate-key race must read
/// the existing record and apply `GrantIssuanceCandidate::resolve` before returning a result.
pub trait GrantIssuanceStore {
    type Error;

    fn record_or_replay(
        &mut self,
        candidate: &GrantIssuanceCandidate,
        created_at_unix: i64,
    ) -> Result<GrantIssuanceResolution, Self::Error>;
}

fn canonical_uuid(value: &str) -> Result<Uuid, DomainError> {
    let parsed = Uuid::parse_str(value).map_err(|_| DomainError::InvalidDeviceIdentity)?;
    (parsed.to_string() == value)
        .then_some(parsed)
        .ok_or(DomainError::InvalidDeviceIdentity)
}

fn validate_non_empty_bounded(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len
}
