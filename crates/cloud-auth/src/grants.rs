use candy_proto::cloud_grant::{
    AccessGrantEnvelopeV1, AccessGrantPayloadV1, ServiceClass, MAX_GRANT_TTL_SECS,
};
use carrier_crypto::cloud_grant::{sign_access_grant, CloudGrantCryptoError};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

pub const PRIVATE_GRANT_TTL_SECS: u64 = 24 * 60 * 60;
const _: () = assert!(PRIVATE_GRANT_TTL_SECS <= MAX_GRANT_TTL_SECS);
const PRIVATE_GRANT_REFRESH_NUMERATOR: u64 = 3;
const PRIVATE_GRANT_REFRESH_DENOMINATOR: u64 = 4;

#[derive(Debug, thiserror::Error)]
pub enum GrantIssueError {
    #[error("private grant requires a customer private service class")]
    InvalidServiceClass,
    #[error("grant time arithmetic overflow")]
    TimeOverflow,
    #[error("Core grant payload rejected")]
    Protocol(#[from] candy_proto::error::ProtocolError),
    #[error("Core grant signing failed")]
    Crypto(#[from] CloudGrantCryptoError),
}

/// A Core-defined signed envelope and its exact wire encoding. Candy Cloud owns no Grant codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedGrant {
    envelope: AccessGrantEnvelopeV1,
    raw: Vec<u8>,
}

impl IssuedGrant {
    pub fn envelope(&self) -> &AccessGrantEnvelopeV1 {
        &self.envelope
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.raw).into()
    }
}

/// Signs protocol-owned Core Grant payloads with the Cloud signing key.
pub struct GrantSigner {
    key_id: String,
    signing_key: SigningKey,
}

impl GrantSigner {
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Applies the product default private-node lifetime then signs the canonical Core payload.
    pub fn issue_private(
        &self,
        mut payload: AccessGrantPayloadV1,
        issued_at: u64,
    ) -> Result<IssuedGrant, GrantIssueError> {
        if payload.service_class != ServiceClass::CustomerPrivate {
            return Err(GrantIssueError::InvalidServiceClass);
        }
        let expires_at = issued_at
            .checked_add(PRIVATE_GRANT_TTL_SECS)
            .ok_or(GrantIssueError::TimeOverflow)?;
        let refresh_after = issued_at
            .checked_add(
                PRIVATE_GRANT_TTL_SECS
                    .checked_mul(PRIVATE_GRANT_REFRESH_NUMERATOR)
                    .ok_or(GrantIssueError::TimeOverflow)?
                    / PRIVATE_GRANT_REFRESH_DENOMINATOR,
            )
            .ok_or(GrantIssueError::TimeOverflow)?;
        payload.issued_at = issued_at;
        payload.not_before = issued_at;
        payload.refresh_after = refresh_after;
        payload.expires_at = expires_at;

        let payload = payload.encode()?;
        let envelope =
            sign_access_grant(payload, self.key_id.as_bytes().to_vec(), &self.signing_key)?;
        let raw = envelope.encode()?;
        Ok(IssuedGrant { envelope, raw })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candy_proto::cloud_grant::{
        AccessGrantEnvelopeV1, DeviceId, DeviceKeyId, EnvironmentId, GrantId, IssuerId, NodePoolId,
        OperatorScopeType, OrganizationId, SubscriptionId, TenantId,
    };
    use candy_proto::features::FeatureSet;
    use carrier_crypto::cloud_grant::verify_access_grant;

    fn payload() -> AccessGrantPayloadV1 {
        AccessGrantPayloadV1 {
            grant_id: GrantId([1; 16]),
            issuer_id: IssuerId([2; 16]),
            environment_id: EnvironmentId([3; 16]),
            organization_id: OrganizationId([4; 16]),
            tenant_id: TenantId([5; 16]),
            subscription_id: SubscriptionId([6; 16]),
            device_id: DeviceId([7; 16]),
            device_key_id: DeviceKeyId([8; 16]),
            device_public_key: [9; 32],
            assurance_level: 2,
            node_pool_id: NodePoolId([10; 16]),
            service_class: ServiceClass::CustomerPrivate,
            operator_scope_type: OperatorScopeType::Customer,
            operator_id: None,
            region_ids: Vec::new(),
            allowed_features: FeatureSet::from_bits(0),
            service_permissions: 1,
            route_policy: None,
            dns_policy: None,
            max_outer_connections_per_node: 2,
            max_outer_connections_per_pool: 4,
            max_active_sessions_per_connection: 128,
            max_udp_flows_per_connection: 256,
            max_pending_opens: 32,
            max_speculative_streams: 8,
            max_datagram_record: 1200,
            upload_rate_bps: 10_000_000,
            download_rate_bps: 20_000_000,
            issued_at: 0,
            not_before: 0,
            refresh_after: 0,
            expires_at: 0,
            policy_generation: 23,
            entitlement_generation: 24,
        }
    }

    #[test]
    fn private_issue_uses_core_codec_and_crypto_with_one_day_ttl() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signer = GrantSigner::new("k1", key.clone());
        let issued = signer
            .issue_private(payload(), 1_800_000_000)
            .expect("valid Core Grant");

        let envelope = AccessGrantEnvelopeV1::decode(issued.raw()).expect("Core envelope");
        verify_access_grant(&envelope, &key.verifying_key()).expect("Core signature");
        let decoded = AccessGrantPayloadV1::decode(&envelope.payload).expect("Core payload");
        assert_eq!(decoded.issued_at, 1_800_000_000);
        assert_eq!(decoded.expires_at, 1_800_086_400);
        assert_eq!(decoded.refresh_after, 1_800_064_800);
        assert_eq!(envelope, *issued.envelope());
    }

    #[test]
    fn issued_grant_digest_is_stable_for_same_core_envelope() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let signer = GrantSigner::new("k1", key);
        let grant = signer.issue_private(payload(), 1_800_000_000).unwrap();
        assert_eq!(grant.digest(), grant.digest());
    }

    #[test]
    fn private_issuer_rejects_non_private_core_payloads() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let signer = GrantSigner::new("k1", key);
        let mut invalid = payload();
        invalid.service_class = ServiceClass::CandySharedAcceleration;
        assert!(matches!(
            signer.issue_private(invalid, 1_800_000_000),
            Err(GrantIssueError::InvalidServiceClass)
        ));
    }
}
