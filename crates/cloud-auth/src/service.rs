use chrono::{TimeZone, Utc};
use cloud_db::{
    authorization::{AuthorizationLookup, AuthorizationRepository},
    enrollment::{EnrollmentOutcome, EnrollmentRepository, EnrollmentWrite},
    repositories::{
        GrantIssuanceRepository, GrantIssuanceWrite, GrantRecordOutcome, StoredGrantRecord,
    },
};

use crate::{
    db_mapping::{private_material_from_record, MappingError},
    grants::{GrantSigner, PRIVATE_GRANT_TTL_SECS},
    issuance::{
        prepare_private_grant, prepare_private_grant_with_id, IssuerConfig, PrepareGrantError,
        PreparedGrant,
    },
    routes::{
        AuthenticatedTenant, EnrollmentReceipt, GrantIssuanceReceipt, GrantIssueCommand,
        GrantServiceError, ServiceFuture, TenantAuthService,
    },
};

pub struct GrantDelivery {
    pub grant_id: uuid::Uuid,
    pub expires_at_unix: i64,
    pub replayed: bool,
    raw: Vec<u8>,
}

pub struct DatabaseTenantAuthService {
    enrollment: EnrollmentRepository,
    grants: GrantIssuanceCoordinator,
}

impl DatabaseTenantAuthService {
    pub fn new(enrollment: EnrollmentRepository, grants: GrantIssuanceCoordinator) -> Self {
        Self { enrollment, grants }
    }
}

impl TenantAuthService for DatabaseTenantAuthService {
    fn enroll(
        &self,
        actor: AuthenticatedTenant,
        enrollment: crate::domain::DeviceEnrollment,
    ) -> ServiceFuture<'_, Result<EnrollmentReceipt, GrantServiceError>> {
        Box::pin(async move {
            let write = EnrollmentWrite {
                device_record_id: enrollment.device.id,
                tenant_id: enrollment.device.tenant_id,
                device_identity: enrollment.device.identity,
                display_name: enrollment.device.display_name,
                key_record_id: enrollment.operational_key.id,
                key_id: enrollment.operational_key.key_id,
                public_key: enrollment.operational_key.public_key,
                assurance_level: 1,
                actor_id: actor.subject_id().to_owned(),
            };
            match self.enrollment.insert(&write).await {
                Ok(EnrollmentOutcome::Inserted) => Ok(EnrollmentReceipt {
                    device_id: write.device_record_id,
                }),
                Ok(EnrollmentOutcome::Conflict) => Err(GrantServiceError::Conflict),
                Err(_) => Err(GrantServiceError::Unavailable),
            }
        })
    }

    fn issue_grant(
        &self,
        command: GrantIssueCommand,
    ) -> ServiceFuture<'_, Result<GrantIssuanceReceipt, GrantServiceError>> {
        Box::pin(async move {
            let issued_at =
                u64::try_from(Utc::now().timestamp()).map_err(|_| GrantServiceError::Internal)?;
            let delivery =
                self.grants
                    .issue(&command, issued_at)
                    .await
                    .map_err(|error| match error {
                        GrantCoordinatorError::Denied
                        | GrantCoordinatorError::Mapping(_)
                        | GrantCoordinatorError::Preparation(
                            PrepareGrantError::Authorization(_)
                            | PrepareGrantError::UnsupportedPermission
                            | PrepareGrantError::UnsupportedServiceClass
                            | PrepareGrantError::MissingRoutePolicy
                            | PrepareGrantError::RoutePolicyMismatch
                            | PrepareGrantError::MissingTunnelFeatures,
                        ) => GrantServiceError::Denied,
                        GrantCoordinatorError::Conflict => GrantServiceError::Conflict,
                        GrantCoordinatorError::Database(_)
                        | GrantCoordinatorError::SigningKeyUnavailable => {
                            GrantServiceError::Unavailable
                        }
                        GrantCoordinatorError::ReplayMismatch
                        | GrantCoordinatorError::Preparation(PrepareGrantError::Signing(_)) => {
                            GrantServiceError::Internal
                        }
                    })?;
            Ok(GrantIssuanceReceipt {
                grant_id: delivery.grant_id,
                expires_at_unix: delivery.expires_at_unix,
                replayed: delivery.replayed,
                access_grant: delivery.raw().to_vec(),
            })
        })
    }
}

impl GrantDelivery {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GrantCoordinatorError {
    #[error("authorization denied")]
    Denied,
    #[error("idempotency conflict")]
    Conflict,
    #[error("required signing key is unavailable")]
    SigningKeyUnavailable,
    #[error("persisted replay metadata is inconsistent")]
    ReplayMismatch,
    #[error("database unavailable")]
    Database(#[from] cloud_db::RepositoryError),
    #[error("authorization snapshot is invalid")]
    Mapping(#[from] MappingError),
    #[error("Grant preparation failed")]
    Preparation(#[from] PrepareGrantError),
}

pub struct GrantIssuanceCoordinator {
    authorization: AuthorizationRepository,
    records: GrantIssuanceRepository,
    signer: GrantSigner,
    issuer: IssuerConfig,
}

impl GrantIssuanceCoordinator {
    pub fn new(
        authorization: AuthorizationRepository,
        records: GrantIssuanceRepository,
        signer: GrantSigner,
        issuer: IssuerConfig,
    ) -> Self {
        Self {
            authorization,
            records,
            signer,
            issuer,
        }
    }

    pub async fn issue(
        &self,
        command: &GrantIssueCommand,
        issued_at: u64,
    ) -> Result<GrantDelivery, GrantCoordinatorError> {
        let lookup = AuthorizationLookup {
            tenant_id: command.request.tenant_id,
            device_id: command.request.device_id,
            device_key_id: command.request.device_key_id,
            node_pool_id: command.request.node_pool_id,
        };
        let record = self
            .authorization
            .load(&lookup)
            .await?
            .ok_or(GrantCoordinatorError::Denied)?;
        let material = private_material_from_record(record)?;
        let prepared = prepare_private_grant(
            &self.signer,
            &self.issuer,
            &command.request_id,
            &command.request,
            &material,
            issued_at,
        )?;
        let expires_at = Utc
            .timestamp_opt(prepared.expires_at as i64, 0)
            .single()
            .ok_or(GrantCoordinatorError::ReplayMismatch)?;
        let write = GrantIssuanceWrite {
            id: prepared.grant_id,
            tenant_id: command.request.tenant_id,
            device_id: command.request.device_id,
            request_id: command.request_id.clone(),
            authorization_generation: prepared.authorization_generation,
            request_fingerprint: prepared.request_fingerprint,
            key_id: self.signer.key_id().to_owned(),
            grant_digest: prepared.issued.digest(),
            expires_at,
        };
        match self.records.record(&write).await? {
            GrantRecordOutcome::Inserted(_) => Ok(delivery(prepared, false)),
            GrantRecordOutcome::Conflict => Err(GrantCoordinatorError::Conflict),
            GrantRecordOutcome::Replayed(existing) => {
                self.rebuild_replay(command, &material, existing)
            }
        }
    }

    fn rebuild_replay(
        &self,
        command: &GrantIssueCommand,
        material: &crate::issuance::PrivateGrantMaterial,
        existing: StoredGrantRecord,
    ) -> Result<GrantDelivery, GrantCoordinatorError> {
        if existing.key_id != self.signer.key_id() {
            return Err(GrantCoordinatorError::SigningKeyUnavailable);
        }
        let expires_at = u64::try_from(existing.expires_at.timestamp())
            .map_err(|_| GrantCoordinatorError::ReplayMismatch)?;
        let issued_at = expires_at
            .checked_sub(PRIVATE_GRANT_TTL_SECS)
            .ok_or(GrantCoordinatorError::ReplayMismatch)?;
        let rebuilt = prepare_private_grant_with_id(
            &self.signer,
            &self.issuer,
            existing.grant_id,
            &command.request_id,
            &command.request,
            material,
            issued_at,
        )?;
        if rebuilt.request_fingerprint != existing.request_fingerprint
            || rebuilt.issued.digest() != existing.grant_digest
        {
            return Err(GrantCoordinatorError::ReplayMismatch);
        }
        Ok(delivery(rebuilt, true))
    }
}

fn delivery(prepared: PreparedGrant, replayed: bool) -> GrantDelivery {
    GrantDelivery {
        grant_id: prepared.grant_id,
        expires_at_unix: prepared.expires_at as i64,
        replayed,
        raw: prepared.issued.raw().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{
            AuthorizationSnapshot, DeviceStatus, EntitlementSnapshot, GrantRequest, ServiceClass,
            SnapshotDevice, SnapshotStatus,
        },
        issuance::{GrantQuota, PrivateGrantMaterial},
        routes::AuthenticatedDevice,
    };
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    #[tokio::test]
    async fn replay_rebuilds_exact_original_envelope() {
        let tenant_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let device_key_id = Uuid::new_v4();
        let node_pool_id = Uuid::new_v4();
        let request = GrantRequest {
            tenant_id,
            device_id,
            device_key_id,
            node_pool_id,
            service_class: ServiceClass::Private,
            service_permission: "private.connect".into(),
        };
        let command = GrantIssueCommand {
            actor: AuthenticatedDevice::new(Uuid::new_v4(), tenant_id, device_id, device_key_id, 2)
                .unwrap(),
            request_id: "request-1".into(),
            request,
        };
        let material = PrivateGrantMaterial {
            organization_id: Uuid::new_v4(),
            subscription_id: Uuid::new_v4(),
            device_key_id,
            device_public_key: [7; 32],
            assurance_level: 2,
            route_policy: None,
            snapshot: AuthorizationSnapshot {
                tenant_id,
                authorization_generation: 9,
                device: SnapshotDevice {
                    id: device_id,
                    tenant_id,
                    status: DeviceStatus::Active,
                },
                subscription_status: SnapshotStatus::Active,
                entitlement: EntitlementSnapshot {
                    id: Uuid::new_v4(),
                    tenant_id,
                    node_pool_id,
                    service_class: ServiceClass::Private,
                    service_permission: "private.connect".into(),
                    status: SnapshotStatus::Active,
                    generation: 4,
                },
                policy_generation: 3,
                revocation_generation: 2,
            },
            quota: GrantQuota {
                allowed_features: 0,
                max_outer_connections_per_node: 2,
                max_outer_connections_per_pool: 4,
                max_active_sessions_per_connection: 128,
                max_udp_flows_per_connection: 256,
                max_pending_opens: 32,
                max_speculative_streams: 8,
                max_datagram_record: 1200,
                upload_rate_bps: 10_000_000,
                download_rate_bps: 20_000_000,
            },
        };
        let issuer = IssuerConfig {
            issuer_id: Uuid::new_v4(),
            environment_id: Uuid::new_v4(),
        };
        let grant_id = Uuid::new_v4();
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let original_signer = GrantSigner::new("k1", signing_key.clone());
        let original = prepare_private_grant_with_id(
            &original_signer,
            &issuer,
            grant_id,
            &command.request_id,
            &command.request,
            &material,
            1_800_000_000,
        )
        .unwrap();
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .connect_lazy("mysql://unused:unused@127.0.0.1/unused")
            .unwrap();
        let coordinator = GrantIssuanceCoordinator::new(
            AuthorizationRepository::new(pool.clone()),
            GrantIssuanceRepository::new(pool),
            GrantSigner::new("k1", signing_key),
            issuer,
        );
        let existing = StoredGrantRecord {
            grant_id,
            request_fingerprint: original.request_fingerprint,
            key_id: "k1".into(),
            grant_digest: original.issued.digest(),
            expires_at: Utc
                .timestamp_opt(original.expires_at as i64, 0)
                .single()
                .unwrap(),
        };
        let replay = coordinator
            .rebuild_replay(&command, &material, existing)
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.raw(), original.issued.raw());
    }
}
