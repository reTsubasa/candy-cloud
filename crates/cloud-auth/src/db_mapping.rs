use cloud_db::authorization::AuthorizationRecord;
use serde::Deserialize;

use crate::{
    domain::{
        AuthorizationSnapshot, DeviceStatus, EntitlementSnapshot, ServiceClass, SnapshotDevice,
        SnapshotStatus,
    },
    issuance::{GrantQuota, PrivateGrantMaterial, RoutePolicyBinding},
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MappingError {
    #[error("invalid device public key")]
    InvalidDevicePublicKey,
    #[error("unsupported service class")]
    UnsupportedServiceClass,
    #[error("invalid persisted status")]
    InvalidStatus,
    #[error("invalid Grant quota")]
    InvalidQuota,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedGrantQuota {
    allowed_features: u64,
    max_outer_connections_per_node: u64,
    max_outer_connections_per_pool: u64,
    max_active_sessions_per_connection: u64,
    max_udp_flows_per_connection: u64,
    max_pending_opens: u64,
    max_speculative_streams: u64,
    max_datagram_record: u64,
    upload_rate_bps: u64,
    download_rate_bps: u64,
}

pub fn private_material_from_record(
    record: AuthorizationRecord,
) -> Result<PrivateGrantMaterial, MappingError> {
    if record.service_class != "PRIVATE" {
        return Err(MappingError::UnsupportedServiceClass);
    }
    let device_public_key: [u8; 32] = record
        .device_public_key
        .try_into()
        .map_err(|_| MappingError::InvalidDevicePublicKey)?;
    let quota: PersistedGrantQuota =
        serde_json::from_str(&record.quota_json).map_err(|_| MappingError::InvalidQuota)?;
    if quota.max_datagram_record == 0 {
        return Err(MappingError::InvalidQuota);
    }
    let route_policy = record
        .route_policy
        .map(|policy| {
            Ok(RoutePolicyBinding {
                tenant_id: record.tenant_id,
                segment_id: policy.segment_id,
                attachment_id: policy.attachment_id,
                site_id: policy.site_id,
                device_id: record.device_id,
                device_key_id: record.device_key_id,
                node_pool_id: record.node_pool_id,
                projection_id: policy.projection_id,
                projection_generation: policy.projection_generation,
                projection_content_hash: policy
                    .projection_content_hash
                    .try_into()
                    .map_err(|_| MappingError::InvalidQuota)?,
                segment_generation: policy.segment_generation,
                segment_content_hash: policy
                    .segment_content_hash
                    .try_into()
                    .map_err(|_| MappingError::InvalidQuota)?,
            })
        })
        .transpose()?;
    Ok(PrivateGrantMaterial {
        organization_id: record.organization_id,
        subscription_id: record.subscription_id,
        device_key_id: record.device_key_id,
        device_public_key,
        assurance_level: record.assurance_level,
        route_policy,
        snapshot: AuthorizationSnapshot {
            tenant_id: record.tenant_id,
            authorization_generation: record.authorization_generation,
            device: SnapshotDevice {
                id: record.device_id,
                tenant_id: record.tenant_id,
                status: device_status(&record.device_status)?,
            },
            subscription_status: subscription_status(&record.subscription_status)?,
            entitlement: EntitlementSnapshot {
                id: record.entitlement_id,
                tenant_id: record.tenant_id,
                node_pool_id: record.node_pool_id,
                service_class: ServiceClass::Private,
                service_permission: record.service_permission,
                status: entitlement_status(&record.entitlement_status)?,
                generation: record.entitlement_generation,
            },
            policy_generation: record.policy_generation,
            revocation_generation: record.revocation_generation,
        },
        quota: GrantQuota {
            allowed_features: quota.allowed_features,
            max_outer_connections_per_node: quota.max_outer_connections_per_node,
            max_outer_connections_per_pool: quota.max_outer_connections_per_pool,
            max_active_sessions_per_connection: quota.max_active_sessions_per_connection,
            max_udp_flows_per_connection: quota.max_udp_flows_per_connection,
            max_pending_opens: quota.max_pending_opens,
            max_speculative_streams: quota.max_speculative_streams,
            max_datagram_record: quota.max_datagram_record,
            upload_rate_bps: quota.upload_rate_bps,
            download_rate_bps: quota.download_rate_bps,
        },
    })
}

fn device_status(value: &str) -> Result<DeviceStatus, MappingError> {
    match value {
        "PENDING" => Ok(DeviceStatus::Pending),
        "ACTIVE" => Ok(DeviceStatus::Active),
        "SUSPENDED" => Ok(DeviceStatus::Suspended),
        "REVOKED" => Ok(DeviceStatus::Revoked),
        _ => Err(MappingError::InvalidStatus),
    }
}

fn subscription_status(value: &str) -> Result<SnapshotStatus, MappingError> {
    match value {
        "TRIAL" => Ok(SnapshotStatus::Trial),
        "ACTIVE" => Ok(SnapshotStatus::Active),
        "GRACE" => Ok(SnapshotStatus::Grace),
        "PAST_DUE" => Ok(SnapshotStatus::Suspended),
        "CANCELLED" | "EXPIRED" => Ok(SnapshotStatus::Expired),
        _ => Err(MappingError::InvalidStatus),
    }
}

fn entitlement_status(value: &str) -> Result<SnapshotStatus, MappingError> {
    match value {
        "ACTIVE" => Ok(SnapshotStatus::Active),
        "SUSPENDED" => Ok(SnapshotStatus::Suspended),
        "REVOKED" => Ok(SnapshotStatus::Revoked),
        _ => Err(MappingError::InvalidStatus),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{GrantRequest, ServiceClass},
        grants::test_support::{request_from_issued, signer},
        issuance::{prepare_private_grant, IssuerConfig, PERMISSION_PRIVATE_TUN_CONNECT},
    };
    use uuid::Uuid;

    fn record() -> AuthorizationRecord {
        AuthorizationRecord {
            organization_id: Uuid::new_v4(), tenant_id: Uuid::new_v4(), subscription_id: Uuid::new_v4(), device_id: Uuid::new_v4(), device_status: "ACTIVE".into(), device_key_id: Uuid::new_v4(), device_public_key: vec![7; 32], assurance_level: 2, node_pool_id: Uuid::new_v4(), service_class: "PRIVATE".into(), entitlement_id: Uuid::new_v4(), service_permission: "private.connect".into(), entitlement_status: "ACTIVE".into(), entitlement_generation: 3, subscription_status: "ACTIVE".into(), policy_generation: 4, revocation_generation: 5, authorization_generation: 6,
            quota_json: r#"{"allowed_features":0,"max_outer_connections_per_node":2,"max_outer_connections_per_pool":4,"max_active_sessions_per_connection":128,"max_udp_flows_per_connection":256,"max_pending_opens":32,"max_speculative_streams":8,"max_datagram_record":1200,"upload_rate_bps":10000000,"download_rate_bps":20000000}"#.into(),
            route_policy: None,
        }
    }

    #[test]
    fn maps_strict_database_snapshot() {
        let material = private_material_from_record(record()).unwrap();
        assert_eq!(material.assurance_level, 2);
        assert_eq!(material.snapshot.authorization_generation, 6);
        assert_eq!(material.quota.max_datagram_record, 1200);
    }

    #[test]
    fn rejects_unknown_quota_fields() {
        let mut value = record();
        value.quota_json = r#"{"allowed_features":0,"unexpected":1}"#.into();
        assert_eq!(
            private_material_from_record(value).unwrap_err(),
            MappingError::InvalidQuota
        );
    }

    #[test]
    fn rejects_route_policy_with_non_sha256_hashes() {
        let mut value = record();
        value.route_policy = Some(cloud_db::authorization::AuthorizationRoutePolicy {
            segment_id: uuid::Uuid::new_v4(),
            attachment_id: uuid::Uuid::new_v4(),
            site_id: uuid::Uuid::new_v4(),
            projection_id: uuid::Uuid::new_v4(),
            projection_generation: 1,
            projection_content_hash: vec![1; 31],
            segment_generation: 1,
            segment_content_hash: vec![2; 32],
        });
        assert_eq!(
            private_material_from_record(value).unwrap_err(),
            MappingError::InvalidQuota
        );
    }

    #[test]
    fn production_projection_record_issues_core_tun_permission() {
        let mut value = record();
        value.service_permission = "private.tun.connect".into();
        value.quota_json = r#"{"allowed_features":9216,"max_outer_connections_per_node":2,"max_outer_connections_per_pool":4,"max_active_sessions_per_connection":128,"max_udp_flows_per_connection":256,"max_pending_opens":32,"max_speculative_streams":8,"max_datagram_record":1200,"upload_rate_bps":10000000,"download_rate_bps":20000000}"#.into();
        let projection_id = Uuid::new_v4();
        let projection_content_hash = vec![0x71; 32];
        value.route_policy = Some(cloud_db::authorization::AuthorizationRoutePolicy {
            segment_id: Uuid::new_v4(),
            attachment_id: Uuid::new_v4(),
            site_id: Uuid::new_v4(),
            projection_id,
            projection_generation: 17,
            projection_content_hash: projection_content_hash.clone(),
            segment_generation: 17,
            segment_content_hash: vec![0x72; 32],
        });
        let request = GrantRequest {
            tenant_id: value.tenant_id,
            device_id: value.device_id,
            device_key_id: value.device_key_id,
            node_pool_id: value.node_pool_id,
            service_class: ServiceClass::Private,
            service_permission: "private.tun.connect".into(),
        };
        let material = private_material_from_record(value).unwrap();

        let prepared = prepare_private_grant(
            &signer("production-projection-test", [3; 32]),
            &IssuerConfig {
                issuer_id: Uuid::new_v4(),
                environment_id: Uuid::new_v4(),
            },
            "production-projection-grant-17",
            &request,
            &material,
            1_800_000_000,
        )
        .unwrap();
        let build_request = request_from_issued(&prepared.issued);
        let payload = &build_request["object"];

        assert_eq!(payload["service_class"], 1);
        assert_eq!(
            payload["service_permissions"],
            PERMISSION_PRIVATE_TUN_CONNECT
        );
        assert_eq!(
            payload["route_policy"]["policy_id_hex"],
            projection_id.simple().to_string()
        );
        assert_eq!(payload["route_policy"]["generation"], 17);
        assert_eq!(payload["route_policy"]["content_hash_hex"], "71".repeat(32));
    }
}
