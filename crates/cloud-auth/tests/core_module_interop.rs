//! Interoperability coverage against a released Candy Core module.
//!
//! This test is intentionally opt-in: normal Cloud builds have no Core source
//! checkout and use the signed module supplied by the release pipeline.

use std::{fs, path::PathBuf, sync::Arc};

use cloud_auth::grants::GrantSigner;
use cloud_core_module::{CoreModule, ModuleRequirements, VerifiedModuleSpec};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn repeated_hex(byte: u8, length: usize) -> String {
    format!("{byte:02x}").repeat(length)
}

fn grant_object() -> Value {
    json!({
        "object_type": "grant_payload_v1",
        "grant_id_hex": repeated_hex(1, 16),
        "issuer_id_hex": repeated_hex(2, 16),
        "environment_id_hex": repeated_hex(3, 16),
        "organization_id_hex": repeated_hex(4, 16),
        "tenant_id_hex": repeated_hex(5, 16),
        "subscription_id_hex": repeated_hex(6, 16),
        "device_id_hex": repeated_hex(7, 16),
        "device_key_id_hex": repeated_hex(8, 16),
        "device_public_key_hex": repeated_hex(9, 32),
        "assurance_level": 2,
        "node_pool_id_hex": repeated_hex(10, 16),
        "service_class": 1,
        "operator_scope_type": 1,
        "operator_id_hex": null,
        "region_ids_hex": [],
        "allowed_features": 0,
        "service_permissions": 1,
        "route_policy": null,
        "dns_policy": null,
        "max_outer_connections_per_node": 2,
        "max_outer_connections_per_pool": 4,
        "max_active_sessions_per_connection": 128,
        "max_udp_flows_per_connection": 256,
        "max_pending_opens": 32,
        "max_speculative_streams": 8,
        "max_datagram_record": 1200,
        "upload_rate_bps": 10_000_000u64,
        "download_rate_bps": 20_000_000u64,
        "issued_at": 1_800_000_000u64,
        "not_before": 1_800_000_000u64,
        "refresh_after": 1_800_064_800u64,
        "expires_at": 1_800_086_400u64,
        "policy_generation": 23,
        "entitlement_generation": 24
    })
}

#[test]
#[ignore = "requires CANDY_CORE_INTEROP_MODULE pointing to a released Core module"]
fn cloud_signs_and_validates_a_real_core_envelope() {
    let module = PathBuf::from(
        std::env::var_os("CANDY_CORE_INTEROP_MODULE")
            .expect("CANDY_CORE_INTEROP_MODULE must point to the shared module"),
    );
    let root = module.parent().expect("Core module has a parent");
    let digest = Sha256::digest(fs::read(&module).expect("read Core module")).into();
    let owner_uid = fs::metadata(root).expect("read Core module root").uid();
    let core = CoreModule::load(
        &VerifiedModuleSpec::new(root, &module, digest, owner_uid),
        &ModuleRequirements {
            wire_protocol: Some("0.3".into()),
            required_objects: ["grant-payload-v1", "grant-envelope-v1"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ..ModuleRequirements::default()
        },
    )
    .expect("load real Core module");
    let signer = GrantSigner::new(
        "grant-key-1",
        SigningKey::from_bytes(&[7; 32]),
        Arc::new(core),
    );
    let request = grant_object();
    let issued = signer
        .issue_private(&request)
        .expect("Core prepare, Cloud signature, assemble and validate");
    assert!(!issued.raw().is_empty());
    assert_ne!(issued.digest(), [0; 32]);
}

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
