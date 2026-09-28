//! Cross-language conformance tests for `policy-projection-v1`.
//!
//! The fixture below is a byte-for-byte copy of the frozen Client vector
//! `contracts/examples/policy_projection.json`, and the expected hash and
//! signature come from `contracts/examples/signature_vector.json`. Cloud and the
//! Client are separate repositories with separate toolchains, so the only thing
//! keeping them compatible is asserting the same numbers on both sides.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use cloud_client_projection::{
    format_content_hash, PolicyProjectionDns, PolicyProjectionDnsEgress, PolicyProjectionDnsMode,
    PolicyProjectionError, PolicyProjectionSigner, PolicyProjectionTrafficMode, PolicyProjectionV1,
    POLICY_PROJECTION_DOMAIN,
};
use ed25519_dalek::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SIGNING_KEY_ID: &str = "cloud-policy-2026-01";
const EXPECTED_CONTENT_HASH: &str =
    "sha256:8b0b0b3d81cd7cc8934315312d712a7a2d534c91f37a7d48ef8621748b6be393";
const EXPECTED_SIGNATURE: &str =
    "og2GE5Y3FJmvMQJ4FOlbeECR7Ckkp+TGXizbung6SB43TlHaCq0IEE3F0m13CfaPNqGNHNNAAcmzrFtAFQJRAA==";
const EXPECTED_PUBLIC_KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const FIXTURE_NODE_ID: &str = "77777777-7777-4777-8777-777777777777";

/// The frozen Client fixture, including the signed fields Cloud must reproduce.
const FIXTURE: &str = include_str!("fixtures/policy_projection.json");

fn fixture() -> PolicyProjectionV1 {
    PolicyProjectionV1::from_envelope_bytes(FIXTURE.as_bytes()).unwrap()
}

/// RFC 8032 Ed25519 test key 1, the key behind the frozen vector.
fn signer() -> PolicyProjectionSigner {
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    PolicyProjectionSigner::new(SIGNING_KEY_ID, SigningKey::from_bytes(&seed)).unwrap()
}

fn global_fixture(egress_node: Uuid) -> PolicyProjectionV1 {
    let mut projection = fixture();
    projection.traffic_mode = PolicyProjectionTrafficMode::Global;
    projection.global_egress.enabled = true;
    projection.global_egress.node_id = egress_node;
    projection.global_egress.dns_egress = PolicyProjectionDnsEgress::SelectedNode;
    projection.dns_projection = PolicyProjectionDns {
        mode: PolicyProjectionDnsMode::CloudGlobal,
        servers: vec!["10.20.0.53".to_owned()],
        search_domains: None,
        leak_protection: true,
    };
    projection
}

#[test]
fn fixture_reproduces_the_frozen_client_content_hash() {
    let projection = fixture();
    let canonical = projection.canonical_bytes().unwrap();
    let hash: [u8; 32] = Sha256::digest(&canonical).into();
    assert_eq!(format_content_hash(&hash), EXPECTED_CONTENT_HASH);
    assert_eq!(projection.content_hash().unwrap(), hash);
}

#[test]
fn hashed_payload_keeps_signing_key_id_and_drops_only_the_signature_fields() {
    let projection = fixture();
    let canonical = projection.canonical_bytes().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    let object = value.as_object().unwrap();
    // Only these two leave the hashed view. Anything else disappearing would
    // silently change the signature every Client computes.
    assert!(!object.contains_key("signature"));
    assert!(!object.contains_key("content_hash"));
    // 26 struct fields minus `signature` and `content_hash`.
    assert_eq!(object.len(), 24);
    assert_eq!(
        object
            .get("signing_key_id")
            .and_then(|value| value.as_str()),
        Some(SIGNING_KEY_ID)
    );
    assert_eq!(
        object.get("projection_id").and_then(|value| value.as_str()),
        Some("11111111-1111-4111-8111-111111111111")
    );
}

#[test]
fn fixture_reproduces_the_frozen_client_signature_and_public_key() {
    let projection = fixture();
    let verifying_key = signer().verifying_key();
    assert_eq!(
        BASE64_STANDARD.encode(verifying_key.to_bytes()),
        EXPECTED_PUBLIC_KEY
    );
    projection.verify(&verifying_key).unwrap();

    // Independent of `verify`, spell out the frozen construction so a change to
    // either the domain prefix or the hashed view fails here rather than in the
    // field.
    let hash = Sha256::digest(projection.canonical_bytes().unwrap());
    let mut message = POLICY_PROJECTION_DOMAIN.to_vec();
    message.extend_from_slice(&hash);
    let signature =
        Signature::from_slice(&BASE64_STANDARD.decode(EXPECTED_SIGNATURE).unwrap()).unwrap();
    verifying_key.verify_strict(&message, &signature).unwrap();
}

#[test]
fn signing_the_fixture_reproduces_the_frozen_bytes_exactly() {
    let mut projection = fixture();
    projection.signing_key_id = String::new();
    projection.content_hash = String::new();
    projection.signature = String::new();
    let signed = signer().sign(projection).unwrap();
    assert_eq!(signed.content_hash, EXPECTED_CONTENT_HASH);
    assert_eq!(signed.signature, EXPECTED_SIGNATURE);
    assert_eq!(signed.signing_key_id, SIGNING_KEY_ID);
}

#[test]
fn signature_verification_fails_for_any_tampered_field() {
    let verifying_key = signer().verifying_key();

    // A tampered but still individually valid payload keeps its old hash, so the
    // hash comparison catches it before the signature is even consulted.
    let mut tampered = fixture();
    tampered.allowed_resources[0].ports = vec![443, 8443];
    assert_eq!(
        tampered.verify(&verifying_key),
        Err(PolicyProjectionError::ContentHashMismatch)
    );

    // Re-signing after tampering restores a self-consistent document, which is
    // why the Client must pin the key id out of band.
    let resigned = signer().sign(tampered).unwrap();
    assert_ne!(resigned.content_hash, EXPECTED_CONTENT_HASH);
    resigned.verify(&verifying_key).unwrap();

    let mut mode_swap = fixture();
    mode_swap.traffic_mode = PolicyProjectionTrafficMode::Global;
    assert_eq!(
        mode_swap.verify(&verifying_key),
        Err(PolicyProjectionError::InvalidProjection)
    );

    let mut duplicated = fixture();
    duplicated.standby_nodes[0].node_id = duplicated.selected_node.node_id;
    assert!(duplicated.verify(&verifying_key).is_err());
}

#[test]
fn projection_signed_by_another_key_is_rejected() {
    let other =
        PolicyProjectionSigner::new(SIGNING_KEY_ID, SigningKey::from_bytes(&[7_u8; 32])).unwrap();
    assert_eq!(
        fixture().verify(&other.verifying_key()),
        Err(PolicyProjectionError::InvalidSignature)
    );
}

#[test]
fn audience_must_match_the_signed_identity() {
    let mut projection = fixture();
    projection.audience.device_key_id = Uuid::from_u128(0xbeef);
    assert_eq!(
        projection.validate(),
        Err(PolicyProjectionError::AudienceMismatch)
    );
    // The top-level fields are the ones the tunnel is actually built from, so a
    // mismatched audience is a hard failure rather than a warning.
    assert_eq!(
        signer().sign(projection),
        Err(PolicyProjectionError::AudienceMismatch)
    );

    let mut nil_audience = fixture();
    nil_audience.audience.user_id = Uuid::nil();
    assert_eq!(
        nil_audience.validate(),
        Err(PolicyProjectionError::AudienceMismatch)
    );
}

#[test]
fn projection_window_never_outlives_the_grant() {
    let mut beyond_grant = fixture();
    beyond_grant.stale_until = beyond_grant.grant_expires_at + 1;
    assert_eq!(
        beyond_grant.validate(),
        Err(PolicyProjectionError::InvalidProjection)
    );

    let mut issued_before_not_before = fixture();
    issued_before_not_before.issued_at = issued_before_not_before.not_before - 1;
    assert!(issued_before_not_before.validate().is_err());

    let mut exactly_at_grant_expiry = fixture();
    exactly_at_grant_expiry.stale_until = exactly_at_grant_expiry.grant_expires_at;
    exactly_at_grant_expiry.selected_node.assignment_lease_until =
        exactly_at_grant_expiry.grant_expires_at;
    exactly_at_grant_expiry.standby_nodes[0].assignment_lease_until =
        exactly_at_grant_expiry.grant_expires_at;
    // Equality is the boundary, not a violation.
    assert!(exactly_at_grant_expiry.validate().is_ok());
}

#[test]
fn traffic_mode_and_global_egress_must_agree() {
    // Global selected but egress not enabled.
    let mut global_without_egress = global_fixture(fixture().selected_node.node_id);
    global_without_egress.global_egress.enabled = false;
    assert_eq!(
        global_without_egress.validate(),
        Err(PolicyProjectionError::InvalidProjection)
    );

    let mut global_without_dns = global_fixture(fixture().selected_node.node_id);
    global_without_dns.global_egress.dns_egress = PolicyProjectionDnsEgress::None;
    assert!(global_without_dns.validate().is_err());

    // Policy mode carrying a latent default route.
    let mut policy_with_egress = fixture();
    policy_with_egress.global_egress.enabled = true;
    policy_with_egress.global_egress.dns_egress = PolicyProjectionDnsEgress::SelectedNode;
    assert!(policy_with_egress.validate().is_err());

    let mut policy_with_dns_egress = fixture();
    policy_with_dns_egress.global_egress.dns_egress = PolicyProjectionDnsEgress::CloudResolver;
    assert!(policy_with_dns_egress.validate().is_err());

    // The active mode must itself be one of the advertised capabilities.
    let mut policy_when_only_global_is_allowed = fixture();
    policy_when_only_global_is_allowed.mode_capabilities =
        vec![PolicyProjectionTrafficMode::Global];
    assert!(policy_when_only_global_is_allowed.validate().is_err());
}

#[test]
fn global_mode_projection_is_accepted_when_fully_specified() {
    let verifying_key = signer().verifying_key();
    let projection = fixture();
    // Either assigned node is a legal egress, including the primary.
    for egress in [
        projection.selected_node.node_id,
        projection.standby_nodes[0].node_id,
    ] {
        let signed = signer().sign(global_fixture(egress)).unwrap();
        assert_eq!(signed.global_egress.node_id, egress);
        signed.verify(&verifying_key).unwrap();
    }

    // A node Cloud never assigned must not become the exit, or global mode would
    // route around the Grant's node set.
    let unassigned = Uuid::new_v4();
    assert_eq!(
        global_fixture(unassigned).validate(),
        Err(PolicyProjectionError::InvalidProjection)
    );
}

#[test]
fn node_lease_cannot_outlive_the_projection() {
    let mut lease_beyond_stale = fixture();
    lease_beyond_stale.selected_node.assignment_lease_until = lease_beyond_stale.stale_until + 1;
    assert!(lease_beyond_stale.validate().is_err());

    let mut standby_beyond_stale = fixture();
    standby_beyond_stale.standby_nodes[0].assignment_lease_until =
        standby_beyond_stale.stale_until + 1;
    assert!(standby_beyond_stale.validate().is_err());
}

#[test]
fn duplicate_standby_nodes_and_empty_underlay_exclusions_are_rejected() {
    let mut duplicated = fixture();
    let standby = duplicated.standby_nodes[0].clone();
    duplicated.standby_nodes.push(standby);
    assert!(duplicated.validate().is_err());

    // `minItems: 1` in the frozen schema: with no exclusions the client would try
    // to tunnel its own underlay transport and talk to itself.
    let mut no_exclusions = fixture();
    no_exclusions.underlay_exclusions.clear();
    assert!(no_exclusions.validate().is_err());

    let mut duplicated_exclusion = fixture();
    duplicated_exclusion
        .underlay_exclusions
        .push(duplicated_exclusion.underlay_exclusions[0].clone());
    assert!(duplicated_exclusion.validate().is_err());
}

#[test]
fn resources_must_authorize_something() {
    let mut empty = fixture();
    empty.allowed_resources[0].domains.clear();
    empty.allowed_resources[0].cidrs.clear();
    assert!(empty.validate().is_err());

    // A domain-only resource is the normal shape and must stay legal.
    let mut domain_only = fixture();
    domain_only.allowed_resources[0].cidrs.clear();
    assert!(domain_only.validate().is_ok());

    let mut port_zero = fixture();
    port_zero.allowed_resources[0].ports = vec![0];
    assert!(port_zero.validate().is_err());
}

#[test]
fn node_assignment_priority_and_transport_are_bounded() {
    let mut zero_priority = fixture();
    zero_priority.selected_node.priority = 0;
    assert!(zero_priority.validate().is_err());

    let mut unknown_transport = fixture();
    unknown_transport.selected_node.transport = "udp".to_owned();
    assert!(unknown_transport.validate().is_err());

    for transport in ["quic", "tls_tcp"] {
        let mut projection = fixture();
        projection.selected_node.transport = transport.to_owned();
        assert!(projection.validate().is_ok(), "transport {transport}");
    }

    let mut control_characters = fixture();
    control_characters.selected_node.endpoint = "edge-a.example.test:443\nHost: evil".to_owned();
    assert!(control_characters.validate().is_err());
}

#[test]
fn unknown_fields_are_rejected_so_a_smuggled_field_cannot_ride_along() {
    let text = FIXTURE.replace(
        "\"traffic_mode\": \"policy\"",
        "\"traffic_mode\": \"policy\", \"local_override\": true",
    );
    assert!(PolicyProjectionV1::from_envelope_bytes(text.as_bytes()).is_err());

    let nested = FIXTURE.replace(
        "\"leak_protection\": true",
        "\"leak_protection\": true, \"fallback_resolver\": \"8.8.8.8\"",
    );
    assert!(PolicyProjectionV1::from_envelope_bytes(nested.as_bytes()).is_err());
}

#[test]
fn envelope_bytes_round_trip_byte_identically() {
    let projection = fixture();
    let bytes = projection.to_envelope_bytes().unwrap();
    let reparsed = PolicyProjectionV1::from_envelope_bytes(&bytes).unwrap();
    assert_eq!(reparsed, projection);
    assert_eq!(reparsed.to_envelope_bytes().unwrap(), bytes);
    // Replay must hand back the original bytes, never a fresh serialization of
    // the struct, so the stored hash stays valid across restarts.
    assert_ne!(bytes, FIXTURE.as_bytes());
    assert_eq!(
        Sha256::digest(&bytes),
        Sha256::digest(
            PolicyProjectionV1::from_envelope_bytes(bytes.as_slice())
                .unwrap()
                .to_envelope_bytes()
                .unwrap()
        )
    );
}

#[test]
fn envelope_reader_rejects_empty_oversized_and_non_json_input() {
    assert!(PolicyProjectionV1::from_envelope_bytes(b"").is_err());
    assert!(PolicyProjectionV1::from_envelope_bytes(b"not json").is_err());
    assert!(PolicyProjectionV1::from_envelope_bytes(&vec![b' '; 1024 * 1024 + 1]).is_err());

    // Truncated but otherwise well-formed input must not panic.
    let truncated = &FIXTURE.as_bytes()[..FIXTURE.len() / 2];
    assert!(PolicyProjectionV1::from_envelope_bytes(truncated).is_err());
}

#[test]
fn helper_rejects_a_negative_or_malformed_content_hash() {
    for malformed in [
        "",
        "8b0b0b3d",
        "sha256:",
        "sha256:zzzz",
        "SHA256:8b0b0b3d81cd7cc8934315312d712a7a2d534c91f37a7d48ef8621748b6be393",
        "sha256:8b0b0b3d81cd7cc8934315312d712a7a2d534c91f37a7d48ef8621748b6be39",
    ] {
        let mut projection = fixture();
        projection.content_hash = malformed.to_owned();
        assert!(
            projection.verify(&signer().verifying_key()).is_err(),
            "content hash {malformed:?} must not verify"
        );
    }
}

#[test]
fn signing_overwrites_a_caller_supplied_key_id_and_hash() {
    let mut projection = fixture();
    projection.signing_key_id = "attacker-supplied".to_owned();
    projection.content_hash =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    projection.signature = "AAAA".to_owned();
    let signed = signer().sign(projection).unwrap();
    assert_eq!(signed.signing_key_id, SIGNING_KEY_ID);
    assert_eq!(signed.content_hash, EXPECTED_CONTENT_HASH);
    assert_eq!(signed.signature, EXPECTED_SIGNATURE);
}

#[test]
fn signer_key_id_must_be_a_safe_identifier() {
    for rejected in ["", "with space", "with/slash", "with\nnewline"] {
        assert!(
            PolicyProjectionSigner::new(rejected, SigningKey::from_bytes(&[1_u8; 32])).is_err(),
            "key id {rejected:?} must be rejected"
        );
    }
    assert!(
        PolicyProjectionSigner::new("a".repeat(129), SigningKey::from_bytes(&[1_u8; 32])).is_err()
    );

    let signer = PolicyProjectionSigner::new(
        "cloud-policy-2026-01:rotated",
        SigningKey::from_bytes(&[1_u8; 32]),
    )
    .unwrap();
    assert_eq!(signer.key_id(), "cloud-policy-2026-01:rotated");
}

#[test]
fn signing_refuses_a_projection_the_client_would_reject() {
    let mut no_exclusions = fixture();
    no_exclusions.underlay_exclusions.clear();
    assert_eq!(
        signer().sign(no_exclusions),
        Err(PolicyProjectionError::InvalidProjection)
    );

    let mut unsupported_mode = fixture();
    unsupported_mode.mode_capabilities = vec![PolicyProjectionTrafficMode::Global];
    // Policy mode is not in the capability list, so the Client would refuse to
    // install this. Cloud must fail at signing time rather than at the device.
    assert!(signer().sign(unsupported_mode).is_err());
}

#[test]
fn dns_projection_search_domains_are_bounded_and_optional() {
    let mut without_search_domains = fixture();
    without_search_domains.dns_projection.search_domains = None;
    let bytes = without_search_domains.to_envelope_bytes().unwrap();
    // An absent optional field must vanish from the wire form rather than
    // serializing as `null`, which would change the hash.
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(!value["dns_projection"]
        .as_object()
        .unwrap()
        .contains_key("search_domains"));
    let signed = signer().sign(without_search_domains).unwrap();
    signed.verify(&signer().verifying_key()).unwrap();

    let mut too_many_servers = fixture();
    too_many_servers.dns_projection.servers =
        (0..9).map(|index| format!("10.0.0.{index}")).collect();
    assert!(too_many_servers.validate().is_err());

    let mut empty_search_domain = fixture();
    empty_search_domain.dns_projection.search_domains = Some(vec![String::new()]);
    assert!(empty_search_domain.validate().is_err());
}

#[test]
fn fixture_is_canonical_so_field_order_never_changes_the_hash() {
    let pretty = fixture().to_envelope_bytes().unwrap();
    let mut reordered: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&pretty).unwrap();
    let rebuilt: serde_json::Map<String, serde_json::Value> =
        reordered.clone().into_iter().rev().collect();
    reordered.clear();
    reordered.extend(rebuilt);
    let shuffled = serde_json::to_vec(&serde_json::Value::Object(reordered)).unwrap();
    let projection = PolicyProjectionV1::from_envelope_bytes(&shuffled).unwrap();
    assert_eq!(
        format_content_hash(&projection.content_hash().unwrap()),
        EXPECTED_CONTENT_HASH
    );
    projection.verify(&signer().verifying_key()).unwrap();
}

#[test]
fn verify_requires_the_projection_to_be_valid_before_the_signature() {
    let mut projection = fixture();
    projection.schema_version = 2;
    assert_eq!(
        projection.verify(&signer().verifying_key()),
        Err(PolicyProjectionError::InvalidProjection)
    );

    let mut nil_projection_id = fixture();
    nil_projection_id.projection_id = Uuid::nil();
    assert!(nil_projection_id.verify(&signer().verifying_key()).is_err());

    let mut zero_generation = fixture();
    zero_generation.generation = 0;
    assert!(zero_generation.verify(&signer().verifying_key()).is_err());
}

#[test]
fn node_assignment_serializes_in_the_frozen_field_order() {
    let projection = fixture();
    let value: serde_json::Value =
        serde_json::from_slice(&projection.to_envelope_bytes().unwrap()).unwrap();
    // RFC 8785 orders object members lexicographically at every level, which is
    // what makes two independently serialized copies hash identically.
    for object in [
        &value,
        &value["audience"],
        &value["selected_node"],
        &value["standby_nodes"][0],
        &value["allowed_resources"][0],
        &value["dns_projection"],
        &value["global_egress"],
    ] {
        let keys: Vec<&str> = object
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "members of {keys:?} are not canonical order");
    }

    let node = &value["selected_node"];
    assert_eq!(node["node_id"], FIXTURE_NODE_ID);
    assert_eq!(node["assignment_lease_until"], 1_899_999_800);
    assert_eq!(node["transport"], "quic");
}

#[test]
fn dns_mode_and_egress_use_the_frozen_snake_case_names() {
    assert_eq!(
        serde_json::to_string(&PolicyProjectionDnsMode::CloudSplit).unwrap(),
        "\"cloud_split\""
    );
    assert_eq!(
        serde_json::to_string(&PolicyProjectionDnsMode::CloudGlobal).unwrap(),
        "\"cloud_global\""
    );
    assert_eq!(
        serde_json::to_string(&PolicyProjectionDnsMode::Disabled).unwrap(),
        "\"disabled\""
    );
    assert_eq!(
        serde_json::to_string(&PolicyProjectionDnsEgress::SelectedNode).unwrap(),
        "\"selected_node\""
    );
    assert_eq!(
        serde_json::to_string(&PolicyProjectionDnsEgress::CloudResolver).unwrap(),
        "\"cloud_resolver\""
    );
    assert_eq!(
        serde_json::to_string(&PolicyProjectionDnsEgress::None).unwrap(),
        "\"none\""
    );
}
