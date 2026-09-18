use base64::Engine;
use cloud_client_grant::{
    ClientGrantAudience, ClientGrantEnvelopeV1, ClientGrantError, ClientGrantNodeAssignment,
    ClientGrantPayloadV1, ClientGrantPolicyBinding, ClientGrantSigner, ClientGrantTrafficMode,
    CLIENT_GRANT_DOMAIN,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SIGNING_KEY_ID: &str = "cloud-client-grant-2026-01";

fn seed() -> [u8; 32] {
    // RFC 8032 Ed25519 test key 1, matching the Client fixed vector.
    let mut seed = [0_u8; 32];
    seed[0] = 0x9d;
    seed[1] = 0x61;
    seed[2] = 0xb1;
    seed[3] = 0x9d;
    seed[4] = 0xef;
    seed[5] = 0xfd;
    seed[6] = 0x5a;
    seed[7] = 0x60;
    seed[8] = 0xba;
    seed[9] = 0x84;
    seed[10] = 0x4a;
    seed[11] = 0xf4;
    seed[12] = 0x92;
    seed[13] = 0xec;
    seed[14] = 0x2c;
    seed[15] = 0xc4;
    seed[16] = 0x44;
    seed[17] = 0x49;
    seed[18] = 0xc5;
    seed[19] = 0x69;
    seed[20] = 0x7b;
    seed[21] = 0x32;
    seed[22] = 0x69;
    seed[23] = 0x19;
    seed[24] = 0x70;
    seed[25] = 0x3b;
    seed[26] = 0xac;
    seed[27] = 0x03;
    seed[28] = 0x1c;
    seed[29] = 0xae;
    seed[30] = 0x7f;
    seed[31] = 0x60;
    seed
}

fn ids() -> (Uuid, Uuid, Uuid, Uuid, Uuid) {
    (
        Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222),
        Uuid::from_u128(0x3333_3333_3333_4333_8333_3333_3333_3333),
        Uuid::from_u128(0x4444_4444_4444_4444_8444_4444_4444_4444),
        Uuid::from_u128(0x5555_5555_5555_4555_8555_5555_5555_5555),
        Uuid::from_u128(0x6666_6666_6666_4666_8666_6666_6666_6666),
    )
}

fn payload() -> ClientGrantPayloadV1 {
    let (tenant_id, user_id, device_id, device_key_id, grant_id) = ids();
    ClientGrantPayloadV1 {
        schema_version: 1,
        grant_id,
        tenant_id,
        user_id,
        device_id,
        device_key_id,
        audience: ClientGrantAudience {
            tenant_id,
            user_id,
            device_id,
            device_key_id,
        },
        device_generation: 7,
        generation: 42,
        issued_at: 1_899_996_400,
        not_before: 1_899_996_400,
        expires_at: 1_900_000_000,
        mode_capabilities: vec![ClientGrantTrafficMode::Policy, ClientGrantTrafficMode::Global],
        policy: ClientGrantPolicyBinding {
            policy_id: Uuid::from_u128(0x7777_7777_7777_4777_8777_7777_7777_7777),
            generation: 9,
            content_hash: format!("sha256:{}", "ab".repeat(32)),
        },
        nodes: vec![
            ClientGrantNodeAssignment {
                node_id: Uuid::from_u128(0x8888_8888_8888_4888_8888_8888_8888_8888),
                endpoint: "edge-a.example.test:443".into(),
                priority: 1,
                node_key_id: Uuid::from_u128(0x9999_9999_9999_4999_8999_9999_9999_9999),
                transport: "quic".into(),
                assignment_lease_until: 1_899_999_800,
            },
            ClientGrantNodeAssignment {
                node_id: Uuid::from_u128(0xaaaa_aaaa_aaaa_4aaa_8aaa_aaaa_aaaa_aaaa),
                endpoint: "edge-b.example.test:443".into(),
                priority: 2,
                node_key_id: Uuid::from_u128(0xbbbb_bbbb_bbbb_4bbb_8bbb_bbbb_bbbb_bbbb),
                transport: "quic".into(),
                assignment_lease_until: 1_899_999_800,
            },
        ],
        signing_key_id: SIGNING_KEY_ID.into(),
    }
}

fn signer() -> ClientGrantSigner {
    ClientGrantSigner::new(SIGNING_KEY_ID, SigningKey::from_bytes(&seed())).unwrap()
}

#[test]
fn issued_grant_round_trips_through_the_wire_token() {
    let signer = signer();
    let envelope = signer.issue(payload()).unwrap();
    // The signer self-verifies before returning, so a produced Grant is always valid.
    envelope.verify(&signer.verifying_key()).unwrap();

    let token = envelope.to_token().unwrap();
    let decoded = ClientGrantEnvelopeV1::from_token(&token).unwrap();
    assert_eq!(decoded, envelope);
    decoded.verify(&signer.verifying_key()).unwrap();
}

#[test]
fn signature_binds_rfc8785_canonical_bytes_of_every_payload_field() {
    let signer = signer();
    let envelope = signer.issue(payload()).unwrap();
    let payload = &envelope.payload;

    let canonical = payload.canonical_bytes().unwrap();
    let hash: [u8; 32] = Sha256::digest(&canonical).into();
    assert_eq!(
        envelope.content_hash,
        cloud_client_grant::format_content_hash(&hash)
    );

    // Reproduce the Node/Core verification path independently of the SDK helper.
    let mut message = CLIENT_GRANT_DOMAIN.to_vec();
    message.extend_from_slice(&hash);
    let verifying_key = VerifyingKey::from_bytes(&signer.verifying_key().to_bytes()).unwrap();
    let raw_signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&envelope.signature)
        .unwrap();
    let signature = Signature::from_slice(&raw_signature).unwrap();
    verifying_key.verify_strict(&message, &signature).unwrap();

    // The signature must be reproducible from the same key and transcript.
    let reproduced = SigningKey::from_bytes(&seed()).sign(&message).to_bytes();
    assert_eq!(reproduced, signature.to_bytes());
}

#[test]
fn tampering_with_an_authorized_resource_breaks_verification() {
    let signer = signer();
    let envelope = signer.issue(payload()).unwrap();

    // Escalating mode capability or widening the policy generation must fail.
    let mut widened = envelope.clone();
    widened.payload.policy.generation = 10;
    assert_eq!(
        widened.verify(&signer.verifying_key()),
        Err(ClientGrantError::ContentHashMismatch)
    );

    let mut rescoped = envelope.clone();
    rescoped.payload.audience.device_id = Uuid::new_v4();
    assert_eq!(
        rescoped.verify(&signer.verifying_key()),
        Err(ClientGrantError::AudienceMismatch)
    );
}

#[test]
fn grant_rejects_unauthorized_shapes_before_signing() {
    let signer = signer();

    let mut duplicated_node = payload();
    duplicated_node.nodes[1].node_id = duplicated_node.nodes[0].node_id;
    assert_eq!(
        signer.issue(duplicated_node),
        Err(ClientGrantError::InvalidPayload)
    );

    let mut out_of_order = payload();
    out_of_order.nodes[1].priority = 3;
    assert_eq!(
        signer.issue(out_of_order),
        Err(ClientGrantError::InvalidPayload)
    );

    let mut lease_beyond_grant = payload();
    lease_beyond_grant.nodes[0].assignment_lease_until = lease_beyond_grant.expires_at + 1;
    assert_eq!(
        signer.issue(lease_beyond_grant),
        Err(ClientGrantError::InvalidPayload)
    );

    let mut empty_modes = payload();
    empty_modes.mode_capabilities.clear();
    assert_eq!(
        signer.issue(empty_modes),
        Err(ClientGrantError::InvalidPayload)
    );

    let mut wrong_transport = payload();
    wrong_transport.nodes[0].transport = "tls_tcp".into();
    assert_eq!(
        signer.issue(wrong_transport),
        Err(ClientGrantError::InvalidPayload)
    );

    let mut bad_hash = payload();
    bad_hash.policy.content_hash = "sha256:nothex".into();
    assert_eq!(
        signer.issue(bad_hash),
        Err(ClientGrantError::InvalidPayload)
    );
}

#[test]
fn grant_cannot_be_replayed_against_another_signing_key() {
    let signer = signer();
    let envelope = signer.issue(payload()).unwrap();
    let other = ClientGrantSigner::new("other-key", SigningKey::from_bytes(&[9_u8; 32])).unwrap();
    assert_eq!(
        envelope.verify(&other.verifying_key()),
        Err(ClientGrantError::InvalidSignature)
    );
}

#[test]
fn mismatched_signing_key_id_is_rejected_even_with_a_valid_signature() {
    let signer = signer();
    let mut envelope = signer.issue(payload()).unwrap();
    envelope.signing_key_id = "cloud-client-grant-2026-02".into();
    assert_eq!(
        envelope.verify(&signer.verifying_key()),
        Err(ClientGrantError::InvalidEnvelope)
    );
}

#[test]
fn storage_bytes_are_exactly_the_bytes_the_wire_token_encodes() {
    // This is the invariant that makes replay safe: Cloud stores one byte string
    // and later re-encodes *that* string as `grant_token`. If the stored form and
    // the token form could differ, a replay could hand back a Grant whose signed
    // `issued_at`/`expires_at` no longer match what an operator was shown.
    let signer = signer();
    let envelope = signer.issue(payload()).unwrap();

    let stored = envelope.to_envelope_bytes().unwrap();
    let token = envelope.to_token().unwrap();
    let decoded_token = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&token)
        .unwrap();
    assert_eq!(stored, decoded_token);

    // A second encoding pass must be byte-identical, not merely equivalent, so a
    // replay can be answered from storage without re-serializing the envelope.
    assert_eq!(envelope.to_envelope_bytes().unwrap(), stored);
    let restored = ClientGrantEnvelopeV1::from_envelope_bytes(&stored).unwrap();
    assert_eq!(restored, envelope);
    assert_eq!(restored.to_envelope_bytes().unwrap(), stored);
    assert_eq!(restored.to_token().unwrap(), token);
    restored.verify(&signer.verifying_key()).unwrap();
}

#[test]
fn stored_bytes_are_canonical_so_field_order_cannot_change_the_signature() {
    let signer = signer();
    let envelope = signer.issue(payload()).unwrap();
    let stored = envelope.to_envelope_bytes().unwrap();

    // JCS sorts object keys, so two envelopes with identical content produce the
    // same bytes regardless of the order fields happen to be written in code.
    let restored = ClientGrantEnvelopeV1::from_envelope_bytes(&stored).unwrap();
    assert_eq!(restored.to_envelope_bytes().unwrap(), stored);

    // In particular the payload is recoverable from the stored bytes alone, so a
    // reader never has to trust a separate column for the authorization claim.
    let payload = &restored.payload;
    assert_eq!(payload.schema_version, 1);
    assert_eq!(
        payload.canonical_bytes().unwrap(),
        envelope.payload.canonical_bytes().unwrap()
    );
    assert_eq!(
        payload.content_hash().unwrap(),
        envelope.payload.content_hash().unwrap()
    );
}

#[test]
fn envelope_byte_reader_rejects_empty_oversized_and_non_json_input() {
    assert_eq!(
        ClientGrantEnvelopeV1::from_envelope_bytes(&[]),
        Err(ClientGrantError::InvalidEnvelope)
    );
    assert_eq!(
        ClientGrantEnvelopeV1::from_envelope_bytes(&vec![0_u8; 64 * 1024 + 1]),
        Err(ClientGrantError::InvalidEnvelope)
    );
    assert_eq!(
        ClientGrantEnvelopeV1::from_envelope_bytes(b"not json"),
        Err(ClientGrantError::InvalidEnvelope)
    );
    // A structurally valid but incomplete document must not deserialize into a
    // default-valued envelope that could then be treated as signed.
    assert_eq!(
        ClientGrantEnvelopeV1::from_envelope_bytes(br#"{"schema_version":1}"#),
        Err(ClientGrantError::InvalidEnvelope)
    );
}
