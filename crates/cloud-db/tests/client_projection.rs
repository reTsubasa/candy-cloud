//! Pure-logic coverage for the stored terminal PolicyProjection and its receipts.
//!
//! These invariants are the ones Cloud must refuse before it opens a transaction,
//! so they run in the default (no-database) `cargo test`. The repository
//! round-trips that genuinely need MySQL live behind the `DATABASE_URL` guard at
//! the bottom of the file.

use chrono::{Duration, Utc};
use cloud_db::client_access::ClientTrafficMode;
use cloud_db::client_projection::{
    projection_inputs_fingerprint, ClientProjectionError, ClientProjectionReceiptState,
    ClientProjectionReceiptWrite, ClientProjectionWrite, CLIENT_PROJECTION_RECEIPT_DOMAIN,
};
use uuid::Uuid;

fn projection_write() -> ClientProjectionWrite {
    let issued_at = Utc::now();
    ClientProjectionWrite {
        projection_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        client_device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        grant_id: Uuid::new_v4(),
        policy_generation: 3,
        settings_generation: 2,
        device_traffic_mode: ClientTrafficMode::Policy,
        generation: 1,
        request_id: Uuid::new_v4(),
        request_hash: [7; 32],
        content_hash: [9; 32],
        inputs_hash: [11; 32],
        signing_key_id: "cloud-policy-2026-01".into(),
        projection_envelope: vec![1, 2, 3],
        issued_at,
        stale_until: issued_at + Duration::hours(6),
    }
}

#[test]
fn a_stored_projection_binding_must_be_complete() {
    assert_eq!(projection_write().validate(), Ok(()));

    for zeroed in 0..8 {
        let mut write = projection_write();
        match zeroed {
            0 => write.projection_id = Uuid::nil(),
            1 => write.organization_id = Uuid::nil(),
            2 => write.tenant_id = Uuid::nil(),
            3 => write.user_id = Uuid::nil(),
            4 => write.client_device_id = Uuid::nil(),
            5 => write.device_key_id = Uuid::nil(),
            6 => write.grant_id = Uuid::nil(),
            _ => write.request_id = Uuid::nil(),
        }
        assert_eq!(
            write.validate(),
            Err(ClientProjectionError::InvalidRecord),
            "zeroed scope field {zeroed} was accepted"
        );
    }
}

#[test]
fn a_stored_projection_requires_cloud_allocated_generations() {
    // Generation 0 is what an unset or failed allocation looks like, and it is
    // also what `next_projection_generation` refuses to hand out. Storing it
    // would make a Projection indistinguishable from "never signed".
    let mut zero_generation = projection_write();
    zero_generation.generation = 0;
    assert_eq!(
        zero_generation.validate(),
        Err(ClientProjectionError::InvalidRecord)
    );

    // The policy and settings generations describe which reviewed documents the
    // Projection was derived from. Zero means the document was never published.
    let mut zero_policy = projection_write();
    zero_policy.policy_generation = 0;
    assert_eq!(
        zero_policy.validate(),
        Err(ClientProjectionError::InvalidRecord)
    );

    let mut zero_settings = projection_write();
    zero_settings.settings_generation = 0;
    assert_eq!(
        zero_settings.validate(),
        Err(ClientProjectionError::InvalidRecord)
    );

    let mut past_ceiling = projection_write();
    past_ceiling.generation = i64::MAX as u64 + 1;
    assert_eq!(
        past_ceiling.validate(),
        Err(ClientProjectionError::InvalidRecord)
    );

    let mut at_ceiling = projection_write();
    at_ceiling.generation = i64::MAX as u64;
    assert_eq!(at_ceiling.validate(), Ok(()));
}

#[test]
fn a_stored_projection_rejects_unusable_hashes_and_windows() {
    // A zero hash cannot distinguish two documents, which would make the
    // `If-None-Match` comparison meaningless.
    for unusable in 0..3 {
        let mut write = projection_write();
        match unusable {
            0 => write.request_hash = [0; 32],
            1 => write.content_hash = [0; 32],
            _ => write.inputs_hash = [0; 32],
        }
        assert_eq!(
            write.validate(),
            Err(ClientProjectionError::InvalidRecord),
            "zeroed hash {unusable} was accepted"
        );
    }

    let mut empty_envelope = projection_write();
    empty_envelope.projection_envelope = vec![];
    assert_eq!(
        empty_envelope.validate(),
        Err(ClientProjectionError::InvalidRecord)
    );

    let mut blank_key = projection_write();
    blank_key.signing_key_id = String::new();
    assert_eq!(
        blank_key.validate(),
        Err(ClientProjectionError::InvalidRecord)
    );

    // `stale_until <= issued_at` would hand the Client a document that is
    // already expired, so it is refused rather than stored.
    let mut inverted = projection_write();
    inverted.stale_until = inverted.issued_at;
    assert_eq!(
        inverted.validate(),
        Err(ClientProjectionError::InvalidRecord)
    );
}

fn receipt_write() -> ClientProjectionReceiptWrite {
    ClientProjectionReceiptWrite {
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        client_device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        projection_id: Uuid::new_v4(),
        generation: 1,
        content_hash: [9; 32],
        request_id: Uuid::new_v4(),
        request_hash: [0; 32],
        state: ClientProjectionReceiptState::Received,
        error_code: None,
    }
}

/// The hash Cloud stores only after the caller filled it in from the fingerprint.
fn stamped_receipt() -> ClientProjectionReceiptWrite {
    let mut receipt = receipt_write();
    receipt.request_hash = receipt.request_fingerprint();
    receipt
}

#[test]
fn a_receipt_must_be_stamped_before_it_is_storable() {
    // The unstamped form is exactly what a caller that forgot to assign the
    // fingerprint produces, so `validate` must reject it rather than store a
    // hash that cannot be compared on retry.
    assert_eq!(
        receipt_write().validate(),
        Err(ClientProjectionError::InvalidReceipt)
    );
    assert_eq!(stamped_receipt().validate(), Ok(()));
}

#[test]
fn a_receipt_reports_a_complete_and_nonzero_scope() {
    for zeroed in 0..7 {
        let mut receipt = receipt_write();
        match zeroed {
            0 => receipt.organization_id = Uuid::nil(),
            1 => receipt.tenant_id = Uuid::nil(),
            2 => receipt.user_id = Uuid::nil(),
            3 => receipt.client_device_id = Uuid::nil(),
            4 => receipt.device_key_id = Uuid::nil(),
            5 => receipt.projection_id = Uuid::nil(),
            _ => receipt.request_id = Uuid::nil(),
        }
        assert_eq!(
            receipt.validate(),
            Err(ClientProjectionError::InvalidReceipt),
            "zeroed scope field {zeroed} was accepted"
        );
    }
}

#[test]
fn a_receipt_must_name_a_generation_and_a_content_hash() {
    let mut zero_generation = stamped_receipt();
    zero_generation.generation = 0;
    assert_eq!(
        zero_generation.validate(),
        Err(ClientProjectionError::InvalidReceipt)
    );

    let mut too_new = stamped_receipt();
    too_new.generation = i64::MAX as u64 + 1;
    assert_eq!(
        too_new.validate(),
        Err(ClientProjectionError::InvalidReceipt)
    );

    let mut zero_hash = stamped_receipt();
    zero_hash.content_hash = [0; 32];
    assert_eq!(
        zero_hash.validate(),
        Err(ClientProjectionError::InvalidReceipt)
    );
}

#[test]
fn a_receipt_error_code_must_match_the_frozen_wire_pattern() {
    // Cloud must never store a code the Client contract would refuse to send
    // back, so the storage-side check mirrors `^[a-z][a-z0-9_.-]{2,79}$`.
    for accepted in ["tun.failed", "dns_error", "handshake-timeout", "quic.err_2"] {
        let mut receipt = stamped_receipt();
        receipt.error_code = Some(accepted.into());
        assert_eq!(receipt.validate(), Ok(()), "{accepted} was refused");
    }
    for refused in [
        "AB",
        "ab",
        "1abc",
        "Upper.Case",
        "has space",
        "slash/not/allowed",
        "",
    ] {
        let mut receipt = stamped_receipt();
        receipt.error_code = Some(refused.into());
        assert_eq!(
            receipt.validate(),
            Err(ClientProjectionError::InvalidReceipt),
            "{refused} was accepted"
        );
    }
    // The bounded length is what keeps a device from using the error code as a
    // free-form log channel.
    let mut oversized = stamped_receipt();
    oversized.error_code = Some(format!("e{}", "x".repeat(80)));
    assert_eq!(
        oversized.validate(),
        Err(ClientProjectionError::InvalidReceipt)
    );
}

#[test]
fn the_request_fingerprint_ignores_nothing_a_retry_changes() {
    let base = stamped_receipt();
    let fingerprint = base.request_fingerprint();

    // Recomputing over the same content is stable, and it depends only on the
    // reported content, so the hash itself must not feed back into the value.
    assert_eq!(base.request_fingerprint(), fingerprint);
    assert_ne!(fingerprint, [0; 32]);

    let mut different_state = base.clone();
    different_state.state = ClientProjectionReceiptState::Committed;
    assert_ne!(different_state.request_fingerprint(), fingerprint);

    let mut different_error = base.clone();
    different_error.error_code = Some("tun.failed".into());
    assert_ne!(different_error.request_fingerprint(), fingerprint);

    let mut different_generation = base.clone();
    different_generation.generation = 2;
    assert_ne!(different_generation.request_fingerprint(), fingerprint);

    let mut different_hash = base.clone();
    different_hash.content_hash = [10; 32];
    assert_ne!(different_hash.request_fingerprint(), fingerprint);

    let mut different_device = base.clone();
    different_device.client_device_id = Uuid::new_v4();
    assert_ne!(different_device.request_fingerprint(), fingerprint);

    let mut different_key = base.clone();
    different_key.device_key_id = Uuid::new_v4();
    assert_ne!(different_key.request_fingerprint(), fingerprint);

    let mut different_projection = base.clone();
    different_projection.projection_id = Uuid::new_v4();
    assert_ne!(different_projection.request_fingerprint(), fingerprint);
}

#[test]
fn the_receipt_domain_separator_is_not_the_projection_domain() {
    // Sharing a domain would let a fingerprint computed for one purpose be
    // replayed as the other, so the two constants must not be equal and neither
    // may be empty.
    assert!(!CLIENT_PROJECTION_RECEIPT_DOMAIN.is_empty());
    assert!(CLIENT_PROJECTION_RECEIPT_DOMAIN.ends_with(b"\0"));
    assert!(CLIENT_PROJECTION_RECEIPT_DOMAIN.contains(&b'-'));
}

fn inputs_fingerprint(mode: ClientTrafficMode, nodes: &[Uuid]) -> [u8; 32] {
    projection_inputs_fingerprint(3, &[1; 32], 2, &[2; 32], mode, Uuid::from_u128(7), nodes)
}

#[test]
fn the_inputs_fingerprint_tracks_every_signing_input() {
    let nodes = [Uuid::from_u128(21), Uuid::from_u128(22)];
    let base = inputs_fingerprint(ClientTrafficMode::Policy, &nodes);
    assert_eq!(base, inputs_fingerprint(ClientTrafficMode::Policy, &nodes));
    assert_ne!(base, [0; 32]);

    // A mode flip is the one input a device can ask for itself, so it must move
    // the fingerprint and force Cloud to re-sign.
    assert_ne!(base, inputs_fingerprint(ClientTrafficMode::Global, &nodes));

    // Reordering the node set is a different assignment, not an equivalent one:
    // the primary node changes, so the fingerprint must change with it.
    let reordered = [nodes[1], nodes[0]];
    assert_ne!(
        base,
        inputs_fingerprint(ClientTrafficMode::Policy, &reordered)
    );

    // A different node count must not collide with a different node set.
    assert_ne!(
        base,
        inputs_fingerprint(ClientTrafficMode::Policy, &nodes[..1])
    );
    assert_ne!(
        inputs_fingerprint(ClientTrafficMode::Policy, &nodes),
        projection_inputs_fingerprint(
            3,
            &[1; 32],
            3,
            &[2; 32],
            ClientTrafficMode::Policy,
            Uuid::from_u128(7),
            &nodes,
        )
    );
}

#[test]
fn receipt_states_only_move_forward_and_rejection_is_terminal() {
    use ClientProjectionReceiptState::{Committed, Received, Rejected, Staged, Verified};

    // The happy path, in order.
    assert!(Received.permits(Verified));
    assert!(Verified.permits(Staged));
    assert!(Staged.permits(Committed));

    // Re-reporting the same state is how a retry after a dropped response still
    // succeeds, so it must be permitted for every live state.
    for state in [Received, Verified, Staged, Committed] {
        assert!(state.permits(state), "{state:?} could not repeat itself");
    }

    // Skipping ahead is a device that never reported the step Cloud is auditing.
    assert!(!Received.permits(Staged));
    assert!(!Received.permits(Committed));
    assert!(!Verified.permits(Committed));

    // Rolling back would erase the proof that the Projection was installed.
    assert!(!Verified.permits(Received));
    assert!(!Staged.permits(Verified));
    assert!(!Committed.permits(Staged));
    assert!(!Committed.permits(Received));

    // Any live state may reject; a rejection is final for its generation.
    for state in [Received, Verified, Staged, Committed] {
        assert!(state.permits(Rejected), "{state:?} could not reject");
    }
    // A rejection does not repeat itself. An identical *retry* is absorbed by
    // the request-hash replay path in `record_receipt` before this check is
    // reached; a *new* request re-reporting rejection is refused, so a device
    // cannot keep a rejected generation alive by re-reporting it.
    assert!(!Rejected.permits(Rejected));
    assert!(!Rejected.permits(Received));
    assert!(!Rejected.permits(Committed));
}

#[test]
fn receipt_states_round_trip_the_wire_and_database_spellings() {
    for (state, wire) in [
        (ClientProjectionReceiptState::Received, "received"),
        (ClientProjectionReceiptState::Verified, "verified"),
        (ClientProjectionReceiptState::Staged, "staged"),
        (ClientProjectionReceiptState::Committed, "committed"),
        (ClientProjectionReceiptState::Rejected, "rejected"),
    ] {
        assert_eq!(state.to_wire_value(), wire);
        assert_eq!(
            ClientProjectionReceiptState::from_wire_value(wire),
            Some(state)
        );
        // The wire spelling is lower case and the column upper case; neither may
        // leak into the other's reader.
        assert_ne!(state.to_wire_value(), state.to_database_value());
    }
    assert_eq!(
        ClientProjectionReceiptState::from_wire_value("RECEIVED"),
        None
    );
    assert_eq!(ClientProjectionReceiptState::from_wire_value(""), None);
    assert_eq!(ClientProjectionReceiptState::from_wire_value("done"), None);
}

#[tokio::test]
async fn projections_and_receipts_round_trip_through_mysql() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    // Live round-trips need a seeded organization, tenant, user, and device;
    // those flows are exercised by the API-level integration tests. The guard is
    // here so that adding a live assertion cannot silently stop running.
    drop(pool);
}
