//! Terminal client Projection, receipt, heartbeat, traffic-mode, and revoke
//! routes.
//!
//! Everything a terminal device does after registration lands here. The module is
//! deliberately *thin*: every decision about what Cloud will authorize lives in
//! `client_projection`, `client_control`, or the storage repositories. What this
//! layer owns is the wire contract -- envelope checking, session-scoped device
//! resolution, HTTP status semantics, and the rule that a replay returns stored
//! bytes instead of re-signed ones.
//!
//! Two properties are load-bearing and easy to regress:
//!
//! * **Session before body.** `ClientSession` is a parts extractor, so an
//!   unauthenticated caller is answered `401` even with a malformed body, and
//!   never learns which fields Cloud validates.
//! * **Cloud faults are 503.** A storage or signing failure is never reported as
//!   a `4xx`. A client that re-registered or tore down its tunnel because Cloud
//!   was briefly unavailable would turn one outage into a fleet-wide one.

use std::sync::Arc;

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use cloud_client_projection::{PolicyProjectionV1, POLICY_PROJECTION_SCHEMA_VERSION};
use cloud_db::client_access::ClientTrafficMode;
use cloud_db::client_control::ClientDeviceLookup;
use cloud_db::client_projection::{ClientProjectionReceiptState, ClientProjectionReceiptWrite};
use cloud_db::client_settings::ClientTrafficModeRequest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client_api::{
    check_device_binding, check_envelope, json_body, resolve_active_device, resolve_device,
    session_user, unix_seconds, ClientSession, CLIENT_API_VERSION,
};
use crate::client_projection::{parse_content_hash, ClientProjectionService, IssuedProjection};
use crate::management::{ApiError, ManagementState};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRequestEnvelope {
    api_version: u16,
    message_type: String,
    request_id: Uuid,
    payload: ProjectionRequestPayload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionRequestPayload {
    device_id: Uuid,
    device_key_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ProjectionResponse {
    api_version: u16,
    message_type: &'static str,
    request_id: Uuid,
    payload: ProjectionResponsePayload,
}

#[derive(Debug, Serialize)]
struct ProjectionResponsePayload {
    device_id: Uuid,
    device_key_id: Uuid,
    grant_id: Uuid,
    projection: PolicyProjectionV1,
    replayed: bool,
}

/// Issues, replays, or re-answers the signed Projection for one owned device.
///
/// `If-None-Match` is honoured against the *content hash* of the stored
/// Projection, which is the same value the client can compute from the document it
/// already holds. A match is answered `304` with no body, so a polling client that
/// is already current costs one round trip and no re-signing.
pub async fn fetch_client_projection(
    State(state): State<Arc<ManagementState>>,
    session: ClientSession,
    Path(device_id): Path<Uuid>,
    headers: HeaderMap,
    body: Result<Json<ProjectionRequestEnvelope>, JsonRejection>,
) -> Result<Response, ApiError> {
    let principal = session.0;
    let envelope = json_body(body)?;
    check_envelope(
        envelope.api_version,
        &envelope.message_type,
        "projection_request",
        envelope.request_id,
    )?;
    check_device_binding(envelope.payload.device_id, device_id)?;
    let control = state
        .client_control
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let projections = state
        .client_projection
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let access = state
        .client_access
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let settings = state
        .client_settings
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let signer = state
        .client_projection_signer
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;

    let device = resolve_active_device(control, &principal, device_id).await?;
    if device.device_key_id != envelope.payload.device_key_id {
        return Err(ApiError::forbidden());
    }
    let service = ClientProjectionService {
        control,
        projections,
        access,
        settings,
        signer,
    };
    let issued = service
        .projection_for_device(&device, envelope.request_id, Utc::now())
        .await
        .map_err(ApiError::from_client_projection)?;
    // The comparison uses the *stored* hash rather than a freshly computed one:
    // on a replay the persisted bytes are authoritative, and re-hashing would
    // create a second source of truth that could disagree with them.
    if if_none_match(&headers)
        .is_some_and(|candidate| candidate == issued.record.content_hash_text())
    {
        return Ok(StatusCode::NOT_MODIFIED.into_response());
    }
    Ok((
        StatusCode::OK,
        Json(ProjectionResponse {
            api_version: CLIENT_API_VERSION,
            message_type: "projection_response",
            request_id: envelope.request_id,
            payload: projection_body(&issued)?,
        }),
    )
        .into_response())
}

/// Re-encodes the *stored* envelope. Re-signing here would re-stamp the validity
/// window, which is exactly what a replay must not do.
fn projection_body(issued: &IssuedProjection) -> Result<ProjectionResponsePayload, ApiError> {
    let projection = PolicyProjectionV1::from_envelope_bytes(&issued.record.projection_envelope)
        .map_err(|_| ApiError::control_plane_unavailable())?;
    if projection.schema_version != POLICY_PROJECTION_SCHEMA_VERSION {
        return Err(ApiError::control_plane_unavailable());
    }
    Ok(ProjectionResponsePayload {
        device_id: projection.device_id,
        device_key_id: issued.record.device_key_id,
        grant_id: issued.record.grant_id,
        projection,
        replayed: issued.replayed,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEnvelope {
    api_version: u16,
    message_type: String,
    request_id: Uuid,
    payload: ReceiptPayload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptPayload {
    device_id: Uuid,
    device_key_id: Uuid,
    projection_id: Uuid,
    generation: u64,
    content_hash: String,
    state: String,
    #[serde(default)]
    error_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReceiptResponse {
    api_version: u16,
    message_type: &'static str,
    request_id: Uuid,
    payload: ReceiptResponsePayload,
}

#[derive(Debug, Serialize)]
struct ReceiptResponsePayload {
    accepted: bool,
    state: &'static str,
}

/// Records one step of a device's Projection install progression.
///
/// That progression is the only signal Cloud has that a document it signed was
/// actually installed and verified rather than merely received, so a report that
/// moves backwards is refused (`400`) rather than quietly accepted.
pub async fn record_client_receipt(
    State(state): State<Arc<ManagementState>>,
    session: ClientSession,
    Path(device_id): Path<Uuid>,
    body: Result<Json<ReceiptEnvelope>, JsonRejection>,
) -> Result<(StatusCode, Json<ReceiptResponse>), ApiError> {
    let principal = session.0;
    let envelope = json_body(body)?;
    check_envelope(
        envelope.api_version,
        &envelope.message_type,
        "receipt_request",
        envelope.request_id,
    )?;
    check_device_binding(envelope.payload.device_id, device_id)?;
    // The device's own fields are parsed before any storage is touched, for the
    // same reason every other route does it: a caller that sent a malformed
    // receipt must be told so, rather than being handed a retryable `503` that
    // hides its own bug behind Cloud's availability.
    let reported = ClientProjectionReceiptState::from_wire_value(&envelope.payload.state)
        .ok_or_else(|| {
            ApiError::bad_request(
                "INVALID_RECEIPT",
                "state must be received, verified, staged, committed, or rejected",
            )
        })?;
    let content_hash = parse_content_hash(&envelope.payload.content_hash).ok_or_else(|| {
        ApiError::bad_request(
            "INVALID_RECEIPT",
            "content_hash must be sha256: followed by 64 hex characters",
        )
    })?;
    let control = state
        .client_control
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let projections = state
        .client_projection
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let device = resolve_active_device(control, &principal, device_id).await?;
    if device.device_key_id != envelope.payload.device_key_id {
        return Err(ApiError::forbidden());
    }
    let mut receipt = ClientProjectionReceiptWrite {
        organization_id: device.organization_id,
        tenant_id: device.tenant_id,
        user_id: device.user_id,
        client_device_id: device.record_id,
        device_key_id: device.device_key_id,
        projection_id: envelope.payload.projection_id,
        generation: envelope.payload.generation,
        content_hash,
        request_id: envelope.request_id,
        request_hash: [0; 32],
        state: reported,
        error_code: envelope.payload.error_code.clone(),
    };
    // Filled after construction because the fingerprint must cover the fully
    // resolved scope (device, key, projection, state) rather than whatever the
    // body claimed, and `validate()` then rejects a zeroed hash if this is ever
    // forgotten.
    receipt.request_hash = receipt.request_fingerprint();
    let outcome = projections
        .record_receipt(&receipt)
        .await
        .map_err(ApiError::from_client_projection_store)?;
    Ok((
        StatusCode::OK,
        Json(ReceiptResponse {
            api_version: CLIENT_API_VERSION,
            message_type: "receipt_response",
            request_id: envelope.request_id,
            payload: ReceiptResponsePayload {
                accepted: true,
                state: outcome.state.to_wire_value(),
            },
        }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatEnvelope {
    api_version: u16,
    message_type: String,
    request_id: Uuid,
    payload: HeartbeatPayload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatPayload {
    device_id: Uuid,
    device_key_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    api_version: u16,
    message_type: &'static str,
    request_id: Uuid,
    payload: HeartbeatResponsePayload,
}

#[derive(Debug, Serialize)]
struct HeartbeatResponsePayload {
    device_id: Uuid,
    device_key_id: Uuid,
    revoked: bool,
    server_time: u64,
}

/// Records liveness for one owned device.
///
/// `touch_device` only matches an `ACTIVE` device with an `ACTIVE` key, so a
/// zero-row update means the device stopped being issuable between the lookup and
/// the write. That is a `409` rather than a `404`: the caller's identity is still
/// valid, the device state moved underneath it.
pub async fn client_heartbeat(
    State(state): State<Arc<ManagementState>>,
    session: ClientSession,
    Path(device_id): Path<Uuid>,
    body: Result<Json<HeartbeatEnvelope>, JsonRejection>,
) -> Result<(StatusCode, Json<HeartbeatResponse>), ApiError> {
    let principal = session.0;
    let envelope = json_body(body)?;
    check_envelope(
        envelope.api_version,
        &envelope.message_type,
        "heartbeat_request",
        envelope.request_id,
    )?;
    check_device_binding(envelope.payload.device_id, device_id)?;
    let control = state
        .client_control
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let device = resolve_active_device(control, &principal, device_id).await?;
    if device.device_key_id != envelope.payload.device_key_id {
        return Err(ApiError::forbidden());
    }
    let touched = control
        .touch_device(
            device.tenant_id,
            device.user_id,
            device.device_id,
            device.device_key_id,
        )
        .await
        .map_err(ApiError::from_client_control)?;
    if !touched {
        return Err(ApiError::conflict(
            "CLIENT_DEVICE_SUSPENDED",
            "the terminal device stopped being active",
        ));
    }
    Ok((
        StatusCode::OK,
        Json(HeartbeatResponse {
            api_version: CLIENT_API_VERSION,
            message_type: "heartbeat_response",
            request_id: envelope.request_id,
            payload: HeartbeatResponsePayload {
                device_id: device.device_id,
                device_key_id: device.device_key_id,
                // Only an ACTIVE device reaches this point, so Cloud has already
                // proven the device is not revoked. The field exists so a client
                // can read the answer rather than infer it from a status code.
                revoked: false,
                server_time: unix_seconds(Utc::now())?,
            },
        }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeEnvelope {
    api_version: u16,
    message_type: String,
    request_id: Uuid,
    payload: RevokePayload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokePayload {
    device_id: Uuid,
    device_key_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    api_version: u16,
    message_type: &'static str,
    request_id: Uuid,
    payload: RevokeResponsePayload,
}

#[derive(Debug, Serialize)]
struct RevokeResponsePayload {
    device_id: Uuid,
    device_key_id: Uuid,
    revoked: bool,
    effective_at: u64,
}

/// Retires one device and everything Cloud issued to it, at the device's own
/// request.
///
/// The device is resolved *without* the `ACTIVE` requirement, so revoking an
/// already-revoked or suspended device is an idempotent success: a client that
/// retries after a dropped response must not be told its own revocation failed. A
/// device that never existed, or belongs to another session, is still a `404`, so
/// no cross-session probe can confirm a device exists.
pub async fn revoke_client_device(
    State(state): State<Arc<ManagementState>>,
    session: ClientSession,
    Path(device_id): Path<Uuid>,
    body: Result<Json<RevokeEnvelope>, JsonRejection>,
) -> Result<(StatusCode, Json<RevokeResponse>), ApiError> {
    let principal = session.0;
    let envelope = json_body(body)?;
    check_envelope(
        envelope.api_version,
        &envelope.message_type,
        "revoke_request",
        envelope.request_id,
    )?;
    check_device_binding(envelope.payload.device_id, device_id)?;
    let control = state
        .client_control
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let projections = state
        .client_projection
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let lookup = resolve_device(control, &principal, device_id).await?;
    let user_id = session_user(&principal)?;
    // Every arm converges on the same cleanup below, so an already-revoked device
    // still has any leftover live Projection swept up rather than answered from a
    // shortcut that skips the work.
    let (record_id, key_id) = match lookup {
        // Already revoked. The device and key rows are gone from `ACTIVE`, so the
        // key cannot be re-verified here and the caller's value is used only to
        // sweep projections it may still match.
        ClientDeviceLookup::Revoked { record_id, .. } => {
            (record_id, envelope.payload.device_key_id)
        }
        ClientDeviceLookup::Suspended { record_id, .. } => {
            (record_id, envelope.payload.device_key_id)
        }
        ClientDeviceLookup::Active(device) => {
            if device.device_key_id != envelope.payload.device_key_id {
                return Err(ApiError::forbidden());
            }
            (device.record_id, device.device_key_id)
        }
    };
    // A zero-row result means the device left `ACTIVE` between the lookup and the
    // write, which for a self-revocation only happens if it was already revoked.
    // The end state the caller asked for holds either way, so this is not an
    // error.
    control
        .revoke_device(
            principal.context.organization_id,
            principal.context.tenant_id,
            user_id,
            device_id,
            key_id,
        )
        .await
        .map_err(ApiError::from_client_control)?;
    // Projections are revoked through their own repository because they are a
    // separate signed artefact with a separate key; leaving one live would let a
    // client keep enforcing a policy Cloud no longer authorizes.
    projections
        .revoke_projections(
            principal.context.organization_id,
            principal.context.tenant_id,
            user_id,
            record_id,
            key_id,
        )
        .await
        .map_err(ApiError::from_client_projection_store)?;
    Ok((
        StatusCode::OK,
        Json(RevokeResponse {
            api_version: CLIENT_API_VERSION,
            message_type: "revoke_response",
            request_id: envelope.request_id,
            payload: RevokeResponsePayload {
                device_id,
                device_key_id: key_id,
                revoked: true,
                effective_at: unix_seconds(Utc::now())?,
            },
        }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficModeEnvelope {
    api_version: u16,
    message_type: String,
    request_id: Uuid,
    payload: TrafficModePayload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficModePayload {
    device_id: Uuid,
    device_key_id: Uuid,
    traffic_mode: String,
}

#[derive(Debug, Serialize)]
pub struct TrafficModeResponse {
    api_version: u16,
    message_type: &'static str,
    request_id: Uuid,
    payload: TrafficModeResponsePayload,
}

#[derive(Debug, Serialize)]
struct TrafficModeResponsePayload {
    device_id: Uuid,
    device_key_id: Uuid,
    previous_mode: &'static str,
    traffic_mode: &'static str,
    replayed: bool,
}

/// Applies the client-visible policy/global switch.
///
/// The permission decision is Cloud's: the requested mode is checked against the
/// `mode_capabilities` of the device's *bound* policy, so a client cannot widen
/// its own traffic scope by asking. Global is refused unless the bound policy both
/// lists `global` and enables global egress.
///
/// A mode change deliberately does not re-sign a Projection here. The next
/// Projection poll sees a different `device_traffic_mode`, which changes the
/// `inputs_hash` and forces Cloud to sign a document that actually describes the
/// new mode.
pub async fn set_client_traffic_mode(
    State(state): State<Arc<ManagementState>>,
    session: ClientSession,
    Path(device_id): Path<Uuid>,
    body: Result<Json<TrafficModeEnvelope>, JsonRejection>,
) -> Result<(StatusCode, Json<TrafficModeResponse>), ApiError> {
    let principal = session.0;
    let envelope = json_body(body)?;
    check_envelope(
        envelope.api_version,
        &envelope.message_type,
        "traffic_mode_request",
        envelope.request_id,
    )?;
    check_device_binding(envelope.payload.device_id, device_id)?;
    let control = state
        .client_control
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let access = state
        .client_access
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let settings = state
        .client_settings
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let requested = parse_traffic_mode(&envelope.payload.traffic_mode)?;
    let device = resolve_active_device(control, &principal, device_id).await?;
    if device.device_key_id != envelope.payload.device_key_id {
        return Err(ApiError::forbidden());
    }
    // Read the bound policy rather than trusting a stored mode: the question is
    // what Cloud currently authorizes, not what the device last recorded. With no
    // bound policy there is no capability, so Global is refused.
    let policy = access
        .bound_policy(
            device.organization_id,
            device.tenant_id,
            device.user_id,
            device.record_id,
        )
        .await
        .map_err(ApiError::from_client_access)?;
    let global_permitted = policy.is_some_and(|policy| {
        policy.global_egress_enabled
            && policy
                .mode_capabilities
                .contains(&ClientTrafficMode::Global)
    });
    let outcome = settings
        .set_traffic_mode(&ClientTrafficModeRequest {
            organization_id: device.organization_id,
            tenant_id: device.tenant_id,
            user_id: device.user_id,
            client_device_id: device.record_id,
            device_key_id: device.device_key_id,
            request_id: envelope.request_id,
            requested,
            global_permitted,
        })
        .await
        .map_err(ApiError::from_client_settings)?;
    Ok((
        StatusCode::OK,
        Json(TrafficModeResponse {
            api_version: CLIENT_API_VERSION,
            message_type: "traffic_mode_response",
            request_id: envelope.request_id,
            payload: TrafficModeResponsePayload {
                device_id: device.device_id,
                device_key_id: device.device_key_id,
                previous_mode: outcome.previous.to_wire_value(),
                traffic_mode: outcome.current.to_wire_value(),
                replayed: outcome.replayed,
            },
        }),
    ))
}

fn parse_traffic_mode(value: &str) -> Result<ClientTrafficMode, ApiError> {
    match value {
        "policy" => Ok(ClientTrafficMode::Policy),
        "global" => Ok(ClientTrafficMode::Global),
        _ => Err(ApiError::bad_request(
            "INVALID_TRAFFIC_MODE",
            "traffic_mode must be policy or global",
        )),
    }
}

/// Reads the `If-None-Match` value, tolerating the weak-validator prefix and
/// surrounding quotes or whitespace. The comparison against the content hash
/// itself stays byte-exact.
fn if_none_match(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::IF_NONE_MATCH)?
        .to_str()
        .ok()
        .map(|value| {
            value
                .trim()
                .trim_start_matches("W/")
                .trim_matches('"')
                .to_owned()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_projection::{parse_content_hash, ClientProjectionError};

    #[test]
    fn traffic_mode_accepts_only_the_two_contracted_values() {
        assert_eq!(
            parse_traffic_mode("policy").unwrap(),
            ClientTrafficMode::Policy
        );
        assert_eq!(
            parse_traffic_mode("global").unwrap(),
            ClientTrafficMode::Global
        );
        // The wire form is lowercase; the database form is not, so accepting the
        // database spelling here would let a storage template leak into the wire.
        assert!(parse_traffic_mode("POLICY").is_err());
        assert!(parse_traffic_mode("split").is_err());
        assert_eq!(
            parse_traffic_mode("split").unwrap_err().code,
            "INVALID_TRAFFIC_MODE"
        );
    }

    #[test]
    fn content_hash_round_trips_and_rejects_non_wire_forms() {
        let hash = [0x8b_u8; 32];
        let text = crate::client_projection::content_hash_text(&hash);
        assert_eq!(
            text,
            "sha256:8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"
        );
        assert_eq!(parse_content_hash(&text), Some(hash));

        // A truncated or unprefixed digest is not a hash Cloud produced.
        assert!(parse_content_hash("sha256:abcd").is_none());
        assert!(parse_content_hash("8b0b0b3d").is_none());
        assert!(parse_content_hash(&format!("sha256:{}", "z".repeat(64))).is_none());
        // The contract fixes one spelling: lower case. Accepting an upper-case
        // digest would let a Client pass here and fail against a stricter peer.
        assert!(parse_content_hash(&format!("sha256:{}", "8B".repeat(32))).is_none());
    }

    #[test]
    fn if_none_match_tolerates_weak_and_quoted_forms() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, "\"abc\"".parse().unwrap());
        assert_eq!(if_none_match(&headers).as_deref(), Some("abc"));

        let mut weak = HeaderMap::new();
        weak.insert(header::IF_NONE_MATCH, "W/\"abc\"".parse().unwrap());
        assert_eq!(if_none_match(&weak).as_deref(), Some("abc"));

        assert!(if_none_match(&HeaderMap::new()).is_none());
    }

    #[test]
    fn projection_errors_never_report_cloud_faults_as_client_errors() {
        // A storage, signing, or node-lease failure must stay retryable, while a
        // stale Grant or a missing policy is a conflict the client resolves.
        assert_eq!(
            ApiError::from_client_projection(ClientProjectionError::Unavailable).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ApiError::from_client_projection(ClientProjectionError::NoActiveNode).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ApiError::from_client_projection(ClientProjectionError::NodeLeaseExpired).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ApiError::from_client_projection(ClientProjectionError::GrantStale).status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::from_client_projection(ClientProjectionError::PolicyNotBound).status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::from_client_projection(ClientProjectionError::NotOwned).status,
            StatusCode::FORBIDDEN
        );
    }
}
