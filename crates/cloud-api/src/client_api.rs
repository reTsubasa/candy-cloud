//! Terminal client control-plane HTTP surface.
//!
//! These routes are the ones a Windows/macOS/Android device calls with a human
//! Cloud session. They are intentionally *not* under
//! `/v1/tenants/{tenant_id}/...`: the tenant and user always come from the
//! session, so a client has no field in which to name another tenant. The only
//! identifiers a client supplies are the ones it minted itself (`device_id`,
//! `device_key_id`, its public key), and Cloud re-checks every one of them
//! against the session scope before signing anything.

use std::sync::Arc;

use axum::{
    extract::{rejection::JsonRejection, FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use cloud_client_grant::{ClientGrantEnvelopeV1, CLIENT_GRANT_SCHEMA_VERSION};
use cloud_db::client_control::{ClientDeviceLookup, ClientDeviceRegistration, ClientPlatform};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client_issuance::{ClientIssuance, ClientIssuanceError};
use crate::management::{ApiError, AuthenticatedPrincipal, ManagementState};

const CLIENT_API_VERSION: u16 = 1;
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// The authenticated human session behind a terminal request.
///
/// This is a *parts* extractor on purpose. axum runs every parts extractor
/// before it touches the request body, so an unauthenticated caller is answered
/// `401` even when it sends a malformed body. Reading the body first would let
/// anyone with a JSON payload learn which fields Cloud validates, and would
/// report a session problem as a request problem.
#[derive(Debug, Clone)]
pub struct ClientSession(pub AuthenticatedPrincipal);

impl<S> FromRequestParts<S> for ClientSession
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedPrincipal>()
            .cloned()
            .map(ClientSession)
            .ok_or_else(ApiError::unauthorized)
    }
}

/// Terminal request bodies are parsed by hand rather than by `Json<T>`, so that a
/// malformed body, an unknown field, or a wrong type always produces the
/// contracted error envelope. Letting axum's default rejection escape would
/// answer `422` with a plain-text body that a client cannot key off.
fn json_body<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    body.map(|Json(value)| value).map_err(|rejection| {
        let (code, message) = match rejection {
            JsonRejection::MissingJsonContentType(_) => (
                "MISSING_CONTENT_TYPE",
                "content-type must be application/json",
            ),
            JsonRejection::JsonSyntaxError(_) => ("INVALID_JSON", "request body is not valid JSON"),
            JsonRejection::JsonDataError(_) => (
                "INVALID_REQUEST",
                "request body does not satisfy the V1 contract",
            ),
            JsonRejection::BytesRejection(_) => (
                "INVALID_REQUEST",
                "request body could not be read",
            ),
            _ => ("INVALID_REQUEST", "request body is not acceptable"),
        };
        ApiError::bad_request(code, message)
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDeviceEnvelope {
    api_version: u16,
    message_type: String,
    request_id: Uuid,
    payload: RegisterDevicePayload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterDevicePayload {
    device_id: Uuid,
    device_key_id: Uuid,
    platform: String,
    display_name: String,
    public_key: String,
    install_id: String,
    #[serde(default)]
    client_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    api_version: u16,
    message_type: &'static str,
    request_id: Uuid,
    payload: RegisterDeviceResponsePayload,
}

#[derive(Debug, Serialize)]
struct RegisterDeviceResponsePayload {
    device_id: Uuid,
    device_key_id: Uuid,
    status: &'static str,
    grant: Option<GrantBody>,
    replayed: bool,
}

/// The wire form of a signed Grant. `grant_token` is the only field a client
/// needs to present for data-plane authorization; the rest is what an operator
/// sees when auditing what Cloud handed out.
#[derive(Debug, Serialize)]
struct GrantBody {
    grant_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    device_id: Uuid,
    device_key_id: Uuid,
    issued_at: u64,
    expires_at: u64,
    generation: u64,
    grant_token: String,
    signing_key_id: String,
}

/// Registers (or idempotently replays) a terminal device public key.
///
/// The device row must exist before a policy can be bound to it, so this
/// endpoint reports `grant: null` for a device Cloud has not yet authorized.
/// That is not an error: the client stays disconnected and retries.
pub async fn register_client_device(
    State(state): State<Arc<ManagementState>>,
    session: ClientSession,
    body: Result<Json<RegisterDeviceEnvelope>, JsonRejection>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), ApiError> {
    let principal = session.0;
    let envelope = json_body(body)?;
    check_envelope(
        envelope.api_version,
        &envelope.message_type,
        "register_device_request",
        envelope.request_id,
    )?;
    let user_id = session_user(&principal)?;
    let platform = parse_platform(&envelope.payload.platform)?;
    let public_key = parse_public_key(&envelope.payload.public_key)?;
    let repository = state
        .client_control
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;

    let request = ClientDeviceRegistration {
        record_id: Uuid::now_v7(),
        organization_id: principal.context.organization_id,
        tenant_id: principal.context.tenant_id,
        user_id,
        device_id: envelope.payload.device_id,
        device_key_id: envelope.payload.device_key_id,
        platform,
        display_name: envelope.payload.display_name.clone(),
        install_id: envelope.payload.install_id.clone(),
        client_version: envelope.payload.client_version.clone(),
        public_key,
        request_id: envelope.request_id,
        actor_id: user_id,
    };
    let outcome = repository
        .register_device(&request)
        .await
        .map_err(ApiError::from_client_control)?;

    match outcome {
        cloud_db::client_control::ClientDeviceRegistrationOutcome::Registered {
            device_id,
            replayed,
        } => {
            // A device that already has an unexpired Grant replays it here so a
            // client that lost local state recovers the Cloud-issued one instead
            // of forcing an operator to re-authorize it.
            let record = repository
                .device_by_wire_id(
                    principal.context.organization_id,
                    principal.context.tenant_id,
                    user_id,
                    device_id,
                )
                .await
                .map_err(ApiError::from_client_control)?;
            let grant = match record {
                Some(ClientDeviceLookup::Active(device)) => repository
                    .active_grant(
                        device.tenant_id,
                        device.record_id,
                        device.device_key_id,
                        Utc::now(),
                    )
                    .await
                    .map_err(ApiError::from_client_control)?
                    .map(|grant| grant_body(&grant))
                    .transpose()?,
                _ => None,
            };
            Ok((
                if replayed {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                Json(RegisterDeviceResponse {
                    api_version: CLIENT_API_VERSION,
                    message_type: "register_device_response",
                    request_id: envelope.request_id,
                    payload: RegisterDeviceResponsePayload {
                        device_id: envelope.payload.device_id,
                        device_key_id: envelope.payload.device_key_id,
                        status: if replayed {
                            "already_registered"
                        } else {
                            "registered"
                        },
                        grant,
                        replayed,
                    },
                }),
            ))
        }
        cloud_db::client_control::ClientDeviceRegistrationOutcome::Revoked {
            device_id,
            device_key_id,
        } => {
            // Revocation is terminal and never silent: the client is told with a
            // `410` *and* a body it can key off, so a client that only looks at
            // the status code and one that only looks at `status` agree.
            Ok((
                StatusCode::GONE,
                Json(RegisterDeviceResponse {
                    api_version: CLIENT_API_VERSION,
                    message_type: "register_device_response",
                    request_id: envelope.request_id,
                    payload: RegisterDeviceResponsePayload {
                        device_id,
                        device_key_id,
                        status: "revoked",
                        grant: None,
                        replayed: false,
                    },
                }),
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequestEnvelope {
    api_version: u16,
    message_type: String,
    request_id: Uuid,
    payload: GrantRequestPayload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequestPayload {
    device_id: Uuid,
    device_key_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct GrantResponse {
    api_version: u16,
    message_type: &'static str,
    request_id: Uuid,
    payload: GrantResponsePayload,
}

#[derive(Debug, Serialize)]
struct GrantResponsePayload {
    device_id: Uuid,
    device_key_id: Uuid,
    grant_id: Uuid,
    issued_at: u64,
    expires_at: u64,
    generation: u64,
    grant_token: String,
    signing_key_id: String,
    replayed: bool,
}

/// Issues, or byte-identically replays, the signed Grant for one owned device.
pub async fn issue_client_grant(
    State(state): State<Arc<ManagementState>>,
    session: ClientSession,
    Path(device_id): Path<Uuid>,
    body: Result<Json<GrantRequestEnvelope>, JsonRejection>,
) -> Result<(StatusCode, Json<GrantResponse>), ApiError> {
    let principal = session.0;
    let envelope = json_body(body)?;
    check_envelope(
        envelope.api_version,
        &envelope.message_type,
        "grant_request",
        envelope.request_id,
    )?;
    if envelope.payload.device_id != device_id {
        return Err(ApiError::bad_request(
            "DEVICE_BINDING_MISMATCH",
            "payload device_id must match the request path",
        ));
    }
    let user_id = session_user(&principal)?;
    let control = state
        .client_control
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let routing = state
        .client_routing
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let access = state
        .client_access
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;
    let signer = state
        .client_grant
        .as_ref()
        .ok_or_else(ApiError::control_plane_unavailable)?;

    let device = match control
        .device_by_wire_id(
            principal.context.organization_id,
            principal.context.tenant_id,
            user_id,
            device_id,
        )
        .await
        .map_err(ApiError::from_client_control)?
    {
        None => {
            return Err(ApiError::not_found(
                "CLIENT_DEVICE_NOT_FOUND",
                "no terminal device is registered for this session",
            ))
        }
        Some(ClientDeviceLookup::Revoked { .. }) => {
            return Err(ApiError::gone(
                "CLIENT_DEVICE_REVOKED",
                "the terminal device is revoked",
            ))
        }
        // Recoverable: re-registering the device key restores service, so this is
        // a conflict rather than a terminal revocation.
        Some(ClientDeviceLookup::Suspended { .. }) => {
            return Err(ApiError::conflict(
                "CLIENT_DEVICE_SUSPENDED",
                "the terminal device has no active key",
            ))
        }
        Some(ClientDeviceLookup::Active(device)) => device,
    };
    if device.device_key_id != envelope.payload.device_key_id {
        return Err(ApiError::forbidden());
    }
    let issuance = ClientIssuance {
        control,
        routing,
        access,
        signer,
    };
    let issued = issuance
        .grant_for_device(&device, envelope.request_id, Utc::now())
        .await
        .map_err(map_issuance_error)?;
    let body = grant_body(&issued.record)?;
    Ok((
        if issued.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(GrantResponse {
            api_version: CLIENT_API_VERSION,
            message_type: "grant_response",
            request_id: envelope.request_id,
            payload: GrantResponsePayload {
                device_id,
                device_key_id: issued.record.device_key_id,
                grant_id: body.grant_id,
                issued_at: body.issued_at,
                expires_at: body.expires_at,
                generation: body.generation,
                grant_token: body.grant_token,
                signing_key_id: body.signing_key_id,
                replayed: issued.replayed,
            },
        }),
    ))
}

fn grant_body(record: &cloud_db::client_control::ClientGrantRecord) -> Result<GrantBody, ApiError> {
    // Re-encode the *stored* envelope. Re-signing here would re-stamp the
    // validity window, which is precisely what a replay must not do.
    let envelope = ClientGrantEnvelopeV1::from_envelope_bytes(&record.grant_envelope)
        .map_err(ApiError::from_client_grant)?;
    if envelope.schema_version != CLIENT_GRANT_SCHEMA_VERSION {
        return Err(ApiError::control_plane_unavailable());
    }
    let issued_at = unix_seconds(record.issued_at)?;
    let expires_at = unix_seconds(record.expires_at)?;
    Ok(GrantBody {
        grant_id: record.grant_id,
        tenant_id: record.tenant_id,
        user_id: record.user_id,
        device_id: envelope.payload.device_id,
        device_key_id: record.device_key_id,
        issued_at,
        expires_at,
        generation: record.generation,
        grant_token: envelope.to_token().map_err(ApiError::from_client_grant)?,
        signing_key_id: record.signing_key_id.clone(),
    })
}

fn unix_seconds(value: DateTime<Utc>) -> Result<u64, ApiError> {
    u64::try_from(value.timestamp()).map_err(|_| ApiError::control_plane_unavailable())
}

fn session_user(principal: &AuthenticatedPrincipal) -> Result<Uuid, ApiError> {
    Uuid::parse_str(&principal.actor_id).map_err(|_| ApiError::unauthorized())
}

fn check_envelope(
    api_version: u16,
    message_type: &str,
    expected: &'static str,
    request_id: Uuid,
) -> Result<(), ApiError> {
    if api_version != CLIENT_API_VERSION {
        return Err(ApiError::bad_request(
            "INVALID_API_VERSION",
            "api_version must be 1",
        ));
    }
    if message_type != expected {
        return Err(ApiError::bad_request(
            "INVALID_MESSAGE_TYPE",
            "message_type does not match the endpoint",
        ));
    }
    if request_id.is_nil() {
        return Err(ApiError::bad_request(
            "INVALID_REQUEST_ID",
            "request_id must be a non-nil UUID",
        ));
    }
    Ok(())
}

fn parse_platform(value: &str) -> Result<ClientPlatform, ApiError> {
    match value {
        "windows" => Ok(ClientPlatform::Windows),
        "macos" => Ok(ClientPlatform::Macos),
        "android" => Ok(ClientPlatform::Android),
        _ => Err(ApiError::bad_request(
            "INVALID_PLATFORM",
            "platform must be windows, macos, or android",
        )),
    }
}

/// Decodes a terminal public key and refuses anything that is not exactly one
/// raw Ed25519 public key, so a client cannot smuggle a private key, a
/// certificate, or a truncated blob into the device registry.
fn parse_public_key(value: &str) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], ApiError> {
    if value.len() < 16 || value.len() > 4096 {
        return Err(ApiError::bad_request(
            "INVALID_PUBLIC_KEY",
            "public_key must be base64url encoded",
        ));
    }
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        ApiError::bad_request("INVALID_PUBLIC_KEY", "public_key must be base64url encoded")
    })?;
    raw.as_slice().try_into().map_err(|_| {
        ApiError::bad_request(
            "INVALID_PUBLIC_KEY",
            "public_key must decode to exactly 32 bytes",
        )
    })
}

fn map_issuance_error(error: ClientIssuanceError) -> ApiError {
    match error {
        ClientIssuanceError::PolicyNotBound => ApiError::conflict(
            "CLIENT_ACCESS_POLICY_NOT_BOUND",
            "no active client access policy is bound to the device",
        ),
        // Returning an older node set here would let Cloud advertise transport
        // it can no longer authorize, so no-node is a retryable 503.
        ClientIssuanceError::NoActiveNode => ApiError::control_plane_unavailable(),
        ClientIssuanceError::Unavailable => ApiError::control_plane_unavailable(),
        ClientIssuanceError::IdempotencyConflict => ApiError::conflict(
            "IDEMPOTENCY_CONFLICT",
            "idempotency key was reused with a different request",
        ),
        ClientIssuanceError::GenerationConflict => ApiError::conflict(
            "CLIENT_GRANT_CONFLICT",
            "client grant generation changed concurrently",
        ),
        ClientIssuanceError::NotOwned => ApiError::forbidden(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_must_be_exactly_one_raw_ed25519_key() {
        let valid = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        assert_eq!(parse_public_key(&valid).unwrap(), [7_u8; 32]);

        // 31 bytes: a truncated key must not be accepted as a device identity.
        let short = URL_SAFE_NO_PAD.encode([7_u8; 31]);
        assert!(parse_public_key(&short).is_err());

        // A 64-byte value looks like an Ed25519 *secret* key; Cloud rejects it
        // rather than storing something that could leak a private key.
        let secret_shaped = URL_SAFE_NO_PAD.encode([7_u8; 64]);
        assert!(parse_public_key(&secret_shaped).is_err());

        assert!(parse_public_key("not base64url!").is_err());
        assert!(parse_public_key("short").is_err());
    }

    #[test]
    fn platform_accepts_only_the_three_contracted_values() {
        assert_eq!(parse_platform("windows").unwrap(), ClientPlatform::Windows);
        assert_eq!(parse_platform("macos").unwrap(), ClientPlatform::Macos);
        assert_eq!(parse_platform("android").unwrap(), ClientPlatform::Android);
        // Linux nodes enroll through the node plane, not here.
        assert!(parse_platform("linux").is_err());
        assert!(parse_platform("Windows").is_err());
    }

    #[test]
    fn envelope_rejects_version_type_and_nil_request_id() {
        let request_id = Uuid::new_v4();
        assert!(check_envelope(1, "register_device_request", "register_device_request", request_id).is_ok());
        assert!(check_envelope(2, "register_device_request", "register_device_request", request_id).is_err());
        assert!(check_envelope(1, "grant_request", "register_device_request", request_id).is_err());
        assert!(check_envelope(1, "register_device_request", "register_device_request", Uuid::nil()).is_err());
    }

    #[test]
    fn issuance_errors_never_report_cloud_faults_as_client_errors() {
        // A storage/signing failure must surface as 503 so a client retries,
        // while a missing policy is a 409 the client resolves by waiting.
        assert_eq!(map_issuance_error(ClientIssuanceError::Unavailable).status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(map_issuance_error(ClientIssuanceError::NoActiveNode).status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(map_issuance_error(ClientIssuanceError::PolicyNotBound).status, StatusCode::CONFLICT);
        assert_eq!(map_issuance_error(ClientIssuanceError::IdempotencyConflict).status, StatusCode::CONFLICT);
        assert_eq!(map_issuance_error(ClientIssuanceError::NotOwned).status, StatusCode::FORBIDDEN);
    }
}
