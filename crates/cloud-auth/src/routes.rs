use std::{future::Future, pin::Pin, sync::Arc};

use axum::{
    extract::{FromRequestParts, Json, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{
    DeviceEnrollment, DomainError, GrantRequest, ServiceClass, MAX_REQUEST_ID_LEN,
};
use crate::enrollment::{
    EnrollmentChallengeCommand, EnrollmentChallengeReceipt, EnrollmentCompleteCommand,
    EnrollmentCompleteReceipt, EnrollmentCoordinator, EnrollmentCoordinatorError,
};

pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Authentication context inserted by an upstream mTLS or bootstrap-token verifier.
/// This crate deliberately does not trust HTTP headers as an identity source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTenant {
    tenant_id: Uuid,
    subject_id: String,
}

impl AuthenticatedTenant {
    pub fn new(tenant_id: Uuid, subject_id: impl Into<String>) -> Result<Self, AuthContextError> {
        let subject_id = subject_id.into();
        if tenant_id.is_nil() {
            return Err(AuthContextError::InvalidTenant);
        }
        if subject_id.is_empty() || subject_id.len() > 120 {
            return Err(AuthContextError::InvalidSubject);
        }
        Ok(Self {
            tenant_id,
            subject_id,
        })
    }

    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthContextError {
    InvalidOrganization,
    InvalidTenant,
    InvalidSubject,
    InvalidDevice,
    InvalidDeviceKey,
    InvalidAssuranceLevel,
}

impl<S> FromRequestParts<S> for AuthenticatedTenant
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(ApiError::Unauthenticated)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDevice {
    organization_id: Uuid,
    tenant_id: Uuid,
    device_id: Uuid,
    device_key_id: Uuid,
    assurance_level: u64,
}

impl AuthenticatedDevice {
    pub fn new(
        organization_id: Uuid,
        tenant_id: Uuid,
        device_id: Uuid,
        device_key_id: Uuid,
        assurance_level: u64,
    ) -> Result<Self, AuthContextError> {
        if organization_id.is_nil() {
            return Err(AuthContextError::InvalidOrganization);
        }
        if tenant_id.is_nil() {
            return Err(AuthContextError::InvalidTenant);
        }
        if device_id.is_nil() {
            return Err(AuthContextError::InvalidDevice);
        }
        if device_key_id.is_nil() {
            return Err(AuthContextError::InvalidDeviceKey);
        }
        if assurance_level > 3 {
            return Err(AuthContextError::InvalidAssuranceLevel);
        }
        Ok(Self {
            organization_id,
            tenant_id,
            device_id,
            device_key_id,
            assurance_level,
        })
    }

    pub const fn organization_id(&self) -> Uuid {
        self.organization_id
    }

    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub const fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub const fn device_key_id(&self) -> Uuid {
        self.device_key_id
    }

    pub const fn assurance_level(&self) -> u64 {
        self.assurance_level
    }
}

impl<S> FromRequestParts<S> for AuthenticatedDevice
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(ApiError::Unauthenticated)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentReceipt {
    pub device_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantIssueCommand {
    pub actor: AuthenticatedDevice,
    pub request_id: String,
    pub request: GrantRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantIssuanceReceipt {
    pub grant_id: Uuid,
    pub expires_at_unix: i64,
    pub replayed: bool,
    pub access_grant: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantServiceError {
    Denied,
    Conflict,
    Unavailable,
    Internal,
}

/// The implementation owns database transactions, authorization snapshots, signing and audit.
/// Handlers never create a database substitute and never receive a signing key or Grant envelope.
pub trait TenantAuthService: Send + Sync + 'static {
    fn enroll(
        &self,
        actor: AuthenticatedTenant,
        enrollment: DeviceEnrollment,
    ) -> ServiceFuture<'_, Result<EnrollmentReceipt, GrantServiceError>>;

    fn issue_grant(
        &self,
        command: GrantIssueCommand,
    ) -> ServiceFuture<'_, Result<GrantIssuanceReceipt, GrantServiceError>>;
}

pub trait EnrollmentHttpService: Send + Sync + 'static {
    fn challenge(
        &self,
        command: EnrollmentChallengeCommand,
    ) -> ServiceFuture<'_, Result<EnrollmentChallengeReceipt, EnrollmentCoordinatorError>>;

    fn complete(
        &self,
        command: EnrollmentCompleteCommand,
    ) -> ServiceFuture<'_, Result<EnrollmentCompleteReceipt, EnrollmentCoordinatorError>>;
}

impl EnrollmentHttpService for EnrollmentCoordinator {
    fn challenge(
        &self,
        command: EnrollmentChallengeCommand,
    ) -> ServiceFuture<'_, Result<EnrollmentChallengeReceipt, EnrollmentCoordinatorError>> {
        Box::pin(async move { EnrollmentCoordinator::challenge(self, command).await })
    }

    fn complete(
        &self,
        command: EnrollmentCompleteCommand,
    ) -> ServiceFuture<'_, Result<EnrollmentCompleteReceipt, EnrollmentCoordinatorError>> {
        Box::pin(async move { EnrollmentCoordinator::complete(self, command).await })
    }
}

/// Builds only routes that require an injected authenticated tenant context. The production binary
/// does not mount this router until it has an mTLS/bootstrap authentication layer.
pub fn authenticated_app<S>(service: Arc<S>) -> Router
where
    S: TenantAuthService,
{
    Router::new()
        .route("/v1/access-grants", post(issue_grant::<S>))
        .with_state(service)
}

pub fn enrollment_app<S>(service: Arc<S>) -> Router
where
    S: EnrollmentHttpService,
{
    Router::new()
        .route("/v1/enrollment/challenges", post(create_challenge::<S>))
        .route("/v1/enrollment/complete", post(complete_enrollment::<S>))
        .with_state(service)
}

async fn create_challenge<S>(
    State(service): State<Arc<S>>,
    Json(request): Json<EnrollmentChallengeHttpRequest>,
) -> Result<(StatusCode, Json<EnrollmentChallengeHttpResponse>), ApiError>
where
    S: EnrollmentHttpService,
{
    let receipt = service
        .challenge(EnrollmentChallengeCommand {
            activation_credential: decode_fixed(&request.activation_credential)?,
            request_id: request.request_id,
            enrollment_instance_id: request.enrollment_instance_id,
            display_name: request.display_name,
            root_public_key: decode_fixed(&request.root_public_key)?,
            operational_public_key: decode_fixed(&request.operational_public_key)?,
            metadata_hash: decode_fixed(&request.metadata_hash)?,
            attestation_hash: decode_fixed(&request.attestation_hash)?,
        })
        .await
        .map_err(ApiError::Enrollment)?;
    let status = if receipt.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        Json(EnrollmentChallengeHttpResponse {
            challenge_id: receipt.challenge_id,
            organization_id: receipt.organization_id,
            server_nonce: encode_base64(receipt.server_nonce),
            expires_at: receipt.expires_at,
            replayed: receipt.replayed,
        }),
    ))
}

async fn complete_enrollment<S>(
    State(service): State<Arc<S>>,
    Json(request): Json<EnrollmentCompleteHttpRequest>,
) -> Result<Json<EnrollmentCompleteHttpResponse>, ApiError>
where
    S: EnrollmentHttpService,
{
    let receipt = service
        .complete(EnrollmentCompleteCommand {
            challenge_id: request.challenge_id,
            request_id: request.request_id,
            operational_proof: decode_fixed(&request.operational_proof)?,
        })
        .await
        .map_err(ApiError::Enrollment)?;
    Ok(Json(EnrollmentCompleteHttpResponse {
        device_id: receipt.device_id,
        device_key_id: receipt.device_key_id,
        certificate_der: encode_base64(receipt.certificate_der),
        certificate_chain_pem: receipt.certificate_chain_pem,
        not_after: receipt.not_after,
        replayed: receipt.replayed,
    }))
}

async fn issue_grant<S>(
    actor: AuthenticatedDevice,
    State(service): State<Arc<S>>,
    Json(request): Json<GrantIssueHttpRequest>,
) -> Result<Json<GrantIssuanceHttpResponse>, ApiError>
where
    S: TenantAuthService,
{
    if request.request_id.is_empty() || request.request_id.len() > MAX_REQUEST_ID_LEN {
        return Err(ApiError::InvalidRequest(DomainError::InvalidRequestId));
    }
    let command = GrantIssueCommand {
        request_id: request.request_id,
        request: GrantRequest {
            tenant_id: actor.tenant_id(),
            device_id: actor.device_id(),
            device_key_id: actor.device_key_id(),
            node_pool_id: request.node_pool_id,
            service_class: request.service_class.into(),
            service_permission: request.service_permission,
        },
        actor,
    };
    let receipt = service
        .issue_grant(command)
        .await
        .map_err(ApiError::Service)?;
    Ok(Json(GrantIssuanceHttpResponse {
        grant_id: receipt.grant_id,
        expires_at_unix: receipt.expires_at_unix,
        replayed: receipt.replayed,
        access_grant: base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            receipt.access_grant,
        ),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentChallengeHttpRequest {
    activation_credential: String,
    request_id: String,
    enrollment_instance_id: String,
    display_name: String,
    root_public_key: String,
    operational_public_key: String,
    metadata_hash: String,
    attestation_hash: String,
}

#[derive(Debug, Serialize)]
struct EnrollmentChallengeHttpResponse {
    challenge_id: Uuid,
    organization_id: Uuid,
    server_nonce: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    replayed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentCompleteHttpRequest {
    challenge_id: Uuid,
    request_id: String,
    operational_proof: String,
}

#[derive(Debug, Serialize)]
struct EnrollmentCompleteHttpResponse {
    device_id: Uuid,
    device_key_id: Uuid,
    certificate_der: String,
    certificate_chain_pem: String,
    not_after: chrono::DateTime<chrono::Utc>,
    replayed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantIssueHttpRequest {
    request_id: String,
    node_pool_id: Uuid,
    service_class: ServiceClassHttp,
    service_permission: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ServiceClassHttp {
    Private,
    CandyShared,
    CandyDedicated,
    Partner,
}

impl From<ServiceClassHttp> for ServiceClass {
    fn from(value: ServiceClassHttp) -> Self {
        match value {
            ServiceClassHttp::Private => Self::Private,
            ServiceClassHttp::CandyShared => Self::CandyShared,
            ServiceClassHttp::CandyDedicated => Self::CandyDedicated,
            ServiceClassHttp::Partner => Self::Partner,
        }
    }
}

#[derive(Debug, Serialize)]
struct GrantIssuanceHttpResponse {
    grant_id: Uuid,
    expires_at_unix: i64,
    replayed: bool,
    access_grant: String,
}

#[derive(Debug, Serialize)]
struct ProblemResponse {
    code: &'static str,
}

#[derive(Debug)]
pub enum ApiError {
    Unauthenticated,
    InvalidEncoding,
    InvalidRequest(DomainError),
    Enrollment(EnrollmentCoordinatorError),
    Service(GrantServiceError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            Self::InvalidEncoding => (StatusCode::BAD_REQUEST, "invalid_encoding"),
            Self::InvalidRequest(error) => (StatusCode::BAD_REQUEST, error.code()),
            Self::Enrollment(EnrollmentCoordinatorError::InvalidRequest) => {
                (StatusCode::BAD_REQUEST, "invalid_request")
            }
            Self::Enrollment(
                EnrollmentCoordinatorError::ActivationUnavailable
                | EnrollmentCoordinatorError::ChallengeUnavailable
                | EnrollmentCoordinatorError::ProofRejected,
            ) => (StatusCode::UNAUTHORIZED, "enrollment_denied"),
            Self::Enrollment(EnrollmentCoordinatorError::Conflict) => {
                (StatusCode::CONFLICT, "conflict")
            }
            Self::Enrollment(EnrollmentCoordinatorError::Unavailable) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
            Self::Service(GrantServiceError::Denied) => (StatusCode::FORBIDDEN, "denied"),
            Self::Service(GrantServiceError::Conflict) => (StatusCode::CONFLICT, "conflict"),
            Self::Service(GrantServiceError::Unavailable) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
            Self::Service(GrantServiceError::Internal) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };
        (status, Json(ProblemResponse { code })).into_response()
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], ApiError> {
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value)
        .map_err(|_| ApiError::InvalidEncoding)?;
    decoded.try_into().map_err(|_| ApiError::InvalidEncoding)
}

fn encode_base64(value: impl AsRef<[u8]>) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value)
}
