use std::{future::Future, pin::Pin, sync::Arc};

use axum::{
    body::Body,
    extract::{FromRequestParts, Json, Request, State},
    http::{header, request::Parts, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::device_identity::{DeviceIdentityAuthenticator, DeviceIdentityError};
use crate::domain::{
    DeviceEnrollment, DomainError, GrantRequest, ServiceClass, MAX_REQUEST_ID_LEN,
};
use crate::enrollment::{
    EnrollmentChallengeCommand, EnrollmentChallengeReceipt, EnrollmentCompleteCommand,
    EnrollmentCompleteReceipt, EnrollmentCoordinator, EnrollmentCoordinatorError,
};
use cloud_db::enrollment::{
    hash_activation_credential, BootstrapExchangeWrite, BootstrapManifestOutcome,
    EnrollmentRepository,
};
use ed25519_dalek::{Signer, SigningKey};

static VERIFIED_DEVICE_CERTIFICATE_HEADER: HeaderName =
    HeaderName::from_static("x-candy-verified-device-certificate-der");

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigurationDelivery {
    pub projection_publication_id: Uuid,
    pub projection_id: Uuid,
    pub segment_id: Uuid,
    pub attachment_id: Uuid,
    pub segment_generation: u64,
    pub projection_generation: u64,
    pub projection_content_hash: [u8; 32],
    pub envelope_sha256: [u8; 32],
    pub signed_envelope: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigurationApplyState {
    Active,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigurationStatusCommand {
    pub actor: AuthenticatedDevice,
    pub projection_publication_id: Uuid,
    pub projection_content_hash: [u8; 32],
    pub envelope_sha256: [u8; 32],
    pub apply_state: RuntimeConfigurationApplyState,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigurationServiceError {
    Conflict,
    Unavailable,
}

pub trait RuntimeConfigurationService: Send + Sync + 'static {
    fn current(
        &self,
        actor: AuthenticatedDevice,
    ) -> ServiceFuture<
        '_,
        Result<Option<RuntimeConfigurationDelivery>, RuntimeConfigurationServiceError>,
    >;

    fn record_status(
        &self,
        command: RuntimeConfigurationStatusCommand,
    ) -> ServiceFuture<'_, Result<(), RuntimeConfigurationServiceError>>;
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

pub fn device_authenticated_app<S>(
    service: Arc<S>,
    authenticator: DeviceIdentityAuthenticator,
) -> Router
where
    S: TenantAuthService,
{
    authenticated_app(service).route_layer(middleware::from_fn_with_state(
        Arc::new(authenticator),
        require_device_identity,
    ))
}

pub fn runtime_configuration_app<S>(service: Arc<S>) -> Router
where
    S: RuntimeConfigurationService,
{
    Router::new()
        .route("/v1/runtime/capabilities", get(runtime_capabilities))
        .route(
            "/v1/runtime/configuration",
            get(current_runtime_configuration::<S>),
        )
        .route(
            "/v1/runtime/configuration/status",
            put(record_runtime_configuration_status::<S>),
        )
        .with_state(service)
}

pub fn device_authenticated_runtime_app<S>(
    service: Arc<S>,
    authenticator: DeviceIdentityAuthenticator,
) -> Router
where
    S: RuntimeConfigurationService,
{
    runtime_configuration_app(service).route_layer(middleware::from_fn_with_state(
        Arc::new(authenticator),
        require_device_identity,
    ))
}

async fn require_device_identity(
    State(authenticator): State<Arc<DeviceIdentityAuthenticator>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let encoded = request
        .headers()
        .get(&VERIFIED_DEVICE_CERTIFICATE_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 96 * 1024)
        .ok_or(ApiError::Unauthenticated)?;
    let certificate_der =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|_| ApiError::Unauthenticated)?;
    let actor = authenticator
        .authenticate_verified_certificate(&certificate_der, chrono::Utc::now())
        .await
        .map_err(|error| match error {
            DeviceIdentityError::InvalidCertificate | DeviceIdentityError::InactiveCertificate => {
                ApiError::Unauthenticated
            }
            DeviceIdentityError::Unavailable => ApiError::Service(GrantServiceError::Unavailable),
        })?;
    request.extensions_mut().insert(actor);
    Ok(next.run(request).await)
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

#[derive(Clone)]
pub struct BootstrapHttpService {
    repository: EnrollmentRepository,
    signing_key: SigningKey,
    signing_key_id: String,
}

impl BootstrapHttpService {
    pub fn new(
        repository: EnrollmentRepository,
        signing_key: SigningKey,
        signing_key_id: String,
    ) -> Self {
        Self {
            repository,
            signing_key,
            signing_key_id,
        }
    }

    fn enrollment_authorization(
        &self,
        bootstrap_hash: &[u8; 32],
        installation_instance_id: &str,
    ) -> [u8; 32] {
        let mut transcript = Vec::with_capacity(64 + installation_instance_id.len());
        transcript.extend_from_slice(b"candy/bootstrap-enrollment-authorization/v1\0");
        transcript.extend_from_slice(bootstrap_hash);
        transcript.extend_from_slice(installation_instance_id.as_bytes());
        Sha256::digest(self.signing_key.sign(&transcript).to_bytes()).into()
    }
}

pub fn bootstrap_app(service: BootstrapHttpService) -> Router {
    Router::new()
        .route("/v1/bootstrap/exchange", post(exchange_bootstrap))
        .with_state(service)
}

async fn exchange_bootstrap(
    State(service): State<BootstrapHttpService>,
    Json(request): Json<BootstrapExchangeHttpRequest>,
) -> Result<Json<BootstrapManifestHttpResponse>, ApiError> {
    if !valid_installation_instance_id(&request.installation_instance_id) {
        return Err(ApiError::Enrollment(
            EnrollmentCoordinatorError::InvalidRequest,
        ));
    }
    let credential = decode_fixed(&request.bootstrap_code)?;
    let bootstrap_hash = hash_activation_credential(&credential);
    let enrollment_credential =
        service.enrollment_authorization(&bootstrap_hash, &request.installation_instance_id);
    let (outcome, record) = service
        .repository
        .exchange_bootstrap_code(
            &bootstrap_hash,
            &BootstrapExchangeWrite {
                installation_instance_id: request.installation_instance_id,
                enrollment_credential_hash: hash_activation_credential(&enrollment_credential),
            },
            chrono::Utc::now(),
        )
        .await
        .map_err(|_| ApiError::Service(GrantServiceError::Unavailable))?;
    let record = match (outcome, record) {
        (BootstrapManifestOutcome::Issued | BootstrapManifestOutcome::Replay, Some(record)) => {
            record
        }
        (BootstrapManifestOutcome::Conflict, _) => {
            return Err(ApiError::Service(GrantServiceError::Conflict))
        }
        _ => return Err(ApiError::Unauthenticated),
    };
    Ok(Json(BootstrapManifestHttpResponse {
        schema_version: 1,
        activation_id: record.activation_id,
        tenant_id: record.tenant_id,
        site_id: record.site_id,
        display_name: record.display_name,
        platform: record.platform,
        architecture: record.architecture,
        enrollment_endpoint: "/auth/v1/enrollment/challenges".into(),
        enrollment_authorization: base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            enrollment_credential,
        ),
        signing_key_id: service.signing_key_id,
        expires_at: record.expires_at,
        replayed: record.replayed,
    }))
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
        certificate_der: encode_standard_base64(receipt.certificate_der),
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

const RUNTIME_CONFIGURATION_MEDIA_TYPE: &str =
    "application/vnd.candy.site-projection-envelope.v1+octet-stream";
const RUNTIME_REFRESH_SECONDS: u64 = 30;

async fn runtime_capabilities(_actor: AuthenticatedDevice) -> Json<RuntimeCapabilitiesResponse> {
    Json(RuntimeCapabilitiesResponse {
        api_version: "v1",
        wire_protocol: "0.3",
        configuration_object: "site_projection_v1",
        configuration_media_type: RUNTIME_CONFIGURATION_MEDIA_TYPE,
        conditional_requests: ["etag", "if-none-match"],
        status_values: ["active", "rejected"],
        refresh: RuntimeRefreshCapabilities {
            minimum_seconds: 15,
            recommended_seconds: RUNTIME_REFRESH_SECONDS,
            maximum_seconds: 300,
            jitter_percent: 20,
        },
    })
}

async fn current_runtime_configuration<S>(
    actor: AuthenticatedDevice,
    State(service): State<Arc<S>>,
    headers: HeaderMap,
) -> Result<Response, ApiError>
where
    S: RuntimeConfigurationService,
{
    let delivery = service
        .current(actor)
        .await
        .map_err(ApiError::RuntimeConfiguration)?;
    let Some(delivery) = delivery else {
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=30"),
        );
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        return Ok(response);
    };
    let etag = configuration_etag(&delivery.envelope_sha256);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| if_none_match(value, &etag))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        insert_configuration_response_headers(&mut response, &delivery, &etag)?;
        return Ok(response);
    }
    let mut response = Response::new(Body::empty());
    insert_configuration_response_headers(&mut response, &delivery, &etag)?;
    *response.body_mut() = Body::from(delivery.signed_envelope);
    Ok(response)
}

async fn record_runtime_configuration_status<S>(
    actor: AuthenticatedDevice,
    State(service): State<Arc<S>>,
    headers: HeaderMap,
    Json(request): Json<RuntimeConfigurationStatusHttpRequest>,
) -> Result<StatusCode, ApiError>
where
    S: RuntimeConfigurationService,
{
    let if_match = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::InvalidRuntimeConfigurationStatus)?;
    let envelope_sha256 =
        parse_configuration_etag(if_match).ok_or(ApiError::InvalidRuntimeConfigurationStatus)?;
    let projection_content_hash = decode_hash(&request.projection_content_hash)
        .ok_or(ApiError::InvalidRuntimeConfigurationStatus)?;
    let (apply_state, error_code) = match request.state {
        RuntimeConfigurationApplyStateHttp::Active if request.error_code.is_none() => {
            (RuntimeConfigurationApplyState::Active, None)
        }
        RuntimeConfigurationApplyStateHttp::Rejected => {
            let error = request
                .error_code
                .filter(|value| valid_runtime_error_code(value))
                .ok_or(ApiError::InvalidRuntimeConfigurationStatus)?;
            (RuntimeConfigurationApplyState::Rejected, Some(error))
        }
        _ => return Err(ApiError::InvalidRuntimeConfigurationStatus),
    };
    service
        .record_status(RuntimeConfigurationStatusCommand {
            actor,
            projection_publication_id: request.projection_publication_id,
            projection_content_hash,
            envelope_sha256,
            apply_state,
            error_code,
        })
        .await
        .map_err(ApiError::RuntimeConfiguration)?;
    Ok(StatusCode::NO_CONTENT)
}

fn insert_configuration_response_headers(
    response: &mut Response,
    delivery: &RuntimeConfigurationDelivery,
    etag: &str,
) -> Result<(), ApiError> {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(RUNTIME_CONFIGURATION_MEDIA_TYPE),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(etag).map_err(|_| ApiError::InvalidRuntimeConfigurationStatus)?,
    );
    for (name, value) in [
        (
            "x-candy-projection-publication-id",
            delivery.projection_publication_id.to_string(),
        ),
        ("x-candy-projection-id", delivery.projection_id.to_string()),
        ("x-candy-segment-id", delivery.segment_id.to_string()),
        ("x-candy-attachment-id", delivery.attachment_id.to_string()),
        (
            "x-candy-segment-generation",
            delivery.segment_generation.to_string(),
        ),
        (
            "x-candy-projection-generation",
            delivery.projection_generation.to_string(),
        ),
        (
            "x-candy-projection-content-hash",
            hex(&delivery.projection_content_hash),
        ),
        ("x-candy-refresh-after", RUNTIME_REFRESH_SECONDS.to_string()),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value)
                .map_err(|_| ApiError::InvalidRuntimeConfigurationStatus)?,
        );
    }
    Ok(())
}

fn configuration_etag(digest: &[u8; 32]) -> String {
    format!("\"sha256-{}\"", hex(digest))
}

fn parse_configuration_etag(value: &str) -> Option<[u8; 32]> {
    let value = value.trim().strip_prefix("\"sha256-")?.strip_suffix('"')?;
    decode_hash(value)
}

fn if_none_match(header_value: &str, current: &str) -> bool {
    header_value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate == current || candidate.strip_prefix("W/") == Some(current)
    })
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut result = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        result[index] = (high << 4) | low;
    }
    Some(result)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn valid_runtime_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_installation_instance_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 120
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapExchangeHttpRequest {
    bootstrap_code: String,
    installation_instance_id: String,
}

#[derive(Debug, Serialize)]
struct BootstrapManifestHttpResponse {
    schema_version: u8,
    activation_id: Uuid,
    tenant_id: Uuid,
    site_id: Uuid,
    display_name: String,
    platform: String,
    architecture: String,
    enrollment_endpoint: String,
    enrollment_authorization: String,
    signing_key_id: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    replayed: bool,
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
struct RuntimeCapabilitiesResponse {
    api_version: &'static str,
    wire_protocol: &'static str,
    configuration_object: &'static str,
    configuration_media_type: &'static str,
    conditional_requests: [&'static str; 2],
    status_values: [&'static str; 2],
    refresh: RuntimeRefreshCapabilities,
}

#[derive(Debug, Serialize)]
struct RuntimeRefreshCapabilities {
    minimum_seconds: u64,
    recommended_seconds: u64,
    maximum_seconds: u64,
    jitter_percent: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfigurationStatusHttpRequest {
    projection_publication_id: Uuid,
    projection_content_hash: String,
    state: RuntimeConfigurationApplyStateHttp,
    error_code: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeConfigurationApplyStateHttp {
    Active,
    Rejected,
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
    InvalidRuntimeConfigurationStatus,
    RuntimeConfiguration(RuntimeConfigurationServiceError),
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
            Self::InvalidRuntimeConfigurationStatus => (
                StatusCode::BAD_REQUEST,
                "invalid_runtime_configuration_status",
            ),
            Self::RuntimeConfiguration(RuntimeConfigurationServiceError::Conflict) => {
                (StatusCode::CONFLICT, "configuration_changed")
            }
            Self::RuntimeConfiguration(RuntimeConfigurationServiceError::Unavailable) => {
                (StatusCode::SERVICE_UNAVAILABLE, "configuration_unavailable")
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

fn encode_standard_base64(value: impl AsRef<[u8]>) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value)
}
