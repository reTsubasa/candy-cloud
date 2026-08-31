use std::{
    collections::HashSet, future::Future, net::Ipv4Addr, pin::Pin, sync::Arc, time::Duration,
};

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
    pub refresh_after_unix: i64,
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
    pub signed_segment_envelope: Vec<u8>,
    pub signed_projection_envelope: Vec<u8>,
    pub route_signing_key_id: String,
    pub route_signing_public_key: [u8; 32],
    pub peer_projection_catalog: Vec<RuntimePeerProjectionDelivery>,
    pub compatibility_generations: Vec<RuntimeCompatibilityGenerationDelivery>,
    pub grant_verification_keys: Vec<RuntimeGrantVerificationKeyDelivery>,
    pub activation_phase: RuntimeConfigurationActivationPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigurationActivationPhase {
    Prepare,
    Commit,
}

impl RuntimeConfigurationActivationPhase {
    fn http_value(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Commit => "commit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCompatibilityGenerationDelivery {
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
    pub signed_segment_envelope: Vec<u8>,
    pub peer_projection_catalog: Vec<RuntimePeerProjectionDelivery>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeGrantVerificationKeyDelivery {
    pub key_id: String,
    pub ed25519_public_key: [u8; 32],
    pub issuer_id: Uuid,
    pub environment_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePeerProjectionDelivery {
    pub projection_id: Uuid,
    pub projection_generation: u64,
    pub projection_content_hash: [u8; 32],
    pub signed_projection_envelope: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeProfileDelivery {
    pub organization_id: Uuid,
    pub organization_name: String,
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub device_name: String,
    pub site_id: Option<Uuid>,
    pub site_name: Option<String>,
    pub segment_id: Option<Uuid>,
    pub segment_name: Option<String>,
    pub attachment_id: Option<Uuid>,
    pub peer_sites: Vec<RuntimePeerSiteDelivery>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimePeerSiteDelivery {
    pub site_id: Uuid,
    pub site_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigurationApplyState {
    Prepared,
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
pub enum RuntimeLifecycle {
    Starting,
    Active,
    Degraded,
    FailOpen,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTelemetryCommand {
    pub actor: AuthenticatedDevice,
    pub boot_id: Uuid,
    pub sequence: u64,
    pub lifecycle: RuntimeLifecycle,
    pub configured_peers: u32,
    pub active_peers: u32,
    pub required_route_owners: u32,
    pub ready_route_owners: u32,
    pub fail_open_required: bool,
    pub last_error_code: Option<String>,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub packet_loss_ppm: Option<u32>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub reconnects: Option<u64>,
    pub path_changes: Option<u64>,
    pub paths: Vec<RuntimePathTelemetryCommand>,
    pub local_networks: Option<Vec<RuntimeLocalNetworkTelemetryCommand>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLocalNetworkTelemetryCommand {
    pub network_id: String,
    pub interface_name: String,
    pub cidr: String,
    pub address: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePathTelemetryCommand {
    pub peer_attachment_id: Uuid,
    pub candidate_id: Option<Uuid>,
    pub path_kind: RuntimePathKind,
    pub transport: String,
    pub connection_epoch: u64,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub packet_loss_ppm: Option<u32>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub reconnects: u64,
    pub path_changes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePathKind {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTransportPreset {
    Current,
    BbrV1,
    Aggressive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTransportIdentityCommand {
    pub actor: AuthenticatedDevice,
    pub request_id: String,
    pub endpoints: Vec<RuntimeTransportEndpointCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTransportEndpointCommand {
    pub endpoint: std::net::SocketAddr,
    pub server_cert_sha256: [u8; 32],
    pub transport_preset: RuntimeTransportPreset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeTransportIdentityDelivery {
    pub node_id: Uuid,
    pub endpoints: Vec<RuntimeTransportEndpointDelivery>,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeTransportEndpointDelivery {
    pub endpoint: String,
    pub server_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigurationServiceError {
    Conflict,
    Unavailable,
}

pub trait RuntimeConfigurationService: Send + Sync + 'static {
    fn profile(
        &self,
        actor: AuthenticatedDevice,
    ) -> ServiceFuture<'_, Result<RuntimeProfileDelivery, RuntimeConfigurationServiceError>>;

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

    fn record_telemetry(
        &self,
        command: RuntimeTelemetryCommand,
    ) -> ServiceFuture<'_, Result<(), RuntimeConfigurationServiceError>>;

    fn publish_transport_identity(
        &self,
        _command: RuntimeTransportIdentityCommand,
    ) -> ServiceFuture<'_, Result<RuntimeTransportIdentityDelivery, RuntimeConfigurationServiceError>>
    {
        Box::pin(async { Err(RuntimeConfigurationServiceError::Unavailable) })
    }

    fn withdraw_transport_identity(
        &self,
        _actor: AuthenticatedDevice,
    ) -> ServiceFuture<'_, Result<(), RuntimeConfigurationServiceError>> {
        Box::pin(async { Err(RuntimeConfigurationServiceError::Unavailable) })
    }
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
        .route("/v1/runtime/profile", get(runtime_profile::<S>))
        .route(
            "/v1/runtime/transport-identity",
            put(publish_runtime_transport_identity::<S>)
                .delete(withdraw_runtime_transport_identity::<S>),
        )
        .route(
            "/v1/runtime/configuration",
            get(current_runtime_configuration::<S>),
        )
        .route(
            "/v1/runtime/configuration/status",
            put(record_runtime_configuration_status::<S>),
        )
        .route("/v1/runtime/telemetry", put(record_runtime_telemetry::<S>))
        .with_state(service)
}

async fn withdraw_runtime_transport_identity<S>(
    actor: AuthenticatedDevice,
    State(service): State<Arc<S>>,
) -> Result<StatusCode, ApiError>
where
    S: RuntimeConfigurationService,
{
    service
        .withdraw_transport_identity(actor)
        .await
        .map_err(ApiError::RuntimeConfiguration)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn publish_runtime_transport_identity<S>(
    actor: AuthenticatedDevice,
    State(service): State<Arc<S>>,
    Json(request): Json<RuntimeTransportIdentityHttpRequest>,
) -> Result<StatusCode, ApiError>
where
    S: RuntimeConfigurationService,
{
    if request.schema_version != 1
        || request.request_id.is_empty()
        || request.request_id.len() > 120
        || !(1..=8).contains(&request.endpoints.len())
        || !request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ApiError::InvalidRuntimeConfigurationStatus);
    }
    let endpoints = request
        .endpoints
        .into_iter()
        .map(|item| {
            Ok(RuntimeTransportEndpointCommand {
                endpoint: item
                    .endpoint
                    .parse()
                    .map_err(|_| ApiError::InvalidRuntimeConfigurationStatus)?,
                server_cert_sha256: decode_hash(&item.server_cert_sha256)
                    .ok_or(ApiError::InvalidRuntimeConfigurationStatus)?,
                transport_preset: match item.transport_preset {
                    RuntimeTransportPresetHttp::Current => RuntimeTransportPreset::Current,
                    RuntimeTransportPresetHttp::BbrV1 => RuntimeTransportPreset::BbrV1,
                    RuntimeTransportPresetHttp::Aggressive => RuntimeTransportPreset::Aggressive,
                },
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let mut unique_endpoints = std::collections::HashSet::new();
    if endpoints
        .iter()
        .any(|endpoint| !unique_endpoints.insert(endpoint.endpoint))
    {
        return Err(ApiError::InvalidRuntimeConfigurationStatus);
    }
    service
        .publish_transport_identity(RuntimeTransportIdentityCommand {
            actor,
            request_id: request.request_id,
            endpoints,
        })
        .await
        .map_err(ApiError::RuntimeConfiguration)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn runtime_profile<S>(
    actor: AuthenticatedDevice,
    State(service): State<Arc<S>>,
) -> Result<Json<RuntimeProfileDelivery>, ApiError>
where
    S: RuntimeConfigurationService,
{
    service
        .profile(actor)
        .await
        .map(Json)
        .map_err(ApiError::RuntimeConfiguration)
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
        refresh_after_unix: receipt.refresh_after_unix,
        replayed: receipt.replayed,
        access_grant: base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            receipt.access_grant,
        ),
    }))
}

const RUNTIME_CONFIGURATION_MEDIA_TYPE: &str =
    "application/vnd.candy.runtime-configuration.v1+json";
const RUNTIME_REFRESH_SECONDS: u64 = 1;
const RUNTIME_WAIT_SECONDS: u64 = 20;
const RUNTIME_WAIT_MAX_SECONDS: u64 = 25;
const RUNTIME_WAIT_POLL_MILLIS: u64 = 500;

async fn runtime_capabilities(_actor: AuthenticatedDevice) -> Json<RuntimeCapabilitiesResponse> {
    Json(RuntimeCapabilitiesResponse {
        api_version: "v1",
        wire_protocol: "0.3",
        configuration_object: "runtime_configuration_v1",
        configuration_media_type: RUNTIME_CONFIGURATION_MEDIA_TYPE,
        conditional_requests: ["etag", "if-none-match", "prefer-wait"],
        status_values: ["prepared", "active", "rejected"],
        refresh: RuntimeRefreshCapabilities {
            minimum_seconds: 1,
            recommended_seconds: RUNTIME_REFRESH_SECONDS,
            maximum_seconds: 300,
            jitter_percent: 20,
            wait_seconds: RUNTIME_WAIT_SECONDS,
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
    let requested_etag = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let wait_seconds = preferred_wait_seconds(&headers);
    let deadline =
        wait_seconds.map(|seconds| tokio::time::Instant::now() + Duration::from_secs(seconds));
    let delivery = loop {
        let delivery = service
            .current(actor.clone())
            .await
            .map_err(ApiError::RuntimeConfiguration)?;
        let unchanged = match (&delivery, requested_etag.as_deref()) {
            (Some(delivery), Some(requested)) => {
                if_none_match(requested, &configuration_etag(&delivery.envelope_sha256))
            }
            (None, None) => true,
            _ => false,
        };
        let Some(deadline) = deadline else {
            break delivery;
        };
        if !unchanged || tokio::time::Instant::now() >= deadline {
            break delivery;
        }
        tokio::time::sleep(Duration::from_millis(RUNTIME_WAIT_POLL_MILLIS)).await;
    };
    let Some(delivery) = delivery else {
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        insert_wait_response_header(&mut response, wait_seconds)?;
        return Ok(response);
    };
    let etag = configuration_etag(&delivery.envelope_sha256);
    if requested_etag
        .as_deref()
        .is_some_and(|value| if_none_match(value, &etag))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        insert_configuration_response_headers(&mut response, &delivery, &etag)?;
        insert_wait_response_header(&mut response, wait_seconds)?;
        return Ok(response);
    }
    let body = serde_json::to_vec(&RuntimeConfigurationHttpResponse {
        schema_version: 1,
        activation_phase: delivery.activation_phase.http_value(),
        projection_publication_id: delivery.projection_publication_id,
        projection_id: delivery.projection_id,
        segment_id: delivery.segment_id,
        attachment_id: delivery.attachment_id,
        segment_generation: delivery.segment_generation,
        projection_generation: delivery.projection_generation,
        projection_content_hash: hex(&delivery.projection_content_hash),
        route_signing_key_id: delivery.route_signing_key_id.clone(),
        route_signing_public_key: hex(&delivery.route_signing_public_key),
        segment_snapshot: encode_base64(delivery.signed_segment_envelope.clone()),
        site_projection: encode_base64(delivery.signed_projection_envelope.clone()),
        peer_projection_catalog: delivery
            .peer_projection_catalog
            .iter()
            .map(runtime_peer_projection_http_response)
            .collect(),
        compatibility_generations: delivery
            .compatibility_generations
            .iter()
            .map(|generation| RuntimeCompatibilityGenerationHttpResponse {
                segment_generation: generation.segment_generation,
                segment_content_hash: hex(&generation.segment_content_hash),
                segment_snapshot: encode_base64(generation.signed_segment_envelope.clone()),
                peer_projection_catalog: generation
                    .peer_projection_catalog
                    .iter()
                    .map(runtime_peer_projection_http_response)
                    .collect(),
            })
            .collect(),
        grant_verification_keys: delivery
            .grant_verification_keys
            .iter()
            .map(|key| RuntimeGrantVerificationKeyHttpResponse {
                key_id: key.key_id.clone(),
                ed25519_public_key: hex(&key.ed25519_public_key),
                issuer_id: key.issuer_id,
                environment_id: key.environment_id,
            })
            .collect(),
    })
    .map_err(|_| ApiError::InvalidRuntimeConfigurationStatus)?;
    let mut response = Response::new(Body::empty());
    insert_configuration_response_headers(&mut response, &delivery, &etag)?;
    insert_wait_response_header(&mut response, wait_seconds)?;
    *response.body_mut() = Body::from(body);
    Ok(response)
}

fn preferred_wait_seconds(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("prefer")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(',').find_map(|preference| {
                let (name, seconds) = preference.trim().split_once('=')?;
                name.eq_ignore_ascii_case("wait")
                    .then(|| seconds.trim().parse::<u64>().ok())
                    .flatten()
            })
        })
        .filter(|seconds| *seconds > 0)
        .map(|seconds| seconds.min(RUNTIME_WAIT_MAX_SECONDS))
}

fn insert_wait_response_header(
    response: &mut Response,
    wait_seconds: Option<u64>,
) -> Result<(), ApiError> {
    if let Some(wait_seconds) = wait_seconds {
        response.headers_mut().insert(
            "preference-applied",
            HeaderValue::from_str(&format!("wait={wait_seconds}"))
                .map_err(|_| ApiError::InvalidRuntimeConfigurationStatus)?,
        );
    }
    Ok(())
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
        RuntimeConfigurationApplyStateHttp::Prepared if request.error_code.is_none() => {
            (RuntimeConfigurationApplyState::Prepared, None)
        }
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

async fn record_runtime_telemetry<S>(
    actor: AuthenticatedDevice,
    State(service): State<Arc<S>>,
    Json(request): Json<RuntimeTelemetryHttpRequest>,
) -> Result<StatusCode, ApiError>
where
    S: RuntimeConfigurationService,
{
    let error_code = request.last_error_code;
    let mut peer_attachments = HashSet::with_capacity(request.paths.len());
    let mut network_ids = HashSet::new();
    if request.schema_version != 1
        || request.boot_id.is_nil()
        || request.sequence == 0
        || request.active_peers > request.configured_peers
        || request.ready_route_owners > request.required_route_owners
        || request.ready_route_owners > request.active_peers
        || request
            .packet_loss_ppm
            .is_some_and(|value| value > 1_000_000)
        || error_code
            .as_deref()
            .is_some_and(|value| !valid_runtime_error_code(value))
        || matches!(request.lifecycle, RuntimeLifecycleHttp::FailOpen) != request.fail_open_required
        || request.paths.len() > 256
        || request
            .local_networks
            .as_ref()
            .is_some_and(|networks| networks.len() > 64)
        || request.paths.iter().any(|path| {
            path.peer_attachment_id.is_nil()
                || path.candidate_id.is_some_and(|value| value.is_nil())
                || path.transport != "quic_udp"
                || path.connection_epoch == 0
                || path.packet_loss_ppm.is_some_and(|value| value > 1_000_000)
                || !peer_attachments.insert(path.peer_attachment_id)
        })
        || request.local_networks.as_ref().is_some_and(|networks| {
            networks.iter().any(|network| {
                network.network_id.len() != 64
                    || !network
                        .network_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || !valid_runtime_token(&network.interface_name, 64, b"_.:-@")
                    || network.kind != "direct_ipv4"
                    || !valid_runtime_network(&network.cidr, &network.address)
                    || !network_ids.insert(network.network_id.as_str())
            })
        })
    {
        return Err(ApiError::InvalidRuntimeTelemetry);
    }
    service
        .record_telemetry(RuntimeTelemetryCommand {
            actor,
            boot_id: request.boot_id,
            sequence: request.sequence,
            lifecycle: match request.lifecycle {
                RuntimeLifecycleHttp::Starting => RuntimeLifecycle::Starting,
                RuntimeLifecycleHttp::Active => RuntimeLifecycle::Active,
                RuntimeLifecycleHttp::Degraded => RuntimeLifecycle::Degraded,
                RuntimeLifecycleHttp::FailOpen => RuntimeLifecycle::FailOpen,
                RuntimeLifecycleHttp::Stopped => RuntimeLifecycle::Stopped,
                RuntimeLifecycleHttp::Unknown => RuntimeLifecycle::Unknown,
            },
            configured_peers: request.configured_peers,
            active_peers: request.active_peers,
            required_route_owners: request.required_route_owners,
            ready_route_owners: request.ready_route_owners,
            fail_open_required: request.fail_open_required,
            last_error_code: error_code,
            rtt_ms: request.rtt_ms,
            jitter_ms: request.jitter_ms,
            packet_loss_ppm: request.packet_loss_ppm,
            rx_bps: request.rx_bps,
            tx_bps: request.tx_bps,
            reconnects: request.reconnects,
            path_changes: request.path_changes,
            paths: request
                .paths
                .into_iter()
                .map(|path| RuntimePathTelemetryCommand {
                    peer_attachment_id: path.peer_attachment_id,
                    candidate_id: path.candidate_id,
                    path_kind: match path.path_kind {
                        RuntimePathKindHttp::Direct => RuntimePathKind::Direct,
                        RuntimePathKindHttp::Relay => RuntimePathKind::Relay,
                    },
                    transport: path.transport,
                    connection_epoch: path.connection_epoch,
                    rtt_ms: path.rtt_ms,
                    jitter_ms: path.jitter_ms,
                    packet_loss_ppm: path.packet_loss_ppm,
                    rx_bps: path.rx_bps,
                    tx_bps: path.tx_bps,
                    reconnects: path.reconnects,
                    path_changes: path.path_changes,
                })
                .collect(),
            local_networks: request.local_networks.map(|networks| {
                networks
                    .into_iter()
                    .map(|network| RuntimeLocalNetworkTelemetryCommand {
                        network_id: network.network_id,
                        interface_name: network.interface_name,
                        cidr: network.cidr,
                        address: network.address,
                        kind: network.kind,
                    })
                    .collect()
            }),
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

fn valid_runtime_token(value: &str, maximum: usize, punctuation: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || punctuation.contains(&byte))
}

fn valid_runtime_network(cidr: &str, address: &str) -> bool {
    if cidr.is_empty() || cidr.len() > 18 || address.is_empty() || address.len() > 15 {
        return false;
    }
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    if prefix.is_empty() || prefix.bytes().any(|byte| !byte.is_ascii_digit()) {
        return false;
    }
    let Ok(network) = network.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(address) = address.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(network);
    network == (u32::from(address) & mask) && network == (network & mask)
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTransportIdentityHttpRequest {
    schema_version: u8,
    request_id: String,
    endpoints: Vec<RuntimeTransportEndpointHttpRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTransportEndpointHttpRequest {
    endpoint: String,
    server_cert_sha256: String,
    transport_preset: RuntimeTransportPresetHttp,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeTransportPresetHttp {
    Current,
    BbrV1,
    Aggressive,
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
    refresh_after_unix: i64,
    replayed: bool,
    access_grant: String,
}

#[derive(Debug, Serialize)]
struct RuntimeCapabilitiesResponse {
    api_version: &'static str,
    wire_protocol: &'static str,
    configuration_object: &'static str,
    configuration_media_type: &'static str,
    conditional_requests: [&'static str; 3],
    status_values: [&'static str; 3],
    refresh: RuntimeRefreshCapabilities,
}

#[derive(Debug, Serialize)]
struct RuntimeConfigurationHttpResponse {
    schema_version: u8,
    activation_phase: &'static str,
    projection_publication_id: Uuid,
    projection_id: Uuid,
    segment_id: Uuid,
    attachment_id: Uuid,
    segment_generation: u64,
    projection_generation: u64,
    projection_content_hash: String,
    route_signing_key_id: String,
    route_signing_public_key: String,
    segment_snapshot: String,
    site_projection: String,
    peer_projection_catalog: Vec<RuntimePeerProjectionHttpResponse>,
    compatibility_generations: Vec<RuntimeCompatibilityGenerationHttpResponse>,
    grant_verification_keys: Vec<RuntimeGrantVerificationKeyHttpResponse>,
}

#[derive(Debug, Serialize)]
struct RuntimeCompatibilityGenerationHttpResponse {
    segment_generation: u64,
    segment_content_hash: String,
    segment_snapshot: String,
    peer_projection_catalog: Vec<RuntimePeerProjectionHttpResponse>,
}

#[derive(Debug, Serialize)]
struct RuntimePeerProjectionHttpResponse {
    projection_id: Uuid,
    projection_generation: u64,
    projection_content_hash: String,
    site_projection: String,
}

fn runtime_peer_projection_http_response(
    projection: &RuntimePeerProjectionDelivery,
) -> RuntimePeerProjectionHttpResponse {
    RuntimePeerProjectionHttpResponse {
        projection_id: projection.projection_id,
        projection_generation: projection.projection_generation,
        projection_content_hash: hex(&projection.projection_content_hash),
        site_projection: encode_base64(projection.signed_projection_envelope.clone()),
    }
}

#[derive(Debug, Serialize)]
struct RuntimeGrantVerificationKeyHttpResponse {
    key_id: String,
    ed25519_public_key: String,
    issuer_id: Uuid,
    environment_id: Uuid,
}

#[derive(Debug, Serialize)]
struct RuntimeRefreshCapabilities {
    minimum_seconds: u64,
    recommended_seconds: u64,
    maximum_seconds: u64,
    jitter_percent: u64,
    wait_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfigurationStatusHttpRequest {
    projection_publication_id: Uuid,
    projection_content_hash: String,
    state: RuntimeConfigurationApplyStateHttp,
    error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTelemetryHttpRequest {
    schema_version: u8,
    boot_id: Uuid,
    sequence: u64,
    lifecycle: RuntimeLifecycleHttp,
    configured_peers: u32,
    active_peers: u32,
    required_route_owners: u32,
    ready_route_owners: u32,
    fail_open_required: bool,
    last_error_code: Option<String>,
    rtt_ms: Option<u32>,
    jitter_ms: Option<u32>,
    packet_loss_ppm: Option<u32>,
    rx_bps: Option<u64>,
    tx_bps: Option<u64>,
    reconnects: Option<u64>,
    path_changes: Option<u64>,
    #[serde(default)]
    paths: Vec<RuntimePathTelemetryHttpRequest>,
    #[serde(default)]
    local_networks: Option<Vec<RuntimeLocalNetworkTelemetryHttpRequest>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLocalNetworkTelemetryHttpRequest {
    network_id: String,
    interface_name: String,
    cidr: String,
    address: String,
    kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePathTelemetryHttpRequest {
    peer_attachment_id: Uuid,
    candidate_id: Option<Uuid>,
    path_kind: RuntimePathKindHttp,
    transport: String,
    connection_epoch: u64,
    rtt_ms: Option<u32>,
    jitter_ms: Option<u32>,
    packet_loss_ppm: Option<u32>,
    rx_bps: Option<u64>,
    tx_bps: Option<u64>,
    reconnects: u64,
    path_changes: u64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimePathKindHttp {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeLifecycleHttp {
    Starting,
    Active,
    Degraded,
    FailOpen,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeConfigurationApplyStateHttp {
    Prepared,
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
    InvalidRuntimeTelemetry,
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
            Self::InvalidRuntimeTelemetry => (StatusCode::BAD_REQUEST, "invalid_runtime_telemetry"),
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
