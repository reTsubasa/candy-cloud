use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub use cloud_db::identity::{
    ActionTokenPurpose, IdentityRepository, IdentityRepositoryError, MembershipRole,
    RegistrationWrite, SessionRecord,
};

const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 1024;

#[derive(Debug, Clone)]
pub struct IdentityConfig {
    pub database_url: String,
    pub signing_key_file: std::path::PathBuf,
    pub verification_key_file: std::path::PathBuf,
    pub signing_key_id: String,
    pub issuer: String,
    pub audience: String,
    pub bind: String,
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub verification_ttl: Duration,
    pub reset_ttl: Duration,
}

impl IdentityConfig {
    pub fn from_env() -> Result<Self> {
        let seconds = |name: &str, default: u64, max: u64| -> Result<Duration> {
            let value = std::env::var(name)
                .unwrap_or_else(|_| default.to_string())
                .parse::<u64>()
                .with_context(|| format!("parse {name}"))?;
            if value == 0 || value > max {
                anyhow::bail!("{name} is outside the allowed range");
            }
            Ok(Duration::from_secs(value))
        };
        let required =
            |name: &str| std::env::var(name).with_context(|| format!("{name} is required"));
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            signing_key_file: std::path::PathBuf::from(required(
                "CLOUD_IDENTITY_SIGNING_KEY_FILE",
            )?),
            verification_key_file: std::path::PathBuf::from(required(
                "CLOUD_IDENTITY_VERIFICATION_KEY_FILE",
            )?),
            signing_key_id: required("CLOUD_IDENTITY_SIGNING_KEY_ID")?,
            issuer: required("CLOUD_IDENTITY_ISSUER")?,
            audience: required("CLOUD_IDENTITY_AUDIENCE")?,
            bind: std::env::var("CLOUD_IDENTITY_BIND").unwrap_or_else(|_| "0.0.0.0:8082".into()),
            access_ttl: seconds("CLOUD_IDENTITY_ACCESS_TTL_SECONDS", 900, 3600)?,
            refresh_ttl: seconds("CLOUD_IDENTITY_REFRESH_TTL_SECONDS", 2_592_000, 31_536_000)?,
            verification_ttl: seconds("CLOUD_IDENTITY_VERIFICATION_TTL_SECONDS", 86_400, 604_800)?,
            reset_ttl: seconds("CLOUD_IDENTITY_RESET_TTL_SECONDS", 900, 3600)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub purpose: ActionTokenPurpose,
    pub recipient: String,
    pub token: String,
}

#[async_trait::async_trait]
pub trait EmailDelivery: Send + Sync {
    async fn send(&self, message: EmailMessage) -> Result<()>;
}

/// Production delivery must be supplied by the deployment. It intentionally fails closed.
pub struct UnconfiguredEmailDelivery;

#[async_trait::async_trait]
impl EmailDelivery for UnconfiguredEmailDelivery {
    async fn send(&self, _message: EmailMessage) -> Result<()> {
        anyhow::bail!("identity email delivery is not configured")
    }
}

#[derive(Clone)]
pub struct IdentityState {
    repository: IdentityRepository,
    signing_key: EncodingKey,
    verification_key: DecodingKey,
    signing_key_id: String,
    issuer: String,
    audience: String,
    access_ttl: Duration,
    refresh_ttl: Duration,
    verification_ttl: Duration,
    reset_ttl: Duration,
    delivery: Arc<dyn EmailDelivery>,
}

impl IdentityState {
    pub fn new(
        repository: IdentityRepository,
        config: &IdentityConfig,
        delivery: Arc<dyn EmailDelivery>,
    ) -> Result<Self> {
        let signing_pem =
            std::fs::read(&config.signing_key_file).context("read identity signing key")?;
        let verification_pem = std::fs::read(&config.verification_key_file)
            .context("read identity verification key")?;
        if config.signing_key_id.is_empty()
            || config.signing_key_id.len() > 64
            || config.issuer.is_empty()
            || config.audience.is_empty()
        {
            anyhow::bail!(
                "identity signing key id, issuer, and audience must be non-empty and bounded"
            );
        }
        Ok(Self {
            repository,
            signing_key: EncodingKey::from_ed_pem(&signing_pem)?,
            verification_key: DecodingKey::from_ed_pem(&verification_pem)?,
            signing_key_id: config.signing_key_id.clone(),
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            access_ttl: config.access_ttl,
            refresh_ttl: config.refresh_ttl,
            verification_ttl: config.verification_ttl,
            reset_ttl: config.reset_ttl,
            delivery,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_with_keys(
        repository: IdentityRepository,
        signing_key: EncodingKey,
        verification_key: DecodingKey,
        delivery: Arc<dyn EmailDelivery>,
    ) -> Self {
        Self {
            repository,
            signing_key,
            verification_key,
            signing_key_id: "test-key".into(),
            issuer: "https://identity.test".into(),
            audience: "candy-cloud-management".into(),
            access_ttl: Duration::from_secs(900),
            refresh_ttl: Duration::from_secs(2_592_000),
            verification_ttl: Duration::from_secs(86_400),
            reset_ttl: Duration::from_secs(900),
            delivery,
        }
    }
}

pub fn build_app(state: IdentityState) -> Router {
    let state = Arc::new(state);
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(ready))
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/refresh", post(refresh))
        .route("/v1/auth/verify-email", post(verify_email))
        .route(
            "/v1/auth/request-email-verification",
            post(request_email_verification),
        )
        .route(
            "/v1/auth/request-password-reset",
            post(request_password_reset),
        )
        .route("/v1/auth/reset-password", post(reset_password))
        .merge(authenticated_routes(state.clone()))
        .with_state(state)
}

fn authenticated_routes(state: Arc<IdentityState>) -> Router<Arc<IdentityState>> {
    Router::new()
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/sessions", get(sessions))
        .route(
            "/v1/auth/sessions/{id}",
            axum::routing::delete(revoke_session),
        )
        .route_layer(middleware::from_fn_with_state(state, require_access_token))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    email: String,
    password: String,
    display_name: String,
    organization_name: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    email: String,
    password: String,
    device_label: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    refresh_token: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    email: String,
    password: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionTokenRequest {
    token: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordResetRequest {
    email: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetPasswordRequest {
    token: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    refresh_token: String,
    user: UserResponse,
    membership: MembershipResponse,
}
#[derive(Debug, Serialize)]
struct UserResponse {
    id: Uuid,
    email: String,
    display_name: String,
    email_verified: bool,
}
#[derive(Debug, Serialize)]
struct MembershipResponse {
    organization_id: Uuid,
    organization_name: String,
    tenant_id: Uuid,
    tenant_name: String,
    role: &'static str,
}
#[derive(Debug, Serialize)]
struct MessageResponse {
    message: &'static str,
}
#[derive(Debug, Serialize)]
struct SessionResponse {
    id: Uuid,
    organization_id: Uuid,
    tenant_id: Uuid,
    role: &'static str,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
struct AccessContext {
    user_id: Uuid,
    session_id: Uuid,
}

impl<S> FromRequestParts<S> for AccessContext
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

async fn register(
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), ApiError> {
    let email = canonical_email(&req.email)?;
    validate_password(&req.password)?;
    if req.organization_name.trim().is_empty()
        || req.organization_name.len() > 200
        || req.display_name.trim().is_empty()
        || req.display_name.len() > 200
    {
        return Err(ApiError::InvalidRequest);
    }
    let user_id = Uuid::now_v7();
    let org_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let hash = hash_password(&req.password)?;
    state
        .repository
        .register_user_and_workspace(&RegistrationWrite {
            user_id,
            email: email.clone(),
            display_name: req.display_name.trim().into(),
            password_hash: hash,
            organization_id: org_id,
            organization_name: req.organization_name.trim().into(),
            tenant_id,
        })
        .await
        .map_err(ApiError::Repository)?;
    let membership = state
        .repository
        .primary_membership(user_id)
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::Unavailable)?;
    let user = state
        .repository
        .find_user_by_email(&email)
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::Unavailable)?;
    let response = issue_session(&state, user, membership, None).await?;
    Ok((StatusCode::CREATED, response))
}

async fn ready(State(state): State<Arc<IdentityState>>) -> Result<&'static str, ApiError> {
    state
        .repository
        .readiness_check()
        .await
        .map_err(ApiError::Repository)?;
    Ok("ready")
}

async fn login(
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let email = canonical_email(&req.email)?;
    validate_password(&req.password)?;
    let user = state
        .repository
        .find_user_by_email(&email)
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::InvalidCredentials)?;
    if !verify_password(&user.password_hash, &req.password) {
        return Err(ApiError::InvalidCredentials);
    }
    if !user.verified || !user.active {
        return Err(ApiError::EmailNotVerified);
    }
    let membership = state
        .repository
        .primary_membership(user.id)
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::Unavailable)?;
    issue_session(&state, user, membership, req.device_label.as_deref()).await
}

async fn refresh(
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    if req.refresh_token.len() < 32 || req.refresh_token.len() > 256 {
        return Err(ApiError::InvalidCredentials);
    }
    let replacement = random_token();
    let now = Utc::now();
    let session = state
        .repository
        .rotate_refresh_token(
            &hash_token(&req.refresh_token),
            Uuid::now_v7(),
            &hash_token(&replacement),
            now + chrono_duration(state.refresh_ttl),
            now,
        )
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::InvalidCredentials)?;
    issue_rotated_session(&state, session, replacement).await
}

async fn verify_email(
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<ActionTokenRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let user_id = state
        .repository
        .consume_action_token(
            ActionTokenPurpose::VerifyEmail,
            &hash_token(&req.token),
            Utc::now(),
        )
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::InvalidToken)?;
    state
        .repository
        .mark_email_verified(user_id, Utc::now())
        .await
        .map_err(ApiError::Repository)?;
    Ok(Json(MessageResponse {
        message: "email_verified",
    }))
}

async fn request_email_verification(
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<CredentialRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let email = canonical_email(&req.email)?;
    validate_password(&req.password)?;
    let user = state
        .repository
        .find_user_by_email(&email)
        .await
        .map_err(ApiError::Repository)?;
    let Some(user) = user else {
        return Ok(Json(MessageResponse {
            message: "if_account_exists_email_sent",
        }));
    };
    if !verify_password(&user.password_hash, &req.password) || user.verified {
        return Ok(Json(MessageResponse {
            message: "if_account_exists_email_sent",
        }));
    }
    send_action_token(
        &state,
        user.id,
        ActionTokenPurpose::VerifyEmail,
        email,
        state.verification_ttl,
    )
    .await?;
    Ok(Json(MessageResponse {
        message: "if_account_exists_email_sent",
    }))
}

async fn request_password_reset(
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let email = canonical_email(&req.email)?;
    if let Some(user) = state
        .repository
        .find_user_by_email(&email)
        .await
        .map_err(ApiError::Repository)?
    {
        send_action_token(
            &state,
            user.id,
            ActionTokenPurpose::ResetPassword,
            email,
            state.reset_ttl,
        )
        .await?;
    }
    Ok(Json(MessageResponse {
        message: "if_account_exists_email_sent",
    }))
}

async fn reset_password(
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    validate_password(&req.password)?;
    let user_id = state
        .repository
        .consume_action_token(
            ActionTokenPurpose::ResetPassword,
            &hash_token(&req.token),
            Utc::now(),
        )
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::InvalidToken)?;
    state
        .repository
        .update_password_and_revoke_sessions(user_id, &hash_password(&req.password)?, Utc::now())
        .await
        .map_err(ApiError::Repository)?;
    Ok(Json(MessageResponse {
        message: "password_updated",
    }))
}

async fn logout(
    State(state): State<Arc<IdentityState>>,
    AccessContext { session_id, .. }: AccessContext,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .repository
        .revoke_current_session(session_id, Utc::now())
        .await
        .map_err(ApiError::Repository)?;
    Ok(Json(MessageResponse {
        message: "signed_out",
    }))
}

async fn sessions(
    State(state): State<Arc<IdentityState>>,
    AccessContext { user_id, .. }: AccessContext,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let records = state
        .repository
        .list_sessions(user_id, Utc::now())
        .await
        .map_err(ApiError::Repository)?;
    Ok(Json(records.into_iter().map(session_response).collect()))
}

async fn revoke_session(
    State(state): State<Arc<IdentityState>>,
    AccessContext { user_id, .. }: AccessContext,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if state
        .repository
        .revoke_session(user_id, id, Utc::now())
        .await
        .map_err(ApiError::Repository)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

async fn require_access_token(
    State(state): State<Arc<IdentityState>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, ApiError> {
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthenticated)?;
    let claims = decode_access_claims(&state, token).ok_or(ApiError::Unauthenticated)?;
    let role = parse_role(&claims.role).ok_or(ApiError::Unauthenticated)?;
    let active = state
        .repository
        .session_is_active(
            claims.sid,
            claims.sub,
            claims.organization_id,
            claims.tenant_id,
            role,
            Utc::now(),
        )
        .await
        .map_err(ApiError::Repository)?;
    if !active {
        return Err(ApiError::Unauthenticated);
    }
    request.extensions_mut().insert(AccessContext {
        user_id: claims.sub,
        session_id: claims.sid,
    });
    Ok(next.run(request).await)
}

async fn issue_session(
    state: &IdentityState,
    user: cloud_db::identity::HumanUser,
    membership: cloud_db::identity::Membership,
    device_label: Option<&str>,
) -> Result<Json<AuthResponse>, ApiError> {
    let session = SessionRecord {
        id: Uuid::now_v7(),
        family_id: Uuid::now_v7(),
        user_id: user.id,
        organization_id: membership.organization_id,
        tenant_id: membership.tenant_id,
        role: membership.role,
        expires_at: Utc::now() + chrono_duration(state.refresh_ttl),
        revoked_at: None,
    };
    let refresh = random_token();
    state
        .repository
        .create_session(
            &session,
            Uuid::now_v7(),
            &hash_token(&refresh),
            session.expires_at,
            device_label,
        )
        .await
        .map_err(ApiError::Repository)?;
    auth_response(state, &session, refresh, &user, &membership)
}

async fn issue_rotated_session(
    state: &IdentityState,
    session: SessionRecord,
    refresh: String,
) -> Result<Json<AuthResponse>, ApiError> {
    let user = state
        .repository
        .find_user_by_session_id(session.id)
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::Unauthenticated)?;
    let membership = state
        .repository
        .primary_membership(session.user_id)
        .await
        .map_err(ApiError::Repository)?
        .ok_or(ApiError::Unavailable)?;
    auth_response(state, &session, refresh, &user, &membership)
}

fn auth_response(
    state: &IdentityState,
    session: &SessionRecord,
    refresh: String,
    user: &cloud_db::identity::HumanUser,
    membership: &cloud_db::identity::Membership,
) -> Result<Json<AuthResponse>, ApiError> {
    let now = Utc::now();
    let exp = now + chrono_duration(state.access_ttl);
    let claims = AccessClaims {
        sub: session.user_id,
        sid: session.id,
        organization_id: session.organization_id,
        tenant_id: session.tenant_id,
        role: role_string(session.role).into(),
        iss: state.issuer.clone(),
        aud: state.audience.clone(),
        exp: exp.timestamp() as u64,
        nbf: now.timestamp() as u64,
        iat: now.timestamp() as u64,
        jti: Uuid::now_v7().to_string(),
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(state.signing_key_id.clone());
    let access = encode(&header, &claims, &state.signing_key).map_err(|_| ApiError::Unavailable)?;
    Ok(Json(AuthResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: state.access_ttl.as_secs(),
        refresh_token: refresh,
        user: UserResponse {
            id: user.id,
            email: user.email.clone(),
            display_name: user.display_name.clone(),
            email_verified: user.verified,
        },
        membership: MembershipResponse {
            organization_id: membership.organization_id,
            organization_name: membership.organization_name.clone(),
            tenant_id: membership.tenant_id,
            tenant_name: membership.tenant_name.clone(),
            role: role_string(membership.role),
        },
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessClaims {
    sub: Uuid,
    sid: Uuid,
    organization_id: Uuid,
    tenant_id: Uuid,
    role: String,
    iss: String,
    aud: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: String,
}
fn decode_access_claims(state: &IdentityState, token: &str) -> Option<AccessClaims> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[&state.issuer]);
    validation.set_audience(&[&state.audience]);
    validation.validate_nbf = true;
    decode::<AccessClaims>(token, &state.verification_key, &validation)
        .ok()
        .map(|data| data.claims)
}
fn session_response(record: SessionRecord) -> SessionResponse {
    SessionResponse {
        id: record.id,
        organization_id: record.organization_id,
        tenant_id: record.tenant_id,
        role: role_string(record.role),
        expires_at: record.expires_at,
        revoked_at: record.revoked_at,
    }
}
fn role_string(role: MembershipRole) -> &'static str {
    match role {
        MembershipRole::OrganizationOwner => "ORGANIZATION_OWNER",
        MembershipRole::TenantAdmin => "TENANT_ADMIN",
        MembershipRole::Operator => "OPERATOR",
        MembershipRole::BillingViewer => "BILLING_VIEWER",
        MembershipRole::Auditor => "AUDITOR",
    }
}

fn parse_role(value: &str) -> Option<MembershipRole> {
    MembershipRole::parse(value).ok()
}
fn canonical_email(value: &str) -> Result<String, ApiError> {
    let email = value.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > 254 || !email.contains('@') || email.contains(['\r', '\n'])
    {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(email)
    }
}
fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.len() < MIN_PASSWORD_LEN || password.len() > MAX_PASSWORD_LEN {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(())
    }
}
fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::Unavailable)
}
fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}
fn chrono_duration(value: Duration) -> ChronoDuration {
    ChronoDuration::from_std(value).expect("bounded identity duration")
}

async fn send_action_token(
    state: &IdentityState,
    user_id: Uuid,
    purpose: ActionTokenPurpose,
    recipient: String,
    ttl: Duration,
) -> Result<(), ApiError> {
    let token = random_token();
    state
        .repository
        .create_action_token(
            Uuid::now_v7(),
            user_id,
            purpose,
            &hash_token(&token),
            Utc::now() + chrono_duration(ttl),
        )
        .await
        .map_err(ApiError::Repository)?;
    state
        .delivery
        .send(EmailMessage {
            purpose,
            recipient,
            token,
        })
        .await
        .map_err(|error| {
            tracing::error!(event = "identity_email_delivery_failed", error = %error);
            ApiError::Unavailable
        })
}

#[derive(Debug, Serialize)]
struct Problem {
    code: &'static str,
}
#[derive(Debug)]
pub enum ApiError {
    Unauthenticated,
    InvalidCredentials,
    EmailNotVerified,
    InvalidToken,
    InvalidRequest,
    NotFound,
    Unavailable,
    Repository(IdentityRepositoryError),
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::EmailNotVerified => (StatusCode::FORBIDDEN, "email_not_verified"),
            Self::InvalidToken => (StatusCode::BAD_REQUEST, "invalid_token"),
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Unavailable | Self::Repository(IdentityRepositoryError::Database(_)) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
            Self::Repository(IdentityRepositoryError::Conflict) => {
                (StatusCode::CONFLICT, "conflict")
            }
            Self::Repository(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        };
        (status, Json(Problem { code })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingEmailDelivery(std::sync::Mutex<Vec<EmailMessage>>);

    #[async_trait::async_trait]
    impl EmailDelivery for RecordingEmailDelivery {
        async fn send(&self, message: EmailMessage) -> Result<()> {
            self.0.lock().expect("test mutex").push(message);
            Ok(())
        }
    }
    #[test]
    fn password_hash_is_argon2id_and_verifies() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(&hash, "correct horse battery staple"));
        assert!(!verify_password(&hash, "wrong password"));
    }
    #[test]
    fn opaque_token_is_never_stored_as_digest() {
        let token = random_token();
        assert_ne!(token.as_bytes(), hash_token(&token));
    }

    #[tokio::test]
    async fn token_claim_verification_rejects_wrong_issuer_and_audience() {
        const PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGrD/e7uKYqSY4twDEsRfMMuLSrODf14dpTiTK6K1YI0
-----END PRIVATE KEY-----
"#;
        const PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2+Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8=
-----END PUBLIC KEY-----
"#;
        let pool = sqlx::MySqlPool::connect_lazy("mysql://unused:unused@127.0.0.1/unused").unwrap();
        let state = IdentityState::test_with_keys(
            IdentityRepository::new(pool),
            EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
            DecodingKey::from_ed_pem(PUBLIC_KEY).unwrap(),
            Arc::new(RecordingEmailDelivery::default()),
        );
        let claims = AccessClaims {
            sub: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            role: "ORGANIZATION_OWNER".into(),
            iss: "wrong".into(),
            aud: "wrong".into(),
            exp: (Utc::now() + ChronoDuration::minutes(5)).timestamp() as u64,
            nbf: Utc::now().timestamp() as u64,
            iat: Utc::now().timestamp() as u64,
            jti: Uuid::new_v4().to_string(),
        };
        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &state.signing_key).unwrap();
        assert!(decode_access_claims(&state, &token).is_none());
    }
}
