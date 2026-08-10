use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, routing::get, Router};
use ed25519_dalek::SigningKey;

use crate::{
    certificates::DeviceCertificateIssuer,
    device_identity::DeviceIdentityAuthenticator,
    enrollment::EnrollmentCoordinator,
    grants::GrantSigner,
    issuance::IssuerConfig,
    keyring::load_signing_key,
    routes::{device_authenticated_app, enrollment_app},
    service::{DatabaseTenantAuthService, GrantIssuanceCoordinator},
};

#[derive(Clone)]
pub struct CloudAuthConfig {
    pub database_url: String,
    pub signing_key_path: PathBuf,
    pub signing_key_id: String,
    pub issuer_id: uuid::Uuid,
    pub environment_id: uuid::Uuid,
    pub device_ca_certificate_path: PathBuf,
    pub device_ca_key_path: PathBuf,
    pub device_ca_key_id: String,
    pub environment: String,
}

impl CloudAuthConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: required_env("DATABASE_URL")?,
            signing_key_path: PathBuf::from(required_env("CLOUD_SIGNING_KEY_FILE")?),
            signing_key_id: required_env("CLOUD_SIGNING_KEY_ID")?,
            issuer_id: parse_uuid_env("CLOUD_ISSUER_ID")?,
            environment_id: parse_uuid_env("CLOUD_ENVIRONMENT_ID")?,
            device_ca_certificate_path: PathBuf::from(required_env("CLOUD_DEVICE_CA_CERT_FILE")?),
            device_ca_key_path: PathBuf::from(required_env("CLOUD_DEVICE_CA_KEY_FILE")?),
            device_ca_key_id: required_env("CLOUD_DEVICE_CA_KEY_ID")?,
            environment: required_env("CLOUD_ENVIRONMENT")?,
        })
    }
}

struct ReadinessState {
    control: cloud_db::control::ControlRepository,
    config: CloudAuthConfig,
}

pub async fn build_app(config: CloudAuthConfig) -> Result<Router> {
    let pool = cloud_db::connect(&config.database_url)
        .await
        .context("connect cloud-auth database")?;
    let control = cloud_db::control::ControlRepository::new(pool.clone());
    control
        .readiness_check()
        .await
        .context("verify cloud-auth database schema")?;
    let grant_signer = load_grant_signer(&config)?;
    let certificate_issuer = load_device_ca(&config)?;
    let enrollment = enrollment_app(Arc::new(EnrollmentCoordinator::new(
        pool.clone(),
        certificate_issuer,
    )));
    let grant_service = Arc::new(DatabaseTenantAuthService::new(
        cloud_db::enrollment::EnrollmentRepository::new(pool.clone()),
        GrantIssuanceCoordinator::new(
            cloud_db::authorization::AuthorizationRepository::new(pool.clone()),
            cloud_db::repositories::GrantIssuanceRepository::new(pool.clone()),
            grant_signer,
            IssuerConfig {
                issuer_id: config.issuer_id,
                environment_id: config.environment_id,
            },
        ),
    ));
    let device_authenticator =
        DeviceIdentityAuthenticator::new(pool.clone(), config.environment.clone())
            .map_err(anyhow::Error::msg)?;
    let grants = device_authenticated_app(grant_service, device_authenticator);
    let readiness = Arc::new(ReadinessState { control, config });
    let health = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(readiness);
    Ok(enrollment.merge(grants).merge(health))
}

async fn live() -> &'static str {
    "ok"
}

async fn ready(State(state): State<Arc<ReadinessState>>) -> (StatusCode, &'static str) {
    if state.control.readiness_check().await.is_ok()
        && validate_grant_signing_key(&state.config).is_ok()
        && load_device_ca(&state.config).is_ok()
    {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "dependency unavailable")
    }
}

fn load_grant_signer(config: &CloudAuthConfig) -> Result<GrantSigner> {
    let bytes = load_signing_key(&config.signing_key_path).context("load Grant signing key")?;
    let seed: &[u8; 32] = bytes
        .expose()
        .try_into()
        .context("parse Grant signing key")?;
    if config.signing_key_id.is_empty() || config.signing_key_id.len() > 80 {
        anyhow::bail!("CLOUD_SIGNING_KEY_ID must be between 1 and 80 bytes");
    }
    Ok(GrantSigner::new(
        config.signing_key_id.clone(),
        SigningKey::from_bytes(seed),
    ))
}

fn validate_grant_signing_key(config: &CloudAuthConfig) -> Result<()> {
    load_grant_signer(config).map(|_| ())
}

fn load_device_ca(config: &CloudAuthConfig) -> Result<DeviceCertificateIssuer> {
    DeviceCertificateIssuer::from_files(
        config.device_ca_key_id.clone(),
        config.environment.clone(),
        &config.device_ca_certificate_path,
        &config.device_ca_key_path,
    )
    .context("load Device CA")
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn parse_uuid_env(name: &str) -> Result<uuid::Uuid> {
    let value = required_env(name)?;
    let parsed = uuid::Uuid::parse_str(&value).with_context(|| format!("parse {name}"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        anyhow::bail!("{name} must be a canonical non-zero UUID");
    }
    Ok(parsed)
}
