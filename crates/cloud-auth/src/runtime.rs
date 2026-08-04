use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, routing::get, Router};
use ed25519_dalek::SigningKey;

use crate::{
    certificates::DeviceCertificateIssuer, enrollment::EnrollmentCoordinator,
    keyring::load_signing_key, routes::enrollment_app,
};

#[derive(Clone)]
pub struct CloudAuthConfig {
    pub database_url: String,
    pub signing_key_path: PathBuf,
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
            device_ca_certificate_path: PathBuf::from(required_env("CLOUD_DEVICE_CA_CERT_FILE")?),
            device_ca_key_path: PathBuf::from(required_env("CLOUD_DEVICE_CA_KEY_FILE")?),
            device_ca_key_id: required_env("CLOUD_DEVICE_CA_KEY_ID")?,
            environment: required_env("CLOUD_ENVIRONMENT")?,
        })
    }
}

struct ReadinessState {
    pool: cloud_db::DbPool,
    config: CloudAuthConfig,
}

pub async fn build_app(config: CloudAuthConfig) -> Result<Router> {
    let pool = cloud_db::connect(&config.database_url)
        .await
        .context("connect cloud-auth database")?;
    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .context("verify cloud-auth database")?;
    validate_grant_signing_key(&config)?;
    let certificate_issuer = load_device_ca(&config)?;
    let enrollment = enrollment_app(Arc::new(EnrollmentCoordinator::new(
        pool.clone(),
        certificate_issuer,
    )));
    let readiness = Arc::new(ReadinessState { pool, config });
    let health = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(readiness);
    Ok(enrollment.merge(health))
}

async fn live() -> &'static str {
    "ok"
}

async fn ready(State(state): State<Arc<ReadinessState>>) -> (StatusCode, &'static str) {
    let database_ready = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    if database_ready
        && validate_grant_signing_key(&state.config).is_ok()
        && load_device_ca(&state.config).is_ok()
    {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "dependency unavailable")
    }
}

fn validate_grant_signing_key(config: &CloudAuthConfig) -> Result<()> {
    let bytes = load_signing_key(&config.signing_key_path).context("load Grant signing key")?;
    let seed: &[u8; 32] = bytes
        .expose()
        .try_into()
        .context("parse Grant signing key")?;
    let _signing_key = SigningKey::from_bytes(seed);
    Ok(())
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
