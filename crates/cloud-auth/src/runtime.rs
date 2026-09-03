use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, routing::get, Router};
use cloud_core_module::{CoreModule, ModuleRequirements, VerifiedModuleSpec};
use ed25519_dalek::SigningKey;

use crate::{
    certificates::DeviceCertificateIssuer,
    device_identity::DeviceIdentityAuthenticator,
    enrollment::EnrollmentCoordinator,
    grants::GrantSigner,
    issuance::IssuerConfig,
    keyring::load_signing_key,
    routes::{
        bootstrap_app, device_authenticated_app, device_authenticated_certificate_renewal_app,
        device_authenticated_runtime_app, enrollment_app, BootstrapHttpService,
    },
    service::{
        DatabaseRuntimeConfigurationService, DatabaseTenantAuthService, GrantIssuanceCoordinator,
    },
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
    pub core_module_root: PathBuf,
    pub core_module_path: PathBuf,
    pub core_module_sha256: [u8; 32],
    pub core_module_owner_uid: u32,
    pub route_signing_key_id: String,
    pub route_signing_public_key: [u8; 32],
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
            core_module_root: PathBuf::from(required_env("CLOUD_CORE_MODULE_ROOT")?),
            core_module_path: PathBuf::from(required_env("CLOUD_CORE_MODULE_PATH")?),
            core_module_sha256: parse_sha256_env("CLOUD_CORE_MODULE_SHA256")?,
            core_module_owner_uid: required_env("CLOUD_CORE_MODULE_OWNER_UID")?
                .parse()
                .context("parse CLOUD_CORE_MODULE_OWNER_UID")?,
            route_signing_key_id: required_env("CANDY_ROUTE_SIGNING_KEY_ID")?,
            route_signing_public_key: parse_sha256_env("CANDY_ROUTE_SIGNING_PUBLIC_KEY_HEX")?,
        })
    }
}

struct ReadinessState {
    control: cloud_db::control::ControlRepository,
    config: CloudAuthConfig,
    core_module_ready: bool,
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
    let (grant_signer, core_module_ready) = match load_grant_signer(&config) {
        Ok(signer) => (Some(signer), true),
        Err(error) => {
            tracing::error!(error = %error, event = "core_module_unavailable", "Core module unavailable; Grant issuance is fail-closed");
            (None, false)
        }
    };
    let certificate_issuer = Arc::new(load_device_ca(&config)?);
    let enrollment_repository = cloud_db::enrollment::EnrollmentRepository::new(pool.clone());
    let enrollment = enrollment_app(Arc::new(EnrollmentCoordinator::new(
        pool.clone(),
        certificate_issuer.clone(),
    )));
    let bootstrap_signing_key = load_signing_seed(&config)?;
    let grant_verification_key = crate::routes::RuntimeGrantVerificationKeyDelivery {
        key_id: config.signing_key_id.clone(),
        ed25519_public_key: bootstrap_signing_key.verifying_key().to_bytes(),
        issuer_id: config.issuer_id,
        environment_id: config.environment_id,
    };
    let bootstrap = bootstrap_app(BootstrapHttpService::new(
        enrollment_repository.clone(),
        bootstrap_signing_key,
        config.signing_key_id.clone(),
    ));
    let grant_service = Arc::new(DatabaseTenantAuthService::new(
        enrollment_repository,
        GrantIssuanceCoordinator::new_optional(
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
    let grants = device_authenticated_app(grant_service, device_authenticator.clone());
    let certificate_renewal = device_authenticated_certificate_renewal_app(
        Arc::new(
            crate::certificate_renewal::CertificateRenewalCoordinator::new(
                pool.clone(),
                certificate_issuer,
            ),
        ),
        device_authenticator.clone(),
    );
    let runtime_configuration = device_authenticated_runtime_app(
        Arc::new(DatabaseRuntimeConfigurationService::new(
            cloud_db::sdwan::SdwanRepository::new(pool.clone()),
            cloud_db::control::ControlRepository::new(pool.clone()),
            config.route_signing_key_id.clone(),
            config.route_signing_public_key,
            vec![grant_verification_key],
        )),
        device_authenticator,
    );
    let readiness = Arc::new(ReadinessState {
        control,
        config,
        core_module_ready,
    });
    let health = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(readiness);
    Ok(bootstrap
        .merge(enrollment)
        .merge(grants)
        .merge(certificate_renewal)
        .merge(runtime_configuration)
        .merge(health))
}

async fn live() -> &'static str {
    "ok"
}

async fn ready(State(state): State<Arc<ReadinessState>>) -> (StatusCode, &'static str) {
    if state.control.readiness_check().await.is_ok()
        && state.core_module_ready
        && validate_grant_signing_key(&state.config).is_ok()
        && load_device_ca(&state.config).is_ok()
    {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "dependency unavailable")
    }
}

fn load_grant_signer(config: &CloudAuthConfig) -> Result<GrantSigner> {
    let signing_key = load_signing_seed(config)?;
    if config.signing_key_id.is_empty() || config.signing_key_id.len() > 64 {
        anyhow::bail!("CLOUD_SIGNING_KEY_ID must be between 1 and 64 bytes");
    }
    let module = Arc::new(
        CoreModule::load(
            &VerifiedModuleSpec::new(
                config.core_module_root.clone(),
                config.core_module_path.clone(),
                config.core_module_sha256,
                config.core_module_owner_uid,
            ),
            &ModuleRequirements {
                wire_protocol: Some("0.3".to_owned()),
                required_objects: ["grant-payload-v1", "grant-envelope-v1"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                ..ModuleRequirements::default()
            },
        )
        .context("load verified Candy Core Cloud module")?,
    );
    Ok(GrantSigner::new(
        config.signing_key_id.clone(),
        signing_key,
        module,
    ))
}

fn load_signing_seed(config: &CloudAuthConfig) -> Result<SigningKey> {
    let bytes = load_signing_key(&config.signing_key_path).context("load Cloud signing key")?;
    let seed: &[u8; 32] = bytes
        .expose()
        .try_into()
        .context("parse Cloud signing key")?;
    Ok(SigningKey::from_bytes(seed))
}

fn validate_grant_signing_key(config: &CloudAuthConfig) -> Result<()> {
    let bytes = load_signing_key(&config.signing_key_path).context("load Grant signing key")?;
    let _: &[u8; 32] = bytes
        .expose()
        .try_into()
        .context("parse Grant signing key")?;
    if config.signing_key_id.is_empty() || config.signing_key_id.len() > 64 {
        anyhow::bail!("CLOUD_SIGNING_KEY_ID must be between 1 and 64 bytes");
    }
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

fn parse_uuid_env(name: &str) -> Result<uuid::Uuid> {
    let value = required_env(name)?;
    let parsed = uuid::Uuid::parse_str(&value).with_context(|| format!("parse {name}"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        anyhow::bail!("{name} must be a canonical non-zero UUID");
    }
    Ok(parsed)
}

fn parse_sha256_env(name: &str) -> Result<[u8; 32]> {
    let value = required_env(name)?;
    if value.len() != 64 {
        anyhow::bail!("{name} must contain exactly 64 hexadecimal characters");
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly 64 hexadecimal characters"))
}

fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => anyhow::bail!("invalid hexadecimal digit in {value:?}"),
    }
}
