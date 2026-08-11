use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use cloud_core_module::{CoreModule, ModuleRequirements, VerifiedModuleSpec};
use cloud_db::sdwan::SdwanRepository;
use cloud_worker::{
    control_publisher::ControlRoutePublisher,
    generation_loop::{GenerationWorker, SegmentGenerationAdapter, SegmentGenerationPublisher},
};
use ed25519_dalek::SigningKey;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info")
        .init();
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = cloud_db::connect(&database_url).await?;
    let control = cloud_db::control::ControlRepository::new(pool.clone());
    control.readiness_check().await?;
    let owner_id = std::env::var("CLOUD_WORKER_ID")
        .unwrap_or_else(|_| format!("cloud-worker-{}", uuid::Uuid::now_v7()));
    let repository = cloud_db::control::GenerationJobRepository::new(pool.clone());
    let key_id = std::env::var("CANDY_ROUTE_SIGNING_KEY_ID")
        .context("CANDY_ROUTE_SIGNING_KEY_ID is required")?;
    let key_hex = std::env::var("CANDY_ROUTE_SIGNING_KEY_HEX")
        .context("CANDY_ROUTE_SIGNING_KEY_HEX is required")?;
    let signing_key = SigningKey::from_bytes(&decode_key(&key_hex)?);
    let core = load_core_module().context("load verified Candy Core Cloud module")?;
    tracing::info!(
        event = "core_module_ready",
        module_version = %core.capabilities().module_version,
        module_path = %core.canonical_path().display(),
        "Candy Core Cloud module is ready"
    );
    let publisher = ControlRoutePublisher::new(
        SdwanRepository::new(pool),
        key_id,
        signing_key,
        Arc::new(core),
    );
    anyhow::ensure!(publisher.ready(), "CANDY_ROUTE_SIGNING_KEY_ID is invalid");
    let adapter = SegmentGenerationAdapter { control, publisher };
    let worker = GenerationWorker::new(repository, adapter, owner_id, Duration::from_secs(60))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::select! {
        result = worker.run(Duration::from_secs(2), shutdown_rx) => result.map_err(Into::into),
        signal = tokio::signal::ctrl_c() => {
            signal?;
            let _ = shutdown_tx.send(true);
            Ok(())
        }
    }
}

fn load_core_module() -> anyhow::Result<CoreModule> {
    let root = PathBuf::from(required_env("CLOUD_CORE_MODULE_ROOT")?);
    let path = PathBuf::from(required_env("CLOUD_CORE_MODULE_PATH")?);
    let sha256 = parse_sha256_env("CLOUD_CORE_MODULE_SHA256")?;
    let owner_uid = required_env("CLOUD_CORE_MODULE_OWNER_UID")?
        .parse()
        .context("parse CLOUD_CORE_MODULE_OWNER_UID")?;
    CoreModule::load(
        &VerifiedModuleSpec::new(root, path, sha256, owner_uid),
        &ModuleRequirements {
            wire_protocol: Some("0.3".to_owned()),
            required_objects: [
                "route-envelope-v1",
                "segment-snapshot-v1",
                "site-projection-v1",
                "shared-hub-admission-v1",
                "mesh-membership-v1",
                "dynamic-route-snapshot-v1",
                "fabric-assignment-v1",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            ..ModuleRequirements::default()
        },
    )
    .map_err(Into::into)
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn parse_sha256_env(name: &str) -> anyhow::Result<[u8; 32]> {
    let value = required_env(name)?;
    anyhow::ensure!(
        value.len() == 64,
        "{name} must contain exactly 64 hexadecimal characters"
    );
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

fn hex_nibble(value: u8) -> anyhow::Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => anyhow::bail!("invalid hexadecimal digit in {value:?}"),
    }
}

fn decode_key(value: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    anyhow::ensure!(
        value.len() == 64,
        "CANDY_ROUTE_SIGNING_KEY_HEX must be 32 bytes"
    );
    let mut key = [0_u8; 32];
    for (index, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("CANDY_ROUTE_SIGNING_KEY_HEX is not hexadecimal"))?;
    }
    anyhow::ensure!(
        key != [0; 32],
        "CANDY_ROUTE_SIGNING_KEY_HEX must not be zero"
    );
    Ok(key)
}
