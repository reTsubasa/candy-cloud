use std::time::Duration;

use anyhow::Context;
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
    let publisher = ControlRoutePublisher::new(SdwanRepository::new(pool), key_id, signing_key);
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
