#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().with_env_filter("info").init();
    tracing::info!("cloud-worker started");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
