use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().with_env_filter("info").init();
    let app = cloud_api::app();
    let addr: SocketAddr = std::env::var("CLOUD_API_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "cloud-api listening");
    axum::serve(listener, app).await?;
    Ok(())
}
