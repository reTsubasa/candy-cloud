#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info")
        .init();
    let app =
        cloud_auth::runtime::build_app(cloud_auth::runtime::CloudAuthConfig::from_env()?).await?;
    let bind = std::env::var("CLOUD_AUTH_BIND").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
