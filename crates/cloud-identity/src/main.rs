use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info")
        .init();
    let config = cloud_identity::IdentityConfig::from_env()?;
    let pool = cloud_db::connect(&config.database_url).await?;
    let repository = cloud_identity::IdentityRepository::new(pool);
    // Login and organization bootstrap do not depend on outbound email. Until
    // a transactional provider is wired in, verification and password-reset
    // requests fail closed instead of exposing a one-time credential.
    let delivery: Arc<dyn cloud_identity::EmailDelivery> =
        Arc::new(cloud_identity::UnconfiguredEmailDelivery);
    let state = cloud_identity::IdentityState::new(repository, &config, delivery)?;
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, issuer = %config.issuer, audience = %config.audience, "cloud-identity listening");
    axum::serve(listener, cloud_identity::build_app(state)).await?;
    Ok(())
}
