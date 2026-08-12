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
    let delivery: Arc<dyn cloud_identity::EmailDelivery> =
        match std::env::var("CLOUD_IDENTITY_EMAIL_WEBHOOK_URL") {
            Ok(url) => Arc::new(cloud_identity::WebhookEmailDelivery::new(
                url,
                std::env::var("CLOUD_IDENTITY_EMAIL_WEBHOOK_AUTHORIZATION").ok(),
            )?),
            Err(_) if config.environment != "production" => {
                Arc::new(cloud_identity::UnconfiguredEmailDelivery)
            }
            Err(_) => anyhow::bail!("CLOUD_IDENTITY_EMAIL_WEBHOOK_URL is required in production"),
        };
    let state = cloud_identity::IdentityState::new(repository, &config, delivery)?;
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, issuer = %config.issuer, audience = %config.audience, "cloud-identity listening");
    axum::serve(listener, cloud_identity::build_app(state)).await?;
    Ok(())
}
