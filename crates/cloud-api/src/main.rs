use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info")
        .init();
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = cloud_db::connect(&database_url).await?;
    let authenticator = cloud_api::auth::ManagementAuthenticator::from_ed25519_public_key_file(
        std::path::Path::new(&std::env::var("CLOUD_API_AUTH_PUBLIC_KEY_FILE")?),
        &std::env::var("CLOUD_API_AUTH_ISSUER")?,
        &std::env::var("CLOUD_API_AUTH_AUDIENCE")?,
    )?
    .with_identity_repository(cloud_db::identity::IdentityRepository::new(pool.clone()));
    let app = cloud_api::app_with_authentication_and_enrollment(
        cloud_db::control::ControlRepository::new(pool.clone()),
        cloud_db::enrollment::EnrollmentRepository::new(pool),
        authenticator,
    );
    let addr: SocketAddr = std::env::var("CLOUD_API_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "cloud-api listening");
    axum::serve(listener, app).await?;
    Ok(())
}
