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
    // Terminal Client Grant signing uses its own trust domain. A missing or
    // unreadable key is not fatal: the management plane still starts and the
    // terminal Grant route answers 503 instead of signing with the wrong key.
    let client_grant = client_grant_signer();
    if client_grant.is_none() {
        tracing::warn!(
            "terminal client grant signing is disabled; set CLIENT_GRANT_SIGNING_KEY_FILE and CLIENT_GRANT_SIGNING_KEY_ID"
        );
    }
    let app = cloud_api::app_with_authentication_and_terminal_client_plane(
        cloud_db::control::ControlRepository::new(pool.clone()),
        cloud_db::enrollment::EnrollmentRepository::new(pool.clone()),
        Some(cloud_db::client_access::ClientAccessPolicyRepository::new(
            pool.clone(),
        )),
        Some(cloud_db::client_control::ClientControlRepository::new(
            pool.clone(),
        )),
        Some(cloud_db::client_routing::ClientNodeRepository::new(
            pool.clone(),
        )),
        client_grant,
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

fn client_grant_signer() -> Option<cloud_client_grant::ClientGrantSigner> {
    let path = std::env::var("CLIENT_GRANT_SIGNING_KEY_FILE").ok()?;
    let key_id = std::env::var("CLIENT_GRANT_SIGNING_KEY_ID").ok()?;
    match cloud_client_grant::ClientGrantSigner::from_key_file(
        std::path::Path::new(&path),
        key_id,
    ) {
        Ok(signer) => Some(signer),
        Err(error) => {
            tracing::error!(%error, "failed to load terminal client grant signing key");
            None
        }
    }
}
