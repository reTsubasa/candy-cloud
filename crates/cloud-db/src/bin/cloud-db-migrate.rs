#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    let pool = cloud_db::connect(&url).await?;
    cloud_db::migrate(&pool).await?;
    Ok(())
}
