#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let check_only = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [argument] if argument == "--check-schema" => true,
        _ => anyhow::bail!("usage: cloud-db-migrate [--check-schema]"),
    };
    let url = std::env::var("DATABASE_URL")?;
    let pool = cloud_db::connect(&url).await?;
    if check_only {
        if cloud_db::schema_is_current(&pool).await? {
            println!("schema_current");
            return Ok(());
        }
        println!("schema_change_required");
        std::process::exit(3);
    }
    cloud_db::migrate(&pool).await?;
    Ok(())
}
