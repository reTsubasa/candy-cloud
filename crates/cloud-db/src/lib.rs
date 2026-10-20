use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};

pub mod accounting;
pub mod authorization;
pub mod certificate_renewal;
pub mod client_access;
pub mod client_assignment_lease;
pub mod client_control;
pub mod client_projection;
pub mod client_routing;
pub mod client_settings;
pub mod control;
pub mod device_identity;
pub mod enrollment;
pub mod enrollment_completion;
pub mod geo_provider;
pub mod identity;
pub mod repositories;
pub mod sdwan;

pub use repositories::RepositoryError;

pub type DbPool = Pool<MySql>;

pub async fn connect(database_url: &str) -> Result<DbPool, sqlx::Error> {
    MySqlPoolOptions::new()
        .max_connections(10)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
}

pub async fn migrate(pool: &DbPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// Read-only deployment gate. Rolling replacement is safe only when the new
/// executable embeds exactly the schema already installed in the database.
pub async fn schema_is_current(pool: &DbPool) -> Result<bool, sqlx::migrate::MigrateError> {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '_sqlx_migrations'",
    ).fetch_one(pool).await?;
    if exists == 0 {
        return Ok(false);
    }
    let installed: Vec<(i64, bool, Vec<u8>)> =
        sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await?;
    let migrator = sqlx::migrate!("./migrations");
    let expected: Vec<_> = migrator
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .collect();
    for (index, (version, success, checksum)) in installed.iter().enumerate() {
        if !success {
            return Err(sqlx::migrate::MigrateError::Dirty(*version));
        }
        let Some(migration) = expected.get(index) else {
            return Err(sqlx::migrate::MigrateError::VersionMissing(*version));
        };
        if *version != migration.version {
            return Err(sqlx::migrate::MigrateError::VersionMissing(*version));
        }
        if checksum.as_slice() != migration.checksum.as_ref() {
            return Err(sqlx::migrate::MigrateError::VersionMismatch(*version));
        }
    }
    Ok(installed.len() == expected.len())
}
