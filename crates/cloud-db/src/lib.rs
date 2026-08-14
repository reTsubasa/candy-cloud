use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};

pub mod accounting;
pub mod authorization;
pub mod control;
pub mod device_identity;
pub mod enrollment;
pub mod enrollment_completion;
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
