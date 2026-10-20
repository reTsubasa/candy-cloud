use std::str::FromStr;

use sqlx::{mysql::MySqlConnectOptions, MySqlPool};
use uuid::Uuid;

#[tokio::test]
async fn deployment_probe_is_read_only_and_rejects_dirty_or_incompatible_history() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let admin = cloud_db::connect(&url).await.unwrap();
    let database = format!("deploy_probe_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE `{database}`"))
        .execute(&admin)
        .await
        .unwrap();
    let options = MySqlConnectOptions::from_str(&url)
        .unwrap()
        .database(&database);
    let pool = MySqlPool::connect_with(options).await.unwrap();
    assert!(!cloud_db::schema_is_current(&pool).await.unwrap());
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tables, 0, "preflight must not initialize the schema");
    cloud_db::migrate(&pool).await.unwrap();
    assert!(cloud_db::schema_is_current(&pool).await.unwrap());
    let last: (i64, Vec<u8>) = sqlx::query_as(
        "SELECT version, checksum FROM _sqlx_migrations ORDER BY version DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET success = FALSE WHERE version = ?")
        .bind(last.0)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        cloud_db::schema_is_current(&pool).await,
        Err(sqlx::migrate::MigrateError::Dirty(_))
    ));
    sqlx::query("UPDATE _sqlx_migrations SET success = TRUE, checksum = ? WHERE version = ?")
        .bind(vec![0_u8; 48])
        .bind(last.0)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        cloud_db::schema_is_current(&pool).await,
        Err(sqlx::migrate::MigrateError::VersionMismatch(_))
    ));
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = ?")
        .bind(last.0)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!cloud_db::schema_is_current(&pool).await.unwrap());
    sqlx::query("INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (?, 'restored test history', TRUE, ?, 0)")
        .bind(last.0).bind(&last.1).execute(&pool).await.unwrap();
    assert!(cloud_db::schema_is_current(&pool).await.unwrap());
    sqlx::query("INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (?, 'future migration', TRUE, ?, 0)")
        .bind(last.0 + 1).bind(&last.1).execute(&pool).await.unwrap();
    assert!(matches!(
        cloud_db::schema_is_current(&pool).await,
        Err(sqlx::migrate::MigrateError::VersionMissing(_))
    ));
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = ?")
        .bind(last.0 + 1)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM _sqlx_migrations ORDER BY version LIMIT 1")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        cloud_db::schema_is_current(&pool).await,
        Err(sqlx::migrate::MigrateError::VersionMissing(_))
    ));
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE `{database}`"))
        .execute(&admin)
        .await
        .unwrap();
}
