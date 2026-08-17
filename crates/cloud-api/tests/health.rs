use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn liveness_does_not_depend_on_database() {
    let response = cloud_api::app()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "ok"
    );
}

#[tokio::test]
async fn readiness_fails_closed_without_database_configuration() {
    std::env::remove_var("DATABASE_URL");
    let response = cloud_api::app()
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn version_is_available_without_management_authentication() {
    let response = cloud_api::app()
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let version: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(version["schema_version"], 1);
    assert_eq!(version["cloud_version"], env!("CARGO_PKG_VERSION"));
    assert!(version["cloud_revision"].is_string());
    assert!(version["core_version"].is_string());
}
