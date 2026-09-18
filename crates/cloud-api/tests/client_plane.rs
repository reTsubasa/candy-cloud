//! Route-level guarantees for the terminal client control plane.
//!
//! Every test here is written so it must fail *before* storage is touched. The
//! repositories are built on `connect_lazy` to a deliberately invalid URL, so a
//! test that reaches MySQL does not fail slowly or subtly: it fails loudly. That
//! is the point: these tests pin the ordering property that Cloud rejects a bad
//! caller without depending on a database being up, which is also what keeps a
//! storage outage from being reported as a client error.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

use cloud_api::domain::{Role, TenantContext};
use cloud_api::management::AuthenticatedPrincipal;
use cloud_api::{app, app_with_principal, app_with_terminal_client_plane_and_principal};
use cloud_client_grant::ClientGrantSigner;
use cloud_db::DbPool;

const SIGNING_KEY_ID: &str = "cloud-client-grant-test";

fn lazy_pool() -> DbPool {
    sqlx::MySqlPool::connect_lazy("mysql://invalid/invalid").unwrap()
}

fn lazy_repository() -> cloud_db::control::ControlRepository {
    cloud_db::control::ControlRepository::new(lazy_pool())
}

fn principal(tenant_id: Uuid, actor_id: String) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        actor_id,
        context: TenantContext {
            organization_id: Uuid::new_v4(),
            tenant_id,
            role: Role::TenantAdmin,
        },
    }
}

fn signer() -> ClientGrantSigner {
    ClientGrantSigner::new(SIGNING_KEY_ID, SigningKey::from_bytes(&[9_u8; 32])).unwrap()
}

/// The full terminal plane with a lazy (never-connected) database, so anything
/// that passes validation fails on storage instead of silently succeeding.
fn terminal_app(principal: AuthenticatedPrincipal) -> axum::Router {
    let pool = lazy_pool();
    app_with_terminal_client_plane_and_principal(
        cloud_db::control::ControlRepository::new(pool.clone()),
        Some(cloud_db::client_access::ClientAccessPolicyRepository::new(
            pool.clone(),
        )),
        Some(cloud_db::client_control::ClientControlRepository::new(
            pool.clone(),
        )),
        Some(cloud_db::client_routing::ClientNodeRepository::new(pool)),
        Some(signer()),
        principal,
    )
}

fn register_body(mutate: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut body = serde_json::json!({
        "api_version": 1,
        "message_type": "register_device_request",
        "request_id": Uuid::new_v4().to_string(),
        "payload": {
            "device_id": Uuid::new_v4().to_string(),
            "device_key_id": Uuid::new_v4().to_string(),
            "platform": "macos",
            "display_name": "MacBook Pro",
            "public_key": URL_SAFE_NO_PAD.encode([7_u8; 32]),
            "install_id": "install-01HXYZ123",
            "client_version": "0.1.0"
        }
    });
    mutate(&mut body);
    serde_json::to_vec(&body).unwrap()
}

fn grant_body(device_id: Uuid, device_key_id: Uuid) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "api_version": 1,
        "message_type": "grant_request",
        "request_id": Uuid::new_v4().to_string(),
        "payload": {
            "device_id": device_id.to_string(),
            "device_key_id": device_key_id.to_string()
        }
    }))
    .unwrap()
}

async fn post(app: axum::Router, uri: String, body: Vec<u8>) -> (StatusCode, String) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn terminal_routes_fail_closed_without_a_session() {
    let device = Uuid::new_v4();
    for (uri, body) in [
        ("/v1/client/devices".to_string(), register_body(|_| {})),
        (
            format!("/v1/client/devices/{device}/grant"),
            grant_body(device, Uuid::new_v4()),
        ),
    ] {
        // `app()` has no principal injected and no authenticator, which is the
        // closest route-level analogue of an absent or expired session.
        let (status, body) = post(app(), uri, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("AUTHENTICATION_REQUIRED"), "{body}");
    }
}

#[tokio::test]
async fn unauthenticated_callers_get_401_even_with_a_malformed_body() {
    // The session is extracted before the body, so a caller that is not signed in
    // learns nothing about which fields Cloud validates.
    let (status, body) = post(app(), "/v1/client/devices".to_string(), b"{".to_vec()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("AUTHENTICATION_REQUIRED"), "{body}");
}

#[tokio::test]
async fn malformed_bodies_produce_the_contracted_error_envelope() {
    let app = app_with_principal(
        lazy_repository(),
        principal(Uuid::new_v4(), Uuid::new_v4().to_string()),
    );
    let uri = "/v1/client/devices".to_string();

    // A syntax error must be a contract error envelope, never axum's default
    // plain-text `422`.
    let (status, body) = post(app.clone(), uri.clone(), b"{".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("INVALID_JSON"), "{body}");
    assert!(body.contains("schema_version"), "{body}");

    // `deny_unknown_fields`: a caller cannot smuggle its own tenant or user.
    let (status, body) = post(
        app.clone(),
        uri.clone(),
        register_body(|body| {
            body["payload"]["tenant_id"] = serde_json::json!(Uuid::new_v4().to_string());
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("INVALID_REQUEST"), "{body}");

    let (status, body) = post(
        app.clone(),
        uri.clone(),
        register_body(|body| {
            body["payload"]["user_id"] = serde_json::json!(Uuid::new_v4().to_string());
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("INVALID_REQUEST"), "{body}");

    // A wrong JSON type is a request error, not a 422.
    let (status, body) = post(
        app.clone(),
        uri.clone(),
        register_body(|body| {
            body["api_version"] = serde_json::json!("1");
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("INVALID_REQUEST"), "{body}");

    // A body with no content type is refused explicitly rather than defaulting.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .body(Body::from(register_body(|_| {})))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn envelope_version_type_and_request_id_are_enforced_before_storage() {
    let app = app_with_principal(
        lazy_repository(),
        principal(Uuid::new_v4(), Uuid::new_v4().to_string()),
    );
    let uri = "/v1/client/devices".to_string();

    let (status, body) = post(
        app.clone(),
        uri.clone(),
        register_body(|body| {
            body["api_version"] = serde_json::json!(2);
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("INVALID_API_VERSION"), "{body}");

    let (status, body) = post(
        app.clone(),
        uri.clone(),
        register_body(|body| {
            body["message_type"] = serde_json::json!("grant_request");
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("INVALID_MESSAGE_TYPE"), "{body}");

    let (status, body) = post(
        app.clone(),
        uri.clone(),
        register_body(|body| {
            body["request_id"] = serde_json::json!(Uuid::nil().to_string());
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("INVALID_REQUEST_ID"), "{body}");
}

#[tokio::test]
async fn platform_and_public_key_are_validated_before_storage() {
    let app = app_with_principal(
        lazy_repository(),
        principal(Uuid::new_v4(), Uuid::new_v4().to_string()),
    );
    let uri = "/v1/client/devices".to_string();

    for platform in ["linux", "Windows", "ios", ""] {
        let (status, body) = post(
            app.clone(),
            uri.clone(),
            register_body(|body| {
                body["payload"]["platform"] = serde_json::json!(platform);
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "platform={platform}");
        assert!(body.contains("INVALID_PLATFORM"), "{body}");
    }

    // A truncated key, a 64-byte secret-key shape, and non-base64 text must all
    // be refused so a client cannot register something that is not a public key.
    for key in [
        URL_SAFE_NO_PAD.encode([7_u8; 31]),
        URL_SAFE_NO_PAD.encode([7_u8; 64]),
        "not base64url!".to_string(),
        "short".to_string(),
    ] {
        let (status, body) = post(
            app.clone(),
            uri.clone(),
            register_body(|body| {
                body["payload"]["public_key"] = serde_json::json!(key);
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "key={key}");
        assert!(body.contains("INVALID_PUBLIC_KEY"), "{body}");
    }
}

#[tokio::test]
async fn a_session_that_cannot_map_to_a_user_id_is_rejected_before_storage() {
    // Terminal device ownership is keyed on the session subject, so a session
    // whose subject is not a user id cannot own a device.
    let app = app_with_principal(
        lazy_repository(),
        principal(Uuid::new_v4(), "operator-1".into()),
    );
    let (status, body) = post(app, "/v1/client/devices".to_string(), register_body(|_| {})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("AUTHENTICATION_REQUIRED"), "{body}");
}

#[tokio::test]
async fn a_valid_request_without_the_client_plane_is_a_retryable_503() {
    // Fail closed, never fail open: with the plane absent Cloud must not invent a
    // Grant, and it must not blame the client either.
    let app = app_with_principal(
        lazy_repository(),
        principal(Uuid::new_v4(), Uuid::new_v4().to_string()),
    );
    let (status, body) = post(app, "/v1/client/devices".to_string(), register_body(|_| {})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("CONTROL_PLANE_UNAVAILABLE"), "{body}");
}

#[tokio::test]
async fn grant_route_rejects_a_device_id_that_does_not_match_the_path() {
    let tenant = Uuid::new_v4();
    let app = terminal_app(principal(tenant, Uuid::new_v4().to_string()));
    let path_device = Uuid::new_v4();
    let (status, body) = post(
        app,
        format!("/v1/client/devices/{path_device}/grant"),
        grant_body(Uuid::new_v4(), Uuid::new_v4()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("DEVICE_BINDING_MISMATCH"), "{body}");
}

#[tokio::test]
async fn grant_route_validates_the_envelope_before_touching_storage() {
    let tenant = Uuid::new_v4();
    let app = terminal_app(principal(tenant, Uuid::new_v4().to_string()));
    let device = Uuid::new_v4();
    let uri = format!("/v1/client/devices/{device}/grant");

    let mut body: serde_json::Value =
        serde_json::from_slice(&grant_body(device, Uuid::new_v4())).unwrap();
    body["message_type"] = serde_json::json!("register_device_request");
    let (status, response) = post(app, uri, serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response.contains("INVALID_MESSAGE_TYPE"), "{response}");
}
