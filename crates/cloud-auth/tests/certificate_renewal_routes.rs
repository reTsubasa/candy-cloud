use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use cloud_auth::{
    certificate_renewal::{
        CertificateRenewalCommand, CertificateRenewalError, CertificateRenewalReceipt,
    },
    routes::{
        certificate_renewal_app, AuthenticatedDevice, CertificateRenewalHttpService, ServiceFuture,
    },
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

struct RecordingRenewalService {
    commands: Mutex<Vec<CertificateRenewalCommand>>,
    result: Mutex<Result<CertificateRenewalReceipt, CertificateRenewalError>>,
}

impl CertificateRenewalHttpService for RecordingRenewalService {
    fn renew_certificate(
        &self,
        command: CertificateRenewalCommand,
    ) -> ServiceFuture<'_, Result<CertificateRenewalReceipt, CertificateRenewalError>> {
        Box::pin(async move {
            self.commands.lock().unwrap().push(command);
            self.result.lock().unwrap().clone()
        })
    }
}

fn actor() -> AuthenticatedDevice {
    AuthenticatedDevice::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        1,
    )
    .unwrap()
}

fn service(
    result: Result<CertificateRenewalReceipt, CertificateRenewalError>,
) -> Arc<RecordingRenewalService> {
    Arc::new(RecordingRenewalService {
        commands: Mutex::new(Vec::new()),
        result: Mutex::new(result),
    })
}

#[tokio::test]
async fn renewal_uses_only_the_authenticated_device_scope() {
    let service = service(Ok(CertificateRenewalReceipt {
        certificate_der: vec![251, 255],
        certificate_chain_pem: "test-chain".into(),
        not_after: chrono::DateTime::from_timestamp(1_800_604_800, 0).unwrap(),
    }));
    let authenticated = actor();
    let response = certificate_renewal_app(service.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/device-certificates/renew")
                .header("content-type", "application/json")
                .extension(authenticated.clone())
                .body(Body::from(r#"{"request_id":"renew-01"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let command = service.commands.lock().unwrap().pop().unwrap();
    assert_eq!(command.request_id, "renew-01");
    assert_eq!(command.actor, authenticated);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.windows(4).any(|item| item == b"+/8="));
}

#[tokio::test]
async fn renewal_rejects_body_supplied_identity() {
    let service = service(Err(CertificateRenewalError::Unavailable));
    let body = format!(
        r#"{{"request_id":"renew-02","device_id":"{}"}}"#,
        Uuid::new_v4()
    );
    let response = certificate_renewal_app(service.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/device-certificates/renew")
                .header("content-type", "application/json")
                .extension(actor())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(service.commands.lock().unwrap().is_empty());
}

#[tokio::test]
async fn renewal_exposes_stable_domain_error_codes() {
    for (error, status, code) in [
        (
            CertificateRenewalError::InvalidRequest,
            StatusCode::BAD_REQUEST,
            "invalid_certificate_renewal_request",
        ),
        (
            CertificateRenewalError::NotDue,
            StatusCode::CONFLICT,
            "certificate_renewal_not_due",
        ),
        (
            CertificateRenewalError::IdentityChanged,
            StatusCode::CONFLICT,
            "device_certificate_changed",
        ),
        (
            CertificateRenewalError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "certificate_renewal_unavailable",
        ),
    ] {
        let response = certificate_renewal_app(service(Err(error)))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/device-certificates/renew")
                    .header("content-type", "application/json")
                    .extension(actor())
                    .body(Body::from(r#"{"request_id":"renew-errors"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
            code
        );
    }
}
