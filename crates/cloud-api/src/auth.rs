use std::{path::Path, sync::Arc};

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::{Role, TenantContext},
    management::{ApiError, AuthenticatedPrincipal},
};

#[derive(Clone)]
pub struct ManagementAuthenticator {
    decoding_key: DecodingKey,
    validation: Validation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagementClaims {
    sub: String,
    organization_id: Uuid,
    tenant_id: Uuid,
    role: Role,
    iss: String,
    aud: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: String,
}

impl ManagementAuthenticator {
    pub fn from_ed25519_public_key_file(
        path: &Path,
        issuer: &str,
        audience: &str,
    ) -> anyhow::Result<Self> {
        let pem = std::fs::read(path)?;
        let decoding_key = DecodingKey::from_ed_pem(&pem)?;
        Self::new(decoding_key, issuer, audience)
    }

    pub fn new(decoding_key: DecodingKey, issuer: &str, audience: &str) -> anyhow::Result<Self> {
        if issuer.is_empty() || issuer.len() > 200 || audience.is_empty() || audience.len() > 200 {
            anyhow::bail!("management token issuer and audience must be bounded");
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.validate_nbf = true;
        validation.leeway = 30;
        validation.reject_tokens_expiring_in_less_than = 5;
        Ok(Self {
            decoding_key,
            validation,
        })
    }

    fn authenticate(&self, token: &str) -> Result<AuthenticatedPrincipal, ApiError> {
        let claims = decode::<ManagementClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|_| ApiError::unauthorized())?
            .claims;
        let _validated_standard_claims =
            (&claims.iss, &claims.aud, claims.exp, claims.nbf, claims.iat);
        if claims.organization_id.is_nil()
            || claims.tenant_id.is_nil()
            || claims.sub.is_empty()
            || claims.sub.len() > 120
            || claims.jti.is_empty()
            || claims.jti.len() > 160
        {
            return Err(ApiError::unauthorized());
        }
        Ok(AuthenticatedPrincipal {
            actor_id: claims.sub,
            context: TenantContext {
                organization_id: claims.organization_id,
                tenant_id: claims.tenant_id,
                role: claims.role,
            },
        })
    }
}

pub async fn require_management_principal(
    State(authenticator): State<Arc<ManagementAuthenticator>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(ApiError::unauthorized)?;
    let principal = authenticator.authenticate(token)?;
    request.extensions_mut().insert(principal);
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use tower::ServiceExt;

    const PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGrD/e7uKYqSY4twDEsRfMMuLSrODf14dpTiTK6K1YI0
-----END PRIVATE KEY-----
"#;
    const PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2+Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8=
-----END PUBLIC KEY-----
"#;

    #[tokio::test]
    async fn verified_bearer_token_injects_principal_into_management_route() {
        let authenticator = ManagementAuthenticator::new(
            DecodingKey::from_ed_pem(PUBLIC_KEY).unwrap(),
            "https://identity.candy.invalid",
            "candy-cloud-management",
        )
        .unwrap();
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
        let tenant_id = Uuid::new_v4();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &ManagementClaims {
                sub: "operator-1".into(),
                organization_id: Uuid::new_v4(),
                tenant_id,
                role: Role::TenantAdmin,
                iss: "https://identity.candy.invalid".into(),
                aud: "candy-cloud-management".into(),
                exp: now + 300,
                nbf: now.saturating_sub(1),
                iat: now,
                jti: Uuid::new_v4().to_string(),
            },
            &EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap();
        let decoded = decode::<ManagementClaims>(
            &token,
            &authenticator.decoding_key,
            &authenticator.validation,
        );
        assert!(decoded.is_ok(), "{decoded:?}");
        let pool = sqlx::MySqlPool::connect_lazy("mysql://invalid/invalid").unwrap();
        let app = crate::app_with_authentication(
            cloud_db::control::ControlRepository::new(pool),
            authenticator,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/tenants/{tenant_id}/sites"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header("x-page-size", "invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
