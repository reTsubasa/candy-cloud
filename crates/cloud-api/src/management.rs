use std::sync::Arc;

use axum::{
    extract::{Extension, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use cloud_control::{
    ControlResourceV1, ResourceKind, ResourceMetadataV1, ResourceSpecV1, ResourceState,
    CONTROL_SCHEMA_V1,
};
use cloud_db::control::{
    ControlRepository, ControlStoreError, MutationContext, MutationOutcome, ResourceMutation,
    ResourcePageRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::{authorize, Action, TenantContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub actor_id: String,
    pub context: TenantContext,
}

#[derive(Clone)]
pub struct ManagementState {
    pub repository: Option<ControlRepository>,
    pub authentication_ready: bool,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    schema_version: u16,
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    pub(crate) fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTHENTICATION_REQUIRED",
            message: "management authentication is required",
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "TENANT_ACCESS_DENIED",
            message: "tenant access is denied",
        }
    }

    fn from_store(error: ControlStoreError) -> Self {
        match error {
            ControlStoreError::InvalidResource(_) | ControlStoreError::InvalidRequest => Self {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_REQUEST",
                message: "request does not satisfy the V1 contract",
            },
            ControlStoreError::NotFound => Self {
                status: StatusCode::NOT_FOUND,
                code: "RESOURCE_NOT_FOUND",
                message: "resource was not found",
            },
            ControlStoreError::RevisionConflict => Self {
                status: StatusCode::PRECONDITION_FAILED,
                code: "REVISION_CONFLICT",
                message: "resource revision does not match If-Match",
            },
            ControlStoreError::ReferenceConflict => Self {
                status: StatusCode::CONFLICT,
                code: "RESOURCE_REFERENCE_CONFLICT",
                message: "resource reference is missing, inconsistent, or still in use",
            },
            ControlStoreError::IdempotencyConflict => Self {
                status: StatusCode::CONFLICT,
                code: "IDEMPOTENCY_CONFLICT",
                message: "idempotency key was reused with a different request",
            },
            ControlStoreError::IdempotencyReplayExpired => Self {
                status: StatusCode::CONFLICT,
                code: "IDEMPOTENCY_REPLAY_EXPIRED",
                message: "idempotency replay window expired; use a new key",
            },
            ControlStoreError::LeaseLost | ControlStoreError::InvalidTransition => Self {
                status: StatusCode::CONFLICT,
                code: "STATE_CONFLICT",
                message: "resource state changed concurrently",
            },
            ControlStoreError::Database(_) => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "CONTROL_PLANE_UNAVAILABLE",
                message: "control plane storage is unavailable",
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                schema_version: CONTROL_SCHEMA_V1,
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    pub resource: ResourceSpecV1,
}

#[derive(Debug, Serialize)]
pub struct ResourceListResponse {
    pub schema_version: u16,
    pub items: Vec<ControlResourceV1>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct MutationResponse {
    pub schema_version: u16,
    pub replayed: bool,
    pub resource: ControlResourceV1,
}

pub async fn list(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<ResourceListResponse>, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ReadConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    let limit = match headers.get("x-page-size") {
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_PAGE_SIZE",
                message: "X-Page-Size must be an integer between 1 and 200",
            })?,
        None => 50,
    };
    let after_id = match headers.get("x-page-after") {
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .and_then(|value| Uuid::parse_str(value).ok())
                .filter(|value| !value.is_nil())
                .ok_or(ApiError {
                    status: StatusCode::BAD_REQUEST,
                    code: "INVALID_PAGE_CURSOR",
                    message: "X-Page-After must be a non-zero UUID",
                })?,
        ),
        None => None,
    };
    let page = ResourcePageRequest::new(limit, after_id).map_err(ApiError::from_store)?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let result = repository
        .list(tenant_id, kind, page)
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(ResourceListResponse {
        schema_version: CONTROL_SCHEMA_V1,
        items: result.items,
        next_cursor: result.next_cursor,
    }))
}

pub async fn get(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection, id)): Path<(Uuid, String, Uuid)>,
) -> Result<Json<ControlResourceV1>, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ReadConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    Ok(Json(
        repository
            .get(tenant_id, kind, id)
            .await
            .map_err(ApiError::from_store)?,
    ))
}

pub async fn create(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Json(body): Json<ResourceRequest>,
) -> Result<Response, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::WriteConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    if body.resource.kind() != kind {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "RESOURCE_KIND_MISMATCH",
            message: "resource body does not match collection",
        });
    }
    let key = required_header(&headers, "idempotency-key")?;
    let id = idempotent_resource_id(tenant_id, &principal.actor_id, &key);
    let resource = ControlResourceV1 {
        metadata: ResourceMetadataV1 {
            schema_version: CONTROL_SCHEMA_V1,
            id,
            tenant_id,
            revision: 1,
            state: ResourceState::Active,
        },
        resource: body.resource,
    };
    let context = mutation_context(
        &principal.actor_id,
        &headers,
        "POST",
        &format!("/v1/tenants/{tenant_id}/{collection}"),
        key,
        &resource,
    )?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let outcome = repository
        .mutate(
            &ResourceMutation {
                context,
                resource,
                expected_revision: None,
            },
            Utc::now(),
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(mutation_response(outcome, StatusCode::CREATED))
}

pub async fn replace(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection, id)): Path<(Uuid, String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<ResourceRequest>,
) -> Result<Response, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::WriteConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    if body.resource.kind() != kind {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "RESOURCE_KIND_MISMATCH",
            message: "resource body does not match collection",
        });
    }
    let expected = if_match(&headers)?;
    let key = required_header(&headers, "idempotency-key")?;
    let resource = ControlResourceV1 {
        metadata: ResourceMetadataV1 {
            schema_version: CONTROL_SCHEMA_V1,
            id,
            tenant_id,
            revision: expected.checked_add(1).ok_or(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_REVISION",
                message: "revision is too large",
            })?,
            state: ResourceState::Active,
        },
        resource: body.resource,
    };
    let context = mutation_context(
        &principal.actor_id,
        &headers,
        "PUT",
        &format!("/v1/tenants/{tenant_id}/{collection}/{id}"),
        key,
        &resource,
    )?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let outcome = repository
        .mutate(
            &ResourceMutation {
                context,
                resource,
                expected_revision: Some(expected),
            },
            Utc::now(),
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(mutation_response(outcome, StatusCode::OK))
}

pub async fn delete(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection, id)): Path<(Uuid, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::WriteConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    let expected = if_match(&headers)?;
    let key = required_header(&headers, "idempotency-key")?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let current = repository
        .get(tenant_id, kind, id)
        .await
        .map_err(ApiError::from_store)?;
    if current.metadata.revision != expected {
        return Err(ApiError::from_store(ControlStoreError::RevisionConflict));
    }
    let mut resource = current;
    resource.metadata.revision = expected.checked_add(1).ok_or(ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "INVALID_REVISION",
        message: "revision is too large",
    })?;
    resource.metadata.state = ResourceState::Deleted;
    let context = mutation_context(
        &principal.actor_id,
        &headers,
        "DELETE",
        &format!("/v1/tenants/{tenant_id}/{collection}/{id}"),
        key,
        &resource,
    )?;
    let outcome = repository
        .mutate(
            &ResourceMutation {
                context,
                resource,
                expected_revision: Some(expected),
            },
            Utc::now(),
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(mutation_response(outcome, StatusCode::OK))
}

fn authorize_tenant(
    principal: &AuthenticatedPrincipal,
    tenant_id: Uuid,
    action: Action,
) -> Result<(), ApiError> {
    if principal.context.tenant_id != tenant_id
        || authorize(
            &principal.context,
            principal.context.organization_id,
            tenant_id,
            action,
        )
        .is_err()
    {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn required_header(headers: &HeaderMap, name: &'static str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 160)
        .map(str::to_owned)
        .ok_or(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "MISSING_IDEMPOTENCY_KEY",
            message: "Idempotency-Key is required",
        })
}

fn if_match(headers: &HeaderMap) -> Result<u64, ApiError> {
    let value = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError {
            status: StatusCode::PRECONDITION_REQUIRED,
            code: "IF_MATCH_REQUIRED",
            message: "If-Match is required",
        })?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    value.parse().map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "INVALID_IF_MATCH",
        message: "If-Match must contain a numeric revision",
    })
}

fn mutation_context(
    actor_id: &str,
    _headers: &HeaderMap,
    method: &str,
    path: &str,
    key: String,
    resource: &ControlResourceV1,
) -> Result<MutationContext, ApiError> {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(path.as_bytes());
    hasher.update(serde_json::to_vec(resource).map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "INVALID_REQUEST",
        message: "request cannot be serialized",
    })?);
    Ok(MutationContext {
        actor_id: actor_id.into(),
        idempotency_key: key,
        request_method: method.into(),
        request_path: path.into(),
        request_hash: hasher.finalize().into(),
        idempotency_replay_until: Utc::now() + Duration::hours(24),
    })
}

fn idempotent_resource_id(tenant_id: Uuid, actor_id: &str, key: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update(actor_id.as_bytes());
    hasher.update(key.as_bytes());
    let mut bytes: [u8; 16] = hasher.finalize()[..16]
        .try_into()
        .expect("digest slice length");
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn mutation_response(outcome: MutationOutcome, status: StatusCode) -> Response {
    let (replayed, resource) = match outcome {
        MutationOutcome::Applied(resource) => (false, resource),
        MutationOutcome::Replayed(resource) => (true, resource),
    };
    (
        if replayed { StatusCode::OK } else { status },
        Json(MutationResponse {
            schema_version: CONTROL_SCHEMA_V1,
            replayed,
            resource,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_match_accepts_numeric_etag_and_rejects_missing_or_weak_values() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            if_match(&headers),
            Err(ApiError {
                status: StatusCode::PRECONDITION_REQUIRED,
                ..
            })
        ));
        headers.insert(header::IF_MATCH, "\"7\"".parse().unwrap());
        assert_eq!(if_match(&headers).unwrap(), 7);
        headers.insert(header::IF_MATCH, "W/\"7\"".parse().unwrap());
        assert!(if_match(&headers).is_err());
    }

    #[test]
    fn resource_id_is_stable_for_idempotent_replay_and_actor_scoped() {
        let tenant = Uuid::new_v4();
        assert_eq!(
            idempotent_resource_id(tenant, "actor-a", "request-1"),
            idempotent_resource_id(tenant, "actor-a", "request-1")
        );
        assert_ne!(
            idempotent_resource_id(tenant, "actor-a", "request-1"),
            idempotent_resource_id(tenant, "actor-b", "request-1")
        );
    }
}
