//! Admin issuer writes guarded by the `issuers:write` scope. Mutations of
//! existing issuers use optimistic preconditions (docs/openapi-admin.yaml).

use axum::{
    Extension, Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
};
use serde::Deserialize;

use crate::domain::models::hosted_issuer::{
    HostedIssuerError, HostedIssuerKeyState, HostedIssuerState,
};
use crate::domain::models::hosted_issuer::{NewHostedIssuer, NewHostedIssuerKey};
use crate::server::{
    AppState,
    auth::AuthenticatedAdmin,
    error::ApiError,
    handlers::admin::{
        hosted_dto, hosted_store_error, issuer_etag, issuer_write_version, key_from_hosted,
        require_scope,
    },
};

/// `state` member of `PATCH /admin/v1/issuers/{issuer_id}`.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerStateInput {
    Active,
    Suspended,
}

/// `PATCH /admin/v1/issuers/{issuer_id}` body: exactly one change. Modeled
/// as the contract's oneOf: a body with both members, or with unknown
/// members, matches neither variant and is rejected as invalid input.
#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum UpdateIssuerRequest {
    State { state: IssuerStateInput },
    Renewal { expires_at: i64 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIssuerRequest {
    display_name: String,
    owner: String,
    public_key: serde_json::Map<String, serde_json::Value>,
    alg: String,
    expires_at: Option<i64>,
}

/// `PATCH /admin/v1/issuers/{issuer_id}/keys/{kid}` body: the contract
/// allows only `{"state": "revoked"}`; anything else is invalid input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateKeyRequest {
    state: String,
}

/// `POST /admin/v1/issuers/{issuer_id}/keys` body. `kid` is deliberately
/// absent: the server assigns it from the public JWK.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddIssuerKeyRequest {
    public_key: serde_json::Map<String, serde_json::Value>,
    alg: String,
}

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError::new(status, code, Some(message.into()))
}

fn managed_by_configuration() -> ApiError {
    error(
        StatusCode::CONFLICT,
        "issuer_managed_by_configuration",
        "static issuers are changed through the registry file",
    )
}

fn reject_static_issuer(state: &AppState, issuer_id: &str) -> Result<(), ApiError> {
    if state.admin_registry.snapshot().issuer(issuer_id).is_some() {
        Err(managed_by_configuration())
    } else {
        Ok(())
    }
}

fn precondition_required() -> ApiError {
    error(
        StatusCode::PRECONDITION_REQUIRED,
        "precondition_required",
        "send If-Issuer-Version or If-Match from the issuer detail response",
    )
}

fn precondition_failed(current_etag: String, current_version: String) -> ApiError {
    ApiError::with_header(
        error(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "the issuer changed; re-read it and retry",
        ),
        header::ETAG,
        HeaderValue::from_str(&current_etag).expect("the ETag is a valid header value"),
    )
    .with_header(
        HeaderName::from_static("issuer-version"),
        HeaderValue::from_str(&current_version)
            .expect("the issuer version is a valid header value"),
    )
}

fn service_unavailable() -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "the issuer store is currently unavailable",
    )
    .retry_after(1)
}

struct IssuerPrecondition<'a> {
    version: Option<&'a str>,
    etag: Option<&'a str>,
}

/// Accepts the merged API's write version and the lifecycle ETag precondition.
fn if_match_value(headers: &HeaderMap) -> Result<IssuerPrecondition<'_>, ApiError> {
    let version = headers
        .get(HeaderName::from_static("if-issuer-version"))
        .map(|value| value.to_str().map(str::trim))
        .transpose()
        .map_err(|_| precondition_required())?;
    let etag = headers
        .get(header::IF_MATCH)
        .map(|value| value.to_str().map(str::trim))
        .transpose()
        .map_err(|_| precondition_required())?;
    if version.is_none() && etag.is_none() {
        return Err(precondition_required());
    }
    Ok(IssuerPrecondition { version, etag })
}

fn check_if_match(
    if_match: IssuerPrecondition<'_>,
    current_etag: &str,
    current_version: &str,
) -> Result<(), ApiError> {
    let matches = if_match
        .version
        .is_none_or(|version| version == current_version)
        && if_match
            .etag
            .is_none_or(|etag| etag == "*" || etag == current_etag);
    if !matches {
        return Err(precondition_failed(
            current_etag.to_owned(),
            current_version.to_owned(),
        ));
    }
    Ok(())
}

fn lifecycle_service(
    state: &AppState,
) -> &crate::server::auth::hosted_service::HostedIssuerLifecycleService {
    // The lifecycle routes are mounted only when the hosted profile builds
    // the service, so a request reaching this handler always finds it.
    state
        .hosted_lifecycle_service
        .as_ref()
        .expect("lifecycle routes are mounted only with the lifecycle service")
}

/// Reads the issuer and its current `ETag`. Static issuers are rejected with
/// the contract's 409 before the store is consulted.
async fn load_issuer_for_update(
    state: &AppState,
    issuer_id: &str,
) -> Result<
    (
        crate::domain::models::hosted_issuer::HostedIssuer,
        String,
        String,
    ),
    ApiError,
> {
    if state.admin_registry.snapshot().issuer(issuer_id).is_some() {
        return Err(managed_by_configuration());
    }
    let Some(store) = state.hosted_issuer_store.as_ref() else {
        return Err(service_unavailable());
    };
    let issuer = store
        .find_issuer(issuer_id)
        .await
        .map_err(hosted_store_error)?
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                "issuer_not_found",
                "no issuer has this id",
            )
        })?;
    let dto = hosted_dto(state, issuer.clone()).await?;
    let etag = issuer_etag(&dto);
    let version = issuer_write_version(&dto);
    Ok((issuer, etag, version))
}

fn lifecycle_error(error: HostedIssuerError) -> ApiError {
    match error {
        HostedIssuerError::NotFound => {
            ApiError::not_found("issuer_not_found", "Hosted issuer or key was not found")
        }
        HostedIssuerError::InvalidExpiry(_) => {
            ApiError::unprocessable("invalid_expiry", "An expired issuer cannot be reactivated")
        }
        HostedIssuerError::Contention { .. } => ApiError::write_contention(),
        HostedIssuerError::Unavailable => service_unavailable(),
        HostedIssuerError::VersionMismatch => ApiError::conflict(
            "issuer_version_mismatch",
            "Issuer version changed; read the current state before retrying",
        ),
        other => {
            tracing::error!(error = %other, "hosted lifecycle write failed");
            ApiError::internal("hosted lifecycle write failed")
        }
    }
}

fn add_key_error(hosted_error: HostedIssuerError) -> ApiError {
    match hosted_error {
        HostedIssuerError::AlreadyExists | HostedIssuerError::KeyMaterialReused => error(
            StatusCode::CONFLICT,
            "key_material_in_use",
            "the key id or public-key material is already reserved",
        ),
        HostedIssuerError::InvalidPublicJwk(_) => {
            ApiError::unprocessable("invalid_public_jwk", "the requested public JWK is invalid")
        }
        HostedIssuerError::KeyQuotaExceeded { .. } => error(
            StatusCode::CONFLICT,
            "key_limit_reached",
            "the issuer has reached its tier's non-revoked key limit",
        ),
        other => lifecycle_error(other),
    }
}

fn new_key_input(
    issuer_id: String,
    mut input: AddIssuerKeyRequest,
) -> Result<NewHostedIssuerKey, ApiError> {
    if input.public_key.contains_key("kid") {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "the server assigns kid; do not include it in public_key",
        ));
    }
    if input
        .public_key
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|alg| alg != input.alg)
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "alg must match public_key.alg when it is supplied",
        ));
    }
    input.public_key.insert(
        "alg".into(),
        serde_json::Value::String(std::mem::take(&mut input.alg)),
    );
    Ok(NewHostedIssuerKey {
        issuer_id,
        jwk: input.public_key,
        not_before: None,
        not_after: None,
    })
}

fn validate_expiry(
    expires_at: i64,
    now: time::OffsetDateTime,
    max_lifetime: std::time::Duration,
) -> Result<time::OffsetDateTime, ApiError> {
    let expiry = time::OffsetDateTime::from_unix_timestamp(expires_at)
        .map_err(|_| ApiError::unprocessable("invalid_expiry", "expires_at is invalid"))?;
    let latest = now
        .checked_add(time::Duration::seconds(max_lifetime.as_secs() as i64))
        .ok_or_else(|| {
            ApiError::unprocessable("invalid_expiry", "sandbox lifetime is too large")
        })?;
    if expiry <= now || expiry > latest {
        return Err(ApiError::unprocessable(
            "invalid_expiry",
            "expires_at must be after now and within the sandbox lifetime",
        ));
    }
    Ok(expiry)
}

pub async fn create_issuer(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    input: Result<Json<CreateIssuerRequest>, JsonRejection>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<crate::server::handlers::admin::IssuerDto>,
    ),
    ApiError,
> {
    require_scope(&admin, "issuers:write")?;
    let Json(input) = input.map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "invalid create issuer request",
        )
    })?;
    let Some(store) = state.hosted_issuer_store.as_ref() else {
        return Err(ApiError::conflict(
            "dynamic_issuers_disabled",
            "portal issuers are only available in the hosted profile",
        ));
    };
    if input.display_name.is_empty() || input.display_name.chars().count() > 100 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "display_name must be 1 to 100 characters",
        ));
    }
    let valid_owner = input
        .owner
        .split_once('|')
        .is_some_and(|(provider, subject)| {
            !provider.is_empty()
                && provider
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !subject.is_empty()
                && input.owner.chars().count() <= 255
        });
    if !valid_owner {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "owner must be provider|subject",
        ));
    }
    let now = time::OffsetDateTime::now_utc();
    let max_lifetime = state.tiers.sandbox_max_lifetime;
    let expires_at = match input.expires_at {
        Some(expiry) => expiry,
        None => now
            .checked_add(time::Duration::seconds(max_lifetime.as_secs() as i64))
            .ok_or_else(|| ApiError::internal("sandbox lifetime is too large"))?
            .unix_timestamp(),
    };
    let expires_at = validate_expiry(expires_at, now, max_lifetime)?;
    let key = new_key_input(
        String::new(),
        AddIssuerKeyRequest {
            public_key: input.public_key,
            alg: input.alg,
        },
    )?;
    let service = crate::server::auth::hosted_service::HostedIssuerService::new(store.clone());
    let issuer = service
        .create_issuer_with_key(
            &state.admin_registry,
            NewHostedIssuer {
                display_name: Some(input.display_name),
                tier: "sandbox".into(),
                owner: Some(input.owner),
                expires_at,
            },
            key,
            &admin.id,
        )
        .await
        .map_err(add_key_error)?;
    let dto = hosted_dto(&state, issuer).await?;
    let mut headers = response_headers(&issuer_etag(&dto), &issuer_write_version(&dto));
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/admin/v1/issuers/{}", dto.id()))
            .expect("generated id is a valid location segment"),
    );
    Ok((StatusCode::CREATED, headers, Json(dto)))
}

fn response_headers(etag: &str, version: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("quoted hash"),
    );
    headers.insert(
        HeaderName::from_static("issuer-version"),
        HeaderValue::from_str(version).expect("issuer version hash"),
    );
    headers
}

/// `PATCH /admin/v1/issuers/{issuer_id}`: suspend or resume a portal issuer.
pub async fn update_issuer(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    Path(issuer_id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<UpdateIssuerRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<crate::server::handlers::admin::IssuerDto>), ApiError> {
    require_scope(&admin, "issuers:write")?;
    reject_static_issuer(&state, &issuer_id)?;
    let service = lifecycle_service(&state);
    let Json(input) = input.map_err(|rejection| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            format!("invalid update issuer request: {rejection}"),
        )
    })?;
    let if_match = if_match_value(&headers)?;
    let (current, current_etag, current_version) =
        load_issuer_for_update(&state, &issuer_id).await?;
    check_if_match(if_match, &current_etag, &current_version)?;
    let requested = match input {
        UpdateIssuerRequest::State { state } => match state {
            IssuerStateInput::Active => HostedIssuerState::Active,
            IssuerStateInput::Suspended => HostedIssuerState::Suspended,
        },
        UpdateIssuerRequest::Renewal { expires_at } => {
            let expiry = validate_expiry(
                expires_at,
                time::OffsetDateTime::now_utc(),
                state.tiers.sandbox_max_lifetime,
            )?;
            let updated = match service
                .set_issuer_expiry(&issuer_id, expiry, current.version, &admin.id)
                .await
            {
                Ok(updated) => updated,
                Err(HostedIssuerError::VersionMismatch) => {
                    let issuer = load_current(&state, &issuer_id).await?;
                    let dto = hosted_dto(&state, issuer).await?;
                    return Err(precondition_failed(
                        issuer_etag(&dto),
                        issuer_write_version(&dto),
                    ));
                }
                Err(other) => return Err(lifecycle_error(other)),
            };
            let dto = hosted_dto(&state, updated).await?;
            return Ok((
                response_headers(&issuer_etag(&dto), &issuer_write_version(&dto)),
                Json(dto),
            ));
        }
    };
    match service
        .set_issuer_state(&issuer_id, requested, current.version, &admin.id)
        .await
    {
        Ok(updated) => {
            let dto = hosted_dto(&state, updated).await?;
            let etag = issuer_etag(&dto);
            Ok((
                response_headers(&etag, &issuer_write_version(&dto)),
                Json(dto),
            ))
        }
        // The version moved after the precondition check: answer with the
        // precondition failure the contract promises, carrying the ETag the
        // issuer has now.
        Err(HostedIssuerError::VersionMismatch) => {
            let issuer = load_current(&state, &issuer_id).await?;
            let dto = hosted_dto(&state, issuer).await?;
            Err(precondition_failed(
                issuer_etag(&dto),
                issuer_write_version(&dto),
            ))
        }
        Err(other) => Err(lifecycle_error(other)),
    }
}

/// `PATCH /admin/v1/issuers/{issuer_id}/keys/{kid}`: revoke a key of a
/// portal issuer. Revoking an already revoked key returns it unchanged.
pub async fn revoke_issuer_key(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    Path((issuer_id, kid)): Path<(String, String)>,
    headers: HeaderMap,
    input: Result<Json<UpdateKeyRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<crate::server::handlers::admin::KeyDto>), ApiError> {
    require_scope(&admin, "issuers:write")?;
    reject_static_issuer(&state, &issuer_id)?;
    let service = lifecycle_service(&state);
    let Json(input) = input.map_err(|rejection| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            format!("invalid update key request: {rejection}"),
        )
    })?;
    if input.state != "revoked" {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "only \"revoked\" is a supported key state",
        ));
    }
    let if_match = if_match_value(&headers)?;
    let (current, current_etag, current_version) =
        load_issuer_for_update(&state, &issuer_id).await?;
    let store = state
        .hosted_issuer_store
        .as_ref()
        .expect("lifecycle routes are mounted only with the hosted issuer store");
    check_if_match(if_match, &current_etag, &current_version)?;
    if let Some(entry) = store
        .find_key_by_kid(&kid)
        .await
        .map_err(hosted_store_error)?
        && entry.issuer.id == issuer_id
        && entry.key.state == HostedIssuerKeyState::Revoked
    {
        return Ok((
            response_headers(&current_etag, &current_version),
            Json(key_from_hosted(entry.key)),
        ));
    }
    let revoked = match service
        .revoke_key(&issuer_id, &kid, current.version, &admin.id)
        .await
    {
        Ok(revoked) => revoked,
        Err(HostedIssuerError::VersionMismatch) => {
            let issuer = load_current(&state, &issuer_id).await?;
            let dto = hosted_dto(&state, issuer).await?;
            return Err(precondition_failed(
                issuer_etag(&dto),
                issuer_write_version(&dto),
            ));
        }
        Err(HostedIssuerError::NotFound) => {
            return Err(error(
                StatusCode::NOT_FOUND,
                "key_not_found",
                "the issuer has no key with this kid",
            ));
        }
        Err(other) => return Err(lifecycle_error(other)),
    };
    // The issuer representation changed (a key state flipped), so the
    // response carries the new ETag for the next change.
    let dto = hosted_dto(&state, load_current(&state, &issuer_id).await?).await?;
    Ok((
        response_headers(&issuer_etag(&dto), &issuer_write_version(&dto)),
        Json(key_from_hosted(revoked)),
    ))
}

/// `POST /admin/v1/issuers/{issuer_id}/keys`: register an active portal key.
/// The SQL store verifies the current issuer version while it commits the key,
/// making the preceding `If-Match` check race-safe.
pub async fn add_issuer_key(
    State(state): State<AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
    Path(issuer_id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<AddIssuerKeyRequest>, JsonRejection>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<crate::server::handlers::admin::KeyDto>,
    ),
    ApiError,
> {
    require_scope(&admin, "issuers:write")?;
    reject_static_issuer(&state, &issuer_id)?;
    let Json(input) = input.map_err(|rejection| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            format!("invalid add issuer key request: {rejection}"),
        )
    })?;
    let if_match = if_match_value(&headers)?;
    let (current, current_etag, current_version) =
        load_issuer_for_update(&state, &issuer_id).await?;
    check_if_match(if_match, &current_etag, &current_version)?;
    let input = new_key_input(issuer_id.clone(), input)?;
    let store = state
        .hosted_issuer_store
        .as_ref()
        .expect("lifecycle routes are mounted only with the hosted issuer store")
        .clone();
    let service = crate::server::auth::hosted_service::HostedIssuerService::new(store);
    let key = match service
        .register_key_if_version(&state.admin_registry, input, current.version, &admin.id)
        .await
    {
        Ok(key) => key,
        Err(HostedIssuerError::VersionMismatch) => {
            let issuer = load_current(&state, &issuer_id).await?;
            let dto = hosted_dto(&state, issuer).await?;
            return Err(precondition_failed(
                issuer_etag(&dto),
                issuer_write_version(&dto),
            ));
        }
        Err(other) => return Err(add_key_error(other)),
    };
    let dto = hosted_dto(&state, load_current(&state, &issuer_id).await?).await?;
    let etag = issuer_etag(&dto);
    let mut response_headers = response_headers(&etag, &issuer_write_version(&dto));
    response_headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/admin/v1/issuers/{issuer_id}/keys/{}", key.kid))
            .expect("generated key id is a valid location segment"),
    );
    Ok((
        StatusCode::CREATED,
        response_headers,
        Json(key_from_hosted(key)),
    ))
}

async fn load_current(
    state: &AppState,
    issuer_id: &str,
) -> Result<crate::domain::models::hosted_issuer::HostedIssuer, ApiError> {
    let Some(store) = state.hosted_issuer_store.as_ref() else {
        return Err(service_unavailable());
    };
    store
        .find_issuer(issuer_id)
        .await
        .map_err(hosted_store_error)?
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                "issuer_not_found",
                "no issuer has this id",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::{AggregationId, PublicJwk};
    use crate::domain::models::hosted_issuer::{
        HostedIssuer, HostedIssuerFilter, HostedIssuerKey, HostedIssuerKeyState,
    };
    use crate::domain::ports::{HostedIssuerLifecycleStore, HostedIssuerStore};
    use crate::server::auth::hosted_service::HostedIssuerLifecycleService;
    use crate::server::auth::issuer_registry::RegistryHandle;
    use crate::test_utils::test_app_state;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::middleware::from_fn_with_state;
    use axum::response::Response;
    use axum::routing::{patch, post};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use time::OffsetDateTime;
    use tower::ServiceExt;

    const ADMIN_EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A\n5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV\nb0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT\n-----END PRIVATE KEY-----";

    fn admin_public_jwk() -> PublicJwk {
        PublicJwk::try_new(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "kid": "admin-key",
                "alg": "ES256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#
            .as_bytes()
            .to_vec(),
        )
        .unwrap()
    }

    /// A key registered to a static issuer; a token signed with it must never
    /// authenticate on the admin listener.
    fn issuer_public_jwk() -> PublicJwk {
        PublicJwk::try_new(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "kid": "issuer-key",
                "alg": "ES256",
                "x": "qM76BbqD3JmWniT4AuSYM5KwxC5WANcPXBpCUQfAf1E",
                "y": "c_dO6JH2BqKs9M6UsDNMQ7RsYMgwqON5Ti19gKb8nLk"
            }"#
            .as_bytes()
            .to_vec(),
        )
        .unwrap()
    }

    /// The wall clock injected into the lifecycle service; pinned so the
    /// expiry rule is deterministic.
    fn service_now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[derive(Default)]
    struct FakeLifecycleStore {
        issuers: Mutex<Vec<HostedIssuer>>,
        keys: Mutex<Vec<HostedIssuerKey>>,
        key_limit: Mutex<Option<usize>>,
    }

    impl FakeLifecycleStore {
        fn issuer(&self, id: &str) -> Option<HostedIssuer> {
            self.issuers
                .lock()
                .unwrap()
                .iter()
                .find(|i| i.id == id)
                .cloned()
        }
        fn insert_issuer(&self, issuer: HostedIssuer) {
            self.issuers.lock().unwrap().push(issuer);
        }
        fn insert_key(&self, key: HostedIssuerKey) {
            self.keys.lock().unwrap().push(key);
        }
    }

    #[async_trait::async_trait]
    impl HostedIssuerStore for FakeLifecycleStore {
        async fn all_issuers(&self) -> Result<Vec<HostedIssuer>, HostedIssuerError> {
            Ok(self.issuers.lock().unwrap().clone())
        }

        async fn list_issuers_after(
            &self,
            _after: Option<&str>,
            _limit: usize,
            _filters: &HostedIssuerFilter,
            _now: OffsetDateTime,
        ) -> Result<Vec<HostedIssuer>, HostedIssuerError> {
            Ok(self.issuers.lock().unwrap().clone())
        }

        async fn issuer_keys(
            &self,
            issuer_id: &str,
        ) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Ok(self
                .keys
                .lock()
                .unwrap()
                .iter()
                .filter(|key| key.issuer_id == issuer_id)
                .cloned()
                .collect())
        }

        async fn find_key_by_kid(
            &self,
            kid: &str,
        ) -> Result<
            Option<crate::domain::models::hosted_issuer::HostedIssuerKeyEntry>,
            HostedIssuerError,
        > {
            let found = {
                let keys = self.keys.lock().unwrap();
                keys.iter()
                    .find(|key| key.kid == kid)
                    .map(|key| (key.issuer_id.clone(), key.clone()))
            };
            match found {
                Some((issuer_id, key)) => {
                    let issuer = self.issuer(&issuer_id).ok_or(HostedIssuerError::NotFound)?;
                    Ok(Some(
                        crate::domain::models::hosted_issuer::HostedIssuerKeyEntry { issuer, key },
                    ))
                }
                None => Ok(None),
            }
        }

        async fn find_issuer(&self, id: &str) -> Result<Option<HostedIssuer>, HostedIssuerError> {
            Ok(self.issuer(id))
        }

        async fn create_issuer(
            &self,
            issuer: HostedIssuer,
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            self.insert_issuer(issuer.clone());
            Ok(issuer)
        }

        async fn create_issuer_with_key(
            &self,
            issuer: HostedIssuer,
            key: HostedIssuerKey,
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            self.insert_key(key);
            self.insert_issuer(issuer.clone());
            Ok(issuer)
        }

        async fn add_key(
            &self,
            key: HostedIssuerKey,
            _actor: &str,
        ) -> Result<(), HostedIssuerError> {
            self.keys.lock().unwrap().push(key);
            Ok(())
        }

        async fn add_key_if_version(
            &self,
            key: HostedIssuerKey,
            expected_version: u64,
            _actor: &str,
        ) -> Result<(), HostedIssuerError> {
            let mut issuers = self.issuers.lock().unwrap();
            let issuer = issuers
                .iter_mut()
                .find(|issuer| issuer.id == key.issuer_id)
                .ok_or(HostedIssuerError::NotFound)?;
            if issuer.version != expected_version {
                return Err(HostedIssuerError::VersionMismatch);
            }
            if let Some(max_keys) = *self.key_limit.lock().unwrap()
                && self
                    .keys
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|stored| {
                        stored.issuer_id == key.issuer_id
                            && stored.state != HostedIssuerKeyState::Revoked
                    })
                    .count()
                    >= max_keys
            {
                return Err(HostedIssuerError::KeyQuotaExceeded { max_keys });
            }
            self.keys.lock().unwrap().push(key);
            issuer.version += 1;
            Ok(())
        }

        async fn all_keys(&self) -> Result<Vec<HostedIssuerKey>, HostedIssuerError> {
            Ok(self.keys.lock().unwrap().clone())
        }

        async fn find_key_by_material(
            &self,
            _material: &str,
        ) -> Result<Option<HostedIssuerKey>, HostedIssuerError> {
            Ok(None)
        }

        async fn find_issuer_ids(
            &self,
            _ids: &[String],
        ) -> Result<HashSet<String>, HostedIssuerError> {
            Ok(HashSet::new())
        }
    }

    #[async_trait::async_trait]
    impl HostedIssuerLifecycleStore for FakeLifecycleStore {
        async fn get_issuer(&self, id: &str) -> Result<HostedIssuer, HostedIssuerError> {
            self.issuer(id).ok_or(HostedIssuerError::NotFound)
        }

        async fn set_issuer_state(
            &self,
            id: &str,
            state: HostedIssuerState,
            expected_version: u64,
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            let mut issuers = self.issuers.lock().unwrap();
            let issuer = issuers
                .iter_mut()
                .find(|issuer| issuer.id == id)
                .ok_or(HostedIssuerError::NotFound)?;
            if issuer.version != expected_version {
                return Err(HostedIssuerError::VersionMismatch);
            }
            if issuer.state != state {
                issuer.state = state;
                issuer.version += 1;
            }
            Ok(issuer.clone())
        }

        async fn set_issuer_expiry(
            &self,
            id: &str,
            expires_at: OffsetDateTime,
            expected_version: u64,
            _actor: &str,
        ) -> Result<HostedIssuer, HostedIssuerError> {
            let mut issuers = self.issuers.lock().unwrap();
            let issuer = issuers
                .iter_mut()
                .find(|issuer| issuer.id == id)
                .ok_or(HostedIssuerError::NotFound)?;
            if issuer.version != expected_version {
                return Err(HostedIssuerError::VersionMismatch);
            }
            if issuer.expires_at != Some(expires_at) {
                issuer.expires_at = Some(expires_at);
                issuer.version += 1;
            }
            Ok(issuer.clone())
        }

        async fn revoke_key(
            &self,
            issuer_id: &str,
            kid: &str,
            expected_version: u64,
            _actor: &str,
        ) -> Result<HostedIssuerKey, HostedIssuerError> {
            let mut issuers = self.issuers.lock().unwrap();
            let issuer = issuers
                .iter_mut()
                .find(|issuer| issuer.id == issuer_id)
                .ok_or(HostedIssuerError::NotFound)?;
            let mut keys = self.keys.lock().unwrap();
            let key = keys
                .iter_mut()
                .find(|key| key.issuer_id == issuer_id && key.kid == kid)
                .ok_or(HostedIssuerError::NotFound)?;
            if key.state == HostedIssuerKeyState::Revoked {
                return Ok(key.clone());
            }
            if issuer.version != expected_version {
                return Err(HostedIssuerError::VersionMismatch);
            }
            key.state = HostedIssuerKeyState::Revoked;
            issuer.version += 1;
            Ok(key.clone())
        }
    }

    fn issuer(id: &str, expires_at: Option<OffsetDateTime>) -> HostedIssuer {
        HostedIssuer {
            id: id.into(),
            display_name: None,
            tier: "standard".into(),
            state: HostedIssuerState::Active,
            owner: None,
            created_at: service_now() - time::Duration::days(30),
            expires_at,
            version: 1,
            aggregation_id: AggregationId::generate(),
        }
    }

    fn key(issuer_id: &str) -> HostedIssuerKey {
        HostedIssuerKey {
            kid: "rotated".into(),
            issuer_id: issuer_id.into(),
            jwk: admin_public_jwk(),
            created_at: service_now() - time::Duration::days(30),
            not_before: None,
            not_after: None,
            state: HostedIssuerKeyState::Active,
        }
    }

    fn registry_yaml(scopes: &[&str]) -> String {
        serde_saphyr::to_string(&serde_json::json!({
            "version": 1,
            "issuers": [{
                "id": "static-issuer",
                "aggregation_id": uuid::Uuid::new_v4(),
                "keys": [{
                    "kid": issuer_public_jwk().key_id(),
                    "alg": "ES256",
                    "jwk": issuer_public_jwk().jwk(),
                }],
            }],
            "admins": [{
                "id": "portal-admin",
                "scopes": scopes,
                "keys": [{
                    "kid": admin_public_jwk().key_id(),
                    "alg": "ES256",
                    "jwk": admin_public_jwk().jwk(),
                }],
            }],
        }))
        .unwrap()
    }

    fn admin_token(typ: &str, kid: &str, iss: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(typ.into());
        header.kid = Some(kid.into());
        let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let secret = EncodingKey::from_ec_pem(ADMIN_EC_PRIVATE_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({"iss": iss, "iat": now, "exp": now + 300, "aud": ["status-list-server-admin"]}),
            &secret,
        )
        .unwrap()
    }

    struct LifecycleApp {
        app: axum::Router,
        state: AppState,
        store: Arc<FakeLifecycleStore>,
    }

    impl LifecycleApp {
        async fn new(scopes: &[&str]) -> Self {
            let store = Arc::new(FakeLifecycleStore::default());
            let mut state = test_app_state(None).await;
            let registry = Arc::new(RegistryHandle::from_yaml(&registry_yaml(scopes)).unwrap());
            state.admin_registry = registry;
            state.admin_auth = crate::server::AdminAuthConfig {
                leeway_secs: 60,
                max_token_lifetime_secs: 300,
                audiences: vec!["status-list-server-admin".into()],
            };
            state.hosted_issuer_store = Some(store.clone());
            state.hosted_lifecycle_service = Some(Arc::new(
                HostedIssuerLifecycleService::with_clock(store.clone(), Arc::new(service_now)),
            ));
            // The same route tree `hosted_admin_routes` mounts on the admin
            // listener.
            let app = axum::Router::new()
                .route("/admin/v1/issuers", post(create_issuer))
                .route("/admin/v1/issuers/{issuer_id}", patch(update_issuer))
                .route("/admin/v1/issuers/{issuer_id}/keys", post(add_issuer_key))
                .route(
                    "/admin/v1/issuers/{issuer_id}/keys/{kid}",
                    patch(revoke_issuer_key),
                )
                .route_layer(from_fn_with_state(
                    state.clone(),
                    crate::server::auth::admin_auth,
                ))
                .with_state(state.clone());
            Self { app, state, store }
        }

        /// The ETag the admin client would have read from
        /// `GET /admin/v1/issuers/{issuer_id}`.
        async fn current_etag(&self, issuer_id: &str) -> String {
            let issuer = self.store.issuer(issuer_id).unwrap();
            let dto = crate::server::handlers::admin::hosted_dto(&self.state, issuer)
                .await
                .unwrap();
            crate::server::handlers::admin::issuer_etag(&dto)
        }

        async fn current_version(&self, issuer_id: &str) -> String {
            let issuer = self.store.issuer(issuer_id).unwrap();
            let dto = crate::server::handlers::admin::hosted_dto(&self.state, issuer)
                .await
                .unwrap();
            crate::server::handlers::admin::issuer_write_version(&dto)
        }

        async fn patch(
            &self,
            uri: &str,
            token: &str,
            if_match: Option<&str>,
            body: &str,
        ) -> Response {
            let mut builder = Request::builder()
                .method(Method::PATCH)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(if_match) = if_match {
                builder = builder.header(header::IF_MATCH, if_match);
            }
            self.app
                .clone()
                .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
                .await
                .unwrap()
        }

        async fn post(
            &self,
            uri: &str,
            token: &str,
            if_match: Option<&str>,
            body: &str,
        ) -> Response {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(if_match) = if_match {
                builder = builder.header(header::IF_MATCH, if_match);
            }
            self.app
                .clone()
                .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
                .await
                .unwrap()
        }
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn write_token() -> String {
        admin_token("statuslist-admin+jwt", "admin-key", "portal-admin")
    }

    #[tokio::test]
    async fn suspend_and_resume_use_if_match_etags() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        app.store.insert_issuer(issuer(
            "portal-issuer",
            Some(service_now() + time::Duration::days(30)),
        ));
        let token = write_token();
        let uri = "/admin/v1/issuers/portal-issuer";

        // No If-Match: the change is refused before anything is read.
        let response = app
            .patch(uri, &token, None, r#"{"state":"suspended"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(body_json(response).await["error"], "precondition_required");

        // A stale If-Match fails with the current ETag attached.
        let response = app
            .patch(uri, &token, Some(r#""stale""#), r#"{"state":"suspended"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert!(response.headers().contains_key(header::ETAG));

        let response = app
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        "If-Issuer-Version",
                        app.current_version("portal-issuer").await,
                    )
                    .header(header::IF_MATCH, r#""stale""#)
                    .body(Body::from(r#"{"state":"suspended"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

        let etag = app.current_etag("portal-issuer").await;
        let response = app
            .patch(uri, &token, Some(&etag), r#"{"state":"suspended"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let suspended_etag = response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = body_json(response).await;
        assert_eq!(body["state"], "suspended");
        assert_ne!(suspended_etag, etag);

        let version = app.current_version("portal-issuer").await;
        crate::test_utils::publish_list(&app.state.service, "portal-issuer", "list-1").await;
        let response = app
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("if-issuer-version", &version)
                    .body(Body::from(r#"{"state":"suspended"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["issuer-version"], version);

        // The old ETag no longer matches after the change.
        let response = app
            .patch(uri, &token, Some(&etag), r#"{"state":"active"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

        // Re-applying the same state is a no-op that keeps the ETag stable.
        let response = app
            .patch(
                uri,
                &token,
                Some(&suspended_etag),
                r#"{"state":"suspended"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::ETAG)
                .unwrap()
                .to_str()
                .unwrap(),
            suspended_etag
        );

        let response = app
            .patch(uri, &token, Some(&suspended_etag), r#"{"state":"active"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["state"], "active");
    }

    #[tokio::test]
    async fn add_key_requires_current_etag_and_returns_the_assigned_key() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        app.store.insert_issuer(issuer(
            "portal-issuer",
            Some(service_now() + time::Duration::days(30)),
        ));
        let token = write_token();
        let etag = app.current_etag("portal-issuer").await;
        let body = r#"{
            "public_key": {
                "kty": "EC", "crv": "P-256",
                "x": "qaCUinBNo9IgFyzWGAu6KfXt3F7eO96BcnzXj5CzedY",
                "y": "BWYxfxFdS_axRuHChV_3uQ1DQFccSMXFqNrBqdBobks"
            },
            "alg": "ES256"
        }"#;

        let response = app
            .post(
                "/admin/v1/issuers/portal-issuer/keys",
                &token,
                Some(&etag),
                body,
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().contains_key(header::LOCATION));
        let next_etag = response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_ne!(next_etag, etag);
        let response_body = body_json(response).await;
        assert_eq!(response_body["state"], "active");
        assert_eq!(
            response_body["kid"],
            "QoRTRSkzlInq0eOmPqJwmZ5OS9pxkN_SIf5KgZP2F8M"
        );
        assert_eq!(app.store.issuer("portal-issuer").unwrap().version, 2);

        let response = app
            .post(
                "/admin/v1/issuers/portal-issuer/keys",
                &token,
                Some(&etag),
                body,
            )
            .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn key_limit_returns_documented_conflict() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        app.store.insert_issuer(issuer(
            "portal-issuer",
            Some(service_now() + time::Duration::days(30)),
        ));
        *app.store.key_limit.lock().unwrap() = Some(2);
        app.store.insert_key(key("portal-issuer"));
        app.store.insert_key(key("portal-issuer"));
        let etag = app.current_etag("portal-issuer").await;
        let response = app
            .post(
                "/admin/v1/issuers/portal-issuer/keys",
                &write_token(),
                Some(&etag),
                r#"{"public_key":{"kty":"EC","crv":"P-256","x":"qaCUinBNo9IgFyzWGAu6KfXt3F7eO96BcnzXj5CzedY","y":"BWYxfxFdS_axRuHChV_3uQ1DQFccSMXFqNrBqdBobks"},"alg":"ES256"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(response).await["error"], "key_limit_reached");
    }

    #[tokio::test]
    async fn patch_requires_write_scope_after_signature_verification() {
        let app = LifecycleApp::new(&["issuers:read"]).await;
        app.store.insert_issuer(issuer(
            "portal-issuer",
            Some(service_now() + time::Duration::days(30)),
        ));
        let token = write_token();

        let response = app
            .patch(
                "/admin/v1/issuers/portal-issuer",
                &token,
                Some("*"),
                r#"{"state":"suspended"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        assert_eq!(body_json(response).await["error"], "insufficient_scope");
        assert!(
            challenge
                .as_deref()
                .is_some_and(|value| value.contains("insufficient_scope"))
        );

        // The revoke route demands the same scope, before any If-Match work.
        let response = app
            .patch(
                "/admin/v1/issuers/portal-issuer/keys/rotated",
                &token,
                Some(r#""anything""#),
                r#"{"state":"revoked"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn issuer_and_management_tokens_are_rejected() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        let uri = "/admin/v1/issuers/static-issuer";

        // A key registered to a static issuer is not an admin key: the kid
        // alone is rejected before any claim is looked at.
        let issuer_token = admin_token("statuslist-admin+jwt", "issuer-key", "static-issuer");
        let response = app
            .patch(uri, &issuer_token, Some("*"), r#"{"state":"suspended"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // An admin key presented with the management token type is rejected.
        let management_token =
            admin_token("statuslist-management+jwt", "admin-key", "portal-admin");
        let response = app
            .patch(
                uri,
                &management_token,
                Some("*"),
                r#"{"state":"suspended"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // A valid admin key with the wrong principal id is not that admin.
        let stranger_token = admin_token("statuslist-admin+jwt", "admin-key", "someone-else");
        let response = app
            .patch(uri, &stranger_token, Some("*"), r#"{"state":"suspended"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn static_issuers_are_managed_by_configuration() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        let token = write_token();

        let response = app
            .patch(
                "/admin/v1/issuers/static-issuer",
                &token,
                Some("*"),
                r#"{"state":"suspended"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            body_json(response).await["error"],
            "issuer_managed_by_configuration"
        );

        let response = app
            .patch(
                "/admin/v1/issuers/static-issuer/keys/some-key",
                &token,
                Some("*"),
                r#"{"state":"revoked"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let response = app
            .post(
                "/admin/v1/issuers/static-issuer/keys",
                &token,
                None,
                r#"{"public_key":{},"alg":"ES256"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn unknown_issuers_and_keys_are_not_found() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        app.store.insert_issuer(issuer(
            "portal-issuer",
            Some(service_now() + time::Duration::days(30)),
        ));
        app.store.insert_key(key("portal-issuer"));
        let token = write_token();

        let response = app
            .patch(
                "/admin/v1/issuers/unknown-issuer",
                &token,
                Some("*"),
                r#"{"state":"suspended"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(response).await["error"], "issuer_not_found");

        let response = app
            .patch(
                "/admin/v1/issuers/portal-issuer/keys/unknown-key",
                &token,
                Some("*"),
                r#"{"state":"revoked"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(response).await["error"], "key_not_found");
    }

    #[tokio::test]
    async fn expired_issuers_cannot_be_reactivated() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        let mut expired = issuer(
            "portal-issuer",
            Some(service_now() - time::Duration::days(1)),
        );
        expired.state = HostedIssuerState::Suspended;
        app.store.insert_issuer(expired);
        let token = write_token();

        let response = app
            .patch(
                "/admin/v1/issuers/portal-issuer",
                &token,
                Some("*"),
                r#"{"state":"active"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body_json(response).await["error"], "invalid_expiry");
    }

    #[tokio::test]
    async fn malformed_and_unknown_bodies_are_rejected() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        app.store.insert_issuer(issuer(
            "portal-issuer",
            Some(service_now() + time::Duration::days(30)),
        ));
        let token = write_token();
        let uri = "/admin/v1/issuers/portal-issuer";

        for body in [
            r#"{"state":"suspended","expires_at":123}"#,
            r#"{"state":"suspended","extra":true}"#,
            r#"{"state":"terminated"}"#,
            r#"{"}"#,
        ] {
            let response = app.patch(uri, &token, Some("*"), body).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "body {body} must be rejected as invalid input"
            );
            assert_eq!(body_json(response).await["error"], "invalid_input");
        }
        let response = app
            .patch(uri, &token, Some("*"), r#"{"expires_at":123}"#)
            .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body_json(response).await["error"], "invalid_expiry");
    }

    #[tokio::test]
    async fn revoking_a_key_is_permanent_and_idempotent() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        app.store.insert_issuer(issuer(
            "portal-issuer",
            Some(service_now() + time::Duration::days(30)),
        ));
        app.store.insert_key(key("portal-issuer"));
        let mut other_key = key("portal-issuer");
        other_key.kid = "other-key".into();
        app.store.insert_key(other_key);
        let token = write_token();
        let uri = "/admin/v1/issuers/portal-issuer/keys/rotated";

        let response = app.patch(uri, &token, None, r#"{"state":"revoked"}"#).await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);

        let response = app
            .patch(uri, &token, Some("*"), r#"{"state":"active"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let etag = app.current_etag("portal-issuer").await;
        let response = app
            .patch(uri, &token, Some(&etag), r#"{"state":"revoked"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let revoked_etag = response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = body_json(response).await;
        assert_eq!(body["kid"], "rotated");
        assert_eq!(body["state"], "revoked");
        assert_ne!(revoked_etag, etag);

        // A stale validator is rejected even when the requested state is unchanged.
        let response = app
            .patch(uri, &token, Some(&etag), r#"{"state":"revoked"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(response.headers()[header::ETAG], revoked_etag);
        assert_eq!(body_json(response).await["error"], "precondition_failed");

        let response = app
            .patch(
                "/admin/v1/issuers/portal-issuer/keys/other-key",
                &token,
                Some(&etag),
                r#"{"state":"revoked"}"#,
            )
            .await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

        let response = app
            .patch(uri, &token, Some(&revoked_etag), r#"{"state":"revoked"}"#)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_assigns_identifiers_and_rejects_caller_supplied_fields() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        let token = write_token();
        let key = serde_json::json!({
            "kty":"EC", "crv":"P-256",
            "x":"qaCUinBNo9IgFyzWGAu6KfXt3F7eO96BcnzXj5CzedY",
            "y":"BWYxfxFdS_axRuHChV_3uQ1DQFccSMXFqNrBqdBobks"
        });
        for field in ["id", "kid", "source", "tier"] {
            let mut body = serde_json::json!({
                "display_name":"Sandbox", "owner":"github|5821374",
                "public_key":key, "alg":"ES256"
            });
            body[field] = serde_json::json!("caller-value");
            let response = app
                .post("/admin/v1/issuers", &token, None, &body.to_string())
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        }
        let request_body = serde_json::json!({
            "display_name":"Sandbox", "owner":"github|5821374",
            "public_key":key, "alg":"ES256"
        });
        let response = app
            .post("/admin/v1/issuers", &token, None, &request_body.to_string())
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().contains_key(header::LOCATION));
        let body = body_json(response).await;
        assert_eq!(body["source"], "portal");
        assert_eq!(body["tier"], "sandbox");
        assert_eq!(body["keys"].as_array().unwrap().len(), 1);
        assert_eq!(
            uuid::Uuid::parse_str(body["id"].as_str().unwrap())
                .unwrap()
                .get_version_num(),
            4
        );

        let read_only = LifecycleApp::new(&["issuers:read"]).await;
        let response = read_only
            .post("/admin/v1/issuers", &token, None, &request_body.to_string())
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn expired_issuer_can_renew_with_bounded_expiry() {
        let app = LifecycleApp::new(&["issuers:write"]).await;
        app.store.insert_issuer(issuer(
            "portal-issuer",
            Some(OffsetDateTime::now_utc() - time::Duration::days(1)),
        ));
        let token = write_token();
        let uri = "/admin/v1/issuers/portal-issuer";
        let etag = app.current_etag("portal-issuer").await;
        let expiry = (OffsetDateTime::now_utc() + time::Duration::days(7)).unix_timestamp();
        let response = app
            .patch(
                uri,
                &token,
                Some(&etag),
                &format!(r#"{{"expires_at":{expiry}}}"#),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["expires_at"], expiry);
        let too_far = (OffsetDateTime::now_utc() + time::Duration::days(31)).unix_timestamp();
        let response = app
            .patch(
                uri,
                &token,
                Some("*"),
                &format!(r#"{{"expires_at":{too_far}}}"#),
            )
            .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body_json(response).await["error"], "invalid_expiry");
    }
}
