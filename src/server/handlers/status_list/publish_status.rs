use axum::{
    extract::rejection::JsonRejection,
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::domain::models::status_list::StatusListError;
use crate::domain::service::PublishStatusListCommand;
use crate::server::{AppState, auth::AuthenticatedIssuer, error::ApiError};

use super::utils::request::{Status, StatusEntry, StatusesRequest};

#[derive(Deserialize)]
pub struct PublishStatusesRequest {
    pub statuses: Vec<StatusEntry>,
    pub size: Option<u32>,
    pub default_status: Option<Status>,
}

impl From<StatusesRequest> for PublishStatusesRequest {
    fn from(request: StatusesRequest) -> Self {
        Self {
            statuses: request.statuses,
            size: None,
            default_status: None,
        }
    }
}

/// Response body of a successful `PUT /status-lists/{list_id}/statuses`.
///
/// `uri` is the absolute URI of the newly created status list. Per spec
/// §5.1/§5.2/§8.3 the issuer MUST embed this exact URI in the Referenced
/// Token's `status.status_list.uri`; the status list token's own `sub` carries
/// the same URI so relying parties can resolve it.
#[derive(Debug, Serialize)]
pub(super) struct PublishStatusResponse {
    pub uri: String,
    pub list_id: String,
    /// Fixed list size actually stored by the server after byte-alignment
    /// rounding, or `None` for caller-managed (grow-on-write) lists.
    pub size: Option<u32>,
    /// Number of bits stored for each status entry.
    pub bits: u8,
}

/// Parse a `list_id` path segment as a UUID, accepting only the lowercase,
/// hyphenated form. [`uuid::Uuid::try_parse`] also accepts braced, `urn:uuid:`,
/// no-hyphen and uppercase forms, which would otherwise be signed verbatim into
/// the published `sub` (the braced form is not even a valid URI).
fn parse_list_id_uuid(list_id: &str) -> Result<uuid::Uuid, String> {
    let uuid = uuid::Uuid::try_parse(list_id).map_err(|err| err.to_string())?;
    if uuid.hyphenated().to_string() != list_id {
        return Err("list_id must be a lowercase, hyphenated UUID".to_string());
    }
    Ok(uuid)
}

/// Build the absolute `sub`/`Location` URI for a status list by appending
/// `/status-lists/{list_id}` to the configured public base URL.
///
/// The base URL was normalized and validated at config load (no query,
/// fragment, or trailing slash — except a root-path base, which normalizes to
/// `https://host/`), so trimming a single trailing slash before appending is
/// enough to guarantee exactly one `/` at the boundary without a double slash.
fn build_status_list_uri(public_base_url: &str, list_id: &str) -> String {
    format!(
        "{}/status-lists/{list_id}",
        public_base_url.trim_end_matches('/')
    )
}

/// Map a publish error to an `ApiError`. A `409` conflict carries the stored
/// list URI as the `Location` header so a racing publisher can adopt the
/// canonical `sub` for the `list_id` it already supplied.
async fn publish_error(appstate: &AppState, list_id: &str, err: StatusListError) -> ApiError {
    if matches!(err, StatusListError::AlreadyExists)
        && let Ok(record) = appstate.service.get_status_list(list_id).await
        && let Ok(value) = axum::http::HeaderValue::try_from(&record.sub)
    {
        return ApiError::conflict(
            "status_list_already_exists",
            "Status list already exists",
        )
        .with_header(axum::http::header::LOCATION, value);
    }
    err.into()
}

/// Publish a new status list.
///
/// Handle PUT /status-lists/{list_id}/statuses request.
///
/// `err(level = "info")` for the reason on `update_status`: the default ERROR
/// level would page on write contention and on a racing publish, both 409s the
/// response layer already logs at the right severity.
#[tracing::instrument(skip_all, fields(list_id = %list_id, issuer = %principal), err(level = "info", Debug))]
pub async fn publish_status(
    State(appstate): State<AppState>,
    principal: AuthenticatedIssuer,
    Path(list_id): Path<String>,
    Json(payload): Json<StatusesRequest>,
) -> Result<impl IntoResponse, ApiError> {
    publish_status_with_options(
        State(appstate),
        principal,
        Path(list_id),
        Json(payload.into()),
    )
    .await
}

async fn publish_status_with_options(
    State(appstate): State<AppState>,
    principal: AuthenticatedIssuer,
    Path(list_id): Path<String>,
    Json(payload): Json<PublishStatusesRequest>,
) -> Result<impl IntoResponse, ApiError> {
    parse_list_id_uuid(&list_id).map_err(|message| ApiError::bad_request("invalid_list_id", message))?;

    let statuses = payload
        .statuses
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();
    let default_status = payload.default_status.map(Into::into);

    // Build the sub URI *before* the write: it depends only on config and
    // `list_id`, so a failure here must never leave a stored list whose URI the
    // issuer cannot see. The value signed into `sub` is what `record.sub` holds
    // afterwards, so the response body echoes exactly what was stored.
    let uri = build_status_list_uri(&appstate.public_base_url, &list_id);

    let policy = appstate.status_list_policy();
    let record = match appstate
        .service
        .publish_status_list(
            PublishStatusListCommand {
                list_id: list_id.clone(),
                issuer: principal.into(),
                sub: uri.clone(),
                statuses,
                size: payload.size,
                default_status,
            },
            &policy,
        )
        .await
    {
        Ok(record) => record,
        Err(err) => return Err(publish_error(&appstate, &list_id, err).await),
    };

    let mut headers = HeaderMap::new();
    let location = axum::http::HeaderValue::try_from(&record.sub).map_err(|err| {
        tracing::error!(
            %record.sub,
            "publish Location header is not a valid HTTP header value: {err}"
        );
        ApiError::internal("generated status list URI cannot be represented as a Location header")
    })?;
    headers.insert(axum::http::header::LOCATION, location);

    Ok((
        StatusCode::CREATED,
        headers,
        Json(PublishStatusResponse {
            uri: record.sub,
            list_id: record.list_id,
            size: record.status_list.size,
            bits: record.status_list.bits,
        }),
    )
        .into_response())
}

pub async fn publish_status_route(
    state: State<AppState>,
    principal: AuthenticatedIssuer,
    path: Path<String>,
    payload: Result<Json<PublishStatusesRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let payload = payload.map_err(|err| {
        ApiError::bad_request(
            "invalid_request_body",
            format!("Invalid status update request body: {err}"),
        )
    })?;
    publish_status_with_options(state, principal, path, payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::server::handlers::status_list::utils::request::{
        Status as RequestStatus, StatusEntry as RequestStatusEntry,
    };
    use crate::test_utils::{authenticated_issuer, test_app_state};
    use axum::{Router, body::Body, body::to_bytes, routing::get, routing::put};
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    use tower::ServiceExt;

    fn decompress(encoded: &str) -> Vec<u8> {
        let decoded = base64url::decode(encoded).unwrap();
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        decompressed
    }

    /// Decode the JWT payload of a freshly served (uncompressed) token so tests
    /// can assert the `sub` claim directly without a verification key.
    fn decode_jwt_claims(jwt: &[u8]) -> serde_json::Value {
        use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
        let jwt = std::str::from_utf8(jwt).expect("JWT body is UTF-8");
        let payload = jwt.split('.').nth(1).expect("JWT has three segments");
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .expect("JWT payload is valid base64url");
        serde_json::from_slice(&decoded).expect("JWT payload is valid JSON")
    }

    /// Extract the `sub` (Subject, label 2) from a freshly served CWT token.
    fn decode_cwt_sub(cwt: &[u8]) -> String {
        use coset::{CborSerializable, TaggedCborSerializable};
        let sign1 = coset::CoseSign1::from_tagged_slice(cwt).expect("CWT is a tagged COSE_Sign1");
        let payload = sign1
            .payload
            .as_ref()
            .expect("CWT carries a payload")
            .to_vec();
        let value: coset::cbor::Value =
            coset::cbor::Value::from_slice(&payload).expect("CWT payload is CBOR");
        let map = match value {
            coset::cbor::Value::Map(map) => map,
            _ => panic!("CWT payload must be a CBOR map"),
        };
        for (label, val) in map {
            if label == coset::cbor::Value::Integer(2.into())
                && let coset::cbor::Value::Text(sub) = val
            {
                return sub;
            }
        }
        panic!("CWT payload must carry a text `sub` claim (label 2)")
    }

    #[tokio::test]
    async fn test_published_token_sub_matches_publish_location() {
        use crate::server::handlers::status_list::get_status_list::get_status_list;
        use crate::server::handlers::status_list::utils::constants::{
            ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT,
        };

        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        // Mirror the production router, which nests the API under `/api/v1`.
        let router = Router::new()
            .nest(
                "/api/v1",
                Router::new()
                    .route(
                        "/status-lists/{list_id}/statuses/",
                        put(publish_status_route),
                    )
                    .route("/status-lists/{list_id}", get(get_status_list)),
            )
            .with_state(app_state.clone());

        // Publish, capturing the Location header and the body `uri`.
        let mut request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri(format!("/api/v1/status-lists/{token_id}/statuses/"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"statuses":[]}"#.to_string()))
            .unwrap();
        request
            .extensions_mut()
            .insert(authenticated_issuer("issuer"));

        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .expect("201 must carry a Location header")
            .to_str()
            .unwrap()
            .to_string();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["list_id"], token_id);
        assert_eq!(
            json["uri"], location,
            "body `uri` must match the Location header"
        );

        // The absolute Location URI must be resolvable: its scheme/authority
        // must match the configured public base URL, and its path must be the
        // route the GET handler serves. The router is nested under `/api/v1` a
        // few lines up, and `oneshot` cannot route by host, so the request
        // below sends only the path; the served token's `sub` must still equal
        // the full absolute URI byte for byte.
        let location_url = url::Url::parse(&location).expect("Location is a valid URL");
        let expected_base =
            url::Url::parse(&app_state.public_base_url).expect("public_base_url is a valid URL");
        assert_eq!(location_url.scheme(), "https");
        assert_eq!(
            location_url.host_str(),
            expected_base.host_str(),
            "Location authority must match the configured public_base_url"
        );
        assert_eq!(
            location_url.port(),
            expected_base.port(),
            "Location port must match the configured public_base_url"
        );
        assert_eq!(
            location_url.path(),
            format!("/api/v1/status-lists/{token_id}"),
            "Location path must map onto the served status-list route"
        );

        // GET that exact URL's path in JWT form and assert `sub` equals it.
        let jwt_resp = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri(location_url.path())
                    .header(axum::http::header::ACCEPT, ACCEPT_STATUS_LISTS_HEADER_JWT)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jwt_resp.status(), StatusCode::OK);
        let jwt_body = to_bytes(jwt_resp.into_body(), usize::MAX).await.unwrap();
        let claims = decode_jwt_claims(&jwt_body);
        assert_eq!(
            claims["sub"].as_str().unwrap(),
            location,
            "JWT sub must equal the publish Location byte for byte"
        );

        // And in CWT form.
        let cwt_resp = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri(location_url.path())
                    .header(axum::http::header::ACCEPT, ACCEPT_STATUS_LISTS_HEADER_CWT)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cwt_resp.status(), StatusCode::OK);
        let cwt_body = to_bytes(cwt_resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            decode_cwt_sub(&cwt_body),
            location,
            "CWT sub must equal the publish Location byte for byte"
        );

        // Compliance-matrix row 8 (§5.1) additionally requires the *stored*
        // `sub` to equal the Referenced Token's URI: the URI listed by the
        // aggregation endpoint must be the same one handed to the issuer at
        // publish time.
        let page = app_state
            .service
            .status_list_repo
            .list_uris(None, 10)
            .await
            .expect("stored rows are readable");
        assert!(
            page.status_lists.contains(&location),
            "stored `sub` must equal the publish Location, got {page:?}"
        );
    }

    /// A configured `public_base_url` whose host differs from `server.domain`
    /// must win for the published `sub`: the server signs the public base URL,
    /// not the ACME domain. This builds the base URL from real config so the
    /// test proves a non-default `public_base_url` actually reaches `sub`.
    #[tokio::test]
    async fn test_published_sub_uses_configured_public_base_url_over_domain() {
        use crate::config::Config;
        use crate::server::handlers::status_list::get_status_list::get_status_list;
        use crate::server::handlers::status_list::utils::constants::ACCEPT_STATUS_LISTS_HEADER_JWT;

        let config = Config::load_from_overrides(&[
            ("server.domain", "statuslist.example.com"),
            (
                "server.public_base_url",
                "https://status.example.org/api/v1",
            ),
        ])
        .expect("config loads");

        let mut app_state = test_app_state(None).await;
        app_state.public_base_url = config.server.resolved_public_base_url();
        let router = Router::new()
            .nest(
                "/api/v1",
                Router::new()
                    .route(
                        "/status-lists/{list_id}/statuses/",
                        put(publish_status_route),
                    )
                    .route("/status-lists/{list_id}", get(get_status_list)),
            )
            .with_state(app_state.clone());

        let token_id = uuid::Uuid::new_v4().to_string();
        let mut request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri(format!("/api/v1/status-lists/{token_id}/statuses/"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"statuses":[]}"#.to_string()))
            .unwrap();
        request
            .extensions_mut()
            .insert(authenticated_issuer("issuer"));

        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .expect("201 must carry a Location header")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            location.starts_with("https://status.example.org/api/v1/status-lists/"),
            "sub must use the configured public_base_url host, got {location}"
        );
        assert!(
            !location.starts_with("https://statuslist.example.com"),
            "sub must not fall back to server.domain, got {location}"
        );

        let location_url = url::Url::parse(&location).expect("Location is a valid URL");
        let jwt_resp = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri(location_url.path())
                    .header(axum::http::header::ACCEPT, ACCEPT_STATUS_LISTS_HEADER_JWT)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jwt_resp.status(), StatusCode::OK);
        let jwt_body = to_bytes(jwt_resp.into_body(), usize::MAX).await.unwrap();
        let claims = decode_jwt_claims(&jwt_body);
        assert_eq!(
            claims["sub"].as_str().unwrap(),
            location,
            "JWT sub must equal the publish Location byte for byte"
        );
    }

    /// The `sub` is fixed when a list is published: rebuilding the server state
    /// with a different `public_base_url` must not rewrite the stored `sub` of
    /// existing lists, because issued credentials still point at the original
    /// host. Both the served token and the aggregation listing must keep the
    /// first base URL.
    #[tokio::test]
    async fn test_stored_sub_survives_public_base_url_change() {
        use crate::server::handlers::status_list::get_status_list::get_status_list;
        use crate::server::handlers::status_list::utils::constants::ACCEPT_STATUS_LISTS_HEADER_JWT;

        let token_id = uuid::Uuid::new_v4().to_string();
        let mut state_original = test_app_state(None).await;
        let mut state_rebased = state_original.clone();
        state_original.public_base_url = "https://one.example/api/v1".to_string();
        state_rebased.public_base_url = "https://two.example/api/v1".to_string();

        // Publish under the original base URL.
        let first_uri = {
            let router = Router::new()
                .nest(
                    "/api/v1",
                    Router::new()
                        .route(
                            "/status-lists/{list_id}/statuses/",
                            put(publish_status_route),
                        )
                        .route("/status-lists/{list_id}", get(get_status_list)),
                )
                .with_state(state_original.clone());
            let mut request = axum::http::Request::builder()
                .method(axum::http::Method::PUT)
                .uri(format!("/api/v1/status-lists/{token_id}/statuses/"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"statuses":[]}"#.to_string()))
                .unwrap();
            request
                .extensions_mut()
                .insert(authenticated_issuer("issuer"));
            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .expect("201 must carry a Location header")
                .to_str()
                .unwrap()
                .to_string()
        };
        assert!(first_uri.starts_with("https://one.example/"));

        // Rebuild the state with a different base URL but the same stored list,
        // then serve the token and the aggregation: both must still use the
        // original URI.
        let rebased_router = Router::new()
            .nest(
                "/api/v1",
                Router::new()
                    .route("/status-lists/{list_id}", get(get_status_list))
                    .route("/aggregation", get(crate::server::handlers::get_aggregation)),
            )
            .with_state(state_rebased.clone());

        let first_path = url::Url::parse(&first_uri)
            .expect("first URI is valid")
            .path()
            .to_string();
        let jwt_resp = rebased_router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri(first_path)
                    .header(axum::http::header::ACCEPT, ACCEPT_STATUS_LISTS_HEADER_JWT)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jwt_resp.status(), StatusCode::OK);
        let jwt_body = to_bytes(jwt_resp.into_body(), usize::MAX).await.unwrap();
        let claims = decode_jwt_claims(&jwt_body);
        assert_eq!(
            claims["sub"].as_str().unwrap(),
            first_uri,
            "served sub must keep the original base URL after a public_base_url change"
        );

        let agg_resp = rebased_router
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/api/v1/aggregation")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(agg_resp.status(), StatusCode::OK);
        let agg_body = to_bytes(agg_resp.into_body(), usize::MAX).await.unwrap();
        let agg: serde_json::Value = serde_json::from_slice(&agg_body).unwrap();
        assert!(
            agg["status_lists"]
                .as_array()
                .map(|arr| arr.iter().any(|u| u.as_str() == Some(&first_uri)))
                .unwrap_or(false),
            "aggregation must keep the original URI, got {agg}"
        );
    }

    #[tokio::test]
    async fn test_publish_token_status_invalid_list_id() {
        let appstate = test_app_state(None).await;
        let issuer = "test-issuer".to_string();
        let payload = StatusesRequest { statuses: vec![] };

        let result = publish_status(
            State(appstate),
            authenticated_issuer(issuer),
            Path("not-a-uuid".to_string()),
            Json(payload),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected error for invalid list_id"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    /// Only the lowercase hyphenated UUID form is accepted as a `list_id`:
    /// braced, `urn:uuid:`, no-hyphen and uppercase forms would otherwise be
    /// signed verbatim into `sub` (the braced form is not even a valid URI).
    #[tokio::test]
    async fn test_publish_rejects_non_canonical_uuid_forms() {
        let canonical = uuid::Uuid::new_v4().to_string();
        let uppercase = canonical.to_uppercase();
        let no_hyphen = canonical.replace('-', "");
        let braced = format!("{{{canonical}}}");
        let urn = format!("urn:uuid:{canonical}");

        for bad in [uppercase.as_str(), no_hyphen.as_str(), braced.as_str(), urn.as_str()] {
            let appstate = test_app_state(None).await;
            let result = publish_status(
                State(appstate),
                authenticated_issuer("issuer"),
                Path(bad.to_string()),
                Json(StatusesRequest { statuses: vec![] }),
            )
            .await;
            let err = match result {
                Ok(_) => panic!("expected {bad:?} to be rejected as an invalid list_id"),
                Err(e) => e,
            };
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert_eq!(err.error, "invalid_list_id");
        }
    }

    #[tokio::test]
    async fn test_publish_status_creates_token() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let response = publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::CREATED);

        let token = app_state.service.get_status_list(&token_id).await.unwrap();
        assert_eq!(token.list_id, token_id);
    }

    #[tokio::test]
    async fn publish_route_rejects_status_values_above_255_as_json_400() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let router = Router::new()
            .route(
                "/status-lists/{list_id}/statuses/",
                put(publish_status_route),
            )
            .with_state(app_state);

        let mut request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri(format!("/status-lists/{token_id}/statuses/"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"statuses":[{"index":0,"status":256}]}"#.to_string(),
            ))
            .unwrap();
        request
            .extensions_mut()
            .insert(authenticated_issuer("issuer"));

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_request_body");
        assert!(
            json["error_description"]
                .as_str()
                .unwrap()
                .contains("not a supported Draft-21 status type")
        );
    }

    #[tokio::test]
    async fn publish_route_creates_pre_sized_list_with_default_and_rejects_oob_update() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let router = Router::new()
            .route(
                "/status-lists/{list_id}/statuses/",
                put(publish_status_route),
            )
            .with_state(app_state.clone());

        let mut request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri(format!("/status-lists/{token_id}/statuses/"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"statuses":[],"size":5,"default_status":1}"#.to_string(),
            ))
            .unwrap();
        request
            .extensions_mut()
            .insert(authenticated_issuer("issuer"));

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .is_some(),
            "201 must carry a Location header"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["list_id"], token_id);
        assert_eq!(
            json["uri"],
            "https://example.com/api/v1/status-lists/".to_string() + &token_id,
            "body `uri` must name the created list"
        );
        // `size` is the rounded value actually stored (5 -> 8), not the request
        // value, so callers learn the real list dimensions from the response.
        assert_eq!(json["size"], 8, "size must be the rounded stored value");
        assert_eq!(json["bits"], 1);

        let token = app_state.service.get_status_list(&token_id).await.unwrap();
        assert_eq!(token.status_list.size, Some(8));
        assert_eq!(decompress(&token.status_list.lst), vec![0xFF]);

        let err = app_state
            .service
            .update_statuses(
                &Issuer("issuer".to_string()),
                &token_id,
                vec![crate::domain::models::status_list::StatusEntry {
                    index: 8,
                    status: crate::domain::models::status_list::Status::Valid,
                }],
                &app_state.status_list_policy(),
            )
            .await
            .unwrap_err();
        let api: ApiError = err.into();
        assert_eq!(api.status, StatusCode::BAD_REQUEST);
        assert_eq!(api.error, "index_out_of_range");
    }

    #[tokio::test]
    async fn publish_route_rejects_zero_size_before_building_list() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let router = Router::new()
            .route(
                "/status-lists/{list_id}/statuses/",
                put(publish_status_route),
            )
            .with_state(app_state);

        let mut request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri(format!("/status-lists/{token_id}/statuses/"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"statuses":[],"size":0}"#.to_string()))
            .unwrap();
        request
            .extensions_mut()
            .insert(authenticated_issuer("issuer"));

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_size");
    }

    #[tokio::test]
    async fn publish_route_rejects_size_above_configured_index_limit() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.max_status_index = 7;
        let router = Router::new()
            .route(
                "/status-lists/{list_id}/statuses/",
                put(publish_status_route),
            )
            .with_state(app_state);

        let mut request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri(format!("/status-lists/{token_id}/statuses/"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"statuses":[],"size":9}"#.to_string()))
            .unwrap();
        request
            .extensions_mut()
            .insert(authenticated_issuer("issuer"));

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_size");
    }

    #[tokio::test]
    async fn fixed_size_update_rejects_unallocated_index() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let policy = app_state.status_list_policy();
        app_state
            .service
            .publish_status_list(
                PublishStatusListCommand {
                    list_id: token_id.clone(),
                    issuer: Issuer("issuer".to_string()),
                    sub: format!("https://example.test/{token_id}"),
                    statuses: vec![],
                    size: Some(8),
                    default_status: None,
                },
                &policy,
            )
            .await
            .unwrap();

        let err = app_state
            .service
            .update_statuses(
                &Issuer("issuer".to_string()),
                &token_id,
                vec![crate::domain::models::status_list::StatusEntry {
                    index: 0,
                    status: crate::domain::models::status_list::Status::Invalid,
                }],
                &app_state.status_list_policy(),
            )
            .await
            .unwrap_err();
        let api: ApiError = err.into();
        assert_eq!(api.status, StatusCode::CONFLICT);
        assert_eq!(api.error, "index_not_allocated");
    }

    #[tokio::test]
    async fn fixed_size_update_accepts_allocated_index() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let policy = app_state.status_list_policy();
        app_state
            .service
            .publish_status_list(
                PublishStatusListCommand {
                    list_id: token_id.clone(),
                    issuer: Issuer("issuer".to_string()),
                    sub: format!("https://example.test/{token_id}"),
                    statuses: vec![],
                    size: Some(8),
                    default_status: None,
                },
                &policy,
            )
            .await
            .unwrap();

        let allocated = app_state
            .service
            .allocate_indices(
                &Issuer("issuer".to_string()),
                &token_id,
                1,
                &app_state.status_list_policy(),
            )
            .await
            .unwrap();

        app_state
            .service
            .update_statuses(
                &Issuer("issuer".to_string()),
                &token_id,
                vec![crate::domain::models::status_list::StatusEntry {
                    index: allocated[0],
                    status: crate::domain::models::status_list::Status::Invalid,
                }],
                &app_state.status_list_policy(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_token_conflict() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let res1 = publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::CREATED);

        let res2 = publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await;

        let err = match res2 {
            Ok(_) => panic!("expected conflict error for duplicate list_id"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::CONFLICT);
    }

    /// Publish is insert-only for a list ID: once `issuer1` creates a list,
    /// another authenticated issuer cannot overwrite or hijack it with PUT.
    /// The original issuer's record must remain intact.
    #[tokio::test]
    async fn test_publish_status_rejects_wrong_issuer_republish() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let result = publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer2"),
            Path(token_id.clone()),
            Json(StatusesRequest {
                statuses: vec![RequestStatusEntry {
                    index: 0,
                    status: RequestStatus::INVALID,
                }],
            }),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected different issuer to be rejected for existing list_id"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.error, "status_list_already_exists");

        let record = app_state.service.get_status_list(&token_id).await.unwrap();
        assert_eq!(record.issuer, Issuer("issuer1".into()));
    }

    /// The losing publisher of a `list_id` race gets 409, not 500 — end to end,
    /// on a real backend.
    ///
    /// `test_token_conflict` above proves the same thing over the in-memory
    /// adapter, where `AlreadyExists` is returned by a `HashMap` lookup. That
    /// says nothing about a relational backend, where the conflict surfaces as a
    /// driver error raised *inside* an open transaction and has to survive the
    /// rollback with its classification intact:
    ///
    /// `sql_err()` → `RepositoryError::DuplicateEntry` (`sql::store::map_insert_err`)
    /// → `StatusListError::AlreadyExists` (`impl From<RepositoryError>` in `outbound::sql`)
    /// → **409** (`server::error`).
    ///
    /// Only the first hop can vary by backend, so the store's own
    /// `assert_duplicate_list_id_is_conflict` carries the
    /// per-backend burden — including the proof that the rolled-back publish
    /// leaves neither a snapshot nor a modified row. What *this* test adds is
    /// that the remaining hops are wired up at all: that the classification the
    /// store produces actually reaches the client as a status code.
    #[cfg(any(feature = "postgres-tests", feature = "mysql"))]
    async fn assert_publish_duplicate_is_conflict(
        db: std::sync::Arc<sea_orm::DatabaseConnection>,
        issuer: &str,
        backend: &str,
    ) {
        use crate::domain::models::credential::{Credential, Issuer, PublicJwk};
        use crate::test_fixtures::TEST_EC_PUBLIC_JWK;
        use crate::test_utils::test_app_state;

        let app_state = test_app_state(Some(db)).await;

        // status_lists.issuer is a foreign key onto credentials.issuer. Seeded
        // through the service rather than the store so this test depends only on
        // the domain API, not on the persistence schema.
        app_state
            .service
            .publish_credential(Credential {
                issuer: Issuer(issuer.to_string()),
                public_key: PublicJwk::try_new(TEST_EC_PUBLIC_JWK.as_bytes().to_vec()).unwrap(),
            })
            .await
            .unwrap();

        // The handler rejects a non-UUID list_id before reaching the service.
        let list_id = uuid::Uuid::new_v4().to_string();
        let publish = || {
            let state = app_state.clone();
            let list_id = list_id.clone();
            async move {
                publish_status(
                    State(state),
                    authenticated_issuer(issuer),
                    Path(list_id),
                    Json(StatusesRequest {
                        statuses: vec![RequestStatusEntry {
                            index: 0,
                            status: RequestStatus::VALID,
                        }],
                    }),
                )
                .await
            }
        };

        let created = publish()
            .await
            .unwrap_or_else(|e| panic!("first publish should succeed on {backend}: {e:?}"))
            .into_response();
        assert_eq!(
            created.status(),
            StatusCode::CREATED,
            "first publish should create the list on {backend}"
        );

        let err = match publish().await {
            Ok(_) => panic!("the losing publisher must not report success on {backend}"),
            Err(e) => e,
        };
        assert_eq!(
            err.status,
            StatusCode::CONFLICT,
            "a duplicate publish must map to 409, not 500, on {backend}"
        );
        // The status code alone does not pin the contract: 409 is also the
        // credential-conflict code. Assert the documented error identity too.
        assert_eq!(
            err.error, "status_list_already_exists",
            "the 409 must carry the status-list conflict code on {backend}"
        );
    }

    /// Postgres is the production backend, and the one where this could
    /// plausibly diverge: a failed statement poisons the transaction (`25P02`),
    /// so a classification read from the rollback rather than from the original
    /// `23505` would degrade to a 500 here and nowhere else.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn test_postgres_publish_duplicate_returns_409_not_500() {
        let test_db =
            crate::outbound::sql::test_containers::postgres_helpers::postgres_connection().await;
        assert_publish_duplicate_is_conflict(
            test_db.db.clone(),
            "issuer-race-postgres",
            "Postgres",
        )
        .await;
    }

    /// The same end-to-end proof on MySQL, whose driver reports duplicate keys
    /// in a different wire format (`1062`) that `sql_err()` has to normalise.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn test_mysql_publish_duplicate_returns_409_not_500() {
        let test_db =
            crate::outbound::sql::test_containers::mysql_helpers::MysqlTestDb::start().await;
        assert_publish_duplicate_is_conflict(
            test_db.connection().await,
            "issuer-race-mysql",
            "MySQL",
        )
        .await;
    }

    /// The snapshot-disabled publish path must also return 409, not 500.
    ///
    /// `snapshot_retention_secs = 0` builds a `Service` with no snapshot repo,
    /// so `publish_status_list` takes its `None` branch into the plain
    /// non-transactional `insert` — a different duplicate-classification call
    /// site from `insert_with_snapshot`, and the one no other end-to-end test
    /// covers. This matters more since `publish_status_list` stopped
    /// pre-checking with `find`: the constraint is now the only thing standing
    /// between a duplicate publish and a 500.
    #[tokio::test]
    async fn test_publish_duplicate_without_snapshots_returns_409() {
        use crate::domain::models::credential::{Credential, Issuer, PublicJwk};
        use crate::test_fixtures::TEST_EC_PUBLIC_JWK;
        use crate::test_utils::test_app_state_without_snapshots;

        let app_state = test_app_state_without_snapshots().await;
        assert!(
            app_state.service.snapshot_repo().is_none(),
            "this test is meaningless unless the snapshot repo is actually absent"
        );

        let issuer = "issuer-no-snapshots";
        app_state
            .service
            .publish_credential(Credential {
                issuer: Issuer(issuer.to_string()),
                public_key: PublicJwk::try_new(TEST_EC_PUBLIC_JWK.as_bytes().to_vec()).unwrap(),
            })
            .await
            .unwrap();

        let list_id = uuid::Uuid::new_v4().to_string();
        let publish = || {
            let state = app_state.clone();
            let list_id = list_id.clone();
            async move {
                publish_status(
                    State(state),
                    authenticated_issuer(issuer),
                    Path(list_id),
                    Json(StatusesRequest {
                        statuses: vec![RequestStatusEntry {
                            index: 0,
                            status: RequestStatus::VALID,
                        }],
                    }),
                )
                .await
            }
        };

        assert_eq!(
            publish()
                .await
                .expect("first publish should succeed")
                .into_response()
                .status(),
            StatusCode::CREATED
        );

        let err = publish()
            .await
            .err()
            .expect("the duplicate publish must not report success");
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.error, "status_list_already_exists");
    }

    /// Registering an issuer twice is a 409.
    ///
    /// `publish_credential` no longer pre-checks with `find`, so this pins that
    /// the primary key on `credentials.issuer` carries the conflict on its own
    /// and still reaches the client as `credentials_already_exist`.
    #[tokio::test]
    async fn test_duplicate_credential_registration_returns_409() {
        use crate::domain::models::credential::{Credential, Issuer, PublicJwk};
        use crate::server::error::ApiError;
        use crate::test_fixtures::TEST_EC_PUBLIC_JWK;

        let app_state = test_app_state(None).await;
        let credential = || Credential {
            issuer: Issuer("issuer-dup-registration".to_string()),
            public_key: PublicJwk::try_new(TEST_EC_PUBLIC_JWK.as_bytes().to_vec()).unwrap(),
        };

        app_state
            .service
            .publish_credential(credential())
            .await
            .expect("first registration should succeed");

        let err: ApiError = app_state
            .service
            .publish_credential(credential())
            .await
            .expect_err("the second registration must be rejected")
            .into();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.error, "credentials_already_exist");
    }

    #[tokio::test]
    async fn test_publish_status_rejects_too_many_statuses() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.max_statuses_per_request = 1;

        let status_entries = vec![
            RequestStatusEntry {
                index: 0,
                status: RequestStatus::VALID,
            },
            RequestStatusEntry {
                index: 1,
                status: RequestStatus::INVALID,
            },
        ];

        let result = publish_status(
            State(app_state),
            authenticated_issuer("issuer"),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_publish_status_rejects_index_too_large() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.max_status_index = 10;

        let status_entries = vec![RequestStatusEntry {
            index: 999_999,
            status: RequestStatus::VALID,
        }];

        let result = publish_status(
            State(app_state),
            authenticated_issuer("issuer"),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.error, "index_too_large");
    }

    #[tokio::test]
    async fn test_publish_status_rejects_duplicate_indices() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let result = publish_status(
            State(app_state),
            authenticated_issuer("issuer"),
            Path(token_id),
            Json(StatusesRequest {
                statuses: vec![
                    RequestStatusEntry {
                        index: 0,
                        status: RequestStatus::INVALID,
                    },
                    RequestStatusEntry {
                        index: 0,
                        status: RequestStatus::SUSPENDED,
                    },
                ],
            }),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected duplicate index update to be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.error, "duplicate_index");
    }

    #[tokio::test]
    async fn test_publish_status_rejects_serialized_list_too_large() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.max_serialized_list_size = 4;

        let mut status_entries = Vec::new();
        for i in 0..200 {
            status_entries.push(RequestStatusEntry {
                index: i,
                status: RequestStatus::INVALID,
            });
        }

        let result = publish_status(
            State(app_state),
            authenticated_issuer("issuer"),
            Path(token_id),
            Json(StatusesRequest {
                statuses: status_entries,
            }),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Covers both publish paths: with and without snapshot retention.
    #[tokio::test]
    async fn test_publish_status_rejects_issuer_over_list_quota() {
        use crate::test_utils::test_app_state_without_snapshots;

        for (mut app_state, path) in [
            (test_app_state(None).await, "with snapshots"),
            (
                test_app_state_without_snapshots().await,
                "without snapshots",
            ),
        ] {
            app_state.max_lists_per_issuer = 2;
            let publish = |issuer: &'static str| {
                publish_status(
                    State(app_state.clone()),
                    authenticated_issuer(issuer),
                    Path(uuid::Uuid::new_v4().to_string()),
                    Json(StatusesRequest { statuses: vec![] }),
                )
            };

            for _ in 0..2 {
                assert!(publish("issuer-full").await.is_ok(), "{path}");
            }

            let err = match publish("issuer-full").await {
                Ok(_) => panic!("the publish past the quota must be refused ({path})"),
                Err(e) => e,
            };
            assert_eq!(err.status, StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(err.error, "list_quota_exceeded", "{path}");
            let response = err.into_response();
            assert!(
                response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .is_none(),
                "waiting never frees a quota slot, so no Retry-After ({path})"
            );

            assert!(
                publish("issuer-with-room").await.is_ok(),
                "another issuer's quota is independent ({path})"
            );
        }
    }
}
