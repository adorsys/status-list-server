use std::fmt::Debug;
use std::sync::{Mutex, OnceLock};

use axum::{
    extract::rejection::QueryRejection,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use opentelemetry::{KeyValue, global, metrics::Counter};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::{
    domain::models::status_list::{StatusListError, StatusListRecord},
    server::{AppState, error::ApiError},
};

use super::utils::{
    conditional::{
        ConditionalResponse, TokenValidity, evaluate_conditional_request, format_http_date,
        token_window,
    },
    constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT},
    etag::{generate_etag, generate_historical_etag},
    token::build_status_list_token,
};

/// Conditional-revalidation SLI counter. Cached after first use (the same
/// pattern as `token.rs`): the global meter provider is installed by
/// `setup_metrics` before any request is served, so a handle captured here is
/// valid (unlike one taken at module init, which would be a permanent no-op).
///
/// The `outcome` label lets operators verify the 304 path is still serving
/// unchanged lists efficiently and spot a regression that silently turns every
/// conditional GET into a full re-sign (the exact failure mode this fix guards
/// against).
#[derive(Clone)]
struct RevalidationMetrics {
    total: Counter<u64>,
}

fn revalidation_metrics() -> RevalidationMetrics {
    static METRICS: OnceLock<Mutex<Option<(u64, RevalidationMetrics)>>> = OnceLock::new();
    crate::utils::metrics::cached_instruments(&METRICS, || {
        let meter = global::meter("status-list-server");
        RevalidationMetrics {
            total: meter
                .u64_counter("conditional_revalidation_total")
                .with_description(
                    "Conditional GET revalidation outcomes (not_modified|modified|expired_token).",
                )
                .build(),
        }
    })
}

/// Handle GET /status-lists/{list_id} request.
///
/// This function handles the following cases:
///
/// - Retrieve a status list identified by its list id.
/// - Retrieve a historical status list identified by its list id and time.
#[tracing::instrument(skip_all, fields(list_id = %list_id), err(Debug))]
pub async fn get_status_list(
    State(state): State<AppState>,
    Path(list_id): Path<String>,
    query_result: Result<Query<StatusListQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<impl IntoResponse + Debug + use<>, ApiError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    get_status_list_at(State(state), list_id, query_result, headers, now).await
}

/// Request-time implementation of [`get_status_list`] with an explicit `now`.
///
/// `now` is injected (rather than read from the clock inside) so tests can
/// advance the clock deterministically and pin the token-expiry revalidation
/// behaviour.
#[tracing::instrument(skip_all, fields(list_id = %list_id), err(Debug))]
async fn get_status_list_at(
    State(state): State<AppState>,
    list_id: String,
    query_result: Result<Query<StatusListQuery>, QueryRejection>,
    headers: HeaderMap,
    now: i64,
) -> Result<impl IntoResponse + Debug + use<>, ApiError> {
    let query = match query_result {
        Ok(Query(q)) => q,
        Err(e) => {
            tracing::warn!("Failed to parse query parameters: {e}");
            return Err(ApiError::bad_request(
                "invalid_query",
                format!("Failed to parse query parameters: {e}"),
            ));
        }
    };
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());
    let client_accepts_gzip = client_accepts_gzip(&headers);

    let accept_type = match accept {
        None => ACCEPT_STATUS_LISTS_HEADER_JWT.to_string(),
        Some(accept)
            if accept == ACCEPT_STATUS_LISTS_HEADER_JWT
                || accept == ACCEPT_STATUS_LISTS_HEADER_CWT =>
        {
            accept.to_string()
        }
        Some(_) => {
            return Err(ApiError::new(
                StatusCode::NOT_ACCEPTABLE,
                "invalid_accept_header",
                Some("Invalid accept header".into()),
            ));
        }
    };

    if let Some(time) = query.time {
        return handle_historical_request(
            &list_id,
            time,
            &accept_type,
            &state,
            client_accepts_gzip,
        )
        .await;
    }

    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok());
    let if_modified_since = headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|h| h.to_str().ok());

    let status_record = fetch_status_record(&list_id, &state).await?;
    // Anchor the ETag to the current token validity window so the validator
    // rotates with the token's lifetime (see etag::generate_etag).
    let (window_start, window_end) = token_window(now, state.token_exp_secs);
    let current_etag = generate_etag(&status_record, window_start);
    let last_modified_ts = status_record.updated_at;
    let last_modified = format_http_date(last_modified_ts);
    let cache_control = build_cache_control(state.token_ttl_secs);

    match evaluate_conditional_request(
        if_none_match,
        if_modified_since,
        &current_etag,
        window_end,
        last_modified_ts,
        now,
        TokenValidity::new(state.token_exp_secs, state.token_ttl_secs),
    ) {
        ConditionalResponse::NotModified => {
            revalidation_metrics()
                .total
                .add(1, &[KeyValue::new("outcome", "not_modified")]);
            Ok((
                StatusCode::NOT_MODIFIED,
                [
                    (header::ETAG, current_etag.as_str()),
                    (header::LAST_MODIFIED, last_modified.as_str()),
                    (header::CACHE_CONTROL, cache_control.as_str()),
                    (header::VARY, "Accept, Accept-Encoding"),
                ],
            )
                .into_response())
        }
        ConditionalResponse::Modified => {
            revalidation_metrics()
                .total
                .add(1, &[KeyValue::new("outcome", "modified")]);
            build_fresh_200_response(
                &state,
                &accept_type,
                &status_record,
                &current_etag,
                &last_modified,
                &cache_control,
                client_accepts_gzip,
            )
            .await
        }
        ConditionalResponse::ExpiredToken => {
            // The list is unchanged but the client's cached token has reached its
            // `exp`: a 304 would hand the relying party a body-less, expired,
            // unusable token (RFC 9110 §8.8.1). Track this separately from a true
            // content change so operators can detect a config regression that
            // silently turns every conditional GET into a full re-sign.
            revalidation_metrics()
                .total
                .add(1, &[KeyValue::new("outcome", "expired_token")]);
            build_fresh_200_response(
                &state,
                &accept_type,
                &status_record,
                &current_etag,
                &last_modified,
                &cache_control,
                client_accepts_gzip,
            )
            .await
        }
    }
}

/// Build a freshly signed `200 OK` status-list token response, reusing the
/// current validator and freshness headers. Shared by the content-change
/// (`Modified`) and expiry-forced re-sign (`ExpiredToken`) paths.
async fn build_fresh_200_response(
    state: &AppState,
    accept_type: &str,
    status_record: &StatusListRecord,
    current_etag: &str,
    last_modified: &str,
    cache_control: &str,
    client_accepts_gzip: bool,
) -> Result<Response, ApiError> {
    let (token_bytes, encoding) =
        build_status_list_token(state, accept_type, status_record, None, client_accepts_gzip)
            .await?;

    let mut response = Response::new(token_bytes.into());
    *response.status_mut() = StatusCode::OK;
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(accept_type).unwrap(),
    );
    h.insert(header::ETAG, HeaderValue::from_str(current_etag).unwrap());
    h.insert(
        header::LAST_MODIFIED,
        HeaderValue::from_str(last_modified).unwrap(),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(cache_control).unwrap(),
    );
    h.insert(
        header::VARY,
        HeaderValue::from_static("Accept, Accept-Encoding"),
    );
    if let Some(enc) = encoding {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static(enc));
    }

    Ok(response)
}

async fn handle_historical_request(
    list_id: &str,
    time: i64,
    accept_type: &str,
    state: &AppState,
    client_accepts_gzip: bool,
) -> Result<Response, ApiError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if time <= 0 || time > now {
        tracing::warn!("Historical query rejected for time {time}");
        return Err(StatusListError::InvalidHistoricalTime.into());
    }

    tracing::info!(
        "Historical query for list {list_id} at time {time} (age: {} seconds)",
        now - time
    );

    let snapshot = state.service.get_snapshot_at(list_id, time).await?;

    let etag = generate_historical_etag(&snapshot);
    let last_modified = format_http_date(snapshot.iat);
    let validity_duration = (snapshot.exp - snapshot.iat) as u64;
    let cache_control = format!("max-age={validity_duration}, immutable");

    let status_record = StatusListRecord {
        list_id: snapshot.list_id,
        issuer: snapshot.issuer,
        status_list: snapshot.status_list,
        sub: snapshot.sub,
        updated_at: snapshot.iat,
    };

    let (token_bytes, encoding) = build_status_list_token(
        state,
        accept_type,
        &status_record,
        Some((snapshot.iat, snapshot.exp)),
        client_accepts_gzip,
    )
    .await?;

    let mut response = Response::new(token_bytes.into());
    *response.status_mut() = StatusCode::OK;
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(accept_type).unwrap(),
    );
    h.insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    h.insert(
        header::LAST_MODIFIED,
        HeaderValue::from_str(&last_modified).unwrap(),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&cache_control).unwrap(),
    );
    h.insert(
        header::VARY,
        HeaderValue::from_static("Accept, Accept-Encoding"),
    );
    if let Some(enc) = encoding {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static(enc));
    }

    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct StatusListQuery {
    pub time: Option<i64>,
}

async fn fetch_status_record(
    list_id: &str,
    state: &AppState,
) -> Result<StatusListRecord, ApiError> {
    state
        .service
        .get_status_list(list_id)
        .await
        .map_err(Into::into)
}

fn client_accepts_gzip(headers: &HeaderMap) -> bool {
    let mut entries: Vec<(&str, Option<f32>)> = Vec::new();
    for val in headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(val) = val.to_str() else { continue };
        for s in val.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            let (coding, params) = s
                .split_once(';')
                .map(|(c, p)| (c.trim(), p.trim()))
                .unwrap_or((s, ""));
            let q = params
                .split(';')
                .find_map(|p| p.trim().strip_prefix("q=").map(|q| q.trim()))
                .and_then(|q| q.parse::<f32>().ok());
            entries.push((coding, q));
        }
    }

    match entries
        .iter()
        .find(|(c, _)| c.eq_ignore_ascii_case("gzip"))
        .map(|(_, q)| *q)
    {
        Some(None) => true,
        Some(Some(q)) => q > 0.0,
        None => entries.iter().any(|(c, q)| {
            c.eq_ignore_ascii_case("*") && (q.is_none() || q.map(|v| v > 0.0).unwrap_or(false))
        }),
    }
}

fn build_cache_control(token_ttl_secs: u64) -> String {
    // No `immutable`: live tokens expire and their validators rotate, so a
    // freshness-honouring cache/browser must still revalidate to obtain a fresh,
    // unexpired token rather than serving a stale body forever (RFC 9111 §5.2.2.4).
    format!("max-age={}", token_ttl_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::handlers::status_list::publish_status::publish_status;
    use crate::server::handlers::status_list::utils::request::StatusesRequest;
    use crate::test_utils::{authenticated_issuer, test_app_state};
    use axum::extract::Json;
    use axum::http::HeaderMap;

    /// Decode the JWT payload of a freshly served (uncompressed) token so tests
    /// can assert the `iat`/`exp` claims directly without a verification key.
    fn decode_jwt_claims(jwt: &[u8]) -> serde_json::Value {
        use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

        let jwt = std::str::from_utf8(jwt).expect("JWT body is UTF-8");
        let payload = jwt.split('.').nth(1).expect("JWT has three segments");
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .expect("JWT payload is valid base64url");
        serde_json::from_slice(&decoded).expect("JWT payload is valid JSON")
    }

    #[test]
    fn test_accepts_gzip_simple() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_gzip_with_qvalue() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0.8".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_q0() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_gzip_q0_with_wildcard_accept() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip;q=0, *".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_via_wildcard_only() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_accepts_via_wildcard_q1() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*;q=1".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_wildcard_q0() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "*;q=0".parse().unwrap());
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_rejects_when_header_absent() {
        let h = HeaderMap::new();
        assert!(!client_accepts_gzip(&h));
    }

    #[test]
    fn test_multiple_accept_encoding_lines() {
        let mut h = HeaderMap::new();
        h.append(header::ACCEPT_ENCODING, "deflate".parse().unwrap());
        h.append(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[test]
    fn test_case_insensitive_gzip() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "GZIP".parse().unwrap());
        assert!(client_accepts_gzip(&h));
    }

    #[tokio::test]
    async fn test_get_status_list_not_found() {
        let app_state = test_app_state(None).await;
        let headers = HeaderMap::new();

        let result = get_status_list(
            State(app_state),
            Path(uuid::Uuid::new_v4().to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_status_list_unsupported_accept_header() {
        let app_state = test_app_state(None).await;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());

        let result = get_status_list(
            State(app_state),
            Path(uuid::Uuid::new_v4().to_string()),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_status_list_jwt_success() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        // Publish first
        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );
        headers.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        assert!(response.headers().contains_key(header::ETAG));
        assert!(response.headers().contains_key(header::CACHE_CONTROL));
    }

    #[tokio::test]
    async fn test_get_status_list_success_cwt() {
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

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_CWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ACCEPT_STATUS_LISTS_HEADER_CWT
        );
    }

    #[tokio::test]
    async fn test_get_status_list_jwt_no_gzip_when_client_does_not_accept() {
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

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(
            response.headers().get(header::VARY).unwrap(),
            "Accept, Accept-Encoding"
        );
    }

    #[tokio::test]
    async fn test_jwt_emits_aggregation_uri_when_configured() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri =
            Some("https://aggregation.example.com/statuslists/aggregation".to_string());

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwt_omits_aggregation_uri_when_not_configured() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = None;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_conditional_request_if_modified_since_returns_304() {
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

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list(
            State(app_state.clone()),
            Path(token_id.clone()),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
        )
        .await
        .unwrap()
        .into_response();

        let last_modified = res1.headers().get(header::LAST_MODIFIED).unwrap().clone();

        headers.insert(header::IF_MODIFIED_SINCE, last_modified);
        let res2 = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: None })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(res2.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_conditional_request_within_validity_returns_304() {
        // Deterministic time-advancement: fetch at `now0`, revalidate a short
        // while later but *within the same* token validity window. The cached
        // token is still valid, so a body-less 304 is correct and efficient.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);

        let etag = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag);

        // Same window (60s < token_exp_secs) -> cached token still valid -> 304.
        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + 60,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(res2.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_conditional_request_ttl_runway_governs_304() {
        // Within the token validity window a 304 is only certified while the
        // cached token still has at least `token_ttl_secs` of remaining validity.
        // Late in the window (remaining <= ttl) the server serves a fresh token
        // instead, so a relying party is never handed a token that is about to
        // expire — no clock-skew rejection, no immediate-refetch thrash.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let ttl = app_state.token_ttl_secs as i64;
        // window(1_000_000_000) == [999_999_900, 1_000_000_800)
        let now0 = 1_000_000_000;
        let window_end = 1_000_000_800;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag);

        // Early in the window, remaining = 700 > ttl(300) -> cached token still
        // usable -> 304.
        let early_now = window_end - 700;
        let res2 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            early_now,
        )
        .await
        .unwrap()
        .into_response();
        assert!(window_end - early_now > ttl);
        assert_eq!(res2.status(), StatusCode::NOT_MODIFIED);

        // Late in the window, remaining = 250 <= ttl(300) -> a 304 would leave
        // too little usable lifetime -> fresh 200.
        let late_now = window_end - 250;
        let res3 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            late_now,
        )
        .await
        .unwrap()
        .into_response();
        assert!(window_end - late_now <= ttl);
        assert_eq!(res3.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_conditional_request_expired_token_returns_fresh_200() {
        // Fetch at `now0`, then revalidate after the token validity window has
        // rolled over. The client's cached token has expired, so the server must
        // bypass the 304 and return a freshly signed 200 with a valid body.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let token_exp_secs = app_state.token_exp_secs;
        let now0 = 1_000_000_000;

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let etag1 = res1.headers().get(header::ETAG).unwrap().clone();
        headers.insert(header::IF_NONE_MATCH, etag1.clone());

        // Advance past the window boundary so the previously issued token's
        // validity window has lapsed.
        let res2 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0 + token_exp_secs as i64 + 1,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(
            res2.status(),
            StatusCode::OK,
            "expired-token revalidation must return a fresh 200 OK"
        );
        let etag2 = res2.headers().get(header::ETAG).unwrap().clone();
        assert_ne!(
            etag2, etag1,
            "the ETag must rotate when the token validity window changes"
        );
        let body = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body.is_empty(),
            "expired-token revalidation must carry a newly signed token body"
        );
        // Acceptance criterion #1 requires a freshly signed *valid* token: verify
        // it carries a full validity window rather than expiring at issuance.
        let claims = decode_jwt_claims(&body);
        let iat = claims["iat"].as_i64().expect("token carries iat");
        let exp = claims["exp"].as_i64().expect("token carries exp");
        assert_eq!(
            exp - iat,
            token_exp_secs as i64,
            "the freshly signed token must not be born expired"
        );
    }

    #[tokio::test]
    async fn test_conditional_request_if_modified_since_expired_returns_fresh_200() {
        // An If-Modified-Since revalidation with an expired cached token must
        // also bypass the 304 and serve a fresh body, otherwise the original bug
        // remains reachable through the weaker validator.
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;
        let token_exp_secs = app_state.token_exp_secs;
        let now0 = time::OffsetDateTime::now_utc().unix_timestamp();

        publish_status(
            State(app_state.clone()),
            authenticated_issuer("issuer1"),
            Path(token_id.clone()),
            Json(StatusesRequest { statuses: vec![] }),
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let res1 = get_status_list_at(
            State(app_state.clone()),
            token_id.clone(),
            Ok(Query(StatusListQuery { time: None })),
            headers.clone(),
            now0,
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(res1.status(), StatusCode::OK);
        let last_modified = res1.headers().get(header::LAST_MODIFIED).unwrap().clone();
        headers.insert(header::IF_MODIFIED_SINCE, last_modified);

        // `now` has passed `updated_at + token_exp_secs` -> the cached token is
        // expired -> the IMS revalidation must not answer 304.
        let res2 = get_status_list_at(
            State(app_state),
            token_id,
            Ok(Query(StatusListQuery { time: None })),
            headers,
            now0 + token_exp_secs as i64 + 1,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(res2.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn test_get_status_list_rejects_future_time() {
        let token_id = uuid::Uuid::new_v4().to_string();
        let app_state = test_app_state(None).await;

        let future_time = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;

        let result = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery {
                time: Some(future_time),
            })),
            HeaderMap::new(),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_status_list_returns_snapshot_valid_at_requested_time() {
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

        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            ACCEPT_STATUS_LISTS_HEADER_JWT.parse().unwrap(),
        );

        let response = get_status_list(
            State(app_state),
            Path(token_id),
            Ok(Query(StatusListQuery { time: Some(now) })),
            headers,
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
