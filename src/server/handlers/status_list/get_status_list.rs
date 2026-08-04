use std::fmt::Debug;

use axum::{
    extract::rejection::QueryRejection,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::{
    domain::models::status_list::{StatusListError, StatusListRecord},
    server::{AppState, error::ApiError},
};

use super::utils::{
    conditional::{ConditionalResponse, evaluate_conditional_request, format_http_date},
    constants::{ACCEPT_STATUS_LISTS_HEADER_CWT, ACCEPT_STATUS_LISTS_HEADER_JWT},
    etag::{generate_etag, generate_historical_etag},
    token::build_status_list_token,
};

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
    let current_etag = generate_etag(&status_record);
    let last_modified_ts = status_record.updated_at;
    let last_modified = format_http_date(last_modified_ts);
    let cache_control = build_cache_control(state.token_ttl_secs);

    match evaluate_conditional_request(
        if_none_match,
        if_modified_since,
        &current_etag,
        last_modified_ts,
    ) {
        ConditionalResponse::NotModified => Ok((
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, current_etag.as_str()),
                (header::LAST_MODIFIED, last_modified.as_str()),
                (header::CACHE_CONTROL, cache_control.as_str()),
                (header::VARY, "Accept, Accept-Encoding"),
            ],
        )
            .into_response()),
        ConditionalResponse::Modified => {
            let (token_bytes, encoding) = build_status_list_token(
                &state,
                &accept_type,
                &status_record,
                None,
                client_accepts_gzip,
            )
            .await?;

            let mut response = Response::new(token_bytes.into());
            *response.status_mut() = StatusCode::OK;
            let h = response.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&accept_type).unwrap(),
            );
            h.insert(header::ETAG, HeaderValue::from_str(&current_etag).unwrap());
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
    }
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
    format!("max-age={}, immutable", token_ttl_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::handlers::status_list::publish_status::publish_status;
    use crate::server::handlers::status_list::utils::request::StatusesRequest;
    use crate::test_utils::test_app_state;
    use axum::Extension;
    use axum::extract::Json;
    use axum::http::HeaderMap;

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
            Extension("issuer1".to_string()),
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
            Extension("issuer1".to_string()),
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
            Extension("issuer1".to_string()),
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
            Extension("issuer1".to_string()),
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
            Extension("issuer1".to_string()),
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
            Extension("issuer1".to_string()),
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
            Extension("issuer1".to_string()),
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
