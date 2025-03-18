use axum::body::Body;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    response::IntoResponse,
};
use chrono::{DateTime, TimeZone, Utc};
use flate2::{write::GzEncoder, Compression};
use std::io::Write;

use crate::{
    database::error::RepositoryError, database::repository::Repository, utils::state::AppState,
};

pub async fn get_status_list(
    State(state): State<AppState>,
    Path(issuer): Path<String>,
    req: Request<Body>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let issuer = issuer.trim().to_string();
    let store = match &state.repository {
        Some(repo) => repo.clone(),
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                RepositoryError::RepositoryNotSet.to_string(),
            ));
        }
    };

    tracing::info!("Looking for status list with issuer: {:?}", issuer);

    match store
        .status_list_token_repository
        .find_one_by(issuer.clone())
        .await
    {
        Ok(Some(status_list)) => {
            let mut headers = HeaderMap::new();

            // Generate ETag based on iat (issued at timestamp)
            let etag = format!("\"{}\"", status_list.iat);
            headers.insert("ETag", HeaderValue::from_str(&etag).unwrap());

            // Convert iat to RFC2822 format for Last-Modified header
            let last_modified = Utc
                .timestamp_opt(status_list.iat as i64, 0)
                .single()
                .map(|dt| dt.to_rfc2822())
                .unwrap_or_default();
            headers.insert(
                "Last-Modified",
                HeaderValue::from_str(&last_modified).unwrap(),
            );

            tracing::info!("Status list found for issuer: {}", issuer);

            // Check if client's cached version is still valid
            if let Some(if_none_match) = req.headers().get("If-None-Match") {
                if if_none_match.as_bytes() == etag.as_bytes() {
                    return Ok((StatusCode::NOT_MODIFIED, headers, Body::empty()).into_response());
                }
            }

            if let Some(if_modified_since) = req.headers().get("If-Modified-Since") {
                if let Ok(if_modified_since) = if_modified_since.to_str() {
                    if let Ok(if_modified_since) = DateTime::parse_from_rfc2822(if_modified_since) {
                        let status_list_time = Utc
                            .timestamp_opt(status_list.iat as i64, 0)
                            .single()
                            .unwrap_or_default();
                        if status_list_time <= if_modified_since {
                            return Ok((
                                StatusCode::NOT_MODIFIED,
                                headers,
                                Body::from(String::new()),
                            )
                                .into_response());
                        }
                    }
                }
            }

            // Set cache control headers based on TTL
            if let Some(ttl) = status_list.ttl.clone() {
                if let Ok(ttl_seconds) = ttl.parse::<u32>() {
                    if ttl_seconds > 0 {
                        headers.insert(
                            "Cache-Control",
                            HeaderValue::from_str(&format!("max-age={}", ttl_seconds)).unwrap(),
                        );
                    }
                }
            }

            // Set content type for status list
            headers.insert(
                "Content-Type",
                HeaderValue::from_str("application/statuslist+jwt").unwrap(),
            );

            // Convert status list to JSON string
            let json_body = serde_json::to_string(&status_list).unwrap();

            // Check if client accepts gzip encoding
            if req
                .headers()
                .get("Accept-Encoding")
                .and_then(|h| h.to_str().ok())
                .is_some_and(|h| h.contains("gzip"))
            {
                // Compress response
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(json_body.as_bytes()).unwrap();
                let compressed_body = encoder.finish().unwrap();

                headers.insert("Content-Encoding", HeaderValue::from_static("gzip"));

                Ok((StatusCode::OK, headers, Body::from(compressed_body)).into_response())
            } else {
                Ok((StatusCode::OK, headers, Body::from(json_body)).into_response())
            }
        }
        Ok(None) => {
            tracing::warn!("No status list found for issuer: {}", issuer);
            Err((StatusCode::NOT_FOUND, "Status list not found".to_string()))
        }
        Err(e) => {
            tracing::error!("Database error: {:?}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
