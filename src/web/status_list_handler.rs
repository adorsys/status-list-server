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
) -> impl IntoResponse {
    tracing::info!("Issuer (trimmed): {:?}", issuer);
    tracing::info!("Issuer (bytes): {:?}", issuer.as_bytes());
    tracing::info!("Issuer (length): {}", issuer.len());
    let issuer = issuer.trim().to_string(); 
    tracing::info!("Issuer after trimming: {:?}", issuer);
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

    match store.status_list_token_repository.find_one_by(issuer.clone()).await {
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
                    return Ok((StatusCode::NOT_MODIFIED, headers, String::new()));
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
                            return Ok((StatusCode::NOT_MODIFIED, headers, String::new()));
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
                .map_or(false, |h| h.contains("gzip"))
            {
                // Compress response
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(json_body.as_bytes()).unwrap();
                let compressed_body = encoder.finish().unwrap();

                headers.insert("Content-Encoding", HeaderValue::from_static("gzip"));

                Ok((
                    StatusCode::OK,
                    headers,
                    String::from_utf8_lossy(&compressed_body).to_string(),
                ))
            } else {
                Ok((StatusCode::OK, headers, json_body))
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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use axum::{
//         body::Body,
//         extract::Request,
//         http::StatusCode,
//     };
//     use serde_json::json;
//     use crate::{
//         database::{connection::establish_connection, repository::{Repository, Store, Table}},
//         model::{Credentials, StatusList, StatusListToken, U8Wrapper},
//         utils::state::AppState,
//     };

//     async fn setup_test_data() -> (AppState, String) {
//         // Set up test database connection
//         std::env::set_var(
//             "DATABASE_URL",
//             "postgres://myuser:mypassword@localhost:5432/mydatabase",
//         );

//         let conn = establish_connection().await;
        
//         // Create test issuer
//         let test_issuer = "test-issuer-download".to_string();
        
//         // Set up credentials
//         let credential_store: Store<Credentials> = Store {
//             table: Table::new(conn.clone(), "credentials".to_string(), "issuer".to_string()),
//         };
        
//         let credential = Credentials::new(
//             test_issuer.clone(),
//             json!("test_public_key"),
//             "RS256".to_string(),
//         );
//         credential_store.insert_one(credential).await.unwrap();

//         // Set up status list
//         let status_list_store: Store<StatusListToken> = Store {
//             table: Table::new(conn.clone(), "status_list_tokens".to_string(), "issuer".to_string()),
//         };

//         let status_list_token = StatusListToken {
//             exp: Some(1735689600),  // Some future date
//             iat: 1704067200,        // Issue date
//             status_list: StatusList {
//                 bits: U8Wrapper(1),
//                 lst: "test_list".to_string(),
//             },
//             sub: test_issuer.clone(),
//             ttl: Some("3600".to_string()), // 1 hour TTL
//         };

//         status_list_store.insert_one(status_list_token).await.unwrap();

//         let state = AppState {
//             repository: Some(crate::utils::state::AppStateRepository {
//                 credential_repository: credential_store,
//                 status_list_token_repository: status_list_store,
//             }),
//         };

//         (state, test_issuer)
//     }

//     #[tokio::test]
//     async fn test_get_status_list_basic() {
//         let (state, test_issuer) = setup_test_data().await;

//         let req = Request::builder()
//             .uri(format!("/statuslists/{}", test_issuer))
//             .body(Body::empty())
//             .unwrap();

//         let response = get_status_list(
//             axum::extract::State(state),
//             axum::extract::Path(test_issuer),
//             req,
//         )
//         .await;

//         // Match on Result before checking response
//         match response {
//             Ok((status, headers, body)) => {
//                 assert_eq!(status, StatusCode::OK);
//                 assert_eq!(
//                     headers.get("Content-Type").unwrap(),
//                     "application/statuslist+jwt"
//                 );
//                 // ... rest of assertions
//             },
//             Err(_) => panic!("Expected Ok response"),
//         }
//     }

//     #[tokio::test]
//     async fn test_get_status_list_caching() {
//         let (state, test_issuer) = setup_test_data().await;

//         // First request to get ETag
//         let initial_req = Request::builder()
//             .uri(format!("/statuslists/{}", test_issuer))
//             .body(Body::empty())
//             .unwrap();

//         let initial_response = get_status_list(
//             axum::extract::State(state.clone()),
//             axum::extract::Path(test_issuer.clone()),
//             initial_req,
//         )
//         .await
//         .unwrap();

//         let etag = initial_response.1.get("ETag").unwrap().clone();

//         // Second request with If-None-Match header
//         let cached_req = Request::builder()
//             .uri(format!("/statuslists/{}", test_issuer))
//             .header("If-None-Match", etag)
//             .body(Body::empty())
//             .unwrap();

//         let cached_response = get_status_list(
//             axum::extract::State(state),
//             axum::extract::Path(test_issuer),
//             cached_req,
//         )
//         .await
//         .unwrap();

//         // Verify we get a 304 Not Modified response
//         assert_eq!(cached_response.0, StatusCode::NOT_MODIFIED);
//         assert!(cached_response.2.is_empty());
//     }

//     #[tokio::test]
//     async fn test_get_status_list_compression() {
//         let (state, test_issuer) = setup_test_data().await;

//         // Request with gzip encoding accepted
//         let req = Request::builder()
//             .uri(format!("/statuslists/{}", test_issuer))
//             .header("Accept-Encoding", "gzip")
//             .body(Body::empty())
//             .unwrap();

//         let response = get_status_list(
//             axum::extract::State(state),
//             axum::extract::Path(test_issuer),
//             req,
//         )
//         .await
//         .unwrap();

//         // Verify gzip encoding
//         assert_eq!(
//             response.1.get("Content-Encoding").unwrap(),
//             "gzip"
//         );
//     }

//     #[tokio::test]
//     async fn test_get_status_list_not_found() {
//         let (state, _) = setup_test_data().await;

//         // Request with non-existent issuer
//         let req = Request::builder()
//             .uri("/statuslists/non-existent-issuer")
//             .body(Body::empty())
//             .unwrap();

//         let response = get_status_list(
//             axum::extract::State(state),
//             axum::extract::Path("non-existent-issuer".to_string()),
//             req,
//         )
//         .await;

//         assert!(response.is_err());
//         let (status, _) = response.unwrap_err();
//         assert_eq!(status, StatusCode::NOT_FOUND);
//     }

//     async fn cleanup_test_data(test_issuer: &str) {
//         let conn = establish_connection().await;
//         let store: Store<Credentials> = Store {
//             table: Table::new(conn, "credentials".to_string(), "issuer".to_string()),
//         };
//         let _ = store.delete_by(test_issuer.to_string()).await;
//     }
// }
