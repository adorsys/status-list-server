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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::{
            connection::establish_connection,
            repository::{Store, Table},
        },
        model::{Credentials, StatusList, StatusListToken, U8Wrapper},
        utils::state::AppStateRepository,
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Helper function to create a test request with dynamic issuer
    fn create_test_request(issuer: &str, headers: Option<HeaderMap>) -> Request<Body> {
        let mut req = Request::builder()
            .uri(format!("/statuslists/{}", issuer.replace("\"", "")))
            .body(Body::empty())
            .unwrap();

        if let Some(headers) = headers {
            *req.headers_mut() = headers;
        }

        req
    }

    // Helper function to create a test status list token
    fn create_test_status_list_token(issuer: &str) -> StatusListToken {
        StatusListToken {
            exp: Some(1735689600),
            iat: 1704067200,
            status_list: StatusList {
                bits: U8Wrapper(1),
                lst: "test-list".to_string(),
            },
            sub: issuer.to_string(),
            ttl: Some("3600".to_string()),
        }
    }

    // Generate a unique test issuer name with quotes
    fn generate_test_issuer() -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("\"test-issuer-{}\"", timestamp)
    }

    #[tokio::test]
    async fn test_status_list_flow() {
        // Set up test database URL
        env::set_var(
            "DATABASE_URL",
            "postgres://myuser:mypassword@localhost:5433/mydatabase",
        );

        // Generate a unique issuer for this test
        let test_issuer = generate_test_issuer();
        let unquoted_issuer = test_issuer.replace("\"", "");

        // Setup connection to existing database
        let conn = establish_connection().await;

        // First, insert the credentials with quoted values
        sqlx::query!(
            r#"
            INSERT INTO credentials (issuer, public_key, alg)
            VALUES ($1, $2, $3)
            "#,
            test_issuer,
            json!({"key": "test-key"}),
            "\"RS256\"" // Note the quoted alg
        )
        .execute(&conn)
        .await
        .expect("Failed to insert test credentials");

        let credential_store: Store<Credentials> = Store {
            table: Table::new(conn.clone(), "credentials".to_owned(), "issuer".to_owned()),
        };

        let status_list_store: Store<StatusListToken> = Store {
            table: Table::new(
                conn.clone(),
                "status_list_tokens".to_owned(),
                "issuer".to_owned(),
            ),
        };

        // Create test status list
        let test_status_list = create_test_status_list_token(&test_issuer);

        // Then insert the status list
        sqlx::query!(
            r#"
            INSERT INTO status_list_tokens (issuer, exp, iat, status_list, sub, ttl)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            test_issuer,
            test_status_list.exp,
            test_status_list.iat,
            serde_json::to_value(&test_status_list.status_list).unwrap(),
            test_issuer,
            test_status_list.ttl
        )
        .execute(&conn)
        .await
        .expect("Failed to insert test status list");

        // Create test state
        let state = AppState {
            repository: Some(AppStateRepository {
                credential_repository: credential_store.clone(),
                status_list_token_repository: status_list_store.clone(),
            }),
        };

        // Test 1: Get status list without compression
        let req = create_test_request(&test_issuer, None);
        let response =
            get_status_list(State(state.clone()), Path(unquoted_issuer.clone()), req).await;

        match response {
            Ok(response) => {
                let (parts, body) = response.into_response().into_parts();
                assert_eq!(parts.status, StatusCode::OK);
                assert!(parts.headers.contains_key("Content-Type"));
                assert!(parts.headers.contains_key("ETag"));
                assert!(parts.headers.contains_key("Last-Modified"));
                assert!(parts.headers.contains_key("Cache-Control"));

                let body_bytes = to_bytes(body, 1024 * 1024).await.unwrap();
                let response_token: StatusListToken = serde_json::from_slice(&body_bytes).unwrap();
                assert_eq!(response_token.sub, test_issuer);
                assert_eq!(response_token.iat, test_status_list.iat);
                assert_eq!(response_token.status_list, test_status_list.status_list);
            }
            Err(e) => panic!("Expected Ok response, got error: {:?}", e),
        }

        // Test 2: Get status list with gzip compression
        let mut headers = HeaderMap::new();
        headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
        let req = create_test_request(&test_issuer, Some(headers));

        let response = get_status_list(State(state), Path(unquoted_issuer.clone()), req).await;

        match response {
            Ok(response) => {
                let (parts, _) = response.into_response().into_parts();
                assert_eq!(parts.status, StatusCode::OK);
                assert_eq!(parts.headers.get("Content-Encoding").unwrap(), "gzip");
            }
            Err(e) => panic!("Expected Ok response, got error: {:?}", e),
        }

        // Cleanup
        sqlx::query!(
            "DELETE FROM status_list_tokens WHERE issuer = $1",
            test_issuer
        )
        .execute(&conn)
        .await
        .expect("Failed to cleanup status list");

        sqlx::query!("DELETE FROM credentials WHERE issuer = $1", test_issuer)
            .execute(&conn)
            .await
            .expect("Failed to cleanup credentials");
    }
}
