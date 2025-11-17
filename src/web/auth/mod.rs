pub mod errors;

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use errors::AuthenticationError;
use hyper::header;
use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::utils::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    exp: usize,
}

/// Authentication middleware acting as a safeguard for unauthorized issuers
pub async fn auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, AuthenticationError> {
    use jsonwebtoken::Algorithm;
    use std::str::FromStr;

    // Try to extract token from Authorization header
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or(AuthenticationError::InvalidAuthorizationHeader)?;

    // We decode without verification to get the issuer
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    let issuer =
        jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation)?
            .claims
            .iss;

    // Check if issuer is in database and get its credentials
    let credential = &state
        .credential_repo
        .find_one_by(&issuer)
        .await
        .map_err(|e| {
            tracing::error!("Failed to find credential for {issuer}: {e:?}");
            AuthenticationError::InternalServer
        })?
        .ok_or(AuthenticationError::IssuerNotFound)?;

    // Get the decoding key
    let decoding_key = DecodingKey::from_jwk(&credential.public_key)?;

    let alg = credential
        .public_key
        .common
        .key_algorithm
        .and_then(|alg| Algorithm::from_str(alg.to_string().as_str()).ok())
        .ok_or(AuthenticationError::UnsupportedAlgorithm)?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&credential.issuer]);

    // Verify the token to ensure that the issuer is the same as the one in the database
    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)?;

    // Insert issuer into request extensions
    request.extensions_mut().insert(token_data.claims.iss);
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{models::credentials, test_utils::test_app_state, utils::state::AppState};
    use axum::{
        body::{to_bytes, Body},
        extract::Request,
        http::StatusCode,
        routing::get,
        Extension, Router,
    };
    use jsonwebtoken::{encode, EncodingKey, Header};
    use jsonwebtoken::{jwk::Jwk, Algorithm};
    use sea_orm::{DatabaseBackend, MockDatabase};
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;

    fn create_test_token(issuer: &str, secret: &EncodingKey, algorithm: Algorithm) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            iss: issuer.to_string(),
            exp: now + 3600,
        };

        let header = Header::new(algorithm);
        encode(&header, &claims, secret).unwrap()
    }

    fn create_test_keypair() -> (String, Jwk) {
        let private_key_pem = "-----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A
            5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV
            b0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT
            -----END PRIVATE KEY-----
        "
        .to_string();

        let public_key = serde_json::from_str(
            r#"{
                "alg": "ES256",
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#,
        )
        .unwrap();

        (private_key_pem, public_key)
    }

    async fn test_handler() -> &'static str {
        "Ok"
    }

    fn create_test_router(state: AppState) -> Router {
        Router::new()
            .route("/test", get(test_handler))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Missing or invalid Authorization header"));
    }

    #[tokio::test]
    async fn test_malformed_authorization_header() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "InvalidToken")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Missing or invalid Authorization header"));
    }

    #[tokio::test]
    async fn test_invalid_jwt_token() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Bearer invalid_jwt_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("InvalidToken"));
    }

    #[tokio::test]
    async fn test_issuer_not_found_in_database() {
        let db = MockDatabase::new(DatabaseBackend::Postgres);
        let db_conn = Arc::new(
            db.append_query_results::<credentials::Model, Vec<_>, _>(vec![vec![]])
                .into_connection(),
        );
        let state = test_app_state(Some(db_conn)).await;
        let app = create_test_router(state);

        let (private_key, _public_key) = create_test_keypair();

        // Valid token, but issuer not found
        let secret = EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap();
        let token = create_test_token("test-issuer", &secret, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Issuer not registered"));
    }

    #[tokio::test]
    async fn test_successful_authentication() {
        let (private_pem, public_key) = create_test_keypair();
        let credential = credentials::Model {
            issuer: "test-issuer".to_string(),
            public_key: public_key.into(),
        };
        let db_conn = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<credentials::Model, Vec<_>, _>(vec![vec![credential]])
            .into_connection();
        let state = test_app_state(Some(Arc::new(db_conn))).await;
        let app = create_test_router(state);

        // Create token
        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = create_test_token("test-issuer", &encoding_key, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Status code : {}",
            response.status()
        );

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body, "Ok");
    }

    #[tokio::test]
    async fn test_token_verification_failure_wrong_key() {
        let (_, public_key) = create_test_keypair();
        let wrong_private_pem = "-----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUBIUj4mRpgdolCfi
            ajH0ju3KgSj8xQAlcvidrAkwOzChRANCAAQ4Wvc8XUs0zEqMKGtRYFnvYtDlzdH2
            7N3Eo65Js7drssgg7eKUSIlnJWMXHxqr8SfECuXi7sewuw2+mxs2adC5
            -----END PRIVATE KEY-----
        "
        .to_string();
        let credential = credentials::Model {
            issuer: "test-issuer".to_string(),
            public_key: public_key.into(),
        };
        let db_conn = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<credentials::Model, Vec<_>, _>(vec![vec![credential]])
            .into_connection();
        let state = test_app_state(Some(Arc::new(db_conn))).await;
        let app = create_test_router(state);

        // Create token with wrong private key
        let wrong_encoding_key = EncodingKey::from_ec_pem(wrong_private_pem.as_bytes()).unwrap();
        let token = create_test_token("test-issuer", &wrong_encoding_key, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("InvalidSignature"), "Body: {}", body);
    }

    #[tokio::test]
    async fn test_expired_token() {
        let (private_pem, public_key) = create_test_keypair();
        let credential = credentials::Model {
            issuer: "test-issuer".to_string(),
            public_key: public_key.into(),
        };
        let db_conn = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<credentials::Model, Vec<_>, _>(vec![vec![credential]])
            .into_connection();
        let state = test_app_state(Some(Arc::new(db_conn))).await;
        let app = create_test_router(state);

        // Create expired token
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let expired_claims = Claims {
            iss: "test-issuer".to_string(),
            exp: now - 3600, // 1 hour ago
        };

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &expired_claims, &encoding_key).unwrap();

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("ExpiredSignature"));
    }

    #[tokio::test]
    async fn test_request_extension_contains_issuer() {
        let (private_pem, public_key) = create_test_keypair();
        let credential = credentials::Model {
            issuer: "test-issuer".to_string(),
            public_key: public_key.into(),
        };
        let db_conn = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<credentials::Model, Vec<_>, _>(vec![vec![credential]])
            .into_connection();
        let state = test_app_state(Some(Arc::new(db_conn))).await;

        // Custom handler to check extensions
        async fn extension_test_handler(Extension(issuer): Extension<String>) -> String {
            assert_eq!(issuer, "test-issuer");
            issuer.clone()
        }

        let app = Router::new()
            .route("/test", get(extension_test_handler))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth))
            .with_state(state);

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = create_test_token("test-issuer", &encoding_key, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body, "test-issuer");
    }
}
