pub mod errors;

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use errors::AuthenticationError;
use hyper::header;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
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
        .find_one_by(issuer.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to find credential for {issuer}: {e:?}");
            AuthenticationError::InternalServer
        })?
        .ok_or(AuthenticationError::IssuerNotFound)?;

    // Get the decoding key
    let decoding_key = match credential.alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(credential.public_key.as_bytes()),
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(credential.public_key.as_bytes())
        }
        Algorithm::EdDSA => DecodingKey::from_ed_pem(credential.public_key.as_bytes()),
        _ => return Err(AuthenticationError::UnsupportedAlgorithm),
    }?;

    let mut validation = Validation::new(credential.alg);
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
    use crate::{
        models::{credentials, Alg},
        test_utils::test_app_state,
        utils::state::AppState,
    };
    use axum::{
        body::{to_bytes, Body},
        extract::Request,
        http::StatusCode,
        routing::get,
        Extension, Router,
    };
    use jsonwebtoken::{encode, EncodingKey, Header};
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

    fn create_test_keypair() -> (String, String) {
        use crate::utils::keygen::Keypair;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let keypair = Keypair::generate().unwrap();
        let public_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap();
        let private_key_pem = keypair.to_pkcs8_pem().unwrap();

        (private_key_pem, public_key_pem)
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
        let (private_pem, public_pem) = create_test_keypair();
        let credential = credentials::Model {
            issuer: "test-issuer".to_string(),
            public_key: public_pem.to_string(),
            alg: Alg(Algorithm::ES256),
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
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body, "Ok");
    }

    #[tokio::test]
    async fn test_token_verification_failure_wrong_key() {
        let (_, public_pem) = create_test_keypair();
        let (wrong_private_pem, _) = create_test_keypair();
        let credential = credentials::Model {
            issuer: "test-issuer".to_string(),
            public_key: public_pem.to_string(),
            alg: Alg(Algorithm::ES256),
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
        assert!(body.contains("InvalidSignature"));
    }

    #[tokio::test]
    async fn test_expired_token() {
        let (private_pem, public_pem) = create_test_keypair();
        let credential = credentials::Model {
            issuer: "test-issuer".to_string(),
            public_key: public_pem.to_string(),
            alg: Alg(Algorithm::ES256),
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
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
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
        let (private_pem, public_pem) = create_test_keypair();
        let credential = credentials::Model {
            issuer: "test-issuer".to_string(),
            public_key: public_pem.to_string(),
            alg: Alg(Algorithm::ES256),
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
