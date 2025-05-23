use axum::{
    body::Body,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;

use hyper::{header, Request};

use crate::{
    auth::{authentication::verify_token, errors::AuthenticationError},
    utils::state::AppState,
};

/// Represents an authenticated issuer in the system.
/// This struct is used to store and pass the authenticated issuer's ID through the request pipeline.
#[derive(Clone)]
pub struct AuthenticatedIssuer(pub String);

/// Implementation of FromRequestParts for AuthenticatedIssuer.
/// This allows Axum to automatically extract and validate the authenticated issuer from incoming requests.
impl<S> FromRequestParts<S> for AuthenticatedIssuer
where
    S: Send + Sync + 'static,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    /// Extracts and validates the authenticated issuer from the request.
    /// This function:
    /// 1. Gets the Authorization header
    /// 2. Extracts the Bearer token
    /// 3. Verifies the token
    /// 4. Extracts the issuer ID from the token
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Get the Authorization header and validate its presence
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header").into_response()
            })?;

        // Extract the token from the Bearer scheme
        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization header format",
            )
                .into_response()
        })?;

        // Verify the token and extract the issuer
        match verify_token(&app_state, token).await {
            Ok(()) => {
                // Extract the issuer from the token header
                let header = jsonwebtoken::decode_header(token)
                    .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token").into_response())?;

                let issuer = header.kid.ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        "Missing issuer identifier in token",
                    )
                        .into_response()
                })?;

                // Store the authenticated issuer in the request extensions
                parts.extensions.insert(AuthenticatedIssuer(issuer.clone()));
                Ok(AuthenticatedIssuer(issuer))
            }
            Err(AuthenticationError::IssuerNotFound) => {
                Err((StatusCode::UNAUTHORIZED, "Issuer not found").into_response())
            }
            // Map all other errors to 401 Unauthorized for token/format errors
            Err(_) => Err((StatusCode::UNAUTHORIZED, "Invalid token").into_response()),
        }
    }
}

/// Middleware function for authentication.
/// This function:
/// 1. Extracts the token from the Authorization header
/// 2. Verifies the token
/// 3. Processes the request body
/// 4. Continues the request pipeline if authentication is successful
pub async fn auth(
    appstate: Arc<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Extract and validate the Bearer token
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                AuthenticationError::MissingAuthHeader.to_string(),
            )
        })?;

    // Verify the token
    match verify_token(&appstate, token).await {
        Ok(_) => {}
        Err(err) => {
            return Err((StatusCode::UNAUTHORIZED, err.to_string()));
        }
    }

    // Process the request body
    let (parts, body) = request.into_parts();
    let collected = BodyExt::collect(body).await.map_err(|err| {
        tracing::error!("Failed to read request body: {err:?}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read request body".to_string(),
        )
    })?;

    let bytes = collected.to_bytes();
    let json_body: Value = serde_json::from_slice(&bytes).map_err(|err| {
        tracing::error!("Failed to parse JSON body: {err:?}");
        (
            StatusCode::BAD_REQUEST,
            "Failed to parse JSON body".to_string(),
        )
    })?;

    // Reconstruct the request with the processed body
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(json_body);

    // Continue the request pipeline
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::keygen::Keypair;
    use axum::{
        body::to_bytes,
        http::{header, HeaderMap, Method, Request},
    };
    use jsonwebtoken::{encode, EncodingKey, Header as JwtHeader};
    use once_cell::sync::Lazy;
    use p256::pkcs8::EncodePublicKey;
    use p256::pkcs8::LineEnding;
    use std::time::{SystemTime, UNIX_EPOCH};

    static INIT: Lazy<()> = Lazy::new(|| {
        dotenvy::dotenv().ok();
    });

    #[tokio::test]

    async fn test_authenticated_issuer_from_request_parts_success() {
        *INIT;
        // Generate keypair and JWT
        let keypair = Keypair::generate().unwrap();
        let public_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap();
        let private_key_pem = keypair.to_pkcs8_pem_bytes().unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let issuer_id = "test-issuer-demo";
        #[derive(serde::Serialize)]
        struct Claims {
            exp: usize,
            iat: usize,
        }
        let claims = Claims {
            exp: now + 3600,
            iat: now,
        };
        let mut header = JwtHeader::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(issuer_id.to_string());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(&private_key_pem).unwrap(),
        )
        .unwrap();

        // Setup AppState with the issuer registered
        let app_state = AppState::setup_test_with_credential(
            issuer_id,
            &public_key_pem,
            jsonwebtoken::Algorithm::ES256,
        )
        .await;

        // Build request parts with Authorization header
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
        let mut parts = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0;
        parts.headers = headers;

        // Call the middleware
        let result = AuthenticatedIssuer::from_request_parts(&mut parts, &app_state).await;
        assert!(result.is_ok());
        let authenticated_issuer = result.unwrap();
        assert_eq!(authenticated_issuer.0, issuer_id);
    }

    #[tokio::test]

    async fn test_missing_authorization_header() {
        *INIT;
        let app_state = crate::utils::state::setup().await;
        let mut parts = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0;
        // No headers set
        let result = AuthenticatedIssuer::from_request_parts(&mut parts, &app_state).await;
        assert!(result.is_err());
        let resp = result.err().unwrap().into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // Check body
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap(); // Set limit to 1MB
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Missing Authorization header"));
    }

    #[tokio::test]

    async fn test_invalid_authorization_header_format() {
        *INIT;
        let app_state = crate::utils::state::setup().await;
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "NotBearer token".parse().unwrap());
        let mut parts = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0;
        parts.headers = headers;
        let result = AuthenticatedIssuer::from_request_parts(&mut parts, &app_state).await;
        assert!(result.is_err());
        let resp = result.err().unwrap().into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // Check body
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Invalid Authorization header format"));
    }

    #[tokio::test]

    async fn test_invalid_token_format() {
        *INIT;
        let app_state = crate::utils::state::setup().await;
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer not.a.jwt".parse().unwrap());
        let mut parts = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0;
        parts.headers = headers;
        let result = AuthenticatedIssuer::from_request_parts(&mut parts, &app_state).await;
        assert!(result.is_err());
        let resp = result.err().unwrap().into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // Check body
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Invalid token"));
    }

    #[tokio::test]

    async fn test_missing_issuer_identifier_in_token() {
        *INIT;
        // Create a valid JWT but without kid
        let keypair = Keypair::generate().unwrap();
        let private_key_pem = keypair.to_pkcs8_pem_bytes().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        #[derive(serde::Serialize)]
        struct Claims {
            exp: usize,
            iat: usize,
        }
        let claims = Claims {
            exp: now + 3600,
            iat: now,
        };
        let header = JwtHeader::new(jsonwebtoken::Algorithm::ES256); // no kid
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(&private_key_pem).unwrap(),
        )
        .unwrap();
        let app_state = crate::utils::state::setup().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
        let mut parts = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0;
        parts.headers = headers;
        let result = AuthenticatedIssuer::from_request_parts(&mut parts, &app_state).await;
        assert!(result.is_err());
        let resp = result.err().unwrap().into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]

    async fn test_invalid_token_verification() {
        *INIT;
        // Create a valid JWT with kid, but not registered in DB
        let keypair = Keypair::generate().unwrap();
        let private_key_pem = keypair.to_pkcs8_pem_bytes().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let issuer_id = "not-registered-issuer";
        #[derive(serde::Serialize)]
        struct Claims {
            exp: usize,
            iat: usize,
        }
        let claims = Claims {
            exp: now + 3600,
            iat: now,
        };
        let mut header = JwtHeader::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(issuer_id.to_string());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(&private_key_pem).unwrap(),
        )
        .unwrap();
        let app_state = crate::utils::state::setup().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
        let mut parts = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0;
        parts.headers = headers;
        let result = AuthenticatedIssuer::from_request_parts(&mut parts, &app_state).await;
        assert!(result.is_err());
        let resp = result.err().unwrap().into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // Check body
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Issuer not found"));
    }

    #[tokio::test]

    async fn test_other_authentication_error() {
        *INIT;
        // Simulate a token with a valid kid, but with an unsupported algorithm
        let keypair = Keypair::generate().unwrap();
        let _public_key_pem = keypair
            .verifying_key()
            .to_public_key_pem(LineEnding::default())
            .unwrap();
        let private_key_pem = keypair.to_pkcs8_pem_bytes().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let issuer_id = "test-issuer-unsupported-alg";
        #[derive(serde::Serialize)]
        struct Claims {
            exp: usize,
            iat: usize,
        }
        let claims = Claims {
            exp: now + 3600,
            iat: now,
        };
        let mut header = JwtHeader::new(jsonwebtoken::Algorithm::HS384);
        header.kid = Some(issuer_id.to_string());
        let token_result = encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(&private_key_pem).unwrap(),
        );

        assert!(
            token_result.is_err(),
            "Expected error for invalid algorithm"
        );
    }
}
