//! Authentication middleware validating bearer JWTs against registered issuer credentials.

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

use crate::server::AppState;

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
    use jsonwebtoken::dangerous::insecure_decode;

    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or(AuthenticationError::InvalidAuthorizationHeader)?;

    let alg = jsonwebtoken::decode_header(token)?.alg;
    let issuer = insecure_decode::<Claims>(token)?.claims.iss;

    let credential = state
        .service
        .find_credential(&issuer)
        .await
        .map_err(|e| {
            tracing::error!("Failed to find credential for {issuer}: {e:?}");
            AuthenticationError::InternalServer
        })?
        .ok_or(AuthenticationError::IssuerNotFound)?;

    let public_key = serde_json::from_slice(credential.public_key.as_bytes())
        .map_err(|_| AuthenticationError::InternalServer)?;
    let decoding_key = DecodingKey::from_jwk(&public_key)?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&credential.issuer.0]);

    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)?;

    request.extensions_mut().insert(token_data.claims.iss);
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::Issuer;
    use crate::test_utils::test_app_state;
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        extract::Request,
        http::{StatusCode, header},
        routing::get,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    fn create_test_router(app_state: AppState) -> Router {
        async fn test_handler() -> &'static str {
            "Ok"
        }
        Router::new()
            .route("/test", get(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                app_state.clone(),
                auth,
            ))
            .with_state(app_state)
    }

    fn test_ec_private_pem() -> String {
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A\n5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV\nb0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT\n-----END PRIVATE KEY-----".to_string()
    }

    fn test_public_jwk() -> crate::domain::models::credential::PublicJwk {
        crate::domain::models::credential::PublicJwk::try_new(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
            }"#
            .as_bytes()
            .to_vec(),
        )
        .unwrap()
    }

    fn create_test_token(issuer: &str, secret: &EncodingKey, alg: Algorithm) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            iss: issuer.to_string(),
            exp: now + 3600,
        };

        let header = Header::new(alg);
        encode(&header, &claims, secret).unwrap()
    }

    #[tokio::test]
    async fn test_missing_authorization_header() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_malformed_authorization_header() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, "Basic invalid_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
    }

    #[tokio::test]
    async fn test_issuer_not_found_in_database() {
        let state = test_app_state(None).await;
        let app = create_test_router(state);

        let private_key = test_ec_private_pem();
        let secret = EncodingKey::from_ec_pem(private_key.as_bytes()).unwrap();
        let token = create_test_token("unregistered-issuer", &secret, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_successful_authentication() {
        let private_pem = test_ec_private_pem();
        let state = test_app_state(None).await;

        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("test-issuer".into()),
                public_key: test_public_jwk(),
            })
            .await
            .unwrap();

        let app = create_test_router(state);

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
        let wrong_private_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUBIUj4mRpgdolCfi\najH0ju3KgSj8xQAlcvidrAkwOzChRANCAAQ4Wvc8XUs0zEqMKGtRYFnvYtDlzdH2\n7N3Eo65Js7drssgg7eKUSIlnJWMXHxqr8SfECuXi7sewuw2+mxs2adC5\n-----END PRIVATE KEY-----";

        let state = test_app_state(None).await;
        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("test-issuer".into()),
                public_key: test_public_jwk(),
            })
            .await
            .unwrap();

        let app = create_test_router(state);

        let wrong_encoding_key = EncodingKey::from_ec_pem(wrong_private_pem.as_bytes()).unwrap();
        let token = create_test_token("test-issuer", &wrong_encoding_key, Algorithm::ES256);

        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_expired_token() {
        let private_pem = test_ec_private_pem();
        let state = test_app_state(None).await;

        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("test-issuer".into()),
                public_key: test_public_jwk(),
            })
            .await
            .unwrap();

        let app = create_test_router(state);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let expired_claims = Claims {
            iss: "test-issuer".to_string(),
            exp: now - 3600,
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
    }

    #[tokio::test]
    async fn test_request_extension_contains_issuer() {
        let private_pem = test_ec_private_pem();
        let state = test_app_state(None).await;

        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("test-issuer".into()),
                public_key: test_public_jwk(),
            })
            .await
            .unwrap();

        async fn extension_test_handler(Extension(issuer): Extension<String>) -> String {
            assert_eq!(issuer, "test-issuer");
            issuer
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
