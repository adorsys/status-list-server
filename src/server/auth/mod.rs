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
use std::time::{SystemTime, UNIX_EPOCH};

use crate::server::AppState;

const JWT_REQUIRED_SPEC_CLAIMS: &[&str] = &["iss", "exp"];
const JWT_REQUIRED_SPEC_CLAIMS_WITH_AUDIENCE: &[&str] = &["iss", "exp", "aud"];

#[derive(Debug, Serialize, Deserialize)]
struct UnverifiedIssuerClaims {
    iss: String,
}

/// Required management claims are non-optional (`iss`, `iat`, `exp`).
/// Optional claims are deserialized as `Option` and validated when present.
#[derive(Debug, Serialize, Deserialize)]
struct ManagementClaims {
    iss: String,
    iat: u64,
    #[serde(default)]
    nbf: Option<u64>,
    exp: u64,
}

impl ManagementClaims {
    fn validate_policy(
        &self,
        now: u64,
        leeway_secs: u64,
        max_token_lifetime_secs: u64,
    ) -> Result<(), AuthenticationError> {
        if self.exp <= self.iat {
            tracing::error!("Management JWT rejected: exp must be later than iat");
            return Err(AuthenticationError::InvalidClaims);
        }

        if self.iat > now.saturating_add(leeway_secs) {
            tracing::error!(
                "Management JWT rejected: iat is in the future beyond configured leeway"
            );
            return Err(AuthenticationError::InvalidClaims);
        }

        if let Some(nbf) = self.nbf
            && nbf > now.saturating_add(leeway_secs)
        {
            tracing::error!(
                "Management JWT rejected: nbf is in the future beyond configured leeway"
            );
            return Err(AuthenticationError::InvalidClaims);
        }

        let lifetime = self.exp.checked_sub(self.iat).ok_or_else(|| {
            tracing::error!("Management JWT rejected: exp must be later than iat");
            AuthenticationError::InvalidClaims
        })?;
        if lifetime > max_token_lifetime_secs {
            tracing::error!("Management JWT rejected: token lifetime exceeds configured maximum");
            return Err(AuthenticationError::InvalidClaims);
        }

        Ok(())
    }
}

#[cfg(test)]
#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    iss: String,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    exp: u64,
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

    let alg = jsonwebtoken::decode_header(token)
        .map_err(|e| {
            tracing::error!("Failed to decode management JWT header: {e:?}");
            AuthenticationError::JwtError(e)
        })?
        .alg;
    let issuer = insecure_decode::<UnverifiedIssuerClaims>(token)
        .map_err(|e| {
            tracing::error!("Failed to decode management JWT issuer claim: {e:?}");
            AuthenticationError::JwtError(e)
        })?
        .claims
        .iss;

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
    validation.leeway = state.management_auth.leeway_secs;
    validation.validate_nbf = true;
    validation.set_issuer(&[&credential.issuer.0]);
    if !state.management_auth.audiences.is_empty() {
        validation.set_required_spec_claims(JWT_REQUIRED_SPEC_CLAIMS_WITH_AUDIENCE);
        validation.set_audience(&state.management_auth.audiences);
    } else {
        // jsonwebtoken can require registered claims like `iss` and `exp`;
        // `iat` is required by deserializing into `ManagementClaims`.
        validation.set_required_spec_claims(JWT_REQUIRED_SPEC_CLAIMS);
        validation.validate_aud = false;
    }

    let token_data = jsonwebtoken::decode::<ManagementClaims>(token, &decoding_key, &validation)
        .map_err(|e| {
            tracing::error!("Failed to decode management JWT: {e:?}");
            AuthenticationError::JwtError(e)
        })?;
    let now = current_unix_timestamp()?;
    token_data.claims.validate_policy(
        now,
        state.management_auth.leeway_secs,
        state.management_auth.max_token_lifetime_secs,
    )?;

    request.extensions_mut().insert(token_data.claims.iss);
    Ok(next.run(request).await)
}

fn current_unix_timestamp() -> Result<u64, AuthenticationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuthenticationError::InternalServer)
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

    fn now() -> u64 {
        current_unix_timestamp().unwrap()
    }

    fn create_test_token(issuer: &str, secret: &EncodingKey, alg: Algorithm) -> String {
        let now = now();

        let claims = TestClaims {
            iss: issuer.to_string(),
            iat: now,
            nbf: None,
            exp: now + 3600,
        };

        let header = Header::new(alg);
        encode(&header, &claims, secret).unwrap()
    }

    fn sign_claims(claims: serde_json::Value, secret: &EncodingKey) -> String {
        let header = Header::new(Algorithm::ES256);
        encode(&header, &claims, secret).unwrap()
    }

    async fn test_state_with_registered_issuer() -> AppState {
        let state = test_app_state(None).await;
        state
            .service
            .publish_credential(crate::domain::models::credential::Credential {
                issuer: Issuer("test-issuer".into()),
                public_key: test_public_jwk(),
            })
            .await
            .unwrap();
        state
    }

    async fn call_with_token(app: Router, token: String) -> axum::response::Response {
        let request = Request::builder()
            .uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        app.oneshot(request).await.unwrap()
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
        let state = test_state_with_registered_issuer().await;
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

        let state = test_state_with_registered_issuer().await;
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
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);

        let now = now();

        let expired_claims = TestClaims {
            iss: "test-issuer".to_string(),
            iat: now - 7200,
            nbf: None,
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
    async fn test_missing_issuer_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iat": now,
                "exp": now + 3600
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_expiration_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_issued_at_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "exp": now + 3600
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_future_issued_at_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now + 120,
                "exp": now + 3600
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_future_not_before_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "nbf": now + 120,
                "exp": now + 3600
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_too_long_lived_token_is_rejected() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "exp": now + 3601
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_wrong_audience_claim_is_rejected() {
        let private_pem = test_ec_private_pem();
        let mut state = test_state_with_registered_issuer().await;
        state.management_auth.audiences = vec!["status-list-server-management".to_string()];
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "aud": "other-service",
                "exp": now + 3600
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_audience_claim_is_ignored_when_no_audience_is_configured() {
        let private_pem = test_ec_private_pem();
        let state = test_state_with_registered_issuer().await;
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "aud": "other-service",
                "exp": now + 3600
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_matching_audience_claim_succeeds_when_audience_is_configured() {
        let private_pem = test_ec_private_pem();
        let mut state = test_state_with_registered_issuer().await;
        state.management_auth.audiences = vec!["status-list-server-management".to_string()];
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "aud": "status-list-server-management",
                "exp": now + 3600
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_missing_audience_claim_is_rejected_when_audience_is_configured() {
        let private_pem = test_ec_private_pem();
        let mut state = test_state_with_registered_issuer().await;
        state.management_auth.audiences = vec!["status-list-server-management".to_string()];
        let app = create_test_router(state);
        let now = now();

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
        let token = sign_claims(
            serde_json::json!({
                "iss": "test-issuer",
                "iat": now,
                "exp": now + 3600
            }),
            &encoding_key,
        );

        let response = call_with_token(app, token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_errors_have_generic_response_message() {
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
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "jwt_error");
        assert_eq!(body["error_description"], "Invalid authentication token");
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
