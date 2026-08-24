use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use jsonwebtoken::jwk::Jwk;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    domain::models::credential::{Credential, Issuer, PublicJwk},
    server::{AppState, auth::errors::AuthenticationError, error::ApiError},
};

/// Request body for registering issuer public key credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialsRequest {
    pub issuer: String,
    pub public_key: Jwk,
}

#[derive(Debug)]
pub enum CredentialError {
    AlreadyExists,
    Port,
    AuthError(AuthenticationError),
}

impl From<AuthenticationError> for CredentialError {
    fn from(value: AuthenticationError) -> Self {
        CredentialError::AuthError(value)
    }
}

/// `err(level = "info")` for the reason on `update_status`: the default ERROR
/// level would page on write contention and on a duplicate registration, both
/// 409s the response layer already logs at the right severity.
#[tracing::instrument(skip_all, fields(issuer = payload.issuer), err(level = "info", Debug))]
pub async fn credential_handler(
    State(state): State<AppState>,
    Json(payload): Json<CredentialsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let public_key_bytes = serde_json::to_vec(&payload.public_key)
        .map_err(|e| ApiError::bad_request("invalid_public_jwk", e.to_string()))?;
    let credential = Credential {
        issuer: Issuer(payload.issuer),
        public_key: PublicJwk::try_new(public_key_bytes)?,
    };
    state.service.publish_credential(credential).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"status": "Credentials stored successfully"})),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_app_state;
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::Request,
        http::{Method, header},
        routing::post,
    };
    use jsonwebtoken::jwk::Jwk;
    use tower::ServiceExt;

    fn create_test_router(app_state: AppState) -> Router {
        Router::new()
            .route("/issue-credential", post(credential_handler))
            .with_state(app_state)
    }

    fn test_jwk() -> Jwk {
        serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "4R_68o1GpW2SvRroSJnCqWzcEX0JRnK3fQf9Rl4Jqig",
                "y": "D0wUeShMhjtWIGilbnCeboV-wkiCUmYPXVjezCml1Uk"
            }
            "#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_publish_credentials_success() {
        let jwk = test_jwk();
        let credentials = CredentialsRequest {
            issuer: "test_issuer".into(),
            public_key: jwk.clone(),
        };
        let app_state = test_app_state(None).await;
        let app = create_test_router(app_state);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/issue-credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&credentials).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_publish_credentials_wrong_key_format() {
        let app_state = test_app_state(None).await;
        let app = create_test_router(app_state);

        let body = r#"{"issuer": "test_issuer", "public_key": "wrong_key"}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/issue-credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_publish_credentials_rejects_oct_key() {
        let app_state = test_app_state(None).await;
        let app = create_test_router(app_state);

        // A symmetric (shared-secret) key must be rejected up front with a 400
        // `invalid_public_jwk` rather than accepted and permanently rejected at
        // request time.
        let body = r#"{"issuer": "test_issuer", "public_key": {"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg"}}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/issue-credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "invalid_public_jwk");
    }
}
