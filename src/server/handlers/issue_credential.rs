use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{
    domain::models::credential::{AggregationId, Credential, Issuer, PublicJwk},
    server::{
        AppState,
        auth::{AuthenticatedIssuer, errors::AuthenticationError},
        error::{ApiError, IntoApiError},
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialsRequest {
    pub issuer: String,
    pub public_key: serde_json::Map<String, serde_json::Value>,
}

/// Issuers can't derive their aggregation URI, so registration returns it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialsResponse {
    pub status: String,
    pub aggregation_id: AggregationId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub issuer: String,
    pub aggregation_id: AggregationId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation_uri: Option<String>,
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

/// Errors log at info, like update_status.
#[tracing::instrument(skip_all, fields(issuer = payload.issuer), err(level = "info", Debug))]
pub async fn credential_handler(
    State(state): State<AppState>,
    Json(payload): Json<CredentialsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let public_key_bytes = serde_json::to_vec(&payload.public_key)
        .map_err(|e| ApiError::bad_request("invalid_public_jwk", e.to_string()))?;
    let issuer = Issuer(payload.issuer);
    let credential = Credential {
        issuer: issuer.clone(),
        public_key: PublicJwk::try_new(public_key_bytes)?,
    };
    let aggregation_id = state.service.publish_credential(credential).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CredentialsResponse {
            status: "Credentials stored successfully".to_string(),
            aggregation_id,
            aggregation_uri: state.aggregation_uri_for(&issuer, aggregation_id),
        }),
    )
        .into_response())
}

/// For issuers registered before aggregation IDs existed, the only way to learn theirs.
#[tracing::instrument(skip_all, fields(issuer = %issuer), err(level = "info", Debug))]
pub async fn get_credential(
    State(state): State<AppState>,
    issuer: AuthenticatedIssuer,
) -> Result<Json<RegistrationResponse>, ApiError> {
    let issuer = issuer.into_issuer();
    let aggregation_id = state
        .service
        .find_aggregation_id(&issuer)
        .await?
        .ok_or_else(|| {
            tracing::warn!(iss = %issuer.0, "Credential disappeared after authentication");
            AuthenticationError::InvalidToken.into_api_error()
        })?;
    let aggregation_uri = state.aggregation_uri_for(&issuer, aggregation_id);
    Ok(Json(RegistrationResponse {
        issuer: issuer.0,
        aggregation_id,
        aggregation_uri,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{authenticated_issuer, register_issuer, test_app_state};
    use axum::{
        Router,
        body::Body,
        extract::Request,
        http::{Method, header},
        routing::post,
    };
    use std::{collections::HashSet, sync::Arc};
    use tower::ServiceExt;

    fn create_test_router(app_state: AppState) -> Router {
        Router::new()
            .route("/issue-credential", post(credential_handler))
            .with_state(app_state)
    }

    fn test_jwk() -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_str(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "kid": "test-key",
                "alg": "ES256",
                "x": "4R_68o1GpW2SvRroSJnCqWzcEX0JRnK3fQf9Rl4Jqig",
                "y": "D0wUeShMhjtWIGilbnCeboV-wkiCUmYPXVjezCml1Uk"
            }
            "#,
        )
        .unwrap()
    }

    async fn register(app_state: AppState) -> CredentialsResponse {
        let credentials = CredentialsRequest {
            issuer: "test_issuer".into(),
            public_key: test_jwk(),
        };
        let response = create_test_router(app_state)
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn test_publish_credentials_success() {
        let app_state = test_app_state(None).await;
        let response = register(app_state.clone()).await;

        assert_eq!(
            app_state
                .service
                .find_aggregation_id(&Issuer("test_issuer".into()))
                .await
                .unwrap(),
            Some(response.aggregation_id)
        );
        assert_eq!(response.aggregation_uri, None);
    }

    #[tokio::test]
    async fn test_publish_credentials_returns_scoped_aggregation_uri() {
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = Some(
            "https://statuslist.example.com/api/v1/aggregation"
                .parse()
                .unwrap(),
        );
        let response = register(app_state).await;

        assert_eq!(
            response.aggregation_uri.unwrap(),
            format!(
                "https://statuslist.example.com/api/v1/aggregation/{}",
                response.aggregation_id
            )
        );
    }

    #[tokio::test]
    async fn test_get_credential_returns_the_issuers_aggregation() {
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = Some(
            "https://statuslist.example.com/api/v1/aggregation"
                .parse()
                .unwrap(),
        );
        let registered = register(app_state.clone()).await;

        let Json(registration) =
            get_credential(State(app_state), authenticated_issuer("test_issuer"))
                .await
                .unwrap();
        assert_eq!(registration.issuer, "test_issuer");
        assert_eq!(registration.aggregation_id, registered.aggregation_id);
        assert_eq!(registration.aggregation_uri, registered.aggregation_uri);
    }

    #[tokio::test]
    async fn test_credentials_withhold_the_aggregation_uri_per_issuer() {
        let mut app_state = test_app_state(None).await;
        app_state.aggregation_uri = Some(
            "https://statuslist.example.com/api/v1/aggregation"
                .parse()
                .unwrap(),
        );
        app_state.aggregation_withheld_from =
            Arc::new(HashSet::from([Issuer::from("test_issuer")]));
        let withheld = register(app_state.clone()).await;
        assert_eq!(withheld.aggregation_uri, None);
        let Json(registration) = get_credential(
            State(app_state.clone()),
            authenticated_issuer("test_issuer"),
        )
        .await
        .unwrap();
        assert_eq!(registration.aggregation_id, withheld.aggregation_id);
        assert_eq!(registration.aggregation_uri, None);

        let other_id = register_issuer(&app_state.service, "other_issuer").await;
        let Json(other) = get_credential(State(app_state), authenticated_issuer("other_issuer"))
            .await
            .unwrap();
        assert_eq!(
            other.aggregation_uri,
            Some(format!(
                "https://statuslist.example.com/api/v1/aggregation/{other_id}"
            ))
        );
    }

    #[tokio::test]
    async fn test_get_credential_for_an_unknown_issuer_is_invalid_token() {
        let app_state = test_app_state(None).await;
        let err = get_credential(State(app_state), authenticated_issuer("nobody"))
            .await
            .unwrap_err();
        let response = err.into_response();
        let expected = AuthenticationError::InvalidToken.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.status(), expected.status());
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            expected.headers()[header::WWW_AUTHENTICATE]
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            axum::body::to_bytes(expected.into_body(), usize::MAX)
                .await
                .unwrap()
        );
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
    async fn test_registration_rejects_private_jwk_member() {
        let app_state = test_app_state(None).await;
        let mut public_key = test_jwk();
        public_key.insert("d".to_string(), serde_json::json!("private-material"));
        let response = create_test_router(app_state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/issue-credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"issuer": "private-key-issuer", "public_key": public_key})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            app_state
                .service
                .find_credential("private-key-issuer")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_registration_rejects_duplicate_kid_across_issuers() {
        let app_state = test_app_state(None).await;
        register(app_state.clone()).await;
        let response = create_test_router(app_state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/issue-credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"issuer": "other-issuer", "public_key": test_jwk()})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            app_state
                .service
                .find_credential_by_kid("test-key")
                .await
                .unwrap()
                .unwrap()
                .issuer,
            Issuer("test_issuer".into())
        );
    }
}
