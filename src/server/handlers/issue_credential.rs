use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use jsonwebtoken::jwk::Jwk;
use serde::{Deserialize, Serialize};

use crate::{
    domain::models::credential::{AggregationId, Credential, Issuer, PublicJwk},
    server::{
        AppState,
        auth::{AuthenticatedIssuer, errors::AuthenticationError},
        error::ApiError,
    },
};

/// Request body for registering issuer public key credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialsRequest {
    pub issuer: String,
    pub public_key: Jwk,
}

/// Response body for a registration. The issuer cannot derive its aggregation
/// URI itself, so it is told here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialsResponse {
    pub status: String,
    pub aggregation_id: AggregationId,
    /// Present when the server advertises an aggregation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation_uri: Option<String>,
}

/// Response body for GET /credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub issuer: String,
    pub aggregation_id: AggregationId,
    /// Present when the server advertises an aggregation endpoint.
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
    let aggregation_id = state.service.publish_credential(credential).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CredentialsResponse {
            status: "Credentials stored successfully".to_string(),
            aggregation_id,
            aggregation_uri: state.aggregation_uri_for(aggregation_id),
        }),
    )
        .into_response())
}

/// Handle GET /credentials: the calling issuer's aggregation ID and URI. The
/// only other place an issuer learns them is the registration response, which
/// issuers registered before aggregation IDs existed never got.
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
        .ok_or_else(|| ApiError::not_found("issuer_not_found", "Issuer is not registered"))?;
    Ok(Json(RegistrationResponse {
        issuer: issuer.0,
        aggregation_id,
        aggregation_uri: state.aggregation_uri_for(aggregation_id),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{authenticated_issuer, test_app_state};
    use axum::{
        Router,
        body::Body,
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
    async fn test_get_credential_for_an_unknown_issuer_is_not_found() {
        let app_state = test_app_state(None).await;
        let err = get_credential(State(app_state), authenticated_issuer("nobody"))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.error, "issuer_not_found");
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
}
