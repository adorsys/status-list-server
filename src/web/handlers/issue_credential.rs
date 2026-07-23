use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use jsonwebtoken::jwk::Jwk;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    application::UseCaseError, domain, state::AppState, web::auth::errors::AuthenticationError,
    web::errors::ApiError,
};

/// Request payload carrying an issuer and its public JWK. Wire-only: the
/// handler converts it into a `domain::Credential` at the boundary.
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

#[tracing::instrument(skip(appstate, credential), fields(issuer = credential.issuer))]
pub async fn credential_handler(
    State(appstate): State<AppState>,
    Json(credential): Json<CredentialsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    publish_credentials(credential.to_owned(), appstate).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"status": "Credentials stored successfully"})),
    )
        .into_response())
}

pub(super) async fn publish_credentials(
    credentials: CredentialsRequest,
    state: AppState,
) -> Result<(), CredentialError> {
    let public_key =
        serde_json::to_vec(&credentials.public_key).map_err(|_| CredentialError::Port)?;
    let credential = domain::Credential {
        issuer: domain::Issuer(credentials.issuer),
        public_key: domain::PublicJwk::try_new(public_key).map_err(|_| CredentialError::Port)?,
    };
    match state.credentials.publish_credential(credential).await {
        Ok(()) => Ok(()),
        Err(UseCaseError::AlreadyExists) => Err(CredentialError::AlreadyExists),
        Err(_) => Err(CredentialError::Port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{adapters::sea_orm::models::credentials, test_utils::test_app_state};
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

    #[tokio::test]
    async fn test_publish_credentials_success() {
        use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
        use std::sync::Arc;

        let jwk = test_jwk();
        let credentials = CredentialsRequest {
            issuer: "test_issuer".into(),
            public_key: jwk.clone(),
        };
        let model = credentials::Model {
            issuer: credentials.issuer.clone(),
            public_key: credentials.public_key.clone().into(),
        };
        let db_conn = Arc::new(
            MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results(vec![vec![], vec![model]])
                .append_exec_results(vec![MockExecResult {
                    rows_affected: 1,
                    last_insert_id: 0,
                }])
                .into_connection(),
        );
        let app_state = test_app_state(Some(db_conn)).await;
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
}
