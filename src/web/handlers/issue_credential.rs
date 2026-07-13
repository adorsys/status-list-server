use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::{
    database::error::RepositoryError, models::Credentials, utils::state::AppState,
    web::auth::errors::AuthenticationError, web::errors::ApiError,
};

#[derive(Debug)]
pub(super) enum CredentialError {
    RepoError(RepositoryError),
    AuthError(AuthenticationError),
}

impl From<RepositoryError> for CredentialError {
    fn from(value: RepositoryError) -> Self {
        CredentialError::RepoError(value)
    }
}

impl From<AuthenticationError> for CredentialError {
    fn from(value: AuthenticationError) -> Self {
        CredentialError::AuthError(value)
    }
}

pub async fn credential_handler(
    State(appstate): State<AppState>,
    Json(credential): Json<Credentials>,
) -> Result<impl IntoResponse, ApiError> {
    publish_credentials(credential.to_owned(), appstate)
        .await
        .map_err(ApiError::from)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"status": "Credentials stored successfully"})),
    )
        .into_response())
}

pub(super) async fn publish_credentials(
    credentials: Credentials,
    state: AppState,
) -> Result<(), CredentialError> {
    let store = &state.credential_repo;
    if store.find_one_by(&credentials.issuer).await?.is_some() {
        return Err(CredentialError::RepoError(RepositoryError::DuplicateEntry));
    }

    let credential = Credentials::new(credentials.issuer, credentials.public_key);
    store.insert_one(credential).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{models::credentials, test_utils::test_app_state};
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
        let credentials = Credentials::new("test_issuer".into(), jwk.clone());
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
